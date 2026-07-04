"""
Run an API-planner baseline for DT recovery.

The baseline has two stages:
1. A frontier API model sees only the incident-facing context
   (system/logs/incident) and generates a complete ordered list of high-level
   recovery actions.
2. The same low-level command-generation and DT execution stack used by the
   main experiments converts each high-level action into commands, executes
   them, and records timing.

This script intentionally does not use the local checkpoint for high-level
action generation or recovery-state prediction. The comparison isolates whether
a frontier API model can directly produce a strong high-level recovery plan
from the same incident context.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

import requests

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from llm_ir_dt.constants.constants import DIGITAL_TWIN
from llm_ir_dt.recovery_loop.command_agent import (
    CommandAgentRequest,
    DeepSeekCommandAgent,
    MockCommandAgent,
    OpenAICommandAgent,
)
from llm_ir_dt.recovery_loop.command_safety import CommandSafetyValidator
from llm_ir_dt.recovery_loop.recovery_executor import RecoveryExecutor
from llm_ir_dt.recovery_loop.schemas import (
    CommandPlan,
    HighLevelAction,
    RECOVERY_STATE_FIELDS,
    RecoveryState,
    dataclass_to_jsonable,
    initial_recovery_state,
)

from run_recovery_loop_llm_state import (
    DEFAULT_INCIDENT,
    DEFAULT_LOGS,
    DEFAULT_SYSTEM,
    TARGET_SERVER_IPS,
    read_text_arg,
)


def extract_json_object(text: str) -> dict[str, Any]:
    decoder = json.JSONDecoder()
    for index, char in enumerate(text):
        if char != "{":
            continue
        try:
            obj, _ = decoder.raw_decode(text[index:])
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            return obj
    raise ValueError(f"No JSON object found in model output: {text[:500]}")


def normalize_action_plan(raw_output: str, *, max_actions: int) -> list[HighLevelAction]:
    parsed = extract_json_object(raw_output)
    raw_actions = parsed.get("Actions") or parsed.get("actions") or parsed.get("Plan") or parsed.get("plan")
    if not isinstance(raw_actions, list):
        raise ValueError("API high-level plan must contain an Actions list")

    actions: list[HighLevelAction] = []
    seen: set[str] = set()
    for item in raw_actions:
        if isinstance(item, str):
            action_text = item.strip()
            explanation = ""
        elif isinstance(item, dict):
            action_text = str(item.get("Action") or item.get("action") or "").strip()
            explanation = str(item.get("Explanation") or item.get("explanation") or "").strip()
        else:
            continue
        key = " ".join(action_text.lower().split())
        if not key or key in seen:
            continue
        seen.add(key)
        actions.append(
            HighLevelAction(
                action=action_text,
                explanation=explanation,
                raw_model_output=raw_output,
            )
        )
        if len(actions) >= max_actions:
            break
    if not actions:
        raise ValueError("API high-level plan did not contain any valid actions")
    return actions


class DeepSeekCompletePlanGenerator:
    """Generate a complete high-level recovery action list with DeepSeek."""

    def __init__(
        self,
        *,
        model: str,
        api_key: str | None = None,
        api_key_env: str = "DEEPSEEK_API_KEY",
        base_url: str = "https://api.deepseek.com",
        timeout_seconds: int = 120,
        max_tokens: int = 3000,
        temperature: float = 0.2,
        top_p: float = 0.9,
        max_attempts: int = 3,
    ) -> None:
        self.model = model
        self.api_key = api_key or os.getenv(api_key_env, "").strip()
        self.api_key_env = api_key_env
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.top_p = top_p
        self.max_attempts = max_attempts
        self.response_attempts: list[dict[str, Any]] = []
        if not self.api_key:
            raise ValueError(f"DeepSeek API key is missing. Set {api_key_env}.")
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")

    def generate(self, *, context: dict[str, str], max_actions: int) -> tuple[list[HighLevelAction], str]:
        prompt = self._build_prompt(context=context, max_actions=max_actions)
        base_payload: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a cybersecurity incident response planner. "
                        "Generate a complete high-level recovery plan as valid JSON."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            "response_format": {"type": "json_object"},
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "top_p": self.top_p,
        }
        self.response_attempts = []
        last_error = "empty response"

        for attempt in range(1, self.max_attempts + 1):
            payload = dict(base_payload)
            if attempt > 1:
                payload.pop("response_format", None)

            response = self._post_with_parameter_fallback(payload)
            attempt_record: dict[str, Any] = {
                "attempt": attempt,
                "used_response_format": "response_format" in payload,
                "status_code": response.status_code,
            }
            if response.status_code >= 400:
                attempt_record["response_text"] = response.text
                self.response_attempts.append(attempt_record)
                raise RuntimeError(
                    f"High-level plan generation failed for {self.model}: "
                    f"HTTP {response.status_code}: {response.text}"
                )

            try:
                data = response.json()
            except ValueError as exc:
                attempt_record["response_text"] = response.text
                attempt_record["error"] = "response was not valid JSON"
                self.response_attempts.append(attempt_record)
                last_error = str(exc)
                if attempt < self.max_attempts:
                    time.sleep(attempt)
                    continue
                break

            attempt_record["response_json"] = data
            raw_output = self._extract_message_text(data)
            if not raw_output:
                finish_reason = self._finish_reason(data)
                attempt_record["error"] = "empty model output"
                attempt_record["finish_reason"] = finish_reason
                self.response_attempts.append(attempt_record)
                last_error = f"empty model output (finish_reason={finish_reason!r})"
                if attempt < self.max_attempts:
                    time.sleep(attempt)
                    continue
                break

            try:
                actions = normalize_action_plan(raw_output, max_actions=max_actions)
            except ValueError as exc:
                attempt_record["error"] = str(exc)
                self.response_attempts.append(attempt_record)
                last_error = str(exc)
                if attempt < self.max_attempts:
                    time.sleep(attempt)
                    continue
                break

            attempt_record["output_source"] = self._message_output_source(data)
            self.response_attempts.append(attempt_record)
            return actions, raw_output

        raise RuntimeError(
            f"High-level plan generation failed for {self.model} after "
            f"{self.max_attempts} attempts: {last_error}"
        )

    @staticmethod
    def _message(data: dict[str, Any]) -> dict[str, Any]:
        choices = data.get("choices")
        if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
            return {}
        message = choices[0].get("message")
        return message if isinstance(message, dict) else {}

    @classmethod
    def _extract_message_text(cls, data: dict[str, Any]) -> str:
        message = cls._message(data)
        for key in ("content", "reasoning_content"):
            text = cls._content_to_text(message.get(key))
            if text:
                return text
        return ""

    @staticmethod
    def _content_to_text(content: Any) -> str:
        if isinstance(content, str):
            return content.strip()
        if not isinstance(content, list):
            return ""

        parts: list[str] = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict):
                text = item.get("text")
                if isinstance(text, str):
                    parts.append(text)
                elif isinstance(text, dict) and isinstance(text.get("value"), str):
                    parts.append(text["value"])
        return "\n".join(part.strip() for part in parts if part.strip()).strip()

    @classmethod
    def _message_output_source(cls, data: dict[str, Any]) -> str:
        message = cls._message(data)
        if cls._content_to_text(message.get("content")):
            return "content"
        if cls._content_to_text(message.get("reasoning_content")):
            return "reasoning_content"
        return "none"

    @staticmethod
    def _finish_reason(data: dict[str, Any]) -> Any:
        choices = data.get("choices")
        if isinstance(choices, list) and choices and isinstance(choices[0], dict):
            return choices[0].get("finish_reason")
        return None

    def _post_with_parameter_fallback(self, payload: dict[str, Any]) -> requests.Response:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        response = requests.post(
            f"{self.base_url}/chat/completions",
            headers=headers,
            json=payload,
            timeout=self.timeout_seconds,
        )
        if response.status_code < 400:
            return response

        text = response.text.lower()
        retried = False
        for parameter in ("top_p", "temperature"):
            if parameter in payload and "unsupported parameter" in text and parameter in text:
                payload = dict(payload)
                payload.pop(parameter, None)
                retried = True
                response = requests.post(
                    f"{self.base_url}/chat/completions",
                    headers=headers,
                    json=payload,
                    timeout=self.timeout_seconds,
                )
                if response.status_code < 400:
                    return response
                text = response.text.lower()
        return response

    def _build_prompt(self, *, context: dict[str, str], max_actions: int) -> str:
        return (
            "Below is the incident-facing context available to the high-level "
            "recovery planner. Use only the system description, logs, incident "
            "description, and prioritized target server. Do not use digital-twin "
            "implementation details and do not include shell commands.\n\n"
            f"### System:\n{context.get('System', '').strip()}\n\n"
            f"### Logs:\n{context.get('Logs', '').strip()}\n\n"
            f"### Incident:\n{context.get('Incident', '').strip()}\n\n"
            f"### Prioritized target server:\n{context.get('TargetServer', '').strip()}\n\n"
            "### Instruction:\n"
            f"Generate a complete ordered list of at most {max_actions} high-level "
            "recovery actions for recovering the prioritized target server from "
            "this incident. The plan should cover containment, assessment, "
            "forensic preservation, eradication, hardening, and service "
            "restoration when applicable. Each action should be concrete enough "
            "for a downstream command-generation agent, but should not contain "
            "shell commands or implementation-specific command syntax.\n\n"
            "Return valid JSON only with exactly this shape:\n"
            "{\n"
            '  "Actions": [\n'
            '    {"Action": "...", "Explanation": "..."},\n'
            '    {"Action": "...", "Explanation": "..."}\n'
            "  ]\n"
            "}"
        )


def run_command(command: list[str], *, cwd: Path) -> float:
    start = time.perf_counter()
    subprocess.run(command, cwd=cwd, check=True)
    return time.perf_counter() - start


def restore_and_attack(
    *,
    wait_seconds: int,
    rebuild_images: bool,
    attack_script: str,
    attack_args: list[str],
) -> dict[str, float]:
    timings: dict[str, float] = {}
    stop_cmd = [sys.executable, "stop.py"]
    start_cmd = [sys.executable, "start.py"]
    if rebuild_images:
        start_cmd.append("--build")
    timings["stop_seconds"] = run_command(stop_cmd, cwd=ROOT)
    timings["start_seconds"] = run_command(start_cmd, cwd=ROOT)
    timings["wait_seconds"] = float(wait_seconds)
    if wait_seconds > 0:
        time.sleep(wait_seconds)
    timings["attack_seconds"] = run_command([sys.executable, attack_script, *attack_args], cwd=ROOT)
    return timings


def plan_for_action(
    *,
    command_agent: Any,
    action: HighLevelAction,
    state: RecoveryState,
    context: dict[str, str],
    dt_context: str,
    server: str,
    server_ip: str,
    attacker_ip: str,
    history_actions: list[HighLevelAction],
) -> CommandPlan:
    return command_agent.generate_plan(
        CommandAgentRequest(
            high_level_action=action,
            current_state=state,
            system=context.get("System", ""),
            logs=context.get("Logs", ""),
            incident=context.get("Incident", ""),
            dt_context=dt_context,
            server=server,
            server_ip=server_ip,
            attacker_ip=attacker_ip,
        )
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run a two-stage API high-level-plan baseline with DT command execution."
    )
    parser.add_argument(
        "--server",
        choices=tuple(TARGET_SERVER_IPS),
        default="server_ssh",
        help="Prioritized target server to recover.",
    )
    parser.add_argument("--server-ip", default=None)
    parser.add_argument("--attacker-ip", default="10.0.1.11")
    parser.add_argument("--max-actions", type=int, default=7)
    parser.add_argument("--api-action-model", default="deepseek-v4-pro")
    parser.add_argument("--api-action-key-env", default="DEEPSEEK_API_KEY")
    parser.add_argument("--api-action-base-url", default="https://api.deepseek.com")
    parser.add_argument("--api-action-timeout-seconds", type=int, default=120)
    parser.add_argument("--api-action-max-tokens", type=int, default=3000)
    parser.add_argument("--api-action-temperature", type=float, default=0.2)
    parser.add_argument("--api-action-top-p", type=float, default=0.9)
    parser.add_argument("--api-action-max-attempts", type=int, default=3)
    parser.add_argument(
        "--command-agent",
        choices=("mock", "openai", "deepseek"),
        default="deepseek",
    )
    parser.add_argument("--openai-model", default="gpt-5.5")
    parser.add_argument("--openai-api-key-env", default="OPENAI_API_KEY")
    parser.add_argument("--openai-base-url", default="https://api.openai.com/v1")
    parser.add_argument("--openai-timeout-seconds", type=int, default=120)
    parser.add_argument("--deepseek-model", default="deepseek-v4-pro")
    parser.add_argument("--deepseek-api-key-env", default="DEEPSEEK_API_KEY")
    parser.add_argument("--deepseek-base-url", default="https://api.deepseek.com")
    parser.add_argument("--deepseek-timeout-seconds", type=int, default=120)
    parser.add_argument("--deepseek-max-tokens", type=int, default=8192)
    parser.add_argument("--system", default=None)
    parser.add_argument("--logs", default=None)
    parser.add_argument("--incident", default=None)
    parser.add_argument("--system-file", default=None)
    parser.add_argument("--logs-file", default=None)
    parser.add_argument("--incident-file", default=None)
    parser.add_argument("--dt-context-file", default=None)
    parser.add_argument("--attack-script", default="run_attack.py")
    parser.add_argument("--attack-arg", action="append", default=[])
    parser.add_argument("--wait-seconds", type=int, default=15)
    parser.add_argument("--rebuild-images", action="store_true")
    parser.add_argument(
        "--artifacts-dir",
        default=str(ROOT / "artifacts" / "recovery_api_deepseekv4pro"),
    )
    args = parser.parse_args()

    server_ip = args.server_ip or TARGET_SERVER_IPS[args.server]
    context = {
        "System": read_text_arg(args.system, args.system_file, DEFAULT_SYSTEM),
        "Logs": read_text_arg(args.logs, args.logs_file, DEFAULT_LOGS),
        "Incident": read_text_arg(args.incident, args.incident_file, DEFAULT_INCIDENT),
        "TargetServer": f"{args.server} / {server_ip}",
    }
    dt_context = (
        Path(args.dt_context_file).expanduser().read_text(encoding="utf-8").strip()
        if args.dt_context_file
        else ""
    )

    if args.command_agent == "openai":
        command_agent = OpenAICommandAgent(
            model=args.openai_model,
            api_key_env=args.openai_api_key_env,
            base_url=args.openai_base_url,
            timeout_seconds=args.openai_timeout_seconds,
        )
    elif args.command_agent == "deepseek":
        command_agent = DeepSeekCommandAgent(
            model=args.deepseek_model,
            api_key_env=args.deepseek_api_key_env,
            base_url=args.deepseek_base_url,
            timeout_seconds=args.deepseek_timeout_seconds,
            max_tokens=args.deepseek_max_tokens,
        )
    else:
        command_agent = MockCommandAgent()

    run_dir = Path(args.artifacts_dir) / "runs" / datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "context.json").write_text(
        json.dumps(
            {
                **context,
                "BaselineType": "api_complete_high_level_plan",
                "HighLevelPlanModel": args.api_action_model,
                "CommandAgent": args.command_agent,
                "CommandModel": args.deepseek_model if args.command_agent == "deepseek" else args.openai_model,
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    plan_generator = DeepSeekCompletePlanGenerator(
        model=args.api_action_model,
        api_key_env=args.api_action_key_env,
        base_url=args.api_action_base_url,
        timeout_seconds=args.api_action_timeout_seconds,
        max_tokens=args.api_action_max_tokens,
        temperature=args.api_action_temperature,
        top_p=args.api_action_top_p,
        max_attempts=args.api_action_max_attempts,
    )
    try:
        high_level_actions, raw_high_level_output = plan_generator.generate(
            context=context,
            max_actions=args.max_actions,
        )
    finally:
        (run_dir / "api_high_level_plan_attempts.json").write_text(
            json.dumps(plan_generator.response_attempts, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    executed_plans_dir = run_dir / "executed_plans"
    failed_plans_dir = run_dir / "failed_plans"
    executed_plans_dir.mkdir(parents=True, exist_ok=True)
    failed_plans_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "api_high_level_plan.json").write_text(
        json.dumps(
            {
                "raw_output": raw_high_level_output,
                "actions": [dataclass_to_jsonable(action) for action in high_level_actions],
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    restore_timings = restore_and_attack(
        wait_seconds=args.wait_seconds,
        rebuild_images=args.rebuild_images,
        attack_script=args.attack_script,
        attack_args=args.attack_arg,
    )

    executor = RecoveryExecutor()
    safety = CommandSafetyValidator()
    executed_plans: list[CommandPlan] = []
    history_actions: list[HighLevelAction] = []
    state = initial_recovery_state()
    step_summaries: list[dict[str, Any]] = []
    execution_start = time.perf_counter()

    for step, action in enumerate(high_level_actions, start=1):
        step_start = time.perf_counter()
        plan = None
        result = None
        try:
            plan = plan_for_action(
                command_agent=command_agent,
                action=action,
                state=state,
                context=context,
                dt_context=dt_context,
                server=args.server,
                server_ip=server_ip,
                attacker_ip=args.attacker_ip,
                history_actions=history_actions,
            )
            safety.validate_plan(plan)
            result = executor.execute_plan(plan, state_before=state)
            success = result.success
            error = ""
        except Exception as exc:
            success = False
            error = f"{type(exc).__name__}: {exc}"

        elapsed = time.perf_counter() - step_start
        if plan is not None and result is not None:
            executed_plans.append(plan)
            history_actions.append(action)
            plan_payload = {
                "step": step,
                "plan": dataclass_to_jsonable(plan),
                "execution": dataclass_to_jsonable(result),
                "wall_clock_time_seconds": elapsed,
            }
            (executed_plans_dir / f"step_{step:03d}.json").write_text(
                json.dumps(plan_payload, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        elif plan is not None:
            failed_payload = {
                "step": step,
                "plan": dataclass_to_jsonable(plan),
                "error": error,
                "wall_clock_time_seconds": elapsed,
            }
            (failed_plans_dir / f"step_{step:03d}.json").write_text(
                json.dumps(failed_payload, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        step_summaries.append(
            {
                "step": step,
                "action": dataclass_to_jsonable(action),
                "success": success,
                "error": error,
                "action_total_time_seconds": result.action_total_time_seconds if result else 0.0,
                "wall_clock_time_seconds": elapsed,
            }
        )
        print(
            f"step={step} success={success} "
            f"action_total_time_seconds={step_summaries[-1]['action_total_time_seconds']:.3f} "
            f"action={action.action}"
        )
        if not success:
            break

    total_wall_clock = time.perf_counter() - execution_start
    summary = {
        "server": args.server,
        "server_ip": server_ip,
        "restore_timings": restore_timings,
        "steps": step_summaries,
        "executed_action_total_time_seconds": sum(
            item["action_total_time_seconds"] for item in step_summaries
        ),
        "execution_wall_clock_time_seconds": total_wall_clock,
        "total_wall_clock_including_restore_seconds": total_wall_clock
        + sum(restore_timings.values()),
    }
    (run_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"Generated {len(high_level_actions)} high-level actions.")
    print(f"Artifacts: {run_dir}")
    print(
        "executed_action_total_time_seconds="
        f"{summary['executed_action_total_time_seconds']:.3f}"
    )
    print(
        "execution_wall_clock_time_seconds="
        f"{summary['execution_wall_clock_time_seconds']:.3f}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
