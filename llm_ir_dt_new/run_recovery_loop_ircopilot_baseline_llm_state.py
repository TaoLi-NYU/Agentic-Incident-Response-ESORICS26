"""
Run an IRCopilot-style IRT baseline for DT recovery.

The baseline changes only high-level recovery-action generation:
1. Each compromised-server recovery task is represented as an Incident
   Response Tree (IRT) with six fixed subtasks aligned to the recovery-state
   dimensions used by the main method.
2. A planner selects the next IRT subtask deterministically, prioritizing
   repair tasks after failures.
3. An API generator converts the selected subtask into one high-level recovery
   action.
4. The standard command agent, DT execution, verification, and timing stack
   executes that action.

This is an IRCopilot-style baseline rather than an exact reproduction of the
original IRCopilot benchmark setup. It preserves IRT decomposition, feedback
updates, and reflection-style repair while controlling command generation and
DT execution.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import requests
import torch
from peft import PeftConfig, PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer

ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = ROOT.parent
PROJECT_SRC = PROJECT_ROOT / "src"
SRC = ROOT / "src"
for path in (PROJECT_ROOT, PROJECT_SRC, SRC):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from llm_ir_dt.recovery_loop.command_agent import (  # noqa: E402
    DeepSeekCommandAgent,
    MockCommandAgent,
    OpenAICommandAgent,
)
from llm_ir_dt.recovery_loop.command_safety import CommandSafetyValidator  # noqa: E402
from llm_ir_dt.recovery_loop.recovery_executor import RecoveryExecutor  # noqa: E402
from llm_ir_dt.recovery_loop.schemas import (  # noqa: E402
    CommandPlan,
    HighLevelAction,
    RECOVERY_STATE_FIELDS,
    RecoveryState,
    dataclass_to_jsonable,
    initial_recovery_state,
    is_terminal_state,
)
from examples.planning_simulation_qwen_lora_DTserver import (  # noqa: E402
    build_action_prompt,
)
from run_recovery_loop_api_baseline_llm_state import (  # noqa: E402
    extract_json_object,
    plan_for_action,
    restore_and_attack,
)
from run_recovery_loop_llm_state import (  # noqa: E402
    DEFAULT_INCIDENT,
    DEFAULT_LOGS,
    DEFAULT_SYSTEM,
    TARGET_SERVER_IPS,
    read_text_arg,
)


SUBTASK_DESCRIPTIONS: dict[str, str] = {
    "is_attack_contained": (
        "Contain the active attack against the target server and prevent "
        "continued attacker access or lateral movement."
    ),
    "is_knowledge_sufficient": (
        "Assess the incident scope for the target server and gather enough "
        "knowledge to guide eradication and recovery."
    ),
    "are_forensics_preserved": (
        "Preserve relevant forensic evidence for the target server, gateway, "
        "IDS, application logs, and attacker-created artifacts."
    ),
    "is_eradicated": (
        "Remove the attacker foothold, malicious artifacts, unauthorized "
        "changes, vulnerable execution path, or persistence mechanism."
    ),
    "is_hardened": (
        "Harden the target server and related access controls to reduce the "
        "chance of recurrence."
    ),
    "is_recovered": (
        "Restore the target service to controlled operation and validate that "
        "the recovered server works securely."
    ),
}


@dataclass
class IRTNode:
    id: str
    recovery_state_field: str
    task: str
    status: str = "to_do"
    repair_attempts: int = 0
    parent_id: str | None = None
    repair_for: str | None = None
    history: list[dict[str, Any]] = field(default_factory=list)


def node_to_jsonable(node: IRTNode) -> dict[str, Any]:
    return {
        "id": node.id,
        "recovery_state_field": node.recovery_state_field,
        "task": node.task,
        "status": node.status,
        "repair_attempts": node.repair_attempts,
        "parent_id": node.parent_id,
        "repair_for": node.repair_for,
        "history": node.history,
    }


def initialize_irt(*, server: str, server_ip: str) -> list[IRTNode]:
    nodes: list[IRTNode] = []
    for index, field_name in enumerate(RECOVERY_STATE_FIELDS, start=1):
        nodes.append(
            IRTNode(
                id=f"1.{index}",
                recovery_state_field=field_name,
                task=(
                    f"{field_name}: {SUBTASK_DESCRIPTIONS[field_name]} "
                    f"Target server: {server} ({server_ip})."
                ),
            )
        )
    return nodes


def find_node(nodes: list[IRTNode], node_id: str) -> IRTNode:
    for node in nodes:
        if node.id == node_id:
            return node
    raise KeyError(f"IRT node not found: {node_id}")


def select_next_subtask(nodes: list[IRTNode]) -> IRTNode | None:
    for node in nodes:
        if node.status == "repairing":
            return node
    for node in nodes:
        if node.status == "to_do":
            return node
    return None


def create_repair_task(nodes: list[IRTNode], failed_node: IRTNode) -> IRTNode:
    repair_attempt = failed_node.repair_attempts + 1
    failed_node.repair_attempts = repair_attempt
    repair_node = IRTNode(
        id=f"{failed_node.id}.repair{repair_attempt}",
        recovery_state_field=failed_node.recovery_state_field,
        task=(
            f"Repair failed subtask {failed_node.id} "
            f"({failed_node.recovery_state_field}). Diagnose why the previous "
            "recovery action failed, then generate a narrower corrective "
            "high-level recovery action for the same target server."
        ),
        status="repairing",
        repair_attempts=repair_attempt,
        parent_id=failed_node.id,
        repair_for=failed_node.id,
    )
    nodes.append(repair_node)
    return repair_node


class APISubtaskActionGenerator:
    """Generate one high-level action for a selected IRT subtask."""

    def __init__(
        self,
        *,
        model: str,
        api_key_env: str,
        base_url: str,
        timeout_seconds: int,
        max_tokens: int,
        temperature: float,
        top_p: float,
        max_attempts: int,
    ) -> None:
        self.model = model
        self.api_key_env = api_key_env
        self.api_key = os.getenv(api_key_env, "").strip()
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.top_p = top_p
        self.max_attempts = max_attempts
        self.response_attempts: list[dict[str, Any]] = []
        if not self.api_key:
            raise ValueError(f"API key is missing. Set {api_key_env}.")
        if max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")

    def generate(
        self,
        *,
        context: dict[str, str],
        irt_nodes: list[IRTNode],
        selected_node: IRTNode,
        current_state: RecoveryState,
        previous_steps: list[dict[str, Any]],
    ) -> tuple[HighLevelAction, str]:
        prompt = self._build_prompt(
            context=context,
            irt_nodes=irt_nodes,
            selected_node=selected_node,
            current_state=current_state,
            previous_steps=previous_steps,
        )
        base_payload: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are the Generator in an IRCopilot-style incident "
                        "response system. Convert one selected IRT subtask into "
                        "one high-level recovery action. Do not generate shell "
                        "commands."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            "response_format": {"type": "json_object"},
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "top_p": self.top_p,
        }
        last_error = "empty response"
        self.response_attempts = []

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
                    f"IRCopilot subtask action generation failed for "
                    f"{self.model}: HTTP {response.status_code}: {response.text}"
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
                action = self._parse_action(raw_output)
            except ValueError as exc:
                attempt_record["error"] = str(exc)
                self.response_attempts.append(attempt_record)
                last_error = str(exc)
                if attempt < self.max_attempts:
                    time.sleep(attempt)
                    continue
                break

            self.response_attempts.append(attempt_record)
            return action, raw_output

        raise RuntimeError(
            f"IRCopilot subtask action generation failed for {self.model} "
            f"after {self.max_attempts} attempts: {last_error}"
        )

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
        for parameter in ("top_p", "temperature"):
            if (
                parameter in payload
                and "unsupported parameter" in text
                and parameter in text
            ):
                payload = dict(payload)
                payload.pop(parameter, None)
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

    @staticmethod
    def _finish_reason(data: dict[str, Any]) -> Any:
        choices = data.get("choices")
        if isinstance(choices, list) and choices and isinstance(choices[0], dict):
            return choices[0].get("finish_reason")
        return None

    @staticmethod
    def _parse_action(raw_output: str) -> HighLevelAction:
        parsed = extract_json_object(raw_output)
        action_text = str(parsed.get("Action") or parsed.get("action") or "").strip()
        explanation = str(
            parsed.get("Explanation") or parsed.get("explanation") or ""
        ).strip()
        if not action_text:
            raise ValueError("Generated JSON must contain an Action string")
        return HighLevelAction(
            action=action_text,
            explanation=explanation,
            raw_model_output=raw_output,
        )

    @staticmethod
    def _build_prompt(
        *,
        context: dict[str, str],
        irt_nodes: list[IRTNode],
        selected_node: IRTNode,
        current_state: RecoveryState,
        previous_steps: list[dict[str, Any]],
    ) -> str:
        return (
            "Below is the incident-facing context and current Incident Response "
            "Tree (IRT). The IRT root task is recovering the prioritized target "
            "server. The six child subtasks are aligned with the recovery-state "
            "dimensions. Generate exactly one high-level recovery action for "
            "the selected IRT subtask. Do not include shell commands, command "
            "syntax, JSON command plans, or digital-twin implementation details.\n\n"
            f"### System:\n{context.get('System', '').strip()}\n\n"
            f"### Logs:\n{context.get('Logs', '').strip()}\n\n"
            f"### Incident:\n{context.get('Incident', '').strip()}\n\n"
            f"### Prioritized target server:\n{context.get('TargetServer', '').strip()}\n\n"
            "### Current recovery state:\n"
            f"{json.dumps(current_state, indent=2)}\n\n"
            "### Current IRT:\n"
            f"{json.dumps([node_to_jsonable(node) for node in irt_nodes], indent=2)}\n\n"
            "### Previous execution summaries:\n"
            f"{json.dumps(previous_steps[-3:], indent=2, ensure_ascii=False)}\n\n"
            "### Selected IRT subtask:\n"
            f"{json.dumps(node_to_jsonable(selected_node), indent=2)}\n\n"
            "Return valid JSON only with exactly this shape:\n"
            "{\n"
            '  "Action": "...",\n'
            '  "Explanation": "..."\n'
            "}"
        )


class LocalCheckpointSubtaskActionGenerator:
    """Generate one IRT-subtask action with the local checkpoint policy."""

    def __init__(
        self,
        *,
        adapter: str,
        base_model: str | None,
        device_map: str,
        torch_dtype: str,
        max_new_tokens: int,
        temperature: float,
        top_p: float,
    ) -> None:
        self.adapter = adapter
        self.base_model = base_model
        self.device_map = device_map
        self.torch_dtype = torch_dtype
        self.max_new_tokens = max_new_tokens
        self.temperature = temperature
        self.top_p = top_p
        self._tokenizer = None
        self._model = None

    def generate(
        self,
        *,
        context: dict[str, str],
        irt_nodes: list[IRTNode],
        selected_node: IRTNode,
        current_state: RecoveryState,
        previous_steps: list[dict[str, Any]],
    ) -> tuple[HighLevelAction, str]:
        tokenizer, model = self._load()
        prompt = self._build_prompt(
            context=context,
            irt_nodes=irt_nodes,
            selected_node=selected_node,
            current_state=current_state,
            previous_steps=previous_steps,
        )
        inputs = tokenizer(prompt, return_tensors="pt")
        inputs = {key: value.to(model.device) for key, value in inputs.items()}
        do_sample = self.temperature > 0.0
        with torch.no_grad():
            output_ids = model.generate(
                **inputs,
                max_new_tokens=self.max_new_tokens,
                do_sample=do_sample,
                temperature=self.temperature if do_sample else None,
                top_p=self.top_p if do_sample else None,
                pad_token_id=tokenizer.pad_token_id,
                eos_token_id=tokenizer.eos_token_id,
            )
        decoded = tokenizer.decode(output_ids[0], skip_special_tokens=True)
        raw_output = decoded[len(prompt):] if decoded.startswith(prompt) else decoded
        raw_output = raw_output.strip()
        action = self._parse_action(raw_output)
        return action, raw_output

    def _load(self):
        if self._tokenizer is not None and self._model is not None:
            return self._tokenizer, self._model

        dtype = getattr(torch, self.torch_dtype)
        peft_config = PeftConfig.from_pretrained(self.adapter)
        base_name = self.base_model or peft_config.base_model_name_or_path
        tokenizer = AutoTokenizer.from_pretrained(base_name, use_fast=True)
        base = AutoModelForCausalLM.from_pretrained(
            base_name,
            device_map=self.device_map,
            torch_dtype=dtype,
        )
        model = PeftModel.from_pretrained(base, self.adapter)
        if tokenizer.pad_token is None:
            tokenizer.pad_token = tokenizer.eos_token
        model.eval()
        self._tokenizer = tokenizer
        self._model = model
        return tokenizer, model

    @staticmethod
    def _parse_action(raw_output: str) -> HighLevelAction:
        parsed = extract_json_object(raw_output)
        if parsed is None:
            action_text = raw_output.strip()
            explanation = ""
        else:
            action_text = str(parsed.get("Action") or parsed.get("action") or "").strip()
            explanation = str(
                parsed.get("Explanation") or parsed.get("explanation") or ""
            ).strip()
        if not action_text:
            raise ValueError("Local checkpoint generated an empty action")
        return HighLevelAction(
            action=action_text,
            explanation=explanation,
            raw_model_output=raw_output,
        )

    @staticmethod
    def _build_prompt(
        *,
        context: dict[str, str],
        irt_nodes: list[IRTNode],
        selected_node: IRTNode,
        current_state: RecoveryState,
        previous_steps: list[dict[str, Any]],
    ) -> str:
        previous_actions = [
            str(step.get("action", {}).get("action", "")).strip()
            for step in previous_steps
            if isinstance(step.get("action"), dict)
            and str(step.get("action", {}).get("action", "")).strip()
        ]
        prompt_context = dict(context)
        prompt_context["Logs"] = (
            f"{context.get('Logs', '').strip()}\n\n"
            "Current IRCopilot-style IRT:\n"
            f"{json.dumps([node_to_jsonable(node) for node in irt_nodes], indent=2)}\n\n"
            "Selected IRT subtask to address now:\n"
            f"{json.dumps(node_to_jsonable(selected_node), indent=2)}\n\n"
            "Generate the next action for this selected subtask only. "
            "If the selected subtask is a repair task, generate a narrower "
            "corrective action for the failed recovery-state dimension."
        ).strip()
        state_tuple = tuple(
            bool(current_state.get(field_name, False))
            for field_name in RECOVERY_STATE_FIELDS
        )
        return build_action_prompt(
            prompt_context,
            state_tuple,
            previous_actions,
        ).rstrip()


def build_command_agent(args: argparse.Namespace) -> Any:
    if args.command_agent == "openai":
        return OpenAICommandAgent(
            model=args.openai_model,
            api_key_env=args.openai_api_key_env,
            base_url=args.openai_base_url,
            timeout_seconds=args.openai_timeout_seconds,
        )
    if args.command_agent == "deepseek":
        return DeepSeekCommandAgent(
            model=args.deepseek_model,
            api_key_env=args.deepseek_api_key_env,
            base_url=args.deepseek_base_url,
            timeout_seconds=args.deepseek_timeout_seconds,
            max_tokens=args.deepseek_max_tokens,
        )
    return MockCommandAgent()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run an IRCopilot-style IRT baseline with standard DT command "
            "execution."
        )
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
    parser.add_argument("--max-repair-attempts", type=int, default=2)
    parser.add_argument(
        "--action-provider",
        choices=("local-model", "api"),
        default="local-model",
        help=(
            "Provider for IRT-subtask high-level recovery actions. "
            "Use local-model for the checkpoint-850 same-policy baseline."
        ),
    )
    parser.add_argument("--adapter", default=None)
    parser.add_argument("--base-model", default=None)
    parser.add_argument("--device-map", default="auto")
    parser.add_argument(
        "--torch-dtype",
        choices=("float16", "bfloat16"),
        default="float16",
    )
    parser.add_argument("--action-max-new-tokens", type=int, default=500)
    parser.add_argument("--action-temperature", type=float, default=0.6)
    parser.add_argument("--action-top-p", type=float, default=0.9)
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
        default=str(ROOT / "artifacts" / "recovery_ircopilot_baseline"),
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.max_actions < 1:
        raise ValueError("--max-actions must be at least 1")
    if args.max_repair_attempts < 1:
        raise ValueError("--max-repair-attempts must be at least 1")

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

    run_dir = (
        Path(args.artifacts_dir)
        / "runs"
        / datetime.now().strftime("%Y%m%d_%H%M%S")
    )
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "irt_updates").mkdir(parents=True, exist_ok=True)
    (run_dir / "selected_subtasks").mkdir(parents=True, exist_ok=True)
    (run_dir / "generated_actions").mkdir(parents=True, exist_ok=True)
    (run_dir / "api_action_attempts").mkdir(parents=True, exist_ok=True)
    (run_dir / "executed_plans").mkdir(parents=True, exist_ok=True)
    (run_dir / "failed_plans").mkdir(parents=True, exist_ok=True)

    command_model = (
        args.deepseek_model
        if args.command_agent == "deepseek"
        else args.openai_model
        if args.command_agent == "openai"
        else "mock"
    )
    (run_dir / "context.json").write_text(
        json.dumps(
            {
                **context,
                "BaselineType": "ircopilot_style_irt",
                "ActionProvider": args.action_provider,
                "HighLevelPlanModel": args.api_action_model,
                "LocalCheckpoint": args.adapter,
                "CommandAgent": args.command_agent,
                "CommandModel": command_model,
                "MaxRepairAttempts": args.max_repair_attempts,
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    irt_nodes = initialize_irt(server=args.server, server_ip=server_ip)
    (run_dir / "irt_initial.json").write_text(
        json.dumps(
            [node_to_jsonable(node) for node in irt_nodes],
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    if args.action_provider == "local-model":
        if not args.adapter:
            raise ValueError("--adapter is required when --action-provider local-model")
        action_generator = LocalCheckpointSubtaskActionGenerator(
            adapter=args.adapter,
            base_model=args.base_model,
            device_map=args.device_map,
            torch_dtype=args.torch_dtype,
            max_new_tokens=args.action_max_new_tokens,
            temperature=args.action_temperature,
            top_p=args.action_top_p,
        )
    else:
        action_generator = APISubtaskActionGenerator(
            model=args.api_action_model,
            api_key_env=args.api_action_key_env,
            base_url=args.api_action_base_url,
            timeout_seconds=args.api_action_timeout_seconds,
            max_tokens=args.api_action_max_tokens,
            temperature=args.api_action_temperature,
            top_p=args.api_action_top_p,
            max_attempts=args.api_action_max_attempts,
        )
    command_agent = build_command_agent(args)
    restore_timings = restore_and_attack(
        wait_seconds=args.wait_seconds,
        rebuild_images=args.rebuild_images,
        attack_script=args.attack_script,
        attack_args=args.attack_arg,
    )

    executor = RecoveryExecutor()
    safety = CommandSafetyValidator()
    current_state = initial_recovery_state()
    history_actions: list[HighLevelAction] = []
    step_summaries: list[dict[str, Any]] = []
    stop_reason = ""
    execution_start = time.perf_counter()

    for step in range(1, args.max_actions + 1):
        selected_node = select_next_subtask(irt_nodes)
        if selected_node is None:
            stop_reason = "all_irt_subtasks_completed"
            break

        (run_dir / "selected_subtasks" / f"step_{step:03d}.json").write_text(
            json.dumps(node_to_jsonable(selected_node), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        try:
            action, raw_action_output = action_generator.generate(
                context=context,
                irt_nodes=irt_nodes,
                selected_node=selected_node,
                current_state=current_state,
                previous_steps=step_summaries,
            )
        finally:
            if hasattr(action_generator, "response_attempts"):
                (run_dir / "api_action_attempts" / f"step_{step:03d}.json").write_text(
                    json.dumps(
                        action_generator.response_attempts,
                        indent=2,
                        ensure_ascii=False,
                    ),
                    encoding="utf-8",
                )

        (run_dir / "generated_actions" / f"step_{step:03d}.json").write_text(
            json.dumps(
                {
                    "selected_subtask": node_to_jsonable(selected_node),
                    "raw_output": raw_action_output,
                    "action": dataclass_to_jsonable(action),
                },
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )

        step_start = time.perf_counter()
        plan: CommandPlan | None = None
        result = None
        try:
            plan = plan_for_action(
                command_agent=command_agent,
                action=action,
                state=current_state,
                context=context,
                dt_context=dt_context,
                server=args.server,
                server_ip=server_ip,
                attacker_ip=args.attacker_ip,
                history_actions=history_actions,
            )
            safety.validate_plan(plan)
            result = executor.execute_plan(plan, state_before=current_state)
            success = result.success
            error = ""
        except Exception as exc:
            success = False
            error = f"{type(exc).__name__}: {exc}"

        elapsed = time.perf_counter() - step_start
        if plan is not None and result is not None:
            payload = {
                "step": step,
                "selected_subtask": node_to_jsonable(selected_node),
                "plan": dataclass_to_jsonable(plan),
                "execution": dataclass_to_jsonable(result),
                "wall_clock_time_seconds": elapsed,
            }
            (run_dir / "executed_plans" / f"step_{step:03d}.json").write_text(
                json.dumps(payload, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        elif plan is not None:
            payload = {
                "step": step,
                "selected_subtask": node_to_jsonable(selected_node),
                "plan": dataclass_to_jsonable(plan),
                "error": error,
                "wall_clock_time_seconds": elapsed,
            }
            (run_dir / "failed_plans" / f"step_{step:03d}.json").write_text(
                json.dumps(payload, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )

        if success:
            if selected_node.repair_for:
                parent = find_node(irt_nodes, selected_node.repair_for)
                parent.status = "completed"
                selected_node.status = "completed"
                current_state[parent.recovery_state_field] = True
            else:
                selected_node.status = "completed"
                current_state[selected_node.recovery_state_field] = True
            history_actions.append(action)
        else:
            if selected_node.repair_for:
                parent = find_node(irt_nodes, selected_node.repair_for)
                parent.status = "failed"
                selected_node.status = "failed"
                parent_repair_attempts = parent.repair_attempts
            else:
                selected_node.status = "failed"
                parent = selected_node
                parent_repair_attempts = selected_node.repair_attempts

            if parent_repair_attempts >= args.max_repair_attempts:
                stop_reason = (
                    f"repair_failed_{parent.recovery_state_field}_"
                    f"{parent_repair_attempts}_times"
                )
            else:
                repair_node = create_repair_task(irt_nodes, parent)
                stop_reason = ""
                selected_node.history.append(
                    {
                        "step": step,
                        "event": "repair_task_created",
                        "repair_task_id": repair_node.id,
                    }
                )

        selected_node.history.append(
            {
                "step": step,
                "success": success,
                "error": error,
                "action": action.action,
            }
        )
        step_summary = {
            "step": step,
            "selected_subtask": node_to_jsonable(selected_node),
            "action": dataclass_to_jsonable(action),
            "success": success,
            "error": error,
            "action_total_time_seconds": (
                result.action_total_time_seconds if result else 0.0
            ),
            "wall_clock_time_seconds": elapsed,
            "current_recovery_state": dict(current_state),
        }
        step_summaries.append(step_summary)
        (run_dir / "irt_updates" / f"step_{step:03d}.json").write_text(
            json.dumps(
                {
                    "step": step,
                    "irt": [node_to_jsonable(node) for node in irt_nodes],
                    "current_recovery_state": current_state,
                    "stop_reason": stop_reason,
                },
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )

        print(
            f"step={step} success={success} "
            f"subtask={selected_node.id}:{selected_node.recovery_state_field} "
            f"action_total_time_seconds={step_summary['action_total_time_seconds']:.3f} "
            f"action={action.action}"
        )

        if stop_reason:
            break
        if is_terminal_state(current_state):
            stop_reason = "terminal_irt_state_reached"
            break

    if not stop_reason:
        stop_reason = "max_actions_reached"

    execution_wall_clock = time.perf_counter() - execution_start
    summary = {
        "server": args.server,
        "server_ip": server_ip,
        "high_level_plan_generation": {
            "method": "ircopilot_style_irt",
            "action_provider": args.action_provider,
            "local_checkpoint": args.adapter,
            "api_action_model": args.api_action_model,
            "generated_action_count": len(step_summaries),
            "terminal_irt_state_reached": is_terminal_state(current_state),
            "stop_reason": stop_reason,
        },
        "restore_timings": restore_timings,
        "final_recovery_state": current_state,
        "irt": [node_to_jsonable(node) for node in irt_nodes],
        "steps": step_summaries,
        "executed_action_total_time_seconds": sum(
            item["action_total_time_seconds"] for item in step_summaries
        ),
        "execution_wall_clock_time_seconds": execution_wall_clock,
        "total_wall_clock_including_restore_seconds": (
            execution_wall_clock + sum(restore_timings.values())
        ),
    }
    (run_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print(f"Generated {len(step_summaries)} high-level actions.")
    print(f"Artifacts: {run_dir}")
    print(
        "executed_action_total_time_seconds="
        f"{summary['executed_action_total_time_seconds']:.3f}"
    )
    print(
        "execution_wall_clock_time_seconds="
        f"{summary['execution_wall_clock_time_seconds']:.3f}"
    )
    print(f"stop_reason={stop_reason}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
