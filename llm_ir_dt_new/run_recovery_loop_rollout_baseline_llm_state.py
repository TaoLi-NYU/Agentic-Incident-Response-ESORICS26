"""
Run a LoRA rollout-planner baseline followed by DT command execution.

The comparison changes only high-level recovery-action generation:
1. The local LoRA planner samples candidate actions, estimates their remaining
   recovery depth with model rollouts, and produces a complete ordered plan.
2. The existing DeepSeek/OpenAI command agent converts each selected action
   into commands, then the standard DT safety, execution, verification, and
   timing path runs those commands.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Sequence

ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = ROOT.parent
PROJECT_SRC = PROJECT_ROOT / "src"
DT_SRC = ROOT / "src"
for path in (PROJECT_ROOT, PROJECT_SRC, DT_SRC):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from examples.planning_simulation_qwen_lora_DTserver import build_planner
from llm_recovery.decision_transformer.planner import (
    RECOVERY_STATE_FIELDS as PLANNER_STATE_FIELDS,
    TERMINAL_STATE,
    PlannerConfig,
)
from llm_ir_dt.recovery_loop.command_agent import (
    DeepSeekCommandAgent,
    MockCommandAgent,
    OpenAICommandAgent,
)
from llm_ir_dt.recovery_loop.command_safety import CommandSafetyValidator
from llm_ir_dt.recovery_loop.recovery_executor import RecoveryExecutor
from llm_ir_dt.recovery_loop.schemas import (
    CommandPlan,
    HighLevelAction,
    RecoveryState,
    dataclass_to_jsonable,
    initial_recovery_state,
)
from run_recovery_loop_api_baseline_llm_state import (
    plan_for_action,
    restore_and_attack,
)
from run_recovery_loop_llm_state import (
    DEFAULT_INCIDENT,
    DEFAULT_LOGS,
    DEFAULT_SYSTEM,
    TARGET_SERVER_IPS,
    read_text_arg,
)


def state_to_jsonable(state: Sequence[bool]) -> dict[str, bool]:
    return {
        field: bool(state[index])
        for index, field in enumerate(PLANNER_STATE_FIELDS)
    }


def extract_action_object(text: str) -> dict[str, Any] | None:
    """Return the first JSON object containing a single high-level action."""
    decoder = json.JSONDecoder()
    for index, char in enumerate(text):
        if char != "{":
            continue
        try:
            parsed, _ = decoder.raw_decode(text[index:])
        except json.JSONDecodeError:
            continue
        if not isinstance(parsed, dict):
            continue
        if parsed.get("Action") or parsed.get("action"):
            return parsed
    return None


def parse_generated_action(raw_output: str) -> HighLevelAction:
    """Convert the rollout planner's raw single-action output to the shared schema."""
    parsed = extract_action_object(raw_output)
    if parsed is None:
        action = raw_output.strip()
        explanation = ""
    else:
        action = str(parsed.get("Action") or parsed.get("action") or "").strip()
        explanation = str(
            parsed.get("Explanation") or parsed.get("explanation") or ""
        ).strip()
    if not action:
        raise ValueError("Rollout planner produced an empty high-level action")
    return HighLevelAction(
        action=action,
        explanation=explanation,
        raw_model_output=raw_output,
    )


def generate_complete_rollout_plan(
    *,
    adapter: str,
    base_model: str | None,
    device_map: str,
    torch_dtype: str,
    config: PlannerConfig,
    context: dict[str, str],
    show_progress: bool,
    show_rollout_progress: bool,
) -> tuple[list[HighLevelAction], dict[str, Any]]:
    """Run the DTserver rollout algorithm and retain a reproducible trace."""
    planner, history = build_planner(
        adapter_path=adapter,
        base_model=base_model,
        device_map=device_map,
        torch_dtype=torch_dtype,
        config=config,
        context=context,
    )
    planner.llm.eval()

    state = tuple(False for _ in PLANNER_STATE_FIELDS)
    selected_actions: list[HighLevelAction] = []
    trace_steps: list[dict[str, Any]] = []
    planning_start = time.perf_counter()

    for step in range(1, config.max_plan_steps + 1):
        if state == TERMINAL_STATE:
            break
        if show_progress:
            print(f"[planning step {step}] state={state_to_jsonable(state)}")

        candidates = planner._sample_actions("", state, config.num_candidates)
        if not candidates:
            trace_steps.append(
                {
                    "step": step,
                    "state_before": state_to_jsonable(state),
                    "candidates": [],
                    "stop_reason": "no_candidate_actions",
                }
            )
            break

        candidate_records: list[dict[str, Any]] = []
        scores: list[float] = []
        for candidate_index, candidate in enumerate(candidates, start=1):
            samples: list[int] = []
            for rollout_index in range(1, config.num_rollout_samples + 1):
                if show_rollout_progress:
                    print(
                        f"  candidate={candidate_index}/{len(candidates)} "
                        f"rollout={rollout_index}/{config.num_rollout_samples}"
                    )
                samples.append(
                    planner._recovery_time("", state, candidate, depth=0)
                )
            score = float(sum(samples)) / float(len(samples))
            scores.append(score)
            candidate_records.append(
                {
                    "candidate_index": candidate_index,
                    "raw_action": candidate,
                    "parsed_action": dataclass_to_jsonable(
                        parse_generated_action(candidate)
                    ),
                    "rollout_recovery_depths": samples,
                    "mean_recovery_depth": score,
                }
            )

        best_index = min(range(len(candidates)), key=lambda index: scores[index])
        selected_raw = candidates[best_index]
        selected_action = parse_generated_action(selected_raw)
        history.append(selected_raw)
        next_state = planner._predict_state("", state, selected_raw)

        step_record: dict[str, Any] = {
            "step": step,
            "state_before": state_to_jsonable(state),
            "candidates": candidate_records,
            "selected_candidate_index": best_index + 1,
            "selected_action": dataclass_to_jsonable(selected_action),
            "selected_mean_recovery_depth": scores[best_index],
            "state_after": (
                state_to_jsonable(next_state) if next_state is not None else None
            ),
        }
        trace_steps.append(step_record)
        selected_actions.append(selected_action)

        if show_progress:
            print(
                f"  selected score={scores[best_index]:.3f} "
                f"action={selected_action.action}"
            )

        if next_state is None:
            step_record["stop_reason"] = "state_prediction_failed"
            break
        state = next_state

    planning_seconds = time.perf_counter() - planning_start
    trace = {
        "algorithm": "lora_candidate_rollout_expected_recovery_depth",
        "config": {
            "num_candidates": config.num_candidates,
            "num_rollout_samples": config.num_rollout_samples,
            "max_plan_steps": config.max_plan_steps,
            "max_rollout_depth": config.max_rollout_depth,
            "action_max_new_tokens": config.action_max_new_tokens,
            "state_max_new_tokens": config.state_max_new_tokens,
            "candidate_temperature": config.candidate_temperature,
            "candidate_top_p": config.candidate_top_p,
            "rollout_temperature": config.rollout_temperature,
            "rollout_top_p": config.rollout_top_p,
        },
        "steps": trace_steps,
        "final_predicted_state": state_to_jsonable(state),
        "reached_terminal_state": state == TERMINAL_STATE,
        "planning_wall_clock_time_seconds": planning_seconds,
    }
    if not selected_actions:
        raise RuntimeError("LoRA rollout planner did not generate any actions")
    return selected_actions, trace


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


def execute_complete_plan(
    *,
    high_level_actions: list[HighLevelAction],
    command_agent: Any,
    context: dict[str, str],
    dt_context: str,
    server: str,
    server_ip: str,
    attacker_ip: str,
    run_dir: Path,
) -> tuple[list[dict[str, Any]], float]:
    """Execute a fixed complete plan using the API baseline's execution semantics."""
    executed_plans_dir = run_dir / "executed_plans"
    failed_plans_dir = run_dir / "failed_plans"
    executed_plans_dir.mkdir(parents=True, exist_ok=True)
    failed_plans_dir.mkdir(parents=True, exist_ok=True)

    executor = RecoveryExecutor()
    safety = CommandSafetyValidator()
    history_actions: list[HighLevelAction] = []
    state: RecoveryState = initial_recovery_state()
    step_summaries: list[dict[str, Any]] = []
    execution_start = time.perf_counter()

    for step, action in enumerate(high_level_actions, start=1):
        step_start = time.perf_counter()
        plan: CommandPlan | None = None
        result = None
        try:
            plan = plan_for_action(
                command_agent=command_agent,
                action=action,
                state=state,
                context=context,
                dt_context=dt_context,
                server=server,
                server_ip=server_ip,
                attacker_ip=attacker_ip,
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
            history_actions.append(action)
            payload = {
                "step": step,
                "plan": dataclass_to_jsonable(plan),
                "execution": dataclass_to_jsonable(result),
                "wall_clock_time_seconds": elapsed,
            }
            (executed_plans_dir / f"step_{step:03d}.json").write_text(
                json.dumps(payload, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        elif plan is not None:
            payload = {
                "step": step,
                "plan": dataclass_to_jsonable(plan),
                "error": error,
                "wall_clock_time_seconds": elapsed,
            }
            (failed_plans_dir / f"step_{step:03d}.json").write_text(
                json.dumps(payload, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )

        step_summaries.append(
            {
                "step": step,
                "action": dataclass_to_jsonable(action),
                "success": success,
                "error": error,
                "action_total_time_seconds": (
                    result.action_total_time_seconds if result else 0.0
                ),
                "wall_clock_time_seconds": elapsed,
            }
        )
        print(
            f"step={step} success={success} "
            f"action_total_time_seconds="
            f"{step_summaries[-1]['action_total_time_seconds']:.3f} "
            f"action={action.action}"
        )
        if not success:
            break

    return step_summaries, time.perf_counter() - execution_start


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Generate a complete high-level plan with the LoRA rollout planner, "
            "then execute it through the standard DT command stack."
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
    parser.add_argument("--adapter", required=True)
    parser.add_argument("--base-model", default=None)
    parser.add_argument("--device-map", default="auto")
    parser.add_argument(
        "--torch-dtype",
        choices=("float16", "bfloat16"),
        default="float16",
    )
    parser.add_argument("--num-candidates", type=int, default=3)
    parser.add_argument("--num-rollouts", type=int, default=2)
    parser.add_argument(
        "--max-actions",
        "--max-plan-steps",
        dest="max_actions",
        type=int,
        default=7,
        help=(
            "Maximum number of high-level actions. --max-plan-steps is kept "
            "as a compatibility alias."
        ),
    )
    parser.add_argument("--max-rollout-depth", type=int, default=7)
    parser.add_argument("--action-max-new-tokens", type=int, default=500)
    parser.add_argument("--state-max-new-tokens", type=int, default=1200)
    parser.add_argument(
        "--action-temperature",
        "--candidate-temperature",
        dest="action_temperature",
        type=float,
        default=0.6,
    )
    parser.add_argument(
        "--action-top-p",
        "--candidate-top-p",
        dest="action_top_p",
        type=float,
        default=0.9,
    )
    parser.add_argument(
        "--state-temperature",
        "--rollout-temperature",
        dest="state_temperature",
        type=float,
        default=0.0,
    )
    parser.add_argument(
        "--state-top-p",
        "--rollout-top-p",
        dest="state_top_p",
        type=float,
        default=0.9,
    )
    parser.add_argument("--show-progress", action="store_true")
    parser.add_argument("--show-rollout-progress", action="store_true")
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
        default=str(ROOT / "artifacts" / "recovery_lora_rollout"),
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.num_candidates < 1 or args.num_rollouts < 1:
        raise ValueError("--num-candidates and --num-rollouts must be at least 1")
    if args.max_actions < 1 or args.max_rollout_depth < 1:
        raise ValueError(
            "--max-actions and --max-rollout-depth must be at least 1"
        )

    server_ip = args.server_ip or TARGET_SERVER_IPS[args.server]
    context = {
        "System": read_text_arg(args.system, args.system_file, DEFAULT_SYSTEM),
        "Logs": read_text_arg(args.logs, args.logs_file, DEFAULT_LOGS),
        "Incident": read_text_arg(
            args.incident, args.incident_file, DEFAULT_INCIDENT
        ),
        "TargetServer": f"{args.server} / {server_ip}",
    }
    dt_context = (
        Path(args.dt_context_file)
        .expanduser()
        .read_text(encoding="utf-8")
        .strip()
        if args.dt_context_file
        else ""
    )

    run_dir = (
        Path(args.artifacts_dir)
        / "runs"
        / datetime.now().strftime("%Y%m%d_%H%M%S")
    )
    run_dir.mkdir(parents=True, exist_ok=True)
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
                "BaselineType": "lora_rollout_complete_high_level_plan",
                "HighLevelPlanModel": args.adapter,
                "CommandAgent": args.command_agent,
                "CommandModel": command_model,
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    config = PlannerConfig(
        num_candidates=args.num_candidates,
        num_rollout_samples=args.num_rollouts,
        max_plan_steps=args.max_actions,
        max_rollout_depth=args.max_rollout_depth,
        action_max_new_tokens=args.action_max_new_tokens,
        state_max_new_tokens=args.state_max_new_tokens,
        candidate_temperature=args.action_temperature,
        candidate_top_p=args.action_top_p,
        rollout_temperature=args.state_temperature,
        rollout_top_p=args.state_top_p,
    )
    high_level_actions, planning_trace = generate_complete_rollout_plan(
        adapter=args.adapter,
        base_model=args.base_model,
        device_map=args.device_map,
        torch_dtype=args.torch_dtype,
        config=config,
        context=context,
        show_progress=args.show_progress,
        show_rollout_progress=args.show_rollout_progress,
    )
    (run_dir / "rollout_high_level_plan.json").write_text(
        json.dumps(
            {
                "actions": [
                    dataclass_to_jsonable(action)
                    for action in high_level_actions
                ],
                "planning_trace": planning_trace,
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    print(f"Generated {len(high_level_actions)} high-level actions.")

    command_agent = build_command_agent(args)
    restore_timings = restore_and_attack(
        wait_seconds=args.wait_seconds,
        rebuild_images=args.rebuild_images,
        attack_script=args.attack_script,
        attack_args=args.attack_arg,
    )
    step_summaries, execution_wall_clock = execute_complete_plan(
        high_level_actions=high_level_actions,
        command_agent=command_agent,
        context=context,
        dt_context=dt_context,
        server=args.server,
        server_ip=server_ip,
        attacker_ip=args.attacker_ip,
        run_dir=run_dir,
    )

    summary = {
        "server": args.server,
        "server_ip": server_ip,
        "high_level_plan_generation": {
            "method": "lora_rollout",
            "adapter": args.adapter,
            "planning_wall_clock_time_seconds": planning_trace[
                "planning_wall_clock_time_seconds"
            ],
            "generated_action_count": len(high_level_actions),
            "reached_predicted_terminal_state": planning_trace[
                "reached_terminal_state"
            ],
        },
        "restore_timings": restore_timings,
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
