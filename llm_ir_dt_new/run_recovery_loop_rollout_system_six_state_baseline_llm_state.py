"""Recover the complete compromised system with one coarse six-state rollout.

Unlike the per-server state-matrix baseline, this ablation keeps exactly one
six-dimensional state for the entire system.  A field is true only when that
criterion is satisfied across all compromised servers.  checkpoint-850 predicts
each transition, a complete high-level plan is produced, and only then are the
selected actions translated to commands and executed in the DT.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass
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

from examples.planning_simulation_qwen_lora_DTserver import build_planner  # noqa: E402
from examples.planning_simulation_qwen_lora_DT import (  # noqa: E402
    ACTION_PROMPT_TEMPLATE as BASE_ACTION_PROMPT_TEMPLATE,
    STATE_PROMPT_TEMPLATE as BASE_STATE_PROMPT_TEMPLATE,
)
from llm_recovery.decision_transformer.planner import (  # noqa: E402
    RECOVERY_STATE_FIELDS,
    TERMINAL_STATE,
    PlannerConfig,
)
from llm_recovery.evaluation.exact_match import _parse_state_json  # noqa: E402
from llm_ir_dt.recovery_loop.command_agent import CommandAgentRequest  # noqa: E402
from llm_ir_dt.recovery_loop.command_safety import CommandSafetyValidator  # noqa: E402
from llm_ir_dt.recovery_loop.recovery_executor import RecoveryExecutor  # noqa: E402
from llm_ir_dt.recovery_loop.schemas import (  # noqa: E402
    CommandPlan,
    HighLevelAction,
    dataclass_to_jsonable,
)
from run_recovery_loop_api_baseline_llm_state import restore_and_attack  # noqa: E402
from run_recovery_loop_llm_state import (  # noqa: E402
    DEFAULT_INCIDENT,
    DEFAULT_LOGS,
    DEFAULT_SYSTEM,
    TARGET_SERVER_IPS,
    read_text_arg,
)
from run_recovery_loop_rollout_baseline_llm_state import (  # noqa: E402
    build_command_agent,
    parse_generated_action,
)
from run_recovery_loop_rollout_system_baseline_llm_state import (  # noqa: E402
    SystemAction,
    infer_compromised_servers,
    local_state_to_jsonable,
)


GlobalState = tuple[bool, ...]


@dataclass(frozen=True)
class PlannedGlobalAction:
    """Selected system action with its coarse predicted state transition."""

    system_action: SystemAction
    state_before: GlobalState
    state_after: GlobalState


def build_global_action_prompt(
    *,
    context: dict[str, str],
    state: GlobalState,
    previous_actions: Sequence[SystemAction],
    compromised_servers: Sequence[str],
) -> str:
    """Adapt the original DT action prompt to unordered whole-system recovery."""
    state_json = json.dumps(local_state_to_jsonable(state), ensure_ascii=True)
    targets_json = json.dumps(
        [
            f"{server} / {TARGET_SERVER_IPS[server]}"
            for server in compromised_servers
        ],
        ensure_ascii=True,
    )
    if previous_actions:
        previous_text = "\n".join(
            "- " + item.action.raw_model_output.strip()
            for item in previous_actions
        ).strip()
    else:
        previous_text = "None."

    prompt = BASE_ACTION_PROMPT_TEMPLATE.format(
        context.get("System", "").strip(),
        context.get("Logs", "").strip(),
        context.get("Incident", "").strip(),
        state_json,
        previous_text,
    ).rstrip()
    prompt = prompt.replace(
        "### State:\n",
        "### Compromised servers (unordered):\n"
        + targets_json
        + "\n\n### State:\n",
        1,
    )
    prompt = prompt.replace(
        "is_recovered: Are primary services restored for users?\n\n",
        "is_recovered: Are primary services restored for users?\n"
        "These six state fields describe the entire compromised system, not an "
        "individual server. A state field is true only when its recovery "
        "criterion has been satisfied for every compromised server.\n\n",
        1,
    )
    prompt = prompt.replace(
        "You are a security operator with advanced knowledge in cybersecurity "
        "and IT systems. You have been given information about a security incident and should",
        "You are a security operator with advanced knowledge in cybersecurity "
        "and IT systems. No server priority or recovery order is provided; select "
        "the appropriate target server or servers from the incident evidence and "
        "the current whole-system state. You have been given information about a "
        "security incident and should",
        1,
    )
    return prompt


def build_global_state_prompt(
    *,
    context: dict[str, str],
    state: GlobalState,
    action: SystemAction,
    previous_actions: Sequence[SystemAction],
    compromised_servers: Sequence[str],
) -> str:
    """Adapt the original DT state prompt to one whole-system six-state."""
    del previous_actions  # The original DT state prompt has no action-history field.
    state_json = json.dumps(local_state_to_jsonable(state), ensure_ascii=True)
    targets_json = json.dumps(
        [
            f"{server} / {TARGET_SERVER_IPS[server]}"
            for server in compromised_servers
        ],
        ensure_ascii=True,
    )
    prompt = BASE_STATE_PROMPT_TEMPLATE.format(
        context.get("System", "").strip(),
        context.get("Logs", "").strip(),
        context.get("Incident", "").strip(),
        state_json,
        action.action.raw_model_output.strip(),
    ).rstrip()
    prompt = prompt.replace(
        "### State:\n",
        "### Compromised servers (unordered):\n"
        + targets_json
        + "\n\n### State:\n",
        1,
    )
    prompt = prompt.replace(
        "is_recovered: Are primary services restored for users?\n\n",
        "is_recovered: Are primary services restored for users?\n"
        "These six state fields describe the entire compromised system, not an "
        "individual server. A state field is true only when its recovery "
        "criterion has been satisfied for every compromised server.\n\n",
        1,
    )
    prompt = prompt.replace(
        "A state variable can only change from 'false' to 'true', it cannot be changed from "
        "'true' to 'false'.\n",
        "A state variable can only change from 'false' to 'true', it cannot be changed from "
        "'true' to 'false'.\nA whole-system state variable must remain "
        "'false' if the corresponding criterion is incomplete for any "
        "compromised server.\n",
        1,
    )
    return prompt


def print_exact_prompt(kind: str, prompt: str) -> None:
    """Print one complete checkpoint prompt with unambiguous boundaries."""
    print(f"\n===== BEGIN CHECKPOINT-850 {kind} PROMPT =====")
    print(prompt)
    print(f"===== END CHECKPOINT-850 {kind} PROMPT =====\n")


def sample_global_actions(
    *,
    planner: Any,
    config: PlannerConfig,
    context: dict[str, str],
    state: GlobalState,
    previous_actions: Sequence[SystemAction],
    compromised_servers: Sequence[str],
    count: int,
    print_prompts: bool = False,
    debug_dir: Path | None = None,
    debug_name: str | None = None,
) -> list[SystemAction]:
    """Sample distinct actions using the checkpoint's original action schema."""
    prompt = build_global_action_prompt(
        context=context,
        state=state,
        previous_actions=previous_actions,
        compromised_servers=compromised_servers,
    )
    if print_prompts:
        print_exact_prompt("ACTION", prompt)
    actions: list[SystemAction] = []
    seen: set[str] = set()
    attempts = 0
    max_attempts = max(count * 4, count)
    rejected_attempts: list[dict[str, Any]] = []
    while len(actions) < count and attempts < max_attempts:
        attempts += 1
        raw_output = planner._generate_text(
            prompt,
            max_new_tokens=config.action_max_new_tokens,
            temperature=config.candidate_temperature,
            top_p=config.candidate_top_p,
        )
        try:
            parsed_action = parse_generated_action(raw_output)
            action = SystemAction(
                action=parsed_action,
                target_servers=tuple(compromised_servers),
            )
        except ValueError as exc:
            rejected_attempts.append(
                {
                    "attempt": attempts,
                    "reason": "parse_error",
                    "error": str(exc),
                    "raw_model_output": raw_output,
                }
            )
            continue
        key = action.action.action
        if key not in seen:
            seen.add(key)
            actions.append(action)
        else:
            rejected_attempts.append(
                {
                    "attempt": attempts,
                    "reason": "duplicate_action",
                    "action": dataclass_to_jsonable(action.action),
                    "raw_model_output": raw_output,
                }
            )
    if debug_dir is not None:
        debug_dir.mkdir(parents=True, exist_ok=True)
        payload = {
            "prompt": prompt,
            "requested_count": count,
            "max_attempts": max_attempts,
            "attempts_used": attempts,
            "accepted_actions": [
                {"action": dataclass_to_jsonable(item.action)}
                for item in actions
            ],
            "rejected_attempts": rejected_attempts,
        }
        output_name = debug_name or "candidate_sampling.json"
        (debug_dir / output_name).write_text(
            json.dumps(payload, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    return actions


def predict_global_state(
    *,
    planner: Any,
    config: PlannerConfig,
    context: dict[str, str],
    state: GlobalState,
    action: SystemAction,
    previous_actions: Sequence[SystemAction],
    compromised_servers: Sequence[str],
    print_prompts: bool = False,
) -> GlobalState | None:
    """Use one checkpoint-850 generation to predict the next global six-state."""
    prompt = build_global_state_prompt(
        context=context,
        state=state,
        action=action,
        previous_actions=previous_actions,
        compromised_servers=compromised_servers,
    )
    if print_prompts:
        print_exact_prompt("STATE", prompt)
    output = planner._generate_text(
        prompt,
        max_new_tokens=config.state_max_new_tokens,
        temperature=config.rollout_temperature,
        top_p=config.rollout_top_p,
    )
    parsed = _parse_state_json(output)
    if parsed is None:
        return None
    return tuple(bool(parsed[field]) for field in RECOVERY_STATE_FIELDS)


def rollout_global_recovery_depth(
    *,
    planner: Any,
    config: PlannerConfig,
    context: dict[str, str],
    compromised_servers: Sequence[str],
    state: GlobalState,
    action: SystemAction,
    previous_actions: Sequence[SystemAction],
    depth: int,
    print_prompts: bool = False,
    debug_dir: Path | None = None,
) -> int:
    """Estimate terminal depth under the coarse whole-system state."""
    if depth >= config.max_rollout_depth:
        return config.max_rollout_depth
    next_state = predict_global_state(
        planner=planner,
        config=config,
        context=context,
        state=state,
        action=action,
        previous_actions=previous_actions,
        compromised_servers=compromised_servers,
        print_prompts=print_prompts,
    )
    if next_state is None:
        return config.max_rollout_depth
    if next_state == TERMINAL_STATE:
        return 1
    next_actions = sample_global_actions(
        planner=planner,
        config=config,
        context=context,
        state=next_state,
        previous_actions=[*previous_actions, action],
        compromised_servers=compromised_servers,
        count=1,
        print_prompts=print_prompts,
        debug_dir=debug_dir,
        debug_name=f"rollout_depth_{depth + 1}.json" if debug_dir is not None else None,
    )
    if not next_actions:
        return config.max_rollout_depth
    return 1 + rollout_global_recovery_depth(
        planner=planner,
        config=config,
        context=context,
        compromised_servers=compromised_servers,
        state=next_state,
        action=next_actions[0],
        previous_actions=[*previous_actions, action],
        depth=depth + 1,
        print_prompts=print_prompts,
    )


def generate_complete_global_plan(
    *,
    adapter: str,
    base_model: str | None,
    device_map: str,
    torch_dtype: str,
    config: PlannerConfig,
    context: dict[str, str],
    compromised_servers: Sequence[str],
    show_progress: bool,
    show_rollout_progress: bool,
    print_prompts: bool,
    debug_dir: Path | None = None,
) -> tuple[list[PlannedGlobalAction], dict[str, Any]]:
    """Generate the complete fixed plan using one global six-state."""
    planner_context = dict(context)
    planner_context["TargetServer"] = "Entire compromised system"
    planner, _ = build_planner(
        adapter_path=adapter,
        base_model=base_model,
        device_map=device_map,
        torch_dtype=torch_dtype,
        config=config,
        context=planner_context,
    )
    planner.llm.eval()

    state: GlobalState = tuple(False for _ in RECOVERY_STATE_FIELDS)
    previous_actions: list[SystemAction] = []
    selected_actions: list[PlannedGlobalAction] = []
    trace_steps: list[dict[str, Any]] = []
    planning_start = time.perf_counter()

    for step in range(1, config.max_plan_steps + 1):
        if state == TERMINAL_STATE:
            break
        if show_progress:
            print(
                f"[planning step {step}] whole_system_state="
                f"{json.dumps(local_state_to_jsonable(state), ensure_ascii=True)}"
            )
        candidates = sample_global_actions(
            planner=planner,
            config=config,
            context=context,
            state=state,
            previous_actions=previous_actions,
            compromised_servers=compromised_servers,
            count=config.num_candidates,
            print_prompts=print_prompts,
            debug_dir=debug_dir,
            debug_name=f"step_{step:03d}_candidates.json" if debug_dir is not None else None,
        )
        if not candidates:
            trace_steps.append(
                {
                    "step": step,
                    "state_before": local_state_to_jsonable(state),
                    "candidates": [],
                    "stop_reason": "no_valid_candidate_actions",
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
                    rollout_global_recovery_depth(
                        planner=planner,
                        config=config,
                        context=context,
                        compromised_servers=compromised_servers,
                        state=state,
                        action=candidate,
                        previous_actions=previous_actions,
                        depth=0,
                        print_prompts=print_prompts,
                        debug_dir=(
                            debug_dir / f"step_{step:03d}_candidate_{candidate_index:02d}"
                            if debug_dir is not None
                            else None
                        ),
                    )
                )
            score = float(sum(samples)) / float(len(samples))
            scores.append(score)
            candidate_records.append(
                {
                    "candidate_index": candidate_index,
                    "action": dataclass_to_jsonable(candidate.action),
                    "rollout_recovery_depths": samples,
                    "mean_recovery_depth": score,
                }
            )

        best_index = min(range(len(candidates)), key=lambda index: scores[index])
        selected = candidates[best_index]
        next_state = predict_global_state(
            planner=planner,
            config=config,
            context=context,
            state=state,
            action=selected,
            previous_actions=previous_actions,
            compromised_servers=compromised_servers,
            print_prompts=print_prompts,
        )
        step_record: dict[str, Any] = {
            "step": step,
            "state_before": local_state_to_jsonable(state),
            "candidates": candidate_records,
            "selected_candidate_index": best_index + 1,
            "selected_action": dataclass_to_jsonable(selected.action),
            "selected_mean_recovery_depth": scores[best_index],
            "state_after": (
                local_state_to_jsonable(next_state)
                if next_state is not None
                else None
            ),
        }
        trace_steps.append(step_record)
        if show_progress:
            print(
                f"  selected score={scores[best_index]:.3f} "
                f"action={selected.action.action}"
            )
        if next_state is None:
            step_record["stop_reason"] = "global_state_prediction_failed"
            break
        selected_actions.append(
            PlannedGlobalAction(
                system_action=selected,
                state_before=state,
                state_after=next_state,
            )
        )
        previous_actions.append(selected)
        state = next_state

    trace = {
        "algorithm": "lora_system_candidate_rollout_single_global_six_state",
        "compromised_servers": list(compromised_servers),
        "state_dimension": len(RECOVERY_STATE_FIELDS),
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
        "final_predicted_state": local_state_to_jsonable(state),
        "reached_terminal_state": state == TERMINAL_STATE,
        "planning_wall_clock_time_seconds": time.perf_counter() - planning_start,
    }
    if not selected_actions:
        raise RuntimeError("Global six-state rollout planner generated no actions")
    return selected_actions, trace


def execute_global_plan(
    *,
    planned_actions: Sequence[PlannedGlobalAction],
    compromised_servers: Sequence[str],
    command_agent: Any,
    context: dict[str, str],
    dt_context: str,
    attacker_ip: str,
    run_dir: Path,
    command_generation_attempts: int,
) -> tuple[list[dict[str, Any]], float]:
    """Generate and execute one cross-container command plan per system action."""
    executed_dir = run_dir / "executed_plans"
    failed_dir = run_dir / "failed_plans"
    executed_dir.mkdir(parents=True, exist_ok=True)
    failed_dir.mkdir(parents=True, exist_ok=True)
    executor = RecoveryExecutor()
    safety = CommandSafetyValidator()
    summaries: list[dict[str, Any]] = []
    execution_start = time.perf_counter()
    recovery_targets = tuple(
        (server, TARGET_SERVER_IPS[server]) for server in compromised_servers
    )

    for step, planned in enumerate(planned_actions, start=1):
        plan: CommandPlan | None = None
        result = None
        error = ""
        generation_errors: list[str] = []
        generation_attempts_used = 0
        wall_start = time.perf_counter()
        try:
            request = CommandAgentRequest(
                high_level_action=planned.system_action.action,
                current_state=local_state_to_jsonable(planned.state_before),
                system=context.get("System", ""),
                logs=context.get("Logs", ""),
                incident=context.get("Incident", ""),
                dt_context=dt_context,
                server="entire_compromised_system",
                server_ip="multiple",
                attacker_ip=attacker_ip,
                recovery_targets=recovery_targets,
            )
            for generation_attempt in range(1, command_generation_attempts + 1):
                generation_attempts_used = generation_attempt
                try:
                    plan = command_agent.generate_plan(request)
                    break
                except Exception as exc:
                    generation_error = (
                        f"attempt {generation_attempt}: {type(exc).__name__}: {exc}"
                    )
                    generation_errors.append(generation_error)
                    print(
                        f"step={step} command_generation_failed "
                        f"{generation_error}",
                        flush=True,
                    )
            if plan is None:
                raise RuntimeError(
                    "Command-plan generation failed after "
                    f"{command_generation_attempts} attempts: "
                    + generation_errors[-1]
                )
            safety.validate_plan(plan)
            result = executor.execute_plan(
                plan,
                state_before=local_state_to_jsonable(planned.state_before),
                state_after=local_state_to_jsonable(planned.state_after),
            )
            success = result.success
        except Exception as exc:
            success = False
            error = f"{type(exc).__name__}: {exc}"
        wall_seconds = time.perf_counter() - wall_start
        action_seconds = result.action_total_time_seconds if result else 0.0
        payload = {
            "step": step,
            "action": dataclass_to_jsonable(planned.system_action.action),
            "compromised_recovery_targets": [
                {"server": server, "server_ip": server_ip}
                for server, server_ip in recovery_targets
            ],
            "state_before": local_state_to_jsonable(planned.state_before),
            "predicted_state_after": local_state_to_jsonable(planned.state_after),
            "plan": dataclass_to_jsonable(plan) if plan is not None else None,
            "execution": dataclass_to_jsonable(result) if result is not None else None,
            "success": success,
            "error": error,
            "command_generation_attempts_used": generation_attempts_used,
            "command_generation_errors": generation_errors,
            "action_total_time_seconds": action_seconds,
            "wall_clock_time_seconds": wall_seconds,
        }
        output_dir = executed_dir if plan is not None and result is not None else failed_dir
        (output_dir / f"step_{step:03d}.json").write_text(
            json.dumps(payload, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        summaries.append(payload)
        print(
            f"step={step} success={success} "
            f"action_total_time_seconds={action_seconds:.3f} "
            f"action={planned.system_action.action.action}"
        )
        if not success:
            break

    return summaries, time.perf_counter() - execution_start


def load_global_plan(path: Path) -> tuple[list[PlannedGlobalAction], dict[str, Any]]:
    """Load a previously generated six-state high-level plan for re-execution."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    raw_actions = payload.get("actions")
    if not isinstance(raw_actions, list) or not raw_actions:
        raise ValueError(f"High-level plan contains no actions: {path}")

    planned_actions: list[PlannedGlobalAction] = []
    for index, item in enumerate(raw_actions, start=1):
        if not isinstance(item, dict) or not isinstance(item.get("action"), dict):
            raise ValueError(f"Invalid action entry {index} in {path}")
        action_data = item["action"]
        state_before_data = item.get("state_before")
        state_after_data = item.get("state_after")
        if not isinstance(state_before_data, dict) or not isinstance(state_after_data, dict):
            raise ValueError(f"Action entry {index} is missing state data in {path}")
        state_before = tuple(
            bool(state_before_data.get(field, False)) for field in RECOVERY_STATE_FIELDS
        )
        state_after = tuple(
            bool(state_after_data.get(field, False)) for field in RECOVERY_STATE_FIELDS
        )
        high_level_action = HighLevelAction(
            action=str(action_data.get("action", "")).strip(),
            explanation=str(action_data.get("explanation", "")).strip(),
            raw_model_output=str(action_data.get("raw_model_output", "")),
        )
        if not high_level_action.action:
            raise ValueError(f"Action entry {index} is empty in {path}")
        planned_actions.append(
            PlannedGlobalAction(
                system_action=SystemAction(
                    action=high_level_action,
                    target_servers=(),
                ),
                state_before=state_before,
                state_after=state_after,
            )
        )

    source_trace = payload.get("planning_trace")
    trace = dict(source_trace) if isinstance(source_trace, dict) else {}
    trace["loaded_from_plan_file"] = str(path)
    trace["source_planning_wall_clock_time_seconds"] = float(
        trace.get("planning_wall_clock_time_seconds", 0.0)
    )
    trace["planning_wall_clock_time_seconds"] = 0.0
    trace.setdefault(
        "final_predicted_state",
        local_state_to_jsonable(planned_actions[-1].state_after),
    )
    trace.setdefault(
        "reached_terminal_state",
        planned_actions[-1].state_after == TERMINAL_STATE,
    )
    return planned_actions, trace


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Generate and execute a whole-system recovery plan using one coarse "
            "checkpoint-850 six-dimensional state."
        )
    )
    parser.add_argument(
        "--compromised-servers",
        nargs="+",
        choices=tuple(TARGET_SERVER_IPS),
        default=None,
        help=(
            "Unordered recovery-target set; inferred from the incident by default."
        ),
    )
    parser.add_argument("--attacker-ip", default="10.0.1.11")
    parser.add_argument("--adapter", required=True)
    parser.add_argument(
        "--high-level-plan-file",
        default=None,
        help=(
            "Reuse actions and predicted states from an existing "
            "rollout_high_level_plan.json instead of generating a new plan."
        ),
    )
    parser.add_argument("--base-model", default=None)
    parser.add_argument("--device-map", default="auto")
    parser.add_argument(
        "--torch-dtype",
        choices=("float16", "bfloat16"),
        default="float16",
    )
    parser.add_argument("--num-candidates", type=int, default=3)
    parser.add_argument("--num-rollouts", type=int, default=2)
    parser.add_argument("--max-actions", type=int, default=7)
    parser.add_argument("--max-rollout-depth", type=int, default=7)
    parser.add_argument("--action-max-new-tokens", type=int, default=500)
    parser.add_argument("--state-max-new-tokens", type=int, default=1200)
    parser.add_argument("--action-temperature", type=float, default=0.6)
    parser.add_argument("--action-top-p", type=float, default=0.9)
    parser.add_argument("--state-temperature", type=float, default=0.0)
    parser.add_argument("--state-top-p", type=float, default=0.9)
    parser.add_argument("--show-progress", action="store_true")
    parser.add_argument("--show-rollout-progress", action="store_true")
    parser.add_argument(
        "--print-prompts",
        action="store_true",
        help=(
            "Print every complete checkpoint-850 action and state prompt, "
            "including expanded System, Logs, Incident, state, and history."
        ),
    )
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
    parser.add_argument(
        "--command-generation-attempts",
        type=int,
        default=3,
        help=(
            "Maximum command-agent generation attempts before an action fails; "
            "commands execute only after a valid plan is produced."
        ),
    )
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
        default=str(ROOT / "artifacts" / "recovery_lora_rollout_system_six_state"),
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.num_candidates < 1 or args.num_rollouts < 1:
        raise ValueError("--num-candidates and --num-rollouts must be at least 1")
    if args.max_actions < 1 or args.max_rollout_depth < 1:
        raise ValueError("--max-actions and --max-rollout-depth must be at least 1")
    if args.command_generation_attempts < 1:
        raise ValueError("--command-generation-attempts must be at least 1")

    context = {
        "System": read_text_arg(args.system, args.system_file, DEFAULT_SYSTEM),
        "Logs": read_text_arg(args.logs, args.logs_file, DEFAULT_LOGS),
        "Incident": read_text_arg(
            args.incident,
            args.incident_file,
            DEFAULT_INCIDENT,
        ),
    }
    compromised_servers = tuple(
        args.compromised_servers
        or infer_compromised_servers(context["Incident"])
    )
    compromised_servers = tuple(
        server for server in TARGET_SERVER_IPS if server in set(compromised_servers)
    )
    context["CompromisedServers"] = ", ".join(
        f"{server} / {TARGET_SERVER_IPS[server]}" for server in compromised_servers
    )
    dt_context = (
        Path(args.dt_context_file).expanduser().read_text(encoding="utf-8").strip()
        if args.dt_context_file
        else ""
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

    run_dir = (
        Path(args.artifacts_dir)
        / "runs"
        / datetime.now().strftime("%Y%m%d_%H%M%S")
    )
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "context.json").write_text(
        json.dumps(
            {
                **context,
                "BaselineType": "lora_rollout_complete_system_six_state_plan",
                "HighLevelPlanModel": args.adapter,
                "CommandAgent": args.command_agent,
                "CommandModel": (
                    args.deepseek_model
                    if args.command_agent == "deepseek"
                    else args.openai_model
                    if args.command_agent == "openai"
                    else "mock"
                ),
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    if args.high_level_plan_file:
        plan_path = Path(args.high_level_plan_file).expanduser().resolve()
        planned_actions, planning_trace = load_global_plan(plan_path)
    else:
        planned_actions, planning_trace = generate_complete_global_plan(
            adapter=args.adapter,
            base_model=args.base_model,
            device_map=args.device_map,
            torch_dtype=args.torch_dtype,
            config=config,
            context=context,
            compromised_servers=compromised_servers,
            show_progress=args.show_progress,
            show_rollout_progress=args.show_rollout_progress,
            print_prompts=args.print_prompts,
            debug_dir=run_dir / "candidate_debug",
        )
    (run_dir / "rollout_high_level_plan.json").write_text(
        json.dumps(
            {
                "actions": [
                    {
                        "action": dataclass_to_jsonable(item.system_action.action),
                        "state_before": local_state_to_jsonable(item.state_before),
                        "state_after": local_state_to_jsonable(item.state_after),
                    }
                    for item in planned_actions
                ],
                "planning_trace": planning_trace,
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    print(
        f"Generated {len(planned_actions)} whole-system high-level actions. "
        f"predicted_terminal={planning_trace['reached_terminal_state']}"
    )

    command_agent = build_command_agent(args)
    restore_timings = restore_and_attack(
        wait_seconds=args.wait_seconds,
        rebuild_images=args.rebuild_images,
        attack_script=args.attack_script,
        attack_args=args.attack_arg,
    )
    step_summaries, execution_wall_clock = execute_global_plan(
        planned_actions=planned_actions,
        compromised_servers=compromised_servers,
        command_agent=command_agent,
        context=context,
        dt_context=dt_context,
        attacker_ip=args.attacker_ip,
        run_dir=run_dir,
        command_generation_attempts=args.command_generation_attempts,
    )
    execution_success = (
        len(step_summaries) == len(planned_actions)
        and all(item["success"] for item in step_summaries)
    )
    summary = {
        "compromised_servers": list(compromised_servers),
        "high_level_plan_generation": {
            "method": "lora_system_rollout_single_global_six_state",
            "adapter": args.adapter,
            "state_dimension": len(RECOVERY_STATE_FIELDS),
            "planning_wall_clock_time_seconds": planning_trace[
                "planning_wall_clock_time_seconds"
            ],
            "generated_action_count": len(planned_actions),
            "reached_predicted_terminal_state": planning_trace[
                "reached_terminal_state"
            ],
        },
        "final_predicted_state": planning_trace["final_predicted_state"],
        "restore_timings": restore_timings,
        "steps": step_summaries,
        "execution_success": execution_success,
        "system_recovery_success": (
            planning_trace["reached_terminal_state"] and execution_success
        ),
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
    print(f"system_recovery_success={summary['system_recovery_success']}")
    return 0 if summary["system_recovery_success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
