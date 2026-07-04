"""Plan and execute recovery for an entire compromised system with LoRA rollouts.

This is the system-wide counterpart of
``run_recovery_loop_rollout_baseline_llm_state.py``.  It preserves the original
two-stage baseline semantics:

1. checkpoint-850 generates a complete high-level plan using predicted state
   transitions only;
2. the fixed plan is translated into commands and executed in the DT.

The planning state is a per-server matrix of six Boolean local-state fields.
State prediction retains the checkpoint's single-server prompt/output format,
but all servers affected by one action are evaluated in one batched
``model.generate`` call.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Sequence

import torch

ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = ROOT.parent
PROJECT_SRC = PROJECT_ROOT / "src"
DT_SRC = ROOT / "src"
for path in (PROJECT_ROOT, PROJECT_SRC, DT_SRC):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from examples.planning_simulation_qwen_lora_DTserver import (  # noqa: E402
    build_planner,
    build_state_prompt,
)
from llm_recovery.decision_transformer.planner import (  # noqa: E402
    RECOVERY_STATE_FIELDS,
    TERMINAL_STATE,
    PlannerConfig,
)
from llm_recovery.evaluation.exact_match import _parse_state_json  # noqa: E402
from llm_ir_dt.recovery_loop.command_safety import (  # noqa: E402
    CommandSafetyValidator,
)
from llm_ir_dt.recovery_loop.recovery_executor import RecoveryExecutor  # noqa: E402
from llm_ir_dt.recovery_loop.schemas import (  # noqa: E402
    CommandPlan,
    HighLevelAction,
    dataclass_to_jsonable,
)
from run_recovery_loop_api_baseline_llm_state import (  # noqa: E402
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
from run_recovery_loop_rollout_baseline_llm_state import (  # noqa: E402
    build_command_agent,
    extract_action_object,
)


LocalState = tuple[bool, ...]
SystemState = dict[str, LocalState]

ALL_SCOPE_PHRASES = (
    "all compromised servers",
    "all affected servers",
    "all compromised hosts",
    "all affected hosts",
    "entire compromised system",
    "entire affected system",
    "across the compromised system",
)


@dataclass(frozen=True)
class SystemAction:
    """One high-level action and the compromised servers it affects."""

    action: HighLevelAction
    target_servers: tuple[str, ...]


@dataclass(frozen=True)
class PlannedSystemAction:
    """Selected action paired with its predicted state transition."""

    system_action: SystemAction
    state_before: SystemState
    state_after: SystemState


def initial_system_state(servers: Sequence[str]) -> SystemState:
    """Return an all-false six-dimensional state for each server."""
    return {
        server: tuple(False for _ in RECOVERY_STATE_FIELDS)
        for server in servers
    }


def local_state_to_jsonable(state: Sequence[bool]) -> dict[str, bool]:
    return {
        field: bool(state[index])
        for index, field in enumerate(RECOVERY_STATE_FIELDS)
    }


def system_state_to_jsonable(state: SystemState) -> dict[str, dict[str, bool]]:
    return {
        server: local_state_to_jsonable(local_state)
        for server, local_state in state.items()
    }


def is_system_terminal(state: SystemState) -> bool:
    """Return true only when every compromised server is locally terminal."""
    return bool(state) and all(local_state == TERMINAL_STATE for local_state in state.values())


def infer_compromised_servers(incident: str) -> tuple[str, ...]:
    """Infer the unordered recovery-target set from the incident description."""
    match = re.search(
        r"Recovery targets identified\s*:\s*([^\n]+)",
        incident,
        flags=re.IGNORECASE,
    )
    if match is None:
        raise ValueError(
            "Could not infer compromised servers: incident text must contain "
            "'Recovery targets identified: ...', or use --compromised-servers."
        )
    segment = match.group(1)
    servers = [
        server
        for server, ip in TARGET_SERVER_IPS.items()
        if re.search(rf"(?<!\d){re.escape(ip)}(?!\d)", segment)
    ]
    if not servers:
        raise ValueError("The recovery-target line contains no recognized server IPs")
    return tuple(servers)


def _resolve_target_token(token: str) -> str | None:
    normalized = token.strip().lower()
    for server, ip in TARGET_SERVER_IPS.items():
        if normalized == server.lower() or normalized == ip:
            return server
    return None


def parse_system_action(raw_output: str, compromised_servers: Sequence[str]) -> SystemAction:
    """Parse one action and enforce its explicit compromised-server scope."""
    parsed = extract_action_object(raw_output)
    if parsed is None:
        raise ValueError("System rollout action must contain a JSON object")

    action_text = str(parsed.get("Action") or parsed.get("action") or "").strip()
    explanation = str(
        parsed.get("Explanation") or parsed.get("explanation") or ""
    ).strip()
    if not action_text:
        raise ValueError("System rollout action is empty")

    allowed = tuple(compromised_servers)
    allowed_set = set(allowed)
    raw_targets = parsed.get("TargetServers", parsed.get("target_servers", []))
    if isinstance(raw_targets, str):
        raw_targets = [raw_targets]
    if not isinstance(raw_targets, list):
        raise ValueError("TargetServers must be a JSON array")

    action_scope_text = action_text.lower()
    all_scope = any(phrase in action_scope_text for phrase in ALL_SCOPE_PHRASES)
    all_scope = all_scope or any(
        str(token).strip().lower() in {"all", "all compromised servers", "entire system"}
        for token in raw_targets
    )

    explicit_targets: list[str] = []
    unknown_targets: list[str] = []
    for token in raw_targets:
        token_text = str(token).strip()
        if token_text.lower() in {"all", "all compromised servers", "entire system"}:
            continue
        resolved = _resolve_target_token(token_text)
        if resolved is None:
            unknown_targets.append(token_text)
        elif resolved not in explicit_targets:
            explicit_targets.append(resolved)
    if unknown_targets:
        raise ValueError(f"Unknown TargetServers entries: {unknown_targets}")

    mentioned_servers = [
        server
        for server, ip in TARGET_SERVER_IPS.items()
        if server.lower() in action_scope_text
        or re.search(rf"(?<!\d){re.escape(ip)}(?!\d)", action_scope_text)
    ]
    outside_scope = (set(explicit_targets) | set(mentioned_servers)) - allowed_set
    if outside_scope:
        raise ValueError(
            "Action targets servers outside this incident's recovery set: "
            + ", ".join(sorted(outside_scope))
        )

    if all_scope:
        targets = allowed
    elif explicit_targets:
        targets = tuple(server for server in allowed if server in explicit_targets)
    else:
        targets = tuple(server for server in allowed if server in mentioned_servers)
    if not targets:
        raise ValueError(
            "Action must explicitly identify at least one compromised server "
            "or state that it applies to all compromised servers"
        )

    return SystemAction(
        action=HighLevelAction(
            action=action_text,
            explanation=explanation,
            raw_model_output=raw_output,
        ),
        target_servers=targets,
    )


def build_system_action_prompt(
    *,
    context: dict[str, str],
    state: SystemState,
    previous_actions: Sequence[SystemAction],
) -> str:
    """Build a no-priority, system-wide action-generation prompt."""
    previous = [
        {
            "Action": item.action.action,
            "TargetServers": list(item.target_servers),
        }
        for item in previous_actions
    ]
    meanings = "\n".join(
        (
            "is_attack_contained: Has the immediate threat been stopped from spreading?",
            "is_knowledge_sufficient: Is enough information available for effective recovery?",
            "are_forensics_preserved: Has relevant evidence been preserved soundly?",
            "is_eradicated: Has the adversary and its foothold been removed?",
            "is_hardened: Has the root cause been remediated to prevent recurrence?",
            "is_recovered: Are primary services restored for users?",
        )
    )
    return (
        "Below is a system description, incident logs, an incident description, "
        "and the current per-server recovery states. Generate the next high-level "
        "action for recovering the entire compromised system. No server priority "
        "or recovery order is provided; select the appropriate target server or "
        "servers from the incident evidence and current states.\n\n"
        f"### System:\n{context.get('System', '').strip()}\n\n"
        f"### Logs:\n{context.get('Logs', '').strip()}\n\n"
        f"### Incident:\n{context.get('Incident', '').strip()}\n\n"
        "### Per-server recovery states:\n"
        f"{json.dumps(system_state_to_jsonable(state), indent=2)}\n\n"
        f"### State field meanings:\n{meanings}\n\n"
        "### Previous selected recovery actions:\n"
        f"{json.dumps(previous, indent=2, ensure_ascii=False)}\n\n"
        "Select a concrete action that advances one or more currently false state "
        "fields without repeating completed work. An action may target one server "
        "or multiple servers when the same operation genuinely applies to each of "
        "them. TargetServers must contain only server names present in the state "
        "matrix. Do not include gateway, client, or IDS as state targets; those may "
        "appear only as supporting infrastructure in Action. Return valid JSON only:\n"
        "{\n"
        '  "Action": "...",\n'
        '  "Explanation": "...",\n'
        '  "TargetServers": ["server_name", "..."]\n'
        "}"
    )


def sample_system_actions(
    *,
    planner: Any,
    config: PlannerConfig,
    context: dict[str, str],
    state: SystemState,
    previous_actions: Sequence[SystemAction],
    compromised_servers: Sequence[str],
    count: int,
) -> list[SystemAction]:
    """Sample distinct, valid system-scoped actions from checkpoint-850."""
    prompt = build_system_action_prompt(
        context=context,
        state=state,
        previous_actions=previous_actions,
    )
    actions: list[SystemAction] = []
    seen: set[tuple[str, tuple[str, ...]]] = set()
    attempts = 0
    max_attempts = max(count * 4, count)
    while len(actions) < count and attempts < max_attempts:
        attempts += 1
        raw_output = planner._generate_text(
            prompt,
            max_new_tokens=config.action_max_new_tokens,
            temperature=config.candidate_temperature,
            top_p=config.candidate_top_p,
        )
        try:
            system_action = parse_system_action(raw_output, compromised_servers)
        except ValueError:
            continue
        key = (system_action.action.action, system_action.target_servers)
        if key not in seen:
            seen.add(key)
            actions.append(system_action)
    return actions


def _batch_generate_state_texts(
    *,
    planner: Any,
    prompts: Sequence[str],
    config: PlannerConfig,
) -> list[str]:
    """Generate one state response per prompt in a single model.generate call."""
    if not prompts:
        return []
    tokenizer = planner.tokenizer
    old_padding_side = tokenizer.padding_side
    tokenizer.padding_side = "left"
    try:
        encoded = tokenizer(
            list(prompts),
            return_tensors="pt",
            padding=True,
        ).to(planner.llm.device)
        do_sample = config.rollout_temperature > 0.0
        generation_args: dict[str, Any] = {
            "max_new_tokens": config.state_max_new_tokens,
            "do_sample": do_sample,
            "eos_token_id": tokenizer.eos_token_id,
            "pad_token_id": tokenizer.pad_token_id,
        }
        if do_sample:
            generation_args["temperature"] = config.rollout_temperature
            generation_args["top_p"] = config.rollout_top_p
        with torch.inference_mode():
            output = planner.llm.generate(**encoded, **generation_args)
        prompt_width = int(encoded["input_ids"].shape[1])
        generated_tokens = output[:, prompt_width:]
        return [text.strip() for text in tokenizer.batch_decode(
            generated_tokens,
            skip_special_tokens=True,
        )]
    finally:
        tokenizer.padding_side = old_padding_side


def apply_state_prediction_outputs(
    *,
    state: SystemState,
    targets: Sequence[str],
    outputs: Sequence[str],
) -> SystemState | None:
    """Apply independently parsed six-state predictions to targeted servers."""
    if len(targets) != len(outputs):
        raise ValueError("State target/output batch lengths do not match")
    next_state = dict(state)
    for server, output in zip(targets, outputs):
        parsed = _parse_state_json(output)
        if parsed is None:
            return None
        next_state[server] = tuple(
            bool(parsed[field]) for field in RECOVERY_STATE_FIELDS
        )
    return next_state


def predict_system_state_batch(
    *,
    planner: Any,
    config: PlannerConfig,
    context: dict[str, str],
    state: SystemState,
    system_action: SystemAction,
) -> SystemState | None:
    """Predict all affected local states using one batched model invocation."""
    prompts: list[str] = []
    for server in system_action.target_servers:
        local_context = dict(context)
        local_context["TargetServer"] = f"{server} / {TARGET_SERVER_IPS[server]}"
        prompts.append(
            build_state_prompt(
                local_context,
                state[server],
                system_action.action.raw_model_output,
            )
        )
    outputs = _batch_generate_state_texts(
        planner=planner,
        prompts=prompts,
        config=config,
    )
    return apply_state_prediction_outputs(
        state=state,
        targets=system_action.target_servers,
        outputs=outputs,
    )


def rollout_recovery_depth(
    *,
    planner: Any,
    config: PlannerConfig,
    context: dict[str, str],
    compromised_servers: Sequence[str],
    state: SystemState,
    action: SystemAction,
    previous_actions: Sequence[SystemAction],
    depth: int,
) -> int:
    """Estimate remaining system recovery depth along one sampled trajectory."""
    if depth >= config.max_rollout_depth:
        return config.max_rollout_depth
    next_state = predict_system_state_batch(
        planner=planner,
        config=config,
        context=context,
        state=state,
        system_action=action,
    )
    if next_state is None:
        return config.max_rollout_depth
    if is_system_terminal(next_state):
        return 1
    next_actions = sample_system_actions(
        planner=planner,
        config=config,
        context=context,
        state=next_state,
        previous_actions=[*previous_actions, action],
        compromised_servers=compromised_servers,
        count=1,
    )
    if not next_actions:
        return config.max_rollout_depth
    return 1 + rollout_recovery_depth(
        planner=planner,
        config=config,
        context=context,
        compromised_servers=compromised_servers,
        state=next_state,
        action=next_actions[0],
        previous_actions=[*previous_actions, action],
        depth=depth + 1,
    )


def generate_complete_system_plan(
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
) -> tuple[list[PlannedSystemAction], dict[str, Any]]:
    """Generate a fixed high-level plan for the complete compromised system."""
    planner_context = dict(context)
    planner_context["TargetServer"] = "Selected dynamically from the system state"
    planner, _ = build_planner(
        adapter_path=adapter,
        base_model=base_model,
        device_map=device_map,
        torch_dtype=torch_dtype,
        config=config,
        context=planner_context,
    )
    planner.llm.eval()

    state = initial_system_state(compromised_servers)
    previous_actions: list[SystemAction] = []
    selected_actions: list[PlannedSystemAction] = []
    trace_steps: list[dict[str, Any]] = []
    planning_start = time.perf_counter()

    for step in range(1, config.max_plan_steps + 1):
        if is_system_terminal(state):
            break
        if show_progress:
            print(
                f"[planning step {step}] system_state="
                f"{json.dumps(system_state_to_jsonable(state), ensure_ascii=True)}"
            )

        candidates = sample_system_actions(
            planner=planner,
            config=config,
            context=context,
            state=state,
            previous_actions=previous_actions,
            compromised_servers=compromised_servers,
            count=config.num_candidates,
        )
        if not candidates:
            trace_steps.append(
                {
                    "step": step,
                    "state_before": system_state_to_jsonable(state),
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
                    rollout_recovery_depth(
                        planner=planner,
                        config=config,
                        context=context,
                        compromised_servers=compromised_servers,
                        state=state,
                        action=candidate,
                        previous_actions=previous_actions,
                        depth=0,
                    )
                )
            score = float(sum(samples)) / float(len(samples))
            scores.append(score)
            candidate_records.append(
                {
                    "candidate_index": candidate_index,
                    "action": dataclass_to_jsonable(candidate.action),
                    "target_servers": list(candidate.target_servers),
                    "rollout_recovery_depths": samples,
                    "mean_recovery_depth": score,
                }
            )

        best_index = min(range(len(candidates)), key=lambda index: scores[index])
        selected = candidates[best_index]
        next_state = predict_system_state_batch(
            planner=planner,
            config=config,
            context=context,
            state=state,
            system_action=selected,
        )
        step_record: dict[str, Any] = {
            "step": step,
            "state_before": system_state_to_jsonable(state),
            "candidates": candidate_records,
            "selected_candidate_index": best_index + 1,
            "selected_action": dataclass_to_jsonable(selected.action),
            "selected_target_servers": list(selected.target_servers),
            "selected_mean_recovery_depth": scores[best_index],
            "state_after": (
                system_state_to_jsonable(next_state)
                if next_state is not None
                else None
            ),
        }
        trace_steps.append(step_record)
        if show_progress:
            print(
                f"  selected score={scores[best_index]:.3f} "
                f"targets={','.join(selected.target_servers)} "
                f"action={selected.action.action}"
            )
        if next_state is None:
            step_record["stop_reason"] = "batched_state_prediction_failed"
            break

        selected_actions.append(
            PlannedSystemAction(
                system_action=selected,
                state_before=dict(state),
                state_after=dict(next_state),
            )
        )
        previous_actions.append(selected)
        state = next_state

    planning_seconds = time.perf_counter() - planning_start
    trace = {
        "algorithm": "lora_system_candidate_rollout_batched_local_states",
        "compromised_servers": list(compromised_servers),
        "state_dimension": len(compromised_servers) * len(RECOVERY_STATE_FIELDS),
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
        "final_predicted_state": system_state_to_jsonable(state),
        "reached_terminal_state": is_system_terminal(state),
        "planning_wall_clock_time_seconds": planning_seconds,
    }
    if not selected_actions:
        raise RuntimeError("System rollout planner did not generate any actions")
    return selected_actions, trace


def _target_specific_action(action: SystemAction, server: str) -> HighLevelAction:
    """Scope command translation to one target while retaining the system action."""
    return HighLevelAction(
        action=(
            f"{action.action.action} For this command plan, implement only the "
            f"portion affecting {server} ({TARGET_SERVER_IPS[server]})."
        ),
        explanation=action.action.explanation,
        raw_model_output=action.action.raw_model_output,
    )


def execute_complete_system_plan(
    *,
    planned_actions: Sequence[PlannedSystemAction],
    command_agent: Any,
    context: dict[str, str],
    dt_context: str,
    attacker_ip: str,
    run_dir: Path,
) -> tuple[list[dict[str, Any]], float]:
    """Translate and execute the fixed plan, recording per-server outcomes."""
    executed_dir = run_dir / "executed_plans"
    failed_dir = run_dir / "failed_plans"
    executed_dir.mkdir(parents=True, exist_ok=True)
    failed_dir.mkdir(parents=True, exist_ok=True)
    executor = RecoveryExecutor()
    safety = CommandSafetyValidator()
    history_actions: list[HighLevelAction] = []
    summaries: list[dict[str, Any]] = []
    execution_start = time.perf_counter()

    for step, planned in enumerate(planned_actions, start=1):
        target_results: list[dict[str, Any]] = []
        action_success = True
        for server in planned.system_action.target_servers:
            target_action = _target_specific_action(planned.system_action, server)
            plan: CommandPlan | None = None
            result = None
            error = ""
            wall_start = time.perf_counter()
            try:
                plan = plan_for_action(
                    command_agent=command_agent,
                    action=target_action,
                    state=local_state_to_jsonable(planned.state_before[server]),
                    context=context,
                    dt_context=dt_context,
                    server=server,
                    server_ip=TARGET_SERVER_IPS[server],
                    attacker_ip=attacker_ip,
                    history_actions=history_actions,
                )
                safety.validate_plan(plan)
                result = executor.execute_plan(
                    plan,
                    state_before=local_state_to_jsonable(planned.state_before[server]),
                )
                success = result.success
            except Exception as exc:
                success = False
                error = f"{type(exc).__name__}: {exc}"
            wall_seconds = time.perf_counter() - wall_start
            payload = {
                "step": step,
                "server": server,
                "system_action": dataclass_to_jsonable(planned.system_action.action),
                "target_servers": list(planned.system_action.target_servers),
                "state_before": local_state_to_jsonable(planned.state_before[server]),
                "predicted_state_after": local_state_to_jsonable(planned.state_after[server]),
                "plan": dataclass_to_jsonable(plan) if plan is not None else None,
                "execution": dataclass_to_jsonable(result) if result is not None else None,
                "success": success,
                "error": error,
                "wall_clock_time_seconds": wall_seconds,
            }
            target_dir = executed_dir if plan is not None and result is not None else failed_dir
            step_dir = target_dir / f"step_{step:03d}"
            step_dir.mkdir(parents=True, exist_ok=True)
            (step_dir / f"{server}.json").write_text(
                json.dumps(payload, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            action_seconds = result.action_total_time_seconds if result else 0.0
            target_results.append(
                {
                    "server": server,
                    "success": success,
                    "error": error,
                    "action_total_time_seconds": action_seconds,
                    "wall_clock_time_seconds": wall_seconds,
                }
            )
            action_success = action_success and success
            print(
                f"step={step} server={server} success={success} "
                f"action_total_time_seconds={action_seconds:.3f} "
                f"action={planned.system_action.action.action}"
            )

        action_total = sum(
            item["action_total_time_seconds"] for item in target_results
        )
        summaries.append(
            {
                "step": step,
                "action": dataclass_to_jsonable(planned.system_action.action),
                "target_servers": list(planned.system_action.target_servers),
                "success": action_success,
                "target_results": target_results,
                "action_total_time_seconds": action_total,
            }
        )
        if action_success:
            history_actions.append(planned.system_action.action)
        else:
            break

    return summaries, time.perf_counter() - execution_start


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Generate a system-wide high-level recovery plan with checkpoint-850 "
            "and batched per-server state prediction, then execute the fixed plan."
        )
    )
    parser.add_argument(
        "--compromised-servers",
        nargs="+",
        choices=tuple(TARGET_SERVER_IPS),
        default=None,
        help=(
            "Unordered recovery-target set. By default it is inferred from the "
            "'Recovery targets identified' line in the incident file."
        ),
    )
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
        type=int,
        default=None,
        help="Maximum selected actions; defaults to six times the server count.",
    )
    parser.add_argument(
        "--max-rollout-depth",
        type=int,
        default=None,
        help="Rollout horizon; defaults to six times the server count.",
    )
    parser.add_argument("--action-max-new-tokens", type=int, default=500)
    parser.add_argument("--state-max-new-tokens", type=int, default=1200)
    parser.add_argument("--action-temperature", type=float, default=0.6)
    parser.add_argument("--action-top-p", type=float, default=0.9)
    parser.add_argument("--state-temperature", type=float, default=0.0)
    parser.add_argument("--state-top-p", type=float, default=0.9)
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
        default=str(ROOT / "artifacts" / "recovery_lora_rollout_system"),
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.num_candidates < 1 or args.num_rollouts < 1:
        raise ValueError("--num-candidates and --num-rollouts must be at least 1")
    if args.max_actions is not None and args.max_actions < 1:
        raise ValueError("--max-actions must be at least 1")
    if args.max_rollout_depth is not None and args.max_rollout_depth < 1:
        raise ValueError("--max-rollout-depth must be at least 1")

    context = {
        "System": read_text_arg(args.system, args.system_file, DEFAULT_SYSTEM),
        "Logs": read_text_arg(args.logs, args.logs_file, DEFAULT_LOGS),
        "Incident": read_text_arg(
            args.incident,
            args.incident_file,
            DEFAULT_INCIDENT,
        ),
    }
    compromised_servers = tuple(args.compromised_servers or infer_compromised_servers(
        context["Incident"]
    ))
    compromised_servers = tuple(
        server for server in TARGET_SERVER_IPS if server in set(compromised_servers)
    )
    context["CompromisedServers"] = ", ".join(
        f"{server} / {TARGET_SERVER_IPS[server]}" for server in compromised_servers
    )
    default_system_horizon = len(compromised_servers) * len(RECOVERY_STATE_FIELDS)
    max_actions = args.max_actions or default_system_horizon
    max_rollout_depth = args.max_rollout_depth or default_system_horizon
    dt_context = (
        Path(args.dt_context_file).expanduser().read_text(encoding="utf-8").strip()
        if args.dt_context_file
        else ""
    )

    config = PlannerConfig(
        num_candidates=args.num_candidates,
        num_rollout_samples=args.num_rollouts,
        max_plan_steps=max_actions,
        max_rollout_depth=max_rollout_depth,
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
                "BaselineType": "lora_rollout_complete_system_plan",
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

    planned_actions, planning_trace = generate_complete_system_plan(
        adapter=args.adapter,
        base_model=args.base_model,
        device_map=args.device_map,
        torch_dtype=args.torch_dtype,
        config=config,
        context=context,
        compromised_servers=compromised_servers,
        show_progress=args.show_progress,
        show_rollout_progress=args.show_rollout_progress,
    )
    (run_dir / "rollout_high_level_plan.json").write_text(
        json.dumps(
            {
                "actions": [
                    {
                        "action": dataclass_to_jsonable(item.system_action.action),
                        "target_servers": list(item.system_action.target_servers),
                        "state_before": system_state_to_jsonable(item.state_before),
                        "state_after": system_state_to_jsonable(item.state_after),
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
        f"Generated {len(planned_actions)} system-wide high-level actions. "
        f"predicted_terminal={planning_trace['reached_terminal_state']}"
    )

    command_agent = build_command_agent(args)
    restore_timings = restore_and_attack(
        wait_seconds=args.wait_seconds,
        rebuild_images=args.rebuild_images,
        attack_script=args.attack_script,
        attack_args=args.attack_arg,
    )
    step_summaries, execution_wall_clock = execute_complete_system_plan(
        planned_actions=planned_actions,
        command_agent=command_agent,
        context=context,
        dt_context=dt_context,
        attacker_ip=args.attacker_ip,
        run_dir=run_dir,
    )
    execution_success = (
        len(step_summaries) == len(planned_actions)
        and all(item["success"] for item in step_summaries)
    )
    summary = {
        "compromised_servers": list(compromised_servers),
        "high_level_plan_generation": {
            "method": "lora_system_rollout_batched_local_state_prediction",
            "adapter": args.adapter,
            "state_dimension": len(compromised_servers) * len(RECOVERY_STATE_FIELDS),
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
