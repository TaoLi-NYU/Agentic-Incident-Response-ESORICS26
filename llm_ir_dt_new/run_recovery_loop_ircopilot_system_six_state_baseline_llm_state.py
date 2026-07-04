"""Run an IRCopilot-style IRT baseline for whole-system DT recovery.

This variant keeps one Incident Response Tree for the entire compromised
system.  Its six child tasks correspond to the six global recovery criteria.
The action generator emits only Action and Explanation text; it may describe
one or more targets, but target names are not parsed or enforced structurally.
The command agent always receives the complete unordered recovery-target set.
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

from llm_ir_dt.recovery_loop.command_agent import CommandAgentRequest  # noqa: E402
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
from examples.planning_simulation_qwen_lora_DT import (  # noqa: E402
    build_action_prompt as build_system_action_prompt,
)
from run_recovery_loop_api_baseline_llm_state import (  # noqa: E402
    restore_and_attack,
)
from run_recovery_loop_ircopilot_baseline_llm_state import (  # noqa: E402
    APISubtaskActionGenerator as BaseAPISubtaskActionGenerator,
    IRTNode,
    LocalCheckpointSubtaskActionGenerator as BaseLocalCheckpointActionGenerator,
    build_command_agent,
    find_node,
    node_to_jsonable,
    select_next_subtask,
)
from run_recovery_loop_llm_state import (  # noqa: E402
    DEFAULT_INCIDENT,
    DEFAULT_LOGS,
    DEFAULT_SYSTEM,
    TARGET_SERVER_IPS,
    read_text_arg,
)
from run_recovery_loop_rollout_system_baseline_llm_state import (  # noqa: E402
    infer_compromised_servers,
)


GLOBAL_SUBTASK_DESCRIPTIONS: dict[str, str] = {
    "is_attack_contained": (
        "Contain active attack paths affecting the compromised system and "
        "prevent continued attacker access or lateral movement."
    ),
    "is_knowledge_sufficient": (
        "Assess the incident across the compromised system and gather enough "
        "knowledge to guide eradication and recovery."
    ),
    "are_forensics_preserved": (
        "Preserve relevant host, gateway, IDS, application, and attacker-created "
        "evidence for the compromised system."
    ),
    "is_eradicated": (
        "Remove attacker footholds, malicious artifacts, unauthorized changes, "
        "vulnerable execution paths, and persistence from the compromised system."
    ),
    "is_hardened": (
        "Harden every affected service and related access path needed to prevent "
        "recurrence across the compromised system."
    ),
    "is_recovered": (
        "Restore and validate all required services across the compromised system "
        "under appropriate monitoring."
    ),
}


def target_records(compromised_servers: Sequence[str]) -> list[dict[str, str]]:
    return [
        {"server": server, "server_ip": TARGET_SERVER_IPS[server]}
        for server in compromised_servers
    ]


def initialize_system_irt(compromised_servers: Sequence[str]) -> list[IRTNode]:
    targets = ", ".join(
        f"{server} ({TARGET_SERVER_IPS[server]})" for server in compromised_servers
    )
    return [
        IRTNode(
            id=f"1.{index}",
            recovery_state_field=field_name,
            task=(
                f"{field_name}: {GLOBAL_SUBTASK_DESCRIPTIONS[field_name]} "
                "This criterion is complete only when it is satisfied for every "
                f"applicable compromised target. Unordered targets: {targets}."
            ),
        )
        for index, field_name in enumerate(RECOVERY_STATE_FIELDS, start=1)
    ]


def create_system_repair_task(
    nodes: list[IRTNode],
    failed_node: IRTNode,
) -> IRTNode:
    repair_attempt = failed_node.repair_attempts + 1
    failed_node.repair_attempts = repair_attempt
    repair_node = IRTNode(
        id=f"{failed_node.id}.repair{repair_attempt}",
        recovery_state_field=failed_node.recovery_state_field,
        task=(
            f"Repair failed whole-system subtask {failed_node.id} "
            f"({failed_node.recovery_state_field}). Use the prior execution "
            "summary and IRT history to diagnose the failure, then generate a "
            "narrower corrective high-level action for the same global recovery "
            "criterion."
        ),
        status="repairing",
        repair_attempts=repair_attempt,
        parent_id=failed_node.id,
        repair_for=failed_node.id,
    )
    nodes.append(repair_node)
    return repair_node


def whole_system_prompt_context(
    *,
    context: dict[str, str],
    irt_nodes: list[IRTNode],
    selected_node: IRTNode,
) -> str:
    return (
        f"{context.get('Logs', '').strip()}\n\n"
        "Whole-system recovery constraints:\n"
        f"{context.get('TargetServer', '').strip()}\n"
        "The Generator may describe one or more applicable servers in the "
        "high-level action, but must not emit a TargetServers field. The command "
        "agent receives the complete recovery-target set and determines concrete "
        "command containers from the action text.\n\n"
        "Current IRCopilot-style whole-system IRT:\n"
        f"{json.dumps([node_to_jsonable(node) for node in irt_nodes], indent=2)}\n\n"
        "Selected global IRT subtask to address now:\n"
        f"{json.dumps(node_to_jsonable(selected_node), indent=2)}\n\n"
        "Generate the next action for this selected global subtask only. If it "
        "is a repair task, use its prior failure history to generate a narrower "
        "corrective action for the same global recovery criterion."
    ).strip()


class WholeSystemAPISubtaskActionGenerator(BaseAPISubtaskActionGenerator):
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
            "Below is the incident context and one Incident Response Tree (IRT) "
            "whose root task is recovery of the entire compromised system. The "
            "six child subtasks are global recovery criteria. Generate exactly "
            "one high-level recovery action for the selected global IRT subtask. "
            "No server priority or recovery order is provided. Do not include "
            "shell commands, command syntax, a TargetServers field, JSON command "
            "plans, or digital-twin implementation details.\n\n"
            f"### System:\n{context.get('System', '').strip()}\n\n"
            f"### Logs:\n{context.get('Logs', '').strip()}\n\n"
            f"### Incident:\n{context.get('Incident', '').strip()}\n\n"
            "### Compromised recovery targets (unordered):\n"
            f"{context.get('TargetServer', '').strip()}\n\n"
            "### Current whole-system recovery state:\n"
            f"{json.dumps(current_state, indent=2)}\n\n"
            "### Current whole-system IRT:\n"
            f"{json.dumps([node_to_jsonable(node) for node in irt_nodes], indent=2)}\n\n"
            "### Previous execution summaries:\n"
            f"{json.dumps(previous_steps[-3:], indent=2, ensure_ascii=False)}\n\n"
            "### Selected global IRT subtask:\n"
            f"{json.dumps(node_to_jsonable(selected_node), indent=2)}\n\n"
            "Return valid JSON only with exactly this shape:\n"
            "{\n"
            '  "Action": "...",\n'
            '  "Explanation": "..."\n'
            "}"
        )


class WholeSystemLocalCheckpointActionGenerator(
    BaseLocalCheckpointActionGenerator
):
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
        prompt_context["Logs"] = whole_system_prompt_context(
            context=context,
            irt_nodes=irt_nodes,
            selected_node=selected_node,
        )
        state_tuple = tuple(
            bool(current_state.get(field_name, False))
            for field_name in RECOVERY_STATE_FIELDS
        )
        return build_system_action_prompt(
            prompt_context,
            state_tuple,
            previous_actions,
        ).rstrip()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run an IRCopilot-style six-subtask IRT for whole-system DT recovery."
        )
    )
    parser.add_argument(
        "--compromised-servers",
        nargs="+",
        choices=tuple(TARGET_SERVER_IPS),
        default=None,
        help="Unordered recovery-target set; inferred from the incident by default.",
    )
    parser.add_argument("--attacker-ip", default="10.0.1.11")
    parser.add_argument("--max-actions", type=int, default=10)
    parser.add_argument("--max-repair-attempts", type=int, default=2)
    parser.add_argument(
        "--action-provider",
        choices=("local-model", "api"),
        default="local-model",
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
    parser.add_argument("--command-generation-attempts", type=int, default=3)
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
        default=str(ROOT / "artifacts" / "recovery_ircopilot_system_six_state"),
    )
    return parser


def main() -> int:
    algorithm_wall_clock_start = time.perf_counter()
    args = build_parser().parse_args()
    if args.max_actions < 1:
        raise ValueError("--max-actions must be at least 1")
    if args.max_repair_attempts < 1:
        raise ValueError("--max-repair-attempts must be at least 1")
    if args.command_generation_attempts < 1:
        raise ValueError("--command-generation-attempts must be at least 1")

    base_context = {
        "System": read_text_arg(args.system, args.system_file, DEFAULT_SYSTEM),
        "Logs": read_text_arg(args.logs, args.logs_file, DEFAULT_LOGS),
        "Incident": read_text_arg(args.incident, args.incident_file, DEFAULT_INCIDENT),
    }
    inferred = args.compromised_servers or infer_compromised_servers(
        base_context["Incident"]
    )
    inferred_set = set(inferred)
    compromised_servers = tuple(
        server for server in TARGET_SERVER_IPS if server in inferred_set
    )
    if not compromised_servers:
        raise ValueError("No compromised recovery targets could be inferred")

    target_text = ", ".join(
        f"{server} / {TARGET_SERVER_IPS[server]}" for server in compromised_servers
    )
    context = {
        **base_context,
        "TargetServer": (
            "Entire compromised system. Compromised recovery targets "
            f"(unordered): {target_text}. No server priority is provided."
        ),
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
    for directory in (
        run_dir,
        run_dir / "irt_updates",
        run_dir / "selected_subtasks",
        run_dir / "generated_actions",
        run_dir / "api_action_attempts",
        run_dir / "executed_plans",
        run_dir / "failed_plans",
    ):
        directory.mkdir(parents=True, exist_ok=True)

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
                "BaselineType": "ircopilot_style_whole_system_irt",
                "CompromisedServers": target_records(compromised_servers),
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

    irt_nodes = initialize_system_irt(compromised_servers)
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
            raise ValueError("--adapter is required with --action-provider local-model")
        action_generator = WholeSystemLocalCheckpointActionGenerator(
            adapter=args.adapter,
            base_model=args.base_model,
            device_map=args.device_map,
            torch_dtype=args.torch_dtype,
            max_new_tokens=args.action_max_new_tokens,
            temperature=args.action_temperature,
            top_p=args.action_top_p,
        )
    else:
        action_generator = WholeSystemAPISubtaskActionGenerator(
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
    current_state: RecoveryState = initial_recovery_state()
    history_actions: list[HighLevelAction] = []
    step_summaries: list[dict[str, Any]] = []
    recovery_targets = tuple(
        (server, TARGET_SERVER_IPS[server]) for server in compromised_servers
    )
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
                (
                    run_dir / "api_action_attempts" / f"step_{step:03d}.json"
                ).write_text(
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
        error = ""
        generation_errors: list[str] = []
        generation_attempts_used = 0
        try:
            request = CommandAgentRequest(
                high_level_action=action,
                current_state=dict(current_state),
                system=context["System"],
                logs=context["Logs"],
                incident=context["Incident"],
                dt_context=dt_context,
                server="entire_compromised_system",
                server_ip="multiple",
                attacker_ip=args.attacker_ip,
                recovery_targets=recovery_targets,
            )
            for attempt in range(1, args.command_generation_attempts + 1):
                generation_attempts_used = attempt
                try:
                    plan = command_agent.generate_plan(request)
                    break
                except Exception as exc:
                    generation_error = (
                        f"attempt {attempt}: {type(exc).__name__}: {exc}"
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
                    f"{args.command_generation_attempts} attempts: "
                    + generation_errors[-1]
                )
            safety.validate_plan(plan)
            result = executor.execute_plan(plan, state_before=current_state)
            success = result.success
        except Exception as exc:
            success = False
            error = f"{type(exc).__name__}: {exc}"

        elapsed = time.perf_counter() - step_start
        action_seconds = result.action_total_time_seconds if result else 0.0
        execution_payload = {
            "step": step,
            "selected_subtask": node_to_jsonable(selected_node),
            "compromised_recovery_targets": target_records(compromised_servers),
            "plan": dataclass_to_jsonable(plan) if plan is not None else None,
            "execution": dataclass_to_jsonable(result) if result is not None else None,
            "error": error,
            "command_generation_attempts_used": generation_attempts_used,
            "command_generation_errors": generation_errors,
            "wall_clock_time_seconds": elapsed,
        }
        output_dir = (
            run_dir / "executed_plans"
            if plan is not None and result is not None
            else run_dir / "failed_plans"
        )
        (output_dir / f"step_{step:03d}.json").write_text(
            json.dumps(execution_payload, indent=2, ensure_ascii=False),
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
                repair_attempts = parent.repair_attempts
            else:
                parent = selected_node
                selected_node.status = "failed"
                repair_attempts = selected_node.repair_attempts
            if repair_attempts >= args.max_repair_attempts:
                stop_reason = (
                    f"repair_failed_{parent.recovery_state_field}_"
                    f"{repair_attempts}_times"
                )
            else:
                repair_node = create_system_repair_task(irt_nodes, parent)
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
                "command_generation_errors": generation_errors,
            }
        )
        step_summary = {
            "step": step,
            "selected_subtask": node_to_jsonable(selected_node),
            "action": dataclass_to_jsonable(action),
            "success": success,
            "error": error,
            "command_generation_attempts_used": generation_attempts_used,
            "command_generation_errors": generation_errors,
            "action_total_time_seconds": action_seconds,
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
            f"action_total_time_seconds={action_seconds:.3f} "
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
    terminal = is_terminal_state(current_state)
    algorithm_wall_clock = time.perf_counter() - algorithm_wall_clock_start
    summary = {
        "compromised_servers": list(compromised_servers),
        "high_level_plan_generation": {
            "method": "ircopilot_style_whole_system_irt",
            "action_provider": args.action_provider,
            "local_checkpoint": args.adapter,
            "api_action_model": args.api_action_model,
            "generated_action_count": len(step_summaries),
            "terminal_irt_state_reached": terminal,
            "stop_reason": stop_reason,
        },
        "restore_timings": restore_timings,
        "final_recovery_state": current_state,
        "irt": [node_to_jsonable(node) for node in irt_nodes],
        "steps": step_summaries,
        "system_recovery_success": terminal,
        "executed_action_total_time_seconds": sum(
            item["action_total_time_seconds"] for item in step_summaries
        ),
        "execution_wall_clock_time_seconds": execution_wall_clock,
        "algorithm_wall_clock_time_seconds": algorithm_wall_clock,
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
        "algorithm_wall_clock_time_seconds="
        f"{summary['algorithm_wall_clock_time_seconds']:.3f}"
    )
    print(f"system_recovery_success={terminal}")
    print(f"stop_reason={stop_reason}")
    return 0 if terminal else 1


if __name__ == "__main__":
    raise SystemExit(main())
