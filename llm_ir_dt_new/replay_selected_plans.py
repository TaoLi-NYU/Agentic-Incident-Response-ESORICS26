"""
Replay previously selected recovery command plans.

This script reuses command plans already saved by a recovery-loop run. It does
not call the high-level action model, does not call a command-generation API,
and does not perform candidate rollout. Use it after resetting the digital twin
to the same baseline when you want to apply an existing recovery playbook.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from llm_ir_dt.recovery_loop.recovery_executor import RecoveryExecutor
from llm_ir_dt.recovery_loop.schemas import CommandPlan, CommandSpec


DEFAULT_SELECTED_PLANS_DIR = (
    ROOT
    / "artifacts"
    / "recovery_loop_llm_state"
    / "runs"
    / "20260602_113134"
    / "selected_plans"
)


def _command_spec_from_json(raw: dict[str, Any]) -> CommandSpec:
    return CommandSpec(
        container=str(raw["container"]),
        command=str(raw["command"]),
        allowed_exit_codes=tuple(int(code) for code in raw.get("allowed_exit_codes", [0])),
        description=str(raw.get("description", "")),
    )


def _load_plan(path: Path) -> CommandPlan:
    obj = json.loads(path.read_text(encoding="utf-8"))
    plan = obj.get("plan", obj)
    return CommandPlan(
        high_level_action=str(plan.get("high_level_action", "")),
        high_level_action_explanation=str(plan.get("high_level_action_explanation", "")),
        commands=tuple(_command_spec_from_json(item) for item in plan.get("commands", [])),
        verification_commands=tuple(
            _command_spec_from_json(item) for item in plan.get("verification_commands", [])
        ),
        expected_state_change=dict(plan.get("expected_state_change", {})),
        rollback_commands=tuple(
            _command_spec_from_json(item) for item in plan.get("rollback_commands", [])
        ),
        raw_model_output=str(plan.get("raw_model_output", "")),
    )


def load_selected_plans(selected_plans_dir: Path) -> list[tuple[Path, CommandPlan]]:
    paths = sorted(selected_plans_dir.glob("step_*.json"))
    if not paths:
        raise SystemExit(f"No selected plan files found in {selected_plans_dir}")
    return [(path, _load_plan(path)) for path in paths]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Replay selected recovery commands from a previous recovery-loop run."
    )
    parser.add_argument(
        "--selected-plans-dir",
        default=str(DEFAULT_SELECTED_PLANS_DIR),
        help="Directory containing selected_plans/step_*.json files.",
    )
    parser.add_argument(
        "--skip-verification-commands",
        action="store_true",
        help="Execute recovery commands only and skip saved verification commands.",
    )
    parser.add_argument(
        "--output-json",
        default=None,
        help="Optional path to save detailed replay results.",
    )
    args = parser.parse_args()

    selected_plans_dir = Path(args.selected_plans_dir).expanduser()
    plans = load_selected_plans(selected_plans_dir)
    executor = RecoveryExecutor()

    replay_results = []
    total_start = time.perf_counter()
    print(f"Replaying {len(plans)} selected plans from {selected_plans_dir}")

    for idx, (path, plan) in enumerate(plans, start=1):
        if args.skip_verification_commands:
            plan = CommandPlan(
                high_level_action=plan.high_level_action,
                high_level_action_explanation=plan.high_level_action_explanation,
                commands=plan.commands,
                verification_commands=(),
                expected_state_change=plan.expected_state_change,
                rollback_commands=plan.rollback_commands,
                raw_model_output=plan.raw_model_output,
            )

        print(f"\nstep={idx} file={path.name}")
        print(f"action={plan.high_level_action}")
        result = executor.execute_plan(plan)
        print(
            f"success={result.success} "
            f"execution_seconds={result.action_execution_time_seconds:.3f} "
            f"verification_seconds={result.action_verification_time_seconds:.3f} "
            f"total_seconds={result.action_total_time_seconds:.3f}"
        )
        for command_result in result.command_results + result.verification_results:
            print(
                f"  [{command_result.phase}] {command_result.container}: "
                f"exit={command_result.exit_code} "
                f"time={command_result.elapsed_seconds:.3f}s "
                f"command={command_result.command}"
            )
            if not command_result.success:
                output = command_result.output.strip()
                if output:
                    print(f"    output={output[:500]}")

        replay_results.append(
            {
                "step": idx,
                "file": str(path),
                "action": plan.high_level_action,
                "success": result.success,
                "action_execution_time_seconds": result.action_execution_time_seconds,
                "action_verification_time_seconds": result.action_verification_time_seconds,
                "action_total_time_seconds": result.action_total_time_seconds,
                "commands": [
                    {
                        "phase": item.phase,
                        "container": item.container,
                        "command": item.command,
                        "exit_code": item.exit_code,
                        "elapsed_seconds": item.elapsed_seconds,
                        "success": item.success,
                        "output": item.output,
                    }
                    for item in result.command_results + result.verification_results
                ],
            }
        )

    total_elapsed = time.perf_counter() - total_start
    print(f"\nReplay complete. total_seconds={total_elapsed:.3f}")

    if args.output_json:
        output_path = Path(args.output_json).expanduser()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(
                {
                    "selected_plans_dir": str(selected_plans_dir),
                    "total_seconds": total_elapsed,
                    "steps": replay_results,
                },
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        print(f"Saved replay results to {output_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
