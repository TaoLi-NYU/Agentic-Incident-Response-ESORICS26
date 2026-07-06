"""Execute recovery command plans in the digital twin."""

from __future__ import annotations

import time

from llm_ir_dt.recovery_loop.schemas import (
    ActionExecutionResult,
    CommandPlan,
    CommandResult,
    CommandSpec,
    RecoveryState,
)


class RecoveryExecutor:
    """Run command plans via DockerManager and collect timings."""

    def execute_plan(
        self,
        plan: CommandPlan,
        *,
        state_before: RecoveryState | None = None,
        state_after: RecoveryState | None = None,
    ) -> ActionExecutionResult:
        """Execute recovery and verification commands for one plan."""
        command_results = tuple(
            self._run_command(spec, phase="recovery") for spec in plan.commands
        )
        verification_results = tuple(
            self._run_command(spec, phase="verification")
            for spec in plan.verification_commands
        )
        action_time = sum(result.elapsed_seconds for result in command_results)
        verification_time = sum(result.elapsed_seconds for result in verification_results)
        all_results = command_results + verification_results
        success = all(result.success for result in all_results)

        return ActionExecutionResult(
            high_level_action=plan.high_level_action,
            high_level_action_explanation=plan.high_level_action_explanation,
            success=success,
            action_execution_time_seconds=action_time,
            action_verification_time_seconds=verification_time,
            action_total_time_seconds=action_time + verification_time,
            command_results=command_results,
            verification_results=verification_results,
            state_before=state_before,
            state_after=state_after,
        )

    def _run_command(self, spec: CommandSpec, phase: str) -> CommandResult:
        from llm_ir_dt.docker_manager.docker_manager import DockerManager

        start = time.perf_counter()
        result = DockerManager.exec_run(spec.container, spec.command)
        elapsed = time.perf_counter() - start
        return CommandResult(
            container=spec.container,
            command=spec.command,
            exit_code=int(result["exit_code"]),
            output=str(result["output"]),
            elapsed_seconds=elapsed,
            phase=phase,
            allowed_exit_codes=spec.allowed_exit_codes,
        )
