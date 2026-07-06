"""Strict real-rollout orchestration for server_ssh."""

from __future__ import annotations

import time
from dataclasses import dataclass, replace

from llm_ir_dt.recovery_loop.action_provider import ActionProvider
from llm_ir_dt.recovery_loop.command_agent import CommandAgent, CommandAgentRequest
from llm_ir_dt.recovery_loop.command_safety import CommandSafetyValidator
from llm_ir_dt.recovery_loop.plan_store import PlanStore
from llm_ir_dt.recovery_loop.recovery_executor import RecoveryExecutor
from llm_ir_dt.recovery_loop.schemas import (
    ActionExecutionResult,
    CandidateEvaluation,
    CommandPlan,
    HighLevelAction,
    RecoveryState,
    has_regression,
    is_terminal_state,
    state_progress,
)
from llm_ir_dt.recovery_loop.state_verifier import StateVerifier
from llm_ir_dt.recovery_loop.baseline_manager import BaselineManager


@dataclass(frozen=True)
class RecoveryLoopConfig:
    """Configuration for the first recovery-loop implementation."""

    server: str = "server_ssh"
    server_ip: str = "10.0.2.11"
    attacker_ip: str = "10.0.1.11"
    num_candidates: int = 3
    num_rollouts: int = 1
    max_plan_steps: int = 6
    max_rollout_depth: int = 2


class RecoveryLoopOrchestrator:
    """Run strict rollout evaluations and select the fastest valid candidate."""

    def __init__(
        self,
        *,
        context: dict[str, str],
        config: RecoveryLoopConfig,
        command_agent: CommandAgent,
        action_provider: ActionProvider,
        safety: CommandSafetyValidator,
        executor: RecoveryExecutor,
        verifier: StateVerifier,
        baseline_manager: BaselineManager,
        plan_store: PlanStore,
        dt_context: str = "",
    ) -> None:
        self.context = context
        self.config = config
        self.command_agent = command_agent
        self.action_provider = action_provider
        self.safety = safety
        self.executor = executor
        self.verifier = verifier
        self.baseline_manager = baseline_manager
        self.plan_store = plan_store
        self.dt_context = dt_context
        self.selected_plans: list[CommandPlan] = []
        self.history_actions: list[HighLevelAction] = []

    def run(self) -> list[CandidateEvaluation]:
        """Run the recovery loop and return selected candidate evaluations."""
        self.plan_store.write_context(self.context)
        selected: list[CandidateEvaluation] = []
        state, _ = self.baseline_manager.restore(self.selected_plans)

        for step in range(1, self.config.max_plan_steps + 1):
            if is_terminal_state(state):
                break
            candidates = self.action_provider.candidates(
                state,
                self.history_actions,
                self.config.num_candidates,
            )
            evaluations = []
            for idx, candidate in enumerate(candidates, start=1):
                for rollout_idx in range(1, self.config.num_rollouts + 1):
                    evaluations.append(
                        self.evaluate_candidate(
                            step,
                            idx,
                            state,
                            candidate,
                            rollout_index=rollout_idx,
                            rollout_count=self.config.num_rollouts,
                        )
                    )
            for evaluation in evaluations:
                self.plan_store.save_candidate_evaluation(evaluation)

            best = self._select_best_candidate(evaluations)
            if best is None:
                break
            selected.append(best)

            first_result = best.action_results[0] if best.action_results else None
            if first_result is None or best.first_action_plan is None:
                break
            plan = best.first_action_plan
            self.selected_plans.append(plan)
            self.history_actions.append(best.high_level_action)
            self.plan_store.save_selected_plan(step=step, plan=plan, evaluation=best)
            state = dict(first_result.state_after or best.state_after)

        return selected

    def evaluate_candidate(
        self,
        step: int,
        candidate_index: int,
        state: RecoveryState,
        candidate: HighLevelAction,
        rollout_index: int = 1,
        rollout_count: int = 1,
    ) -> CandidateEvaluation:
        """Restore baseline and run strict real rollout for one candidate."""
        wall_start = time.perf_counter()
        restored_state, baseline_time = self.baseline_manager.restore(self.selected_plans)
        if restored_state != state:
            return CandidateEvaluation(
                step=step,
                candidate_index=candidate_index,
                server=self.config.server,
                server_ip=self.config.server_ip,
                high_level_action=candidate,
                success=False,
                valid=False,
                state_before=state,
                state_after=restored_state,
                rollout_total_time_seconds=0.0,
                baseline_restore_time_seconds=baseline_time,
                wall_clock_time_seconds=time.perf_counter() - wall_start,
                action_results=(),
                invalid_reason=f"baseline state mismatch: expected={state}, actual={restored_state}",
                rollout_index=rollout_index,
                rollout_count=rollout_count,
            )

        action_results: list[ActionExecutionResult] = []
        rollout_state = dict(state)
        next_action = candidate
        first_action_plan: CommandPlan | None = None
        rollout_time = 0.0
        invalid_reason = ""

        for depth in range(self.config.max_rollout_depth):
            del depth
            before = dict(rollout_state)
            try:
                plan = self._plan_for_action(next_action, rollout_state)
                if first_action_plan is None:
                    first_action_plan = plan
                self.safety.validate_plan(plan)
                exec_result = self.executor.execute_plan(plan, state_before=before)
            except Exception as exc:
                invalid_reason = f"{type(exc).__name__}: {exc}"
                break
            verification = self.verifier.verify()
            after = verification.state
            exec_result = ActionExecutionResult(
                high_level_action=exec_result.high_level_action,
                high_level_action_explanation=exec_result.high_level_action_explanation,
                success=exec_result.success,
                action_execution_time_seconds=exec_result.action_execution_time_seconds,
                action_verification_time_seconds=exec_result.action_verification_time_seconds,
                action_total_time_seconds=exec_result.action_total_time_seconds,
                command_results=exec_result.command_results,
                verification_results=exec_result.verification_results,
                state_before=before,
                state_after=after,
            )
            action_results.append(exec_result)
            rollout_time += exec_result.action_total_time_seconds

            if not exec_result.success:
                invalid_reason = "command execution failed"
                break
            if has_regression(before, after):
                invalid_reason = "state regression detected"
                break
            rollout_state = after
            if is_terminal_state(rollout_state):
                break
            rollout_candidates = self.action_provider.candidates(
                rollout_state,
                self.history_actions + [next_action],
                1,
            )
            if not rollout_candidates:
                invalid_reason = "no rollout action generated"
                break
            next_action = rollout_candidates[0]

        progress = state_progress(state, rollout_state)
        success = bool(action_results) and all(result.success for result in action_results)
        valid = success and progress > 0 and not invalid_reason
        if not valid and not invalid_reason:
            invalid_reason = "candidate did not improve recovery state"

        return CandidateEvaluation(
            step=step,
            candidate_index=candidate_index,
            server=self.config.server,
            server_ip=self.config.server_ip,
            high_level_action=candidate,
            success=success,
            valid=valid,
            state_before=state,
            state_after=rollout_state,
            rollout_total_time_seconds=rollout_time,
            baseline_restore_time_seconds=baseline_time,
            wall_clock_time_seconds=time.perf_counter() - wall_start,
            action_results=tuple(action_results),
            first_action_plan=first_action_plan,
            invalid_reason=invalid_reason,
            rollout_index=rollout_index,
            rollout_count=rollout_count,
        )

    def _select_best_candidate(
        self,
        evaluations: list[CandidateEvaluation],
    ) -> CandidateEvaluation | None:
        grouped: dict[int, list[CandidateEvaluation]] = {}
        for evaluation in evaluations:
            grouped.setdefault(evaluation.candidate_index, []).append(evaluation)

        scored: list[tuple[float, float, CandidateEvaluation]] = []
        for samples in grouped.values():
            if len(samples) != self.config.num_rollouts:
                continue
            if not all(sample.valid for sample in samples):
                continue
            avg_progress = sum(
                state_progress(sample.state_before, sample.state_after)
                for sample in samples
            ) / len(samples)
            avg_time = sum(sample.rollout_total_time_seconds for sample in samples) / len(samples)
            representative = min(samples, key=lambda item: item.rollout_total_time_seconds)
            scored.append(
                (
                    avg_progress,
                    avg_time,
                    replace(representative, rollout_total_time_seconds=avg_time),
                )
            )

        if not scored:
            return None
        return min(scored, key=lambda item: (-item[0], item[1]))[2]

    def _plan_for_action(
        self,
        action: HighLevelAction,
        current_state: RecoveryState,
    ) -> CommandPlan:
        request = CommandAgentRequest(
            system=self.context.get("System", ""),
            logs=self.context.get("Logs", ""),
            incident=self.context.get("Incident", ""),
            server=self.config.server,
            server_ip=self.config.server_ip,
            attacker_ip=self.config.attacker_ip,
            current_state=current_state,
            high_level_action=action,
            dt_context=self.dt_context,
        )
        return self.command_agent.generate_plan(request)
