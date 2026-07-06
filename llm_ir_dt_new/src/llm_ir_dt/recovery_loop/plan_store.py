"""Artifact persistence for recovery-loop runs."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from llm_ir_dt.recovery_loop.schemas import CandidateEvaluation, CommandPlan, dataclass_to_jsonable


class PlanStore:
    """Persist selected plans and candidate evaluations."""

    def __init__(self, root: Path | str = "artifacts/recovery_loop") -> None:
        run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.run_dir = Path(root) / "runs" / run_id
        self.selected_dir = self.run_dir / "selected_plans"
        self.evaluations_dir = self.run_dir / "candidate_evaluations"
        self.selected_dir.mkdir(parents=True, exist_ok=True)
        self.evaluations_dir.mkdir(parents=True, exist_ok=True)

    def write_context(self, context: dict[str, Any]) -> None:
        """Persist run context."""
        self._write_json(self.run_dir / "context.json", context)

    def save_candidate_evaluation(self, evaluation: CandidateEvaluation) -> None:
        """Persist one candidate evaluation."""
        step_dir = self.evaluations_dir / f"step_{evaluation.step:03d}"
        step_dir.mkdir(parents=True, exist_ok=True)
        name = f"candidate_{evaluation.candidate_index:03d}"
        if evaluation.rollout_count > 1:
            name += f"_rollout_{evaluation.rollout_index:03d}"
        path = step_dir / f"{name}.json"
        self._write_json(path, dataclass_to_jsonable(evaluation))

    def save_selected_plan(
        self,
        *,
        step: int,
        plan: CommandPlan,
        evaluation: CandidateEvaluation,
    ) -> None:
        """Persist the plan selected for a planning step."""
        self.selected_dir.mkdir(parents=True, exist_ok=True)
        path = self.selected_dir / f"step_{step:03d}.json"
        payload = {
            "step": step,
            "plan": dataclass_to_jsonable(plan),
            "evaluation": dataclass_to_jsonable(evaluation),
        }
        self._write_json(path, payload)

    def load_selected_plans(self) -> list[CommandPlan]:
        """
        Return selected plans.

        Replay currently happens in-memory in the first implementation. Loading
        back into dataclasses will be added when resume support is needed.
        """
        return []

    def _write_json(self, path: Path, payload: Any) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
