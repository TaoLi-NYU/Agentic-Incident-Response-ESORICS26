"""Tests for rollout-baseline high-level action parsing."""

from __future__ import annotations

import unittest

from run_recovery_loop_rollout_baseline_llm_state import (
    extract_action_object,
    parse_generated_action,
    state_to_jsonable,
)


class RolloutBaselinePlanGeneratorTests(unittest.TestCase):
    def test_parses_action_json_after_reasoning(self) -> None:
        raw = (
            "<think>Assess the current state.</think>\n"
            '{"Action":"Isolate server_ssh","Explanation":"Contain access."}'
        )
        action = parse_generated_action(raw)

        self.assertEqual(action.action, "Isolate server_ssh")
        self.assertEqual(action.explanation, "Contain access.")
        self.assertEqual(action.raw_model_output, raw)

    def test_falls_back_to_plain_action_text(self) -> None:
        action = parse_generated_action("Preserve forensic evidence")

        self.assertEqual(action.action, "Preserve forensic evidence")
        self.assertEqual(action.explanation, "")

    def test_ignores_unrelated_json_before_action(self) -> None:
        raw = (
            '{"state":"analysis"}\n'
            '{"Action":"Restore SSH","Explanation":"Return service."}'
        )

        self.assertEqual(
            extract_action_object(raw),
            {"Action": "Restore SSH", "Explanation": "Return service."},
        )

    def test_serializes_planner_state(self) -> None:
        state = state_to_jsonable((True, False, True, False, True, False))

        self.assertTrue(state["is_attack_contained"])
        self.assertFalse(state["is_knowledge_sufficient"])
        self.assertFalse(state["is_recovered"])


if __name__ == "__main__":
    unittest.main()
