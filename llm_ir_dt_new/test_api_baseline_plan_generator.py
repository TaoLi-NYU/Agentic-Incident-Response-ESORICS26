"""Regression tests for API high-level plan response handling."""

from __future__ import annotations

import unittest
from unittest.mock import Mock, patch

from run_recovery_loop_api_baseline_llm_state import DeepSeekCompletePlanGenerator


VALID_PLAN = (
    '{"Actions": [{"Action": "Contain the host", '
    '"Explanation": "Limit attacker access."}]}'
)


def response_with(payload: dict) -> Mock:
    response = Mock()
    response.status_code = 200
    response.json.return_value = payload
    response.text = ""
    return response


class CompletePlanGeneratorTests(unittest.TestCase):
    def generator(self, *, max_attempts: int = 3) -> DeepSeekCompletePlanGenerator:
        return DeepSeekCompletePlanGenerator(
            model="claude-opus-4-8",
            api_key="test-key",
            base_url="https://example.invalid/v1",
            max_attempts=max_attempts,
        )

    def test_retries_empty_content_without_response_format(self) -> None:
        empty = response_with(
            {
                "choices": [
                    {"message": {"content": ""}, "finish_reason": "stop"}
                ]
            }
        )
        valid = response_with(
            {
                "choices": [
                    {"message": {"content": VALID_PLAN}, "finish_reason": "stop"}
                ]
            }
        )
        generator = self.generator()

        with patch("run_recovery_loop_api_baseline_llm_state.requests.post") as post:
            post.side_effect = [empty, valid]
            with patch("run_recovery_loop_api_baseline_llm_state.time.sleep"):
                actions, raw_output = generator.generate(
                    context={"TargetServer": "server_ssh / 10.0.2.11"},
                    max_actions=7,
                )

        self.assertEqual(actions[0].action, "Contain the host")
        self.assertEqual(raw_output, VALID_PLAN)
        self.assertIn("response_format", post.call_args_list[0].kwargs["json"])
        self.assertNotIn("response_format", post.call_args_list[1].kwargs["json"])
        self.assertEqual(len(generator.response_attempts), 2)

    def test_uses_reasoning_content_when_content_is_empty(self) -> None:
        response = response_with(
            {
                "choices": [
                    {
                        "message": {
                            "content": "",
                            "reasoning_content": VALID_PLAN,
                        },
                        "finish_reason": "stop",
                    }
                ]
            }
        )
        generator = self.generator()

        with patch(
            "run_recovery_loop_api_baseline_llm_state.requests.post",
            return_value=response,
        ):
            actions, raw_output = generator.generate(
                context={"TargetServer": "server_ssh / 10.0.2.11"},
                max_actions=7,
            )

        self.assertEqual(actions[0].action, "Contain the host")
        self.assertEqual(raw_output, VALID_PLAN)
        self.assertEqual(
            generator.response_attempts[0]["output_source"],
            "reasoning_content",
        )

    def test_raises_clear_error_after_repeated_empty_responses(self) -> None:
        empty = response_with(
            {
                "choices": [
                    {"message": {"content": None}, "finish_reason": "stop"}
                ]
            }
        )
        generator = self.generator(max_attempts=2)

        with patch(
            "run_recovery_loop_api_baseline_llm_state.requests.post",
            side_effect=[empty, empty],
        ):
            with patch("run_recovery_loop_api_baseline_llm_state.time.sleep"):
                with self.assertRaisesRegex(RuntimeError, "after 2 attempts"):
                    generator.generate(
                        context={"TargetServer": "server_ssh / 10.0.2.11"},
                        max_actions=7,
                    )

        self.assertEqual(len(generator.response_attempts), 2)


if __name__ == "__main__":
    unittest.main()
