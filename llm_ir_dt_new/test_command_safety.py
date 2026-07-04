"""Regression tests for recovery command safety parsing."""

from __future__ import annotations

import unittest

from llm_ir_dt.recovery_loop.command_safety import (
    CommandSafetyError,
    CommandSafetyValidator,
)
from llm_ir_dt.recovery_loop.command_agent import CommandAgentRequest, OpenAICommandAgent
from llm_ir_dt.recovery_loop.schemas import CommandSpec, HighLevelAction, initial_recovery_state


class CommandSafetyValidatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.validator = CommandSafetyValidator()

    def validate(self, command: str) -> None:
        self.validator.validate_command(
            CommandSpec(
                container="gateway",
                command=command,
                allowed_exit_codes=(0,),
                description="test",
            )
        )

    def test_allows_regex_alternation_inside_single_quotes(self) -> None:
        self.validate(
            "iptables -L FORWARD -n -v | "
            "grep -E 'SSH_BRUTE|LATERAL_SMB|LATERAL_HTTP'"
        )

    def test_allows_semicolons_inside_double_quotes(self) -> None:
        self.validate(
            "curl -s -H \"User-Agent: () { :;}; marker\" "
            "http://10.0.2.13/cgi-bin/vulnerable | grep -q marker"
        )

    def test_splits_real_shell_operators(self) -> None:
        self.validate(
            "iptables-save | grep -q DROP && true || true; iptables-save"
        )

    def test_allows_quoted_shell_operators_as_arguments(self) -> None:
        self.validate("grep -q 'a&&b||c;d|e' /tmp/recovery_evidence/input.txt")

    def test_rejects_unclosed_quote(self) -> None:
        with self.assertRaisesRegex(CommandSafetyError, "unclosed quote"):
            self.validate("grep -q 'unterminated /tmp/recovery_evidence/input.txt")

    def test_rejects_trailing_escape(self) -> None:
        with self.assertRaisesRegex(CommandSafetyError, "trailing escape"):
            self.validate("grep -q pattern /tmp/recovery_evidence/input.txt\\")


class CommandAgentPromptTests(unittest.TestCase):
    def test_http_remediation_verifies_security_property_not_exact_status(self) -> None:
        agent = object.__new__(OpenAICommandAgent)
        request = CommandAgentRequest(
            system="test system",
            logs="test logs",
            incident="test incident",
            server="server_shellshock",
            server_ip="10.0.2.13",
            attacker_ip="10.0.1.11",
            current_state=initial_recovery_state(),
            high_level_action=HighLevelAction(
                action="Validate Shellshock remediation.",
            ),
            dt_context="test context",
        )

        prompt = agent._user_prompt(request)

        self.assertIn("validate security properties", prompt)
        self.assertIn("Never make recovery success depend", prompt)
        self.assertIn("grep -q 500", prompt)
        self.assertIn("injected marker or command output is absent", prompt)
        self.assertIn("Check legitimate service availability separately", prompt)


if __name__ == "__main__":
    unittest.main()
