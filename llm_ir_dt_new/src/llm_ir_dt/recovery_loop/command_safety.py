"""Safety validation for generated command plans."""

from __future__ import annotations

import re
import shlex

from llm_ir_dt.recovery_loop.schemas import CommandPlan, CommandSpec


ALLOWED_CONTAINERS: set[str] = {
    "gateway",
    "client",
    "server_ssh",
    "server_samba",
    "server_shellshock",
    "server_web1",
    "server_web2",
}

ALLOWED_COMMANDS: set[str] = {
    # Read-only verification and inspection commands used by recovery plans.
    "apachectl",
    "cat",
    "chmod",
    "cp",
    "crontab",
    "curl",
    "find",
    "grep",
    "head",
    "hostname",
    "ip",
    "iptables",
    "iptables-save",
    "ls",
    "mkdir",
    "nginx",
    "passwd",
    "pgrep",
    "ping",
    "pkill",
    "ps",
    "sed",
    "service",
    "smbclient",
    "smbd",
    "ss",
    "sshd",
    "stat",
    "tar",
    "test",
    "touch",
    "true",
    "uname",
}

DANGEROUS_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\brm\s+-[^;&|]*r[^;&|]*\s+/", re.IGNORECASE),
    re.compile(r"\bmkfs\b", re.IGNORECASE),
    re.compile(r"\bdd\s+.*\bof=/dev/", re.IGNORECASE),
    re.compile(r"\bshutdown\b|\breboot\b|\bpoweroff\b", re.IGNORECASE),
    re.compile(r"curl\s+.*\|\s*(sh|bash)", re.IGNORECASE),
    re.compile(r"wget\s+.*\|\s*(sh|bash)", re.IGNORECASE),
    re.compile(r"/dev/tcp/", re.IGNORECASE),
    re.compile(r"\bnc\s+.*-e\b", re.IGNORECASE),
)

ALLOWED_REDIRECT_PREFIXES: tuple[str, ...] = (
    "/dev/null",
    "/tmp/",
    "/var/ir/evidence211/",
    "/tmp/recovery_artifacts/",
    "/tmp/recovery_evidence/",
    "/tmp/recovery_evidence_gateway_",
)


class CommandSafetyError(ValueError):
    """Raised when a command plan fails safety validation."""


class CommandSafetyValidator:
    """Validate command plans before execution."""

    def validate_plan(self, plan: CommandPlan) -> None:
        """Raise if the command plan is unsafe."""
        if not plan.commands:
            raise CommandSafetyError("Command plan has no recovery commands.")
        if not plan.verification_commands:
            raise CommandSafetyError("Command plan has no verification commands.")

        for command in (
            list(plan.commands)
            + list(plan.verification_commands)
            + list(plan.rollback_commands)
        ):
            self.validate_command(command)

    def validate_command(self, spec: CommandSpec) -> None:
        """Raise if a single command is unsafe."""
        if spec.container not in ALLOWED_CONTAINERS:
            raise CommandSafetyError(f"Container is not allowed: {spec.container}")
        command = spec.command.strip()
        if not command:
            raise CommandSafetyError("Empty command is not allowed.")

        for pattern in DANGEROUS_PATTERNS:
            if pattern.search(command):
                raise CommandSafetyError(f"Dangerous command pattern: {command}")

        self._validate_redirects(command)
        self._validate_segments(command)

    def _validate_segments(self, command: str) -> None:
        for segment in self._split_shell_segments(command):
            segment = segment.strip()
            if not segment:
                continue
            try:
                tokens = shlex.split(segment, posix=True)
            except ValueError as exc:
                raise CommandSafetyError(f"Cannot parse command segment: {segment}") from exc
            if not tokens:
                continue
            executable = tokens[0].split("/")[-1]
            if executable not in ALLOWED_COMMANDS:
                raise CommandSafetyError(
                    f"Command executable is not allowlisted: {executable}"
                )
            if executable == "crontab":
                self._validate_crontab_tokens(tokens)

    def _split_shell_segments(self, command: str) -> list[str]:
        """Split shell operators outside quotes without interpreting the command."""
        segments: list[str] = []
        current: list[str] = []
        quote: str | None = None
        escaped = False
        index = 0

        while index < len(command):
            char = command[index]

            if escaped:
                current.append(char)
                escaped = False
                index += 1
                continue

            if char == "\\" and quote != "'":
                current.append(char)
                escaped = True
                index += 1
                continue

            if quote is not None:
                current.append(char)
                if char == quote:
                    quote = None
                index += 1
                continue

            if char in {"'", '"'}:
                current.append(char)
                quote = char
                index += 1
                continue

            if command.startswith("&&", index) or command.startswith("||", index):
                segments.append("".join(current).strip())
                current = []
                index += 2
                continue

            if char in {";", "|"}:
                segments.append("".join(current).strip())
                current = []
                index += 1
                continue

            current.append(char)
            index += 1

        if escaped:
            raise CommandSafetyError(
                f"Cannot parse command with trailing escape: {command}"
            )
        if quote is not None:
            raise CommandSafetyError(
                f"Cannot parse command with unclosed quote: {command}"
            )

        segments.append("".join(current).strip())
        return segments

    def _validate_redirects(self, command: str) -> None:
        for match in re.finditer(r"(?:^|\s)(?:\d?>>|>>|\d?>)\s*([^&\s;|]+)", command):
            target = match.group(1).strip("'\"")
            if not target.startswith(ALLOWED_REDIRECT_PREFIXES):
                raise CommandSafetyError(
                    f"Redirection target is outside allowed artifact paths: {target}"
                )

    def _validate_crontab_tokens(self, tokens: list[str]) -> None:
        """Allow only read-only crontab inspection, optionally redirected."""
        command_tokens: list[str] = []
        for token in tokens:
            if token in {">", ">>", "1>", "1>>", "2>", "2>>"}:
                break
            if re.match(r"^\d?>>?.+", token):
                break
            command_tokens.append(token)

        if command_tokens == ["crontab", "-l"]:
            return
        if (
            len(command_tokens) == 4
            and command_tokens[1] == "-u"
            and command_tokens[2]
            and command_tokens[3] == "-l"
        ):
            return
        raise CommandSafetyError(
            "crontab is allowlisted only for read-only listing, optionally redirected "
            "to an allowed artifact path: 'crontab -l' or 'crontab -u USER -l'"
        )
