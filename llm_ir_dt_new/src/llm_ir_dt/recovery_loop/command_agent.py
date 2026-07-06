"""Command-plan generation for high-level recovery actions."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Any

import requests

from llm_ir_dt.recovery_loop.command_safety import ALLOWED_COMMANDS
from llm_ir_dt.recovery_loop.command_safety import ALLOWED_CONTAINERS
from llm_ir_dt.recovery_loop.command_safety import ALLOWED_REDIRECT_PREFIXES
from llm_ir_dt.recovery_loop.schemas import RECOVERY_STATE_FIELDS
from llm_ir_dt.recovery_loop.schemas import CommandPlan, CommandSpec, HighLevelAction, RecoveryState


@dataclass(frozen=True)
class CommandAgentRequest:
    """Input to a command agent."""

    system: str
    logs: str
    incident: str
    server: str
    server_ip: str
    attacker_ip: str
    current_state: RecoveryState
    high_level_action: HighLevelAction
    dt_context: str = ""
    recovery_targets: tuple[tuple[str, str], ...] = ()


class CommandAgent:
    """Interface for high-level-action to command-plan translation."""

    def generate_plan(self, request: CommandAgentRequest) -> CommandPlan:
        """Generate a command plan."""
        raise NotImplementedError


class OpenAICommandAgent(CommandAgent):
    """OpenAI Responses API backed command agent."""

    def __init__(
        self,
        *,
        model: str = "gpt-5.5",
        api_key: str | None = None,
        api_key_env: str = "OPENAI_API_KEY",
        base_url: str = "https://api.openai.com/v1",
        timeout_seconds: int = 120,
    ) -> None:
        self.model = model
        self.api_key = api_key or os.getenv(api_key_env, "").strip()
        self.api_key_env = api_key_env
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        if not self.api_key:
            raise ValueError(f"OpenAI API key is missing. Set {api_key_env}.")

    def generate_plan(self, request: CommandAgentRequest) -> CommandPlan:
        payload = {
            "model": self.model,
            "input": [
                {
                    "role": "system",
                    "content": self._system_prompt(),
                },
                {
                    "role": "user",
                    "content": self._user_prompt(request),
                },
            ],
            "text": {
                "format": {
                    "type": "json_schema",
                    "name": "command_plan",
                    "strict": True,
                    "schema": self._schema(),
                }
            },
        }
        response = requests.post(
            f"{self.base_url}/responses",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=self.timeout_seconds,
        )
        if response.status_code >= 400:
            raise RuntimeError(
                f"OpenAI command generation failed: HTTP {response.status_code}: {response.text}"
            )
        data = response.json()
        text = self._extract_output_text(data)
        parsed = self._loads_json(text)
        return self._plan_from_json(request, parsed, raw_model_output=text)

    def _system_prompt(self) -> str:
        return (
            "You are a cybersecurity recovery command planner for a controlled Docker digital twin. "
            "Generate concrete bash command plans only for the provided lab containers. "
            "Do not include destructive host-level commands. Do not use network downloads, reverse shells, "
            "or commands outside the described digital twin. Generate simple allowlist-friendly shell commands "
            "that can be parsed and timed deterministically. Return only the JSON schema requested."
        )

    def _user_prompt(self, request: CommandAgentRequest) -> str:
        if request.recovery_targets:
            return self._whole_system_user_prompt(request)
        state_json = json.dumps(request.current_state, ensure_ascii=True)
        containers = ", ".join(sorted(ALLOWED_CONTAINERS))
        executables = ", ".join(sorted(ALLOWED_COMMANDS))
        redirect_prefixes = ", ".join(ALLOWED_REDIRECT_PREFIXES)
        return (
            "Create a bash command plan for this high-level recovery action.\n\n"
            f"System:\n{request.system}\n\n"
            f"Logs:\n{request.logs}\n\n"
            f"Incident:\n{request.incident}\n\n"
            f"Digital Twin Command Context:\n{request.dt_context or 'None provided.'}\n\n"
            f"Target server: {request.server} / {request.server_ip}\n"
            f"Attacker IP: {request.attacker_ip}\n"
            f"Current recovery state: {state_json}\n\n"
            f"High-level action:\n{request.high_level_action.action}\n\n"
            f"Action explanation:\n{request.high_level_action.explanation}\n\n"
            f"Use only these containers: {containers}.\n"
            f"Use only these command executables: {executables}.\n"
            f"If redirecting output, redirect only under: {redirect_prefixes}.\n"
            "Do not guess interface names, file paths, service paths, or tool availability that "
            "are not explicitly stated in the system description, logs, incident context, or "
            "Digital Twin Command Context. Use only resources supported by the provided context; "
            "when a resource is not established, use a read-only discovery command and do not "
            "perform a later operation in the same plan that depends on an unobserved discovery result.\n"
            "Do not use sudo, docker, bash, sh, python, perl, awk, wget, nc, rm, echo, printf, "
            "package managers, or host-level commands.\n"
            "Never output a command whose executable is rm. For eradication, prefer disabling access, "
            "changing vulnerable configuration, killing active attacker tooling with pkill, and writing "
            "the target-specific eradicated.marker after the remedial action succeeds.\n"
            "When an eradication or cleanup step needs to neutralize an attacker-created file without "
            "using rm, do not use shell redirection patterns such as 'true > FILE', ': > FILE', or "
            "'cat /dev/null > FILE'. These can fail due to file ownership or shell redirection semantics "
            "in this lab. Prefer 'cp /dev/null FILE' to truncate a file, or use chmod/mv patterns only "
            "if they are simpler and already justified by the recovery action. If a file is expected to "
            "be removed or emptied, verify that outcome with 'test -s FILE' using allowed_exit_codes [1] "
            "or an equivalent size/absence check.\n"
            "For credential-rotation or trust-reset actions in this Docker lab, do not write to "
            "/root/.ssh/authorized_keys, /home/*/.ssh/authorized_keys, /etc/shadow, or real key/token "
            "files. Record completion with a target-specific credential_rotated.marker under "
            "/tmp/recovery_artifacts/<server>/ and verify the marker, or inspect credential-related "
            "configuration as evidence without modifying real credential files.\n"
            "Never use 'pkill -f vulnerable' in server_shellshock. It can kill the command shell itself. "
            "For Shellshock eradication/hardening, preserve /usr/lib/cgi-bin/vulnerable first, then use "
            "'chmod -x /usr/lib/cgi-bin/vulnerable', 'apachectl restart', and "
            "'touch /tmp/recovery_artifacts/server_shellshock/eradicated.marker'.\n"
            "Use simple shell syntax only. Do not use shell negation with !, find -exec, xargs, "
            "command substitution, backticks, heredocs, loops, functions, subshells, environment-variable "
            "assignments, glob-heavy recursive operations, or backslash line continuations. "
            "Do not generate commands that require quoting a literal semicolon for find -exec. "
            "Avoid complex conditionals; prefer separate command objects and explicit verification commands.\n"
            "If you need to inspect files found by find, do not use find -exec. Prefer a direct known path, "
            "or save a simple file listing with 'find PATH -type f > DEST'. If you need a negative check, "
            "do not use '! grep'; use a positive 'grep -q' check with the appropriate allowed_exit_codes "
            "or use 'test' where possible. Keep grep commands simple: use only 'grep -q PATTERN PATH' "
            "or 'ps aux | grep [p]attern'. Do not use grep -E, grep -i, grep -Ei, unclosed quotes, "
            "or multi-line grep patterns.\n"
            "This is a minimal Docker lab, not a full VM. Do not use systemctl. "
            "Do not use 'service sshd stop' or stop SSH for recovery. "
            "The server_ssh container starts SSH directly with /usr/sbin/sshd. "
            "To validate or recover SSH service health, use '/usr/sbin/sshd -t', "
            "'pkill sshd 2>/dev/null || true; /usr/sbin/sshd', 'pgrep sshd', or "
            "'ps aux | grep [s]shd'.\n"
            "Use DT-specific evidence directories exactly: "
            "/tmp/recovery_evidence/server_ssh/, /tmp/recovery_artifacts/server_ssh/, "
            "/tmp/recovery_evidence_gateway_/, or /var/ir/evidence211/. "
            "Do not invent directories such as /tmp/recovery_evidence_ssh. "
            f"For the current target server, prefer /tmp/recovery_evidence/{request.server}/ "
            f"and /tmp/recovery_artifacts/{request.server}/.\n"
            "For non-SSH target servers, the verifier still uses the six recovery states but "
            "checks target-specific service evidence and health. Use the target server name and IP "
            "provided above, not a hardcoded server_ssh/10.0.2.11 pair, unless the target is server_ssh. "
            "Do not add server_ssh commands or server_ssh verification checks when the target is "
            "server_samba, server_shellshock, server_web1, or server_web2, unless the high-level action "
            "explicitly requires SSH-host evidence. Optional cross-host evidence must not be required "
            "for command-plan success; use allowed_exit_codes [0, 1] for optional verification checks.\n"
            "For server_samba, useful recovery artifacts include samba logs, share listings, "
            "guest ok = no, read only = yes, smbd health, and an eradicated.marker. "
            "For server_samba restoration, if the plan will verify SMB access from the client, "
            "the recovery commands must first remove the exact temporary gateway containment "
            f"rules between {request.attacker_ip} and {request.server_ip}: "
            f"'iptables -D FORWARD -s {request.attacker_ip} -d {request.server_ip} -j DROP "
            "2>/dev/null || true' and "
            f"'iptables -D FORWARD -s {request.server_ip} -d {request.attacker_ip} -j DROP "
            "2>/dev/null || true'. Never use 'iptables -F'. After removing those exact rules, "
            "restart smbd, verify its process and TCP port 445 locally, and only then use "
            f"'smbclient -L //{request.server_ip} -N' from the client when anonymous listing is "
            "intended to remain available. If guest access has been disabled as part of hardening, "
            "do not require an anonymous '-N' listing to succeed; use local smbd/port/configuration "
            "checks or an explicitly authorized credential instead.\n"
            "For server_shellshock, useful recovery artifacts include Apache logs, the CGI file, "
            "chmod -x /usr/lib/cgi-bin/vulnerable, apachectl health, and an eradicated.marker. "
            "For server_web1/server_web2, useful recovery artifacts include nginx logs, nginx -t, "
            "sshd health, and hardened/eradicated markers when appropriate. If you need to verify "
            "that the vulnerable upload process is gone, prefer 'ps aux | grep [v]ulnerable_upload_server.py' "
            "with allowed_exit_codes [1] or verify only local Nginx health. Do not use "
            "'pgrep -f vulnerable_upload_server.py' because it is brittle and can match unintended "
            "command lines. For server_web2, do not make gateway Snort process health a mandatory "
            "recovery verification; treat it as optional cross-host evidence only, and if you inspect "
            "it use allowed_exit_codes [0, 1].\n"
            "For server_web2 diagnostic-service eradication, do not rely on chmod alone because "
            "it does not stop an already running process. Stop the vulnerable diagnostic server "
            "with 'pkill -9 -f [v]ulnerable_diag_server.py 2>/dev/null || true', then make "
            "/opt/vulnerable_diag_server.py non-executable or unreadable. Do not use "
            "'pkill -f /opt/vulnerable_diag_server.py' because it can match and kill the "
            "current shell command, producing exit code 137. Verify process absence with "
            "'ps aux | grep [v]ulnerable_diag_server.py' using allowed_exit_codes [1], "
            "not with pgrep -f. Do not verify attacker marker-file unreadability with "
            "'test -r' from root; root may still report the file as readable after chmod 000.\n"
            "Container log files may be missing. Commands that read /var/log/auth.log, "
            "/var/log/syslog, /var/log/snort/alert, /etc/shadow, or /home/admin should "
            "end with '2>/dev/null || true' when absence is acceptable. Do not make optional log files "
            "hard verification requirements with allowed_exit_codes [0]; either omit the optional "
            "verification or allow [0, 1].\n"
            "For server_web1/server_web2 evidence preservation, nginx access/error logs and "
            "vulnerable service logs may be missing or empty. They may be copied with "
            "2>/dev/null || true, but do not require 'test -s' on those log files with "
            "allowed_exit_codes [0]. If verifying optional web logs, use allowed_exit_codes [0, 1]. "
            "Use stable required evidence checks such as non-empty ip_addr.txt, ip_route.txt, "
            "processes.txt, passwd.txt, copied service source files, or marker/evidence directories.\n"
            "For server_ssh eradication, do not require 'pgrep -u admin' to return no output as "
            "a hard success criterion. It may be used only as optional evidence of cleanup, and "
            "if you inspect it treat lingering admin-owned shell processes as non-fatal unless "
            "they are clearly part of attacker activity. Prefer the eradication marker plus account "
            "locking and direct attacker-process termination as the required checks.\n"
            "For server_ssh actions that terminate unauthorized SSH sessions, do not require "
            "'pgrep -u admin' to be empty as the primary success condition. Treat it as optional "
            "diagnostic evidence only. Prefer verifying that sshd is healthy, that the active "
            "listener on port 22 remains up, and that fresh client-side SSH login attempts with "
            "the compromised credentials fail after session termination and credential reset.\n"
            "For the selected target server, prefer concrete checks and commands involving "
            "gateway iptables, client connectivity tests to the target IP, target-server evidence "
            "collection, target-server hardening, and target-server service health. For server_ssh "
            "this means sshd_config and SSH service health; for other servers use their service-specific "
            "files and daemons.\n"
            "Prefer these proven DT command patterns:\n"
            "- Containment: gateway iptables DROP rules between 10.0.1.11 and 10.0.2.11, "
            "then verify with iptables-save and client ping failure.\n"
            "For same-subnet server-to-server lateral-movement containment, do not rely only on "
            "gateway FORWARD rules. In this lab topology, same-subnet traffic may bypass the "
            "gateway path that the verifier inspects. If the high-level action asks to restrict "
            f"the current target server {request.server}/{request.server_ip} from reaching other "
            "10.0.2.x servers, add endpoint-local rules on the host that actually sees the traffic: "
            "use INPUT-chain DROP rules on the receiving target, or OUTPUT-chain DROP rules on the "
            "source/pivot, depending on the traffic direction. For example, to stop a peer from "
            f"reaching {request.server_ip}, a target-side INPUT rule such as "
            f"'iptables -I INPUT -s {request.attacker_ip} -d {request.server_ip} -j DROP' may be needed, "
            "and verify from the pivot or target container that ping or service probing to that peer "
            "fails with allowed_exit_codes [1, 2]. For a server_ssh containment action that mentions "
            "east-west reachability, include at least one explicit rule that blocks the observed pivot "
            f"host {request.attacker_ip} or the relevant peer server from reaching {request.server_ip}; "
            "gateway-only FORWARD rules are not sufficient if same-subnet traffic still reaches the target.\n"
            "For containment, do not add broad gateway rules that match only "
            f"'-s {request.server_ip}' or only '-d {request.server_ip}'. Keep temporary containment "
            "rules narrow and explicit, and include both source and destination when the traffic path "
            "is known. Do not include rollback_commands unless explicitly requested.\n"
            "If a later recovery action needs to restore user-facing service after a prior containment "
            "step, remove or relax the temporary gateway FORWARD DROP rules between the attacker/client "
            f"and target before client-side service verification. For this request, use commands such as "
            f"'iptables -D FORWARD -s {request.attacker_ip} -d {request.server_ip} -j DROP 2>/dev/null || true' "
            f"and 'iptables -D FORWARD -s {request.server_ip} -d {request.attacker_ip} -j DROP 2>/dev/null || true' "
            f"when full client access must be restored. If an earlier plan used broad rules, also delete "
            f"'iptables -D FORWARD -s {request.server_ip} -j DROP 2>/dev/null || true' and "
            f"'iptables -D FORWARD -d {request.server_ip} -j DROP 2>/dev/null || true' before client-side "
            "verification. If isolation must remain in place, verify only local target service health "
            "with service-specific commands, and do not claim full user-facing recovery.\n"
            "For server_web1/server_web2 restoration after containment, remove both gateway "
            "FORWARD DROP rules and target-container OUTPUT DROP rules before any client-side "
            "HTTP/SSH reachability verification. For server_web2 this means deleting specific "
            "target-container OUTPUT rules such as "
            "'iptables -D OUTPUT -d 10.0.2.11 -j DROP 2>/dev/null || true', "
            "'iptables -D OUTPUT -d 10.0.2.12 -j DROP 2>/dev/null || true', "
            "'iptables -D OUTPUT -d 10.0.2.13 -j DROP 2>/dev/null || true', and "
            "'iptables -D OUTPUT -d 10.0.2.14 -j DROP 2>/dev/null || true' in the target "
            "container, in addition to deleting gateway rules between the attacker/client and "
            "target. If those containment rules are intentionally kept, verify only local service "
            "health and do not use client-side curl as a required recovery verification. If a client "
            "curl check is still used while containment remains, treat exit code 28 as acceptable "
            "timeout evidence and include it in allowed_exit_codes.\n"
            "For server_web1 restoration specifically, do not attempt a client-side HTTP "
            "validation against http://10.0.2.14/ until any temporary containment rules that "
            "mention 10.0.2.14 or the attacker/client 10.0.1.11 have been removed. If client "
            "reachability is required, first delete the relevant FORWARD DROP rules on the "
            "gateway, then verify the root page from the client. If isolation must remain in "
            "place, verify only local Nginx health and do not require client curl. If curl is used "
            "anyway under containment, allowed_exit_codes [0, 28] are acceptable for timeout behavior.\n"
            "For server_web1 upload-incident restoration, do not require the attacker-uploaded "
            "artifact such as /uploads/observed_web1_5server.html to remain reachable with HTTP "
            "200 after cleanup. Recovery should either remove unauthorized uploaded content or "
            "ensure it is inert and non-executable. Verify normal Nginx health, safe upload "
            "directory permissions, hardened/eradicated markers, and absence or non-executability "
            "of attacker-uploaded artifacts instead. For the uploaded file itself, do not use "
            "'test -r' from root as the success criterion; use a size-based or removal-based "
            "check such as 'test -s' with allowed_exit_codes [1] after truncation or deletion, "
            "or verify that a web-accessible copy is no longer present. Also do not require the "
            "vulnerable upload service process vulnerable_upload_server.py to be running if the recovery action "
            "disabled it as part of hardening; if checking it, use optional allowed_exit_codes "
            "[0, 1] or verify only that Nginx remains healthy. For the process-absence check, "
            "prefer a stable command such as 'ps aux | grep [v]ulnerable_upload_server.py' with "
            "allowed_exit_codes [1] instead of 'pgrep -f vulnerable_upload_server.py'.\n"
            "If client-side curl is used to confirm that the uploaded artifact is no longer "
            "reachable, treat exit code 28 as acceptable success evidence in this lab. Use "
            "allowed_exit_codes [0, 28] for that curl check, and prefer local file checks when "
            "possible.\n"
            "When using curl to verify that containment blocks access, a timeout is success evidence. "
            "Curl may return exit code 28 for operation timed out; include 28 in allowed_exit_codes "
            "for containment checks that are expected to fail or time out, e.g. allowed_exit_codes "
            "[1, 2, 7, 28].\n"
            "All client-side curl verification commands must include a short timeout such as "
            "'--connect-timeout 2 --max-time 5' so failed access does not consume minutes.\n"
            "For HTTP vulnerability-remediation verification, validate security properties instead "
            "of requiring one exact HTTP status code. Never make recovery success depend on a check "
            "such as piping an HTTP status to 'grep -q 500'. A remediated or disabled vulnerable "
            "endpoint may legitimately return 403, 404, 410, 500, refuse the connection, or time out. "
            "The required security check is that the injected marker or command output is absent; "
            "express this with a positive grep command whose expected non-match uses "
            "allowed_exit_codes [1], and include curl transport outcomes such as 7 or 28 when the "
            "endpoint may be intentionally unreachable. Check legitimate service availability "
            "separately using a normal non-vulnerable page or a local service-health command. Do not "
            "treat the vulnerable endpoint itself as the availability probe.\n"
            "- Forensics: mkdir -p /tmp/recovery_evidence/server_ssh or /var/ir/evidence211, "
            "then save ip addr, ip route, ps aux, /etc/passwd, /etc/ssh/sshd_config, "
            "and optional auth.log/home_admin files with 2>/dev/null || true.\n"
            "When saving command output to evidence files, file names must not contain spaces. "
            "Use processes.txt for ps aux output, not a file named 'ps aux'.\n"
            "- Knowledge: collect client ip addr, ip route, ps aux, /root/.ssh/known_hosts, "
            "and /opt/passwords.txt with optional reads guarded by 2>/dev/null || true.\n"
            "- Eradication: kill attacker tooling on client with pkill hydra/nmap/sshpass/ssh, "
            "disable vulnerable access/configuration on the target, and write an eradicated.marker. "
            "Do not use rm.\n"
            "- Hardening: edit /etc/ssh/sshd_config using sed to set PermitRootLogin no, "
            "PasswordAuthentication no, and MaxAuthTries 3; validate with /usr/sbin/sshd -t; "
            "restart sshd with 'pkill sshd 2>/dev/null || true; /usr/sbin/sshd'. Verify the "
            "effective SSH configuration, not the literal text layout of sshd_config, using "
            "separate commands such as '/usr/sbin/sshd -T | grep -q "
            "\"^permitrootlogin no$\"', '/usr/sbin/sshd -T | grep -q "
            "\"^passwordauthentication no$\"', and '/usr/sbin/sshd -T | grep -q "
            "\"^pubkeyauthentication yes$\"'. Do not require an explicit "
            "'PubkeyAuthentication yes' line to exist in sshd_config because OpenSSH defaults "
            "may enable it even when the directive is absent or commented.\n"
            "Use curl for HTTP checks from the client container only. Do not use curl inside "
            "server_shellshock, server_web1, or server_web2 unless the system context explicitly says "
            "curl is installed there. For local service health on server_shellshock, use apachectl "
            "and ps aux | grep [a]pache instead of curl http://127.0.0.1/.\n"
            "- Recovery: remove or relax temporary containment rules if user-facing service access must "
            "be verified from the client, then verify the target service. For server_ssh recovery, "
            "use local SSH health checks only: '/usr/sbin/sshd -t', 'pgrep -x sshd', 'ss -ltn | "
            "grep -q \":22 \"', and 'ps aux | grep [s]shd'. Do not use curl or telnet-style probes "
            "for SSH port verification. For server_samba recovery, remove the exact temporary "
            "gateway DROP rules for the target before any client-side smbclient check; never flush "
            "the complete firewall. If guest access was disabled, do not use anonymous smbclient "
            "success as a mandatory recovery condition. For server_shellshock verify apachectl health and HTTP service "
            "locally or from client only after temporary DROP rules are removed.\n"
            "Every command object must include container, command, allowed_exit_codes, and description. "
            "Never use exit as a command or as part of a shell snippet. "
            "Use allowed_exit_codes [0] for normal success. If a verification command is expected to fail "
            "to prove containment, use [1, 2]."
        )

    def _whole_system_user_prompt(self, request: CommandAgentRequest) -> str:
        """Build one command-generation request for a whole-system action."""
        state_json = json.dumps(request.current_state, ensure_ascii=True)
        containers = ", ".join(sorted(ALLOWED_CONTAINERS))
        executables = ", ".join(sorted(ALLOWED_COMMANDS))
        redirect_prefixes = ", ".join(ALLOWED_REDIRECT_PREFIXES)
        targets = "\n".join(
            f"- {server} / {server_ip}"
            for server, server_ip in request.recovery_targets
        )
        return (
            "Create one bash command plan for this whole-system high-level "
            "recovery action. The plan may contain commands for multiple lab "
            "containers. Decide which recovery targets are affected from the "
            "action and incident evidence; the high-level action does not contain "
            "a separate target-selection field.\n\n"
            f"System:\n{request.system}\n\n"
            f"Logs:\n{request.logs}\n\n"
            f"Incident:\n{request.incident}\n\n"
            f"Digital Twin Command Context:\n{request.dt_context or 'None provided.'}\n\n"
            f"Compromised recovery targets:\n{targets}\n\n"
            f"Attacker IP: {request.attacker_ip}\n"
            f"Current whole-system recovery state: {state_json}\n\n"
            f"High-level action:\n{request.high_level_action.action}\n\n"
            f"Action explanation:\n{request.high_level_action.explanation}\n\n"
            "Generate only commands needed to implement this action. Each command "
            "must name its actual execution container. Do not repeat the action "
            "mechanically on every recovery target. Whole-system actions may use "
            "multiple target containers and the gateway in one plan.\n"
            f"Use only these containers: {containers}.\n"
            f"Use only these command executables: {executables}.\n"
            f"If redirecting output, redirect only under: {redirect_prefixes}.\n"
            "Use only paths, services, interfaces, and tools established by the "
            "provided context. If a resource is not established, use a read-only "
            "discovery command and do not make a later command in the same plan "
            "depend on an unobserved discovery result.\n"
            "Do not use sudo, docker, bash, sh, python, perl, awk, wget, nc, rm, "
            "echo, printf, package managers, host-level commands, command "
            "substitution, heredocs, loops, functions, or multi-line commands.\n"
            "Keep commands simple and allowlist-friendly. Use target-specific "
            "directories under /tmp/recovery_evidence/<server>/ and "
            "/tmp/recovery_artifacts/<server>/. Before writing, copying, moving, "
            "archiving, or redirecting output to any destination file, use a "
            "directory that the provided context establishes as existing, or "
            "first create its parent directory with a separate 'mkdir -p "
            "PARENT_DIRECTORY' command in the same plan. Do not assume that an "
            "allowed redirect prefix means the directory already exists. For "
            "gateway evidence, prefer /tmp/recovery_evidence_gateway_/ and create "
            "it with 'mkdir -p /tmp/recovery_evidence_gateway_' before the first "
            "write. Treat missing optional logs and "
            "optional cross-host checks as non-fatal with suitable allowed exit "
            "codes. In particular, /var/log/auth.log, /var/log/syslog, Samba log "
            "files, Apache access/error logs, and /var/log/snort/alert may be "
            "missing or empty in this Docker lab. If a collection command accepts "
            "a missing source with '2>/dev/null || true', do not later require "
            "that collected file to be non-empty with a strict 'test -s' using "
            "allowed_exit_codes [0]. Either omit that optional verification or "
            "use allowed_exit_codes [0, 1]. Keep strict [0] verification only for "
            "stable required evidence such as ip_addr.txt, ip_route.txt, "
            "processes.txt, passwd.txt, configuration copies known to exist, and "
            "successfully created disk-image archives. For live root-filesystem "
            "acquisition with tar, use allowed_exit_codes [0, 1], because tar "
            "exit code 1 can mean files changed while the running filesystem was "
            "being read. Always verify the resulting archive with a separate "
            "'test -s ARCHIVE' command using allowed_exit_codes [0]. Never accept "
            "tar exit code 2. This exception applies only to live filesystem "
            "archive commands, not to other recovery commands.\n"
            "For each affected target, include concrete verification of the "
            "outcome requested by the action. Do not require unrelated targets "
            "or services to pass verification. Do not include rollback commands "
            "unless the action explicitly requests rollback.\n"
            "Every command object must include container, command, "
            "allowed_exit_codes, and description. Use allowed_exit_codes [0] for "
            "normal success; when expected failure proves containment, use [1, 2]."
        )

    def _schema(self) -> dict[str, Any]:
        state_properties = {
            field: {"type": "boolean"} for field in RECOVERY_STATE_FIELDS
        }
        command_spec = {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "container": {
                    "type": "string",
                    "enum": [
                        "gateway",
                        "client",
                        "server_ssh",
                        "server_samba",
                        "server_shellshock",
                        "server_web1",
                        "server_web2",
                    ],
                },
                "command": {"type": "string"},
                "allowed_exit_codes": {
                    "type": "array",
                    "items": {"type": "integer"},
                },
                "description": {"type": "string"},
            },
            "required": [
                "container",
                "command",
                "allowed_exit_codes",
                "description",
            ],
        }
        return {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "commands": {
                    "type": "array",
                    "items": command_spec,
                },
                "verification_commands": {
                    "type": "array",
                    "items": command_spec,
                },
                "expected_state_change": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": state_properties,
                    "required": list(RECOVERY_STATE_FIELDS),
                },
                "rollback_commands": {
                    "type": "array",
                    "items": command_spec,
                },
            },
            "required": [
                "commands",
                "verification_commands",
                "expected_state_change",
                "rollback_commands",
            ],
        }

    def _extract_output_text(self, data: dict[str, Any]) -> str:
        if isinstance(data.get("output_text"), str):
            return str(data["output_text"])
        chunks: list[str] = []
        for item in data.get("output", []):
            if not isinstance(item, dict):
                continue
            for content in item.get("content", []):
                if not isinstance(content, dict):
                    continue
                if content.get("type") in {"output_text", "text"} and isinstance(
                    content.get("text"),
                    str,
                ):
                    chunks.append(str(content["text"]))
        if chunks:
            return "".join(chunks)
        raise RuntimeError(f"Could not extract text from OpenAI response: {data}")

    def _loads_json(self, text: str) -> dict[str, Any]:
        cleaned = text.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.removeprefix("```json").removeprefix("```").strip()
            cleaned = cleaned.removesuffix("```").strip()
        parsed = json.loads(cleaned)
        if not isinstance(parsed, dict):
            raise ValueError("Command-agent response JSON must be an object.")
        return parsed

    def _plan_from_json(
        self,
        request: CommandAgentRequest,
        parsed: dict[str, Any],
        raw_model_output: str,
    ) -> CommandPlan:
        return CommandPlan(
            high_level_action=request.high_level_action.action,
            high_level_action_explanation=request.high_level_action.explanation,
            raw_model_output=raw_model_output,
            commands=tuple(self._command_from_json(item) for item in parsed["commands"]),
            verification_commands=tuple(
                self._command_from_json(item) for item in parsed["verification_commands"]
            ),
            expected_state_change={
                field: bool(parsed["expected_state_change"].get(field, False))
                for field in RECOVERY_STATE_FIELDS
            },
            rollback_commands=tuple(
                self._command_from_json(item) for item in parsed["rollback_commands"]
            ),
        )

    def _command_from_json(self, item: dict[str, Any]) -> CommandSpec:
        return CommandSpec(
            container=str(item["container"]),
            command=str(item["command"]),
            allowed_exit_codes=tuple(int(code) for code in item["allowed_exit_codes"]),
            description=str(item["description"]),
        )


class DeepSeekCommandAgent(OpenAICommandAgent):
    """DeepSeek Chat Completions backed command agent."""

    def __init__(
        self,
        *,
        model: str = "deepseek-v4-pro",
        api_key: str | None = None,
        api_key_env: str = "DEEPSEEK_API_KEY",
        base_url: str = "https://api.deepseek.com",
        timeout_seconds: int = 120,
        max_tokens: int = 4096,
    ) -> None:
        self.model = model
        self.api_key = api_key or os.getenv(api_key_env, "").strip()
        self.api_key_env = api_key_env
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.max_tokens = max_tokens
        if not self.api_key:
            raise ValueError(f"DeepSeek API key is missing. Set {api_key_env}.")

    def generate_plan(self, request: CommandAgentRequest) -> CommandPlan:
        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": self._system_prompt(),
                },
                {
                    "role": "user",
                    "content": self._deepseek_user_prompt(request),
                },
            ],
            "response_format": {"type": "json_object"},
            "max_tokens": self.max_tokens,
        }
        response = requests.post(
            f"{self.base_url}/chat/completions",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=self.timeout_seconds,
        )
        if response.status_code >= 400:
            raise RuntimeError(
                f"DeepSeek command generation failed: HTTP {response.status_code}: {response.text}"
            )
        data = response.json()
        text = self._extract_chat_message_content(data)
        parsed = self._loads_json(text)
        return self._plan_from_json(request, parsed, raw_model_output=text)

    def _deepseek_user_prompt(self, request: CommandAgentRequest) -> str:
        return (
            self._user_prompt(request)
            + "\n\nReturn valid JSON only, with exactly this JSON object shape:\n"
            + json.dumps(self._example_output(), indent=2, ensure_ascii=True)
        )

    def _example_output(self) -> dict[str, Any]:
        state = {field: False for field in RECOVERY_STATE_FIELDS}
        state["is_attack_contained"] = True
        return {
            "commands": [
                {
                    "container": "gateway",
                    "command": "iptables -I FORWARD -s 10.0.1.11 -d 10.0.2.11 -j DROP",
                    "allowed_exit_codes": [0],
                    "description": "Block attacker traffic to the SSH server.",
                }
            ],
            "verification_commands": [
                {
                    "container": "gateway",
                    "command": "iptables-save",
                    "allowed_exit_codes": [0],
                    "description": "Show active gateway firewall rules.",
                },
                {
                    "container": "client",
                    "command": "ping -c 2 10.0.2.11",
                    "allowed_exit_codes": [1, 2],
                    "description": "Confirm client traffic to the target is blocked.",
                },
            ],
            "expected_state_change": state,
            "rollback_commands": [],
        }

    def _extract_chat_message_content(self, data: dict[str, Any]) -> str:
        choices = data.get("choices", [])
        if not choices or not isinstance(choices[0], dict):
            raise RuntimeError(f"Could not extract DeepSeek choices: {data}")
        message = choices[0].get("message", {})
        if not isinstance(message, dict) or not isinstance(message.get("content"), str):
            raise RuntimeError(f"Could not extract DeepSeek message content: {data}")
        content = str(message["content"]).strip()
        if not content:
            raise RuntimeError(f"DeepSeek returned empty message content: {data}")
        return content


class MockCommandAgent(CommandAgent):
    """
    Deterministic command agent for the first server_ssh implementation.

    It maps common high-level action intents to concrete commands. This lets the
    recovery loop validate baseline restore, execution, timing, state checking,
    and action selection before adding OpenAI/Codex API calls.
    """

    def generate_plan(self, request: CommandAgentRequest) -> CommandPlan:
        text = request.high_level_action.action.lower()
        if request.server != "server_ssh" and request.server_ip != "10.0.2.11":
            raise ValueError("MockCommandAgent only supports server_ssh / 10.0.2.11")

        if self._contains_any(text, ("block", "contain", "isolate")):
            return self._contain(request)
        if self._contains_any(text, ("preserve", "forensic", "evidence")):
            return self._preserve_forensics(request)
        if self._contains_any(text, ("collect", "gather", "information", "investigate", "log", "logs")):
            return self._collect_knowledge(request)
        if self._contains_any(text, ("eradicate", "remove", "terminate", "kill")):
            return self._eradicate(request)
        if self._contains_any(text, ("harden", "disable", "password", "root login", "configuration")):
            return self._harden(request)
        if self._contains_any(text, ("recover", "restore", "restart", "service", "health")):
            return self._recover(request)
        return self._collect_knowledge(request)

    def _contains_any(self, text: str, terms: tuple[str, ...]) -> bool:
        for term in terms:
            pattern = r"(?<!\w)" + re.escape(term) + r"(?!\w)"
            if re.search(pattern, text):
                return True
        return False

    def _base_plan(
        self,
        request: CommandAgentRequest,
        commands: list[CommandSpec],
        verification: list[CommandSpec],
        expected: RecoveryState,
        rollback: list[CommandSpec] | None = None,
    ) -> CommandPlan:
        return CommandPlan(
            high_level_action=request.high_level_action.action,
            high_level_action_explanation=request.high_level_action.explanation,
            raw_model_output=request.high_level_action.raw_model_output,
            commands=tuple(commands),
            verification_commands=tuple(verification),
            expected_state_change=expected,
            rollback_commands=tuple(rollback or []),
        )

    def _contain(self, request: CommandAgentRequest) -> CommandPlan:
        rule = f"-s {request.attacker_ip} -d {request.server_ip} -j DROP"
        return self._base_plan(
            request,
            commands=[
                CommandSpec(
                    "gateway",
                    f"iptables -C FORWARD {rule} 2>/dev/null || iptables -I FORWARD {rule}",
                    description="Block attacker traffic to the SSH server at the gateway.",
                )
            ],
            verification=[
                CommandSpec("gateway", "iptables -S FORWARD"),
                CommandSpec(
                    "client",
                    f"ping -c 1 -W 1 {request.server_ip}",
                    allowed_exit_codes=(1, 2),
                    description="Ping should fail after containment.",
                ),
            ],
            expected={"is_attack_contained": True},
            rollback=[
                CommandSpec(
                    "gateway",
                    f"iptables -D FORWARD {rule} 2>/dev/null || true",
                )
            ],
        )

    def _collect_knowledge(self, request: CommandAgentRequest) -> CommandPlan:
        artifact_dir = "/tmp/recovery_artifacts/server_ssh"
        return self._base_plan(
            request,
            commands=[
                CommandSpec("server_ssh", f"mkdir -p {artifact_dir}"),
                CommandSpec("server_ssh", f"ip addr > {artifact_dir}/ip_addr.txt"),
                CommandSpec("server_ssh", f"ip route > {artifact_dir}/ip_route.txt"),
                CommandSpec("server_ssh", f"ps aux > {artifact_dir}/processes.txt"),
                CommandSpec("server_ssh", f"cat /etc/passwd > {artifact_dir}/passwd.txt"),
                CommandSpec(
                    "server_ssh",
                    f"cat /var/log/auth.log > {artifact_dir}/auth_log.txt 2>/dev/null || true",
                    allowed_exit_codes=(0,),
                ),
            ],
            verification=[
                CommandSpec("server_ssh", f"test -s {artifact_dir}/ip_addr.txt"),
                CommandSpec("server_ssh", f"test -s {artifact_dir}/passwd.txt"),
            ],
            expected={"is_knowledge_sufficient": True},
        )

    def _preserve_forensics(self, request: CommandAgentRequest) -> CommandPlan:
        evidence_dir = "/tmp/recovery_evidence/server_ssh"
        return self._base_plan(
            request,
            commands=[
                CommandSpec("server_ssh", f"mkdir -p {evidence_dir}"),
                CommandSpec("server_ssh", f"cat /etc/passwd > {evidence_dir}/passwd.txt"),
                CommandSpec(
                    "server_ssh",
                    f"cat /var/log/auth.log > {evidence_dir}/auth_log.txt 2>/dev/null || true",
                ),
                CommandSpec("server_ssh", f"ls -la /home/admin > {evidence_dir}/home_admin.txt"),
                CommandSpec("gateway", "iptables -S > /tmp/recovery_evidence_gateway_iptables.rules"),
            ],
            verification=[
                CommandSpec("server_ssh", f"test -s {evidence_dir}/passwd.txt"),
                CommandSpec("server_ssh", f"test -s {evidence_dir}/home_admin.txt"),
            ],
            expected={"are_forensics_preserved": True},
        )

    def _eradicate(self, request: CommandAgentRequest) -> CommandPlan:
        marker = "/tmp/recovery_artifacts/server_ssh/eradicated.marker"
        return self._base_plan(
            request,
            commands=[
                CommandSpec("server_ssh", "mkdir -p /tmp/recovery_artifacts/server_ssh"),
                CommandSpec("server_ssh", "pkill -u admin 2>/dev/null || true"),
                CommandSpec("server_ssh", "passwd -l admin 2>/dev/null || true"),
                CommandSpec("server_ssh", f"touch {marker}"),
            ],
            verification=[
                CommandSpec("server_ssh", f"test -f {marker}"),
            ],
            expected={"is_eradicated": True},
        )

    def _harden(self, request: CommandAgentRequest) -> CommandPlan:
        cfg = "/etc/ssh/sshd_config"
        return self._base_plan(
            request,
            commands=[
                CommandSpec(
                    "server_ssh",
                    f"sed -i 's/^#\\?PermitRootLogin .*/PermitRootLogin no/' {cfg}",
                ),
                CommandSpec(
                    "server_ssh",
                    f"sed -i 's/^#\\?PasswordAuthentication .*/PasswordAuthentication no/' {cfg}",
                ),
                CommandSpec(
                    "server_ssh",
                    "grep -Eq '^[#[:space:]]*PermitRootLogin[[:space:]]+no' /etc/ssh/sshd_config",
                ),
                CommandSpec(
                    "server_ssh",
                    "grep -Eq '^[#[:space:]]*PasswordAuthentication[[:space:]]+no' /etc/ssh/sshd_config",
                ),
                CommandSpec("server_ssh", "pkill -HUP sshd 2>/dev/null || /usr/sbin/sshd"),
            ],
            verification=[
                CommandSpec(
                    "server_ssh",
                    "grep -Eq '^[#[:space:]]*PermitRootLogin[[:space:]]+no' /etc/ssh/sshd_config",
                ),
                CommandSpec(
                    "server_ssh",
                    "grep -Eq '^[#[:space:]]*PasswordAuthentication[[:space:]]+no' /etc/ssh/sshd_config",
                ),
            ],
            expected={"is_hardened": True},
        )

    def _recover(self, request: CommandAgentRequest) -> CommandPlan:
        return self._base_plan(
            request,
            commands=[
                CommandSpec("server_ssh", "/usr/sbin/sshd 2>/dev/null || true"),
            ],
            verification=[
                CommandSpec("server_ssh", "pgrep -x sshd"),
                CommandSpec("server_ssh", "ss -ltn | grep -q ':22 '"),
            ],
            expected={"is_recovered": True},
        )
