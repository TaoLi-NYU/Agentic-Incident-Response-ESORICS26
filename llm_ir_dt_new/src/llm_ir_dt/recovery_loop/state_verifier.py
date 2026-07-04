"""Rule-based recovery-state verification for the digital twin."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from llm_ir_dt.recovery_loop.schemas import RECOVERY_STATE_FIELDS, RecoveryState


@dataclass(frozen=True)
class StateVerification:
    """Structured state verification result."""

    state: RecoveryState
    evidence: dict[str, Any]


class StateVerifier:
    """Interface for state verifiers."""

    def verify(self) -> StateVerification:
        """Verify the current recovery state."""
        raise NotImplementedError


class ServerSSHStateVerifier(StateVerifier):
    """Rule-based verifier for server_ssh / 10.0.2.11."""

    def __init__(
        self,
        *,
        attacker_ip: str = "10.0.1.11",
        server_ip: str = "10.0.2.11",
    ) -> None:
        self.attacker_ip = attacker_ip
        self.server_ip = server_ip

    def verify(self) -> StateVerification:
        evidence: dict[str, Any] = {}

        iptables = self._run("gateway", "iptables -S FORWARD")
        ping = self._run("client", f"ping -c 1 -W 1 {self.server_ip}")
        evidence["iptables_forward"] = iptables
        evidence["client_ping_target"] = ping
        has_drop = (
            self.attacker_ip in iptables["output"]
            and self.server_ip in iptables["output"]
            and "DROP" in iptables["output"]
        )
        is_attack_contained = has_drop and int(ping["exit_code"]) != 0

        knowledge_ip = self._test_any(
            "server_ssh",
            (
                "/tmp/recovery_artifacts/server_ssh/ip_addr.txt",
                "/var/ir/evidence211/ip_addr.txt",
            ),
        )
        knowledge_passwd = self._test_any(
            "server_ssh",
            (
                "/tmp/recovery_artifacts/server_ssh/passwd.txt",
                "/var/ir/evidence211/passwd.txt",
            ),
        )
        evidence["knowledge_ip_addr"] = knowledge_ip
        evidence["knowledge_passwd"] = knowledge_passwd
        is_knowledge_sufficient = (
            int(knowledge_ip["exit_code"]) == 0
            and int(knowledge_passwd["exit_code"]) == 0
        )

        forensics_passwd = self._test_any(
            "server_ssh",
            (
                "/tmp/recovery_evidence/server_ssh/passwd.txt",
                "/var/ir/evidence211/passwd.txt",
            ),
        )
        forensics_home = self._test_any(
            "server_ssh",
            (
                "/tmp/recovery_evidence/server_ssh/home_admin.txt",
                "/var/ir/evidence211/home_admin.txt",
            ),
        )
        evidence["forensics_passwd"] = forensics_passwd
        evidence["forensics_home_admin"] = forensics_home
        are_forensics_preserved = (
            int(forensics_passwd["exit_code"]) == 0
            and int(forensics_home["exit_code"]) == 0
        )

        eradicated_marker = self._run(
            "server_ssh", "test -f /tmp/recovery_artifacts/server_ssh/eradicated.marker"
        )
        evidence["eradicated_marker"] = eradicated_marker
        is_eradicated = int(eradicated_marker["exit_code"]) == 0

        root_login = self._run(
            "server_ssh", "grep -q '^PermitRootLogin no' /etc/ssh/sshd_config"
        )
        password_auth = self._run(
            "server_ssh", "grep -q '^PasswordAuthentication no' /etc/ssh/sshd_config"
        )
        evidence["harden_root_login"] = root_login
        evidence["harden_password_auth"] = password_auth
        is_hardened = int(root_login["exit_code"]) == 0 and int(password_auth["exit_code"]) == 0

        sshd_proc = self._run("server_ssh", "pgrep -x sshd")
        sshd_port = self._run("server_ssh", "ss -ltn | grep -q ':22 '")
        evidence["sshd_process"] = sshd_proc
        evidence["sshd_port"] = sshd_port
        is_service_healthy = (
            int(sshd_proc["exit_code"]) == 0
            and int(sshd_port["exit_code"]) == 0
        )
        evidence["is_service_healthy"] = is_service_healthy
        is_recovered = (
            is_service_healthy
            and is_attack_contained
            and is_knowledge_sufficient
            and are_forensics_preserved
            and is_eradicated
            and is_hardened
        )

        state: RecoveryState = {
            "is_attack_contained": is_attack_contained,
            "is_knowledge_sufficient": is_knowledge_sufficient,
            "are_forensics_preserved": are_forensics_preserved,
            "is_eradicated": is_eradicated,
            "is_hardened": is_hardened,
            "is_recovered": is_recovered,
        }
        return StateVerification(
            state={field: bool(state.get(field, False)) for field in RECOVERY_STATE_FIELDS},
            evidence=evidence,
        )

    def _run(self, container: str, command: str) -> dict[str, Any]:
        try:
            from llm_ir_dt.docker_manager.docker_manager import DockerManager

            return DockerManager.exec_run(container, command)
        except Exception as exc:
            return {
                "container": container,
                "command": command,
                "exit_code": 255,
                "output": str(exc),
            }

    def _test_any(self, container: str, paths: tuple[str, ...]) -> dict[str, Any]:
        for path in paths:
            result = self._run(container, f"test -s {path}")
            if int(result["exit_code"]) == 0:
                result["matched_path"] = path
                return result
        result["checked_paths"] = list(paths)
        return result


class TargetServerStateVerifier(StateVerifier):
    """Rule-based verifier for non-SSH target servers."""

    def __init__(
        self,
        *,
        server: str,
        server_ip: str,
        attacker_ip: str = "10.0.1.11",
    ) -> None:
        self.server = server
        self.server_ip = server_ip
        self.attacker_ip = attacker_ip
        self.artifact_dir = f"/tmp/recovery_artifacts/{server}"
        self.evidence_dir = f"/tmp/recovery_evidence/{server}"

    def verify(self) -> StateVerification:
        evidence: dict[str, Any] = {}

        iptables = self._run("gateway", "iptables -S FORWARD")
        ping = self._run("client", f"ping -c 1 -W 1 {self.server_ip}")
        evidence["iptables_forward"] = iptables
        evidence["client_ping_target"] = ping
        has_drop = (
            self.attacker_ip in iptables["output"]
            and self.server_ip in iptables["output"]
            and "DROP" in iptables["output"]
        )
        is_attack_contained = has_drop and int(ping["exit_code"]) != 0

        knowledge_ip = self._test_any(
            (
                f"{self.artifact_dir}/ip_addr.txt",
                "/var/ir/evidence211/ip_addr.txt",
            )
        )
        knowledge_processes = self._test_any(
            (
                f"{self.artifact_dir}/processes.txt",
                "/var/ir/evidence211/processes.txt",
            )
        )
        evidence["knowledge_ip_addr"] = knowledge_ip
        evidence["knowledge_processes"] = knowledge_processes
        is_knowledge_sufficient = (
            int(knowledge_ip["exit_code"]) == 0
            and int(knowledge_processes["exit_code"]) == 0
        )

        forensics = self._verify_forensics()
        evidence["target_forensics"] = forensics
        are_forensics_preserved = int(forensics["exit_code"]) == 0

        eradicated_marker = self._test_file_any(
            (
                f"{self.artifact_dir}/eradicated.marker",
                "/var/ir/evidence211/eradicated.marker",
            )
        )
        evidence["eradicated_marker"] = eradicated_marker
        is_eradicated = int(eradicated_marker["exit_code"]) == 0

        hardening = self._verify_hardening()
        evidence["target_hardening"] = hardening
        is_hardened = int(hardening["exit_code"]) == 0

        service = self._verify_service_health()
        evidence["target_service_health"] = service
        is_service_healthy = int(service["exit_code"]) == 0
        evidence["is_service_healthy"] = is_service_healthy

        is_recovered = (
            is_service_healthy
            and is_attack_contained
            and is_knowledge_sufficient
            and are_forensics_preserved
            and is_eradicated
            and is_hardened
        )

        state: RecoveryState = {
            "is_attack_contained": is_attack_contained,
            "is_knowledge_sufficient": is_knowledge_sufficient,
            "are_forensics_preserved": are_forensics_preserved,
            "is_eradicated": is_eradicated,
            "is_hardened": is_hardened,
            "is_recovered": is_recovered,
        }
        return StateVerification(
            state={field: bool(state.get(field, False)) for field in RECOVERY_STATE_FIELDS},
            evidence=evidence,
        )

    def _verify_forensics(self) -> dict[str, Any]:
        if self.server == "server_samba":
            return self._test_any(
                (
                    f"{self.evidence_dir}/samba_logs.txt",
                    f"{self.evidence_dir}/share_listing.txt",
                    f"{self.evidence_dir}/share.tar.gz",
                    "/var/ir/evidence211/samba_log.log",
                    "/var/ir/evidence211/samba_logs.txt",
                    "/var/ir/evidence211/share_listing.txt",
                    "/var/ir/evidence211/share.tar.gz",
                )
            )
        if self.server == "server_shellshock":
            return self._test_any(
                (
                    f"{self.evidence_dir}/apache_access.log",
                    f"{self.evidence_dir}/apache_error.log",
                    f"{self.evidence_dir}/cgi_file.sh",
                    "/var/ir/evidence211/apache_access.log",
                    "/var/ir/evidence211/apache_error.log",
                    "/var/ir/evidence211/cgi_file.sh",
                )
            )
        if self.server in {"server_web1", "server_web2"}:
            return self._test_any(
                (
                    f"{self.evidence_dir}/nginx_access.log",
                    f"{self.evidence_dir}/nginx_error.log",
                    f"{self.evidence_dir}/passwd.txt",
                    "/var/ir/evidence211/nginx_access.log",
                    "/var/ir/evidence211/nginx_error.log",
                    "/var/ir/evidence211/passwd.txt",
                )
            )
        return self._test_any(
            (
                f"{self.evidence_dir}/passwd.txt",
                f"{self.evidence_dir}/processes.txt",
                "/var/ir/evidence211/passwd.txt",
                "/var/ir/evidence211/processes.txt",
            )
        )

    def _verify_hardening(self) -> dict[str, Any]:
        if self.server == "server_samba":
            guest = self._run(
                self.server,
                "grep -E '^[[:space:]]*guest ok = no[[:space:]]*$' /etc/samba/smb.conf",
            )
            readonly = self._run(
                self.server,
                "grep -E '^[[:space:]]*read only = yes[[:space:]]*$' /etc/samba/smb.conf",
            )
            return self._combine("samba_hardening", (guest, readonly))
        if self.server == "server_shellshock":
            executable = self._run(self.server, "test -x /usr/lib/cgi-bin/vulnerable")
            result = dict(executable)
            result["exit_code"] = 1 if int(executable["exit_code"]) == 0 else 0
            result["description"] = "vulnerable CGI is not executable"
            return result
        if self.server in {"server_web1", "server_web2"}:
            nginx = self._run(self.server, "nginx -t")
            sshd_config = self._run(self.server, "/usr/sbin/sshd -t")
            marker = self._test_file_any(
                (
                    f"{self.artifact_dir}/hardened.marker",
                    "/var/ir/evidence211/hardened.marker",
                )
            )
            if int(marker["exit_code"]) == 0:
                return marker
            return self._combine("web_hardening", (nginx, sshd_config))
        return self._test_file_any(
            (
                f"{self.artifact_dir}/hardened.marker",
                "/var/ir/evidence211/hardened.marker",
            )
        )

    def _verify_service_health(self) -> dict[str, Any]:
        if self.server == "server_samba":
            return self._run(self.server, "ps aux | grep '[s]mbd'")
        if self.server == "server_shellshock":
            return self._run(self.server, "ps aux | grep '[a]pache'")
        if self.server in {"server_web1", "server_web2"}:
            nginx = self._run(self.server, "ps aux | grep '[n]ginx'")
            sshd = self._run(self.server, "pgrep -x sshd")
            return self._combine("web_service_health", (nginx, sshd))
        return self._run(self.server, "ps aux")

    def _run(self, container: str, command: str) -> dict[str, Any]:
        try:
            from llm_ir_dt.docker_manager.docker_manager import DockerManager

            return DockerManager.exec_run(container, command)
        except Exception as exc:
            return {
                "container": container,
                "command": command,
                "exit_code": 255,
                "output": str(exc),
            }

    def _test_any(self, paths: tuple[str, ...]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for path in paths:
            result = self._run(self.server, f"test -s {path}")
            if int(result["exit_code"]) == 0:
                result["matched_path"] = path
                return result
        result["checked_paths"] = list(paths)
        return result

    def _test_file_any(self, paths: tuple[str, ...]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for path in paths:
            result = self._run(self.server, f"test -f {path}")
            if int(result["exit_code"]) == 0:
                result["matched_path"] = path
                return result
        result["checked_paths"] = list(paths)
        return result

    def _combine(self, label: str, results: tuple[dict[str, Any], ...]) -> dict[str, Any]:
        return {
            "container": self.server,
            "command": label,
            "exit_code": 0 if all(int(item["exit_code"]) == 0 for item in results) else 1,
            "output": "\n".join(str(item.get("output", "")) for item in results),
            "details": list(results),
        }


def make_state_verifier(
    *,
    server: str,
    server_ip: str,
    attacker_ip: str = "10.0.1.11",
) -> StateVerifier:
    """Create the verifier for a selected target server."""
    if server == "server_ssh":
        return ServerSSHStateVerifier(attacker_ip=attacker_ip, server_ip=server_ip)
    return TargetServerStateVerifier(
        server=server,
        server_ip=server_ip,
        attacker_ip=attacker_ip,
    )
