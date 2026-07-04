"""
Recover the digital twin after a compromise by exporting key evidence,
tearing down the lab, and redeploying clean containers.
"""
import json
import logging
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from llm_ir_dt.constants.constants import DIGITAL_TWIN
from llm_ir_dt.docker_manager.docker_manager import DockerManager

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)8s] %(message)s "
           "(%(filename)s:%(lineno)s)",
)
logger = logging.getLogger(__name__)

FORENSIC_COMMANDS: dict[str, list[tuple[str, str]]] = {
    "client": [
        ("ip_addr", "ip addr"),
        ("ip_route", "ip route"),
        ("processes", "ps aux"),
        ("known_hosts", "cat /root/.ssh/known_hosts 2>/dev/null || true"),
        ("password_list", "cat /opt/passwords.txt 2>/dev/null || true"),
    ],
    "server_ssh": [
        ("ip_addr", "ip addr"),
        ("ip_route", "ip route"),
        ("processes", "ps aux"),
        ("passwd", "cat /etc/passwd"),
        ("shadow_access", "cat /etc/shadow 2>/dev/null || echo permission denied"),
        ("auth_log", "cat /var/log/auth.log 2>/dev/null || true"),
        ("home_admin", "ls -la /home/admin"),
    ],
    "server_samba": [
        ("ip_addr", "ip addr"),
        ("ip_route", "ip route"),
        ("processes", "ps aux"),
        ("samba_logs", "find /var/log/samba -maxdepth 1 -type f -exec sh -c 'for f do echo \"===== $f =====\"; cat \"$f\"; done' sh {} + 2>/dev/null || true"),
        ("share_listing", "ls -la /srv/share 2>/dev/null || true"),
    ],
    "server_shellshock": [
        ("ip_addr", "ip addr"),
        ("ip_route", "ip route"),
        ("processes", "ps aux"),
        ("passwd", "cat /etc/passwd"),
        ("apache_access_log", "cat /var/log/apache2/access.log 2>/dev/null || true"),
        ("apache_error_log", "cat /var/log/apache2/error.log 2>/dev/null || true"),
        ("cgi_file", "cat /usr/lib/cgi-bin/vulnerable 2>/dev/null || true"),
    ],
}


def write_json(path: Path, data: Any) -> None:
    """Write JSON data with stable formatting."""
    path.write_text(
        json.dumps(data, indent=2, ensure_ascii=True),
        encoding="utf-8",
    )


def write_text(path: Path, content: str) -> None:
    """Write UTF-8 text content to disk."""
    path.write_text(content, encoding="utf-8")


def export_evidence(evidence_dir: Path) -> None:
    """Export status, alerts, and selected host artifacts."""
    logger.info("Exporting evidence to %s", evidence_dir)
    evidence_dir.mkdir(parents=True, exist_ok=True)

    status = DockerManager.status()
    write_json(evidence_dir / "status.json", status)

    alerts = DockerManager.read_alerts()
    write_json(evidence_dir / "alerts.json", alerts["alerts"])
    write_text(evidence_dir / "alerts.raw", alerts["raw"])

    for container_id, commands in FORENSIC_COMMANDS.items():
        container_dir = evidence_dir / container_id
        container_dir.mkdir(parents=True, exist_ok=True)
        for name, command in commands:
            try:
                result = DockerManager.exec_run(container_id, command)
            except Exception as exc:  # pragma: no cover - best effort export
                logger.warning(
                    "Failed to export %s from %s: %s",
                    name, container_id, exc,
                )
                write_text(
                    container_dir / f"{name}.error.txt",
                    str(exc),
                )
                continue

            write_json(container_dir / f"{name}.json", result)
            write_text(container_dir / f"{name}.txt", result["output"])


def stop_twin() -> None:
    """Stop and remove all digital twin resources."""
    logger.info("Stopping compromised environment")
    for item in DockerManager.stop(DIGITAL_TWIN.DEFAULT_CONFIG):
        logger.info("Stop: %s", item)


def rebuild_images() -> None:
    """Rebuild all Docker images."""
    logger.info("Rebuilding Docker images")
    build_result = DockerManager.build_images()
    if build_result["exit_code"] != 0:
        raise RuntimeError(build_result["stderr"])


def deploy_clean_twin() -> None:
    """Deploy a fresh clean instance of the digital twin."""
    logger.info("Deploying clean environment")
    for item in DockerManager.deploy(DIGITAL_TWIN.DEFAULT_CONFIG):
        logger.info("Deploy: %s", item)

    logger.info("Waiting for services to initialize")
    time.sleep(15)


def verify_recovery() -> dict[str, Any]:
    """Run basic health checks after redeployment."""
    checks = {
        "status": DockerManager.status(DIGITAL_TWIN.DEFAULT_CONFIG),
        "ping_ssh": DockerManager.exec_run("client", "ping -c 2 10.0.2.11"),
        "web1": DockerManager.exec_run("client", "curl -s http://10.0.2.14/"),
        "web2": DockerManager.exec_run("client", "curl -s http://10.0.2.15/"),
        "ssh_home": DockerManager.exec_run("server_ssh", "ls -la /home/admin"),
    }
    return checks


def main() -> None:
    """
    Export evidence, rebuild the lab, and verify clean recovery.
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    evidence_dir = ROOT / "artifacts" / f"recovery_{timestamp}"
    evidence_dir.mkdir(parents=True, exist_ok=True)

    status = DockerManager.status(DIGITAL_TWIN.DEFAULT_CONFIG)
    if status["deployed"]:
        export_evidence(evidence_dir)
        stop_twin()
    else:
        logger.info("Digital twin is not currently deployed; skipping evidence export")

    rebuild_images()
    deploy_clean_twin()

    verification = verify_recovery()
    write_json(evidence_dir / "recovery_verification.json", verification)

    clear_result = DockerManager.clear_alerts()
    write_json(evidence_dir / "clear_alerts.json", clear_result)

    logger.info("Recovery complete")
    logger.info("Evidence and verification written to %s", evidence_dir)
    logger.info("Verification: %s", verification)


if __name__ == "__main__":
    main()
