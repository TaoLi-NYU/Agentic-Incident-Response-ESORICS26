"""
Run a few demo commands on the digital twin and read Snort alerts.
"""
import logging
import sys
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


def main() -> None:
    """
    Execute hardcoded demo commands and read alerts.
    """
    # Check status
    status = DockerManager.status()
    logger.info("Status: %s", status)

    # Connectivity test
    result = DockerManager.exec_run("client", "ping -c 2 10.0.2.11")
    logger.info("Ping result: %s", result)

    # List files on SSH server
    result = DockerManager.exec_run(
        "server_ssh", "ls -la /home/admin",
    )
    logger.info("SSH server /home/admin: %s", result)

    # Check web server
    result = DockerManager.exec_run(
        "client", "curl -s http://10.0.2.14/",
    )
    logger.info("Web1 response: %s", result)

    # Read Snort alerts
    alerts = DockerManager.read_alerts()
    logger.info("Alerts (%d):", len(alerts["alerts"]))
    for alert in alerts["alerts"]:
        logger.info("  %s", alert)


if __name__ == "__main__":
    main()
