"""
Digital Twin Incident Response Testbed demo script.

Builds Docker images, deploys the digital twin, executes
network commands from the client, reads Snort alerts, and
stops the twin.
"""
import logging
import time

from llm_ir_dt.constants.constants import DIGITAL_TWIN
from llm_ir_dt.docker_manager.docker_manager import DockerManager

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)8s] %(message)s "
           "(%(filename)s:%(lineno)s)",
)
logger = logging.getLogger(__name__)


def main() -> None:
    """
    Run the full digital twin demo workflow.
    """
    # 1. Build Docker images
    logger.info("Building Docker images...")
    build_result = DockerManager.build_images()
    if build_result["exit_code"] != 0:
        logger.error("Image build failed: %s",
                     build_result["stderr"])
        return
    logger.info("Docker images built successfully")

    # 2. Deploy the digital twin
    logger.info("Deploying digital twin...")
    config = DIGITAL_TWIN.DEFAULT_CONFIG
    for item in DockerManager.deploy(config):
        logger.info("Deploy: %s", item)

    # 3. Wait for services to start
    logger.info("Waiting for services to initialize...")
    time.sleep(15)

    # 4. Check status
    status = DockerManager.status()
    logger.info("Status: %s", status)

    # 5. Connectivity test from client
    logger.info("Running connectivity test...")
    result = DockerManager.exec_run(
        "client", "ping -c2 10.0.2.11",
    )
    logger.info("Ping result: %s", result)

    # 6. Read Snort alerts
    alerts = DockerManager.read_alerts()
    logger.info("Alerts: %s", alerts)

    # 7. Stop the twin
    logger.info("Stopping digital twin...")
    for item in DockerManager.stop():
        logger.info("Stop: %s", item)

    logger.info("Done.")


if __name__ == "__main__":
    main()
