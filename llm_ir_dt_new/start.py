"""
Start the digital twin: build images, deploy containers, verify.
"""
import logging
import sys
import time
from pathlib import Path

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


def main() -> None:
    """
    Build Docker images, deploy the digital twin, and verify status.

    If the twin is already running, skip deployment.
    """
    status = DockerManager.status()
    if status["deployed"]:
        logger.info("Digital twin already running: %s", status)
        return

    logger.info("Building Docker images...")
    build_result = DockerManager.build_images()
    if build_result["exit_code"] != 0:
        logger.error("Image build failed: %s",
                     build_result["stderr"])
        return
    logger.info("Docker images built successfully")

    logger.info("Deploying digital twin...")
    config = DIGITAL_TWIN.DEFAULT_CONFIG
    for item in DockerManager.deploy(config):
        logger.info("Deploy: %s", item)

    logger.info("Waiting for services to initialize...")
    time.sleep(15)

    status = DockerManager.status()
    logger.info("Status: %s", status)
    logger.info("Digital twin started.")


if __name__ == "__main__":
    main()
