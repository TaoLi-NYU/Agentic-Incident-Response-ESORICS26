"""
Stop the digital twin: remove all containers and networks.
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
    Stop and remove all digital twin containers and networks.
    """
    logger.info("Stopping digital twin...")
    for item in DockerManager.stop():
        logger.info("Stop: %s", item)
    logger.info("Digital twin stopped.")


if __name__ == "__main__":
    main()
