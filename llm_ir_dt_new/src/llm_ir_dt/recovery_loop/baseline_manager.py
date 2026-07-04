"""Baseline restoration for fair candidate evaluation."""

from __future__ import annotations

import subprocess
import sys
import time
import os
from pathlib import Path

from llm_ir_dt.constants.constants import DIGITAL_TWIN
from llm_ir_dt.recovery_loop.recovery_executor import RecoveryExecutor
from llm_ir_dt.recovery_loop.schemas import CommandPlan, RecoveryState
from llm_ir_dt.recovery_loop.state_verifier import StateVerifier


class BaselineManager:
    """Restore the same baseline before each candidate rollout."""

    def __init__(
        self,
        *,
        project_root: Path,
        executor: RecoveryExecutor,
        verifier: StateVerifier,
        wait_seconds: int = 15,
        rebuild_images: bool = False,
        attack_command: list[str] | None = None,
    ) -> None:
        self.project_root = project_root
        self.executor = executor
        self.verifier = verifier
        self.wait_seconds = wait_seconds
        self.rebuild_images = rebuild_images
        self.attack_command = attack_command or ["run_attack.py"]

    def restore(self, history_plans: list[CommandPlan]) -> tuple[RecoveryState, float]:
        """Restore baseline and replay selected plans."""
        from llm_ir_dt.docker_manager.docker_manager import DockerManager

        start = time.perf_counter()
        for _ in DockerManager.stop(DIGITAL_TWIN.DEFAULT_CONFIG):
            pass

        if self.rebuild_images:
            build = subprocess.run(
                ["docker", "compose", "build"],
                cwd=str(self.project_root),
                capture_output=True,
                text=True,
                check=False,
            )
            if build.returncode != 0:
                raise RuntimeError(str(build.stderr))

        for _ in DockerManager.deploy(DIGITAL_TWIN.DEFAULT_CONFIG):
            pass
        time.sleep(self.wait_seconds)
        DockerManager.clear_alerts()
        self._run_attack()

        for plan in history_plans:
            self.executor.execute_plan(plan)

        state = self.verifier.verify().state
        elapsed = time.perf_counter() - start
        return state, elapsed

    def _run_attack(self) -> None:
        env = dict(os.environ)
        src = str(self.project_root / "src")
        env["PYTHONPATH"] = src + os.pathsep + env.get("PYTHONPATH", "")
        result = subprocess.run(
            [sys.executable, str(self.project_root / self.attack_command[0]), *self.attack_command[1:]],
            cwd=str(self.project_root),
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"{' '.join(self.attack_command)} failed\n"
                f"stdout:\n{result.stdout}\n"
                f"stderr:\n{result.stderr}"
            )
