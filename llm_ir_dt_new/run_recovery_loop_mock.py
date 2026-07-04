"""
Run the recovery loop for one prioritized target server.

This entry point can use a mock command agent or an API-backed command agent
for command-plan generation. It executes generated command plans in the Docker
digital twin, so only run it when Docker is available and the lab may be reset.
"""

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from llm_ir_dt.recovery_loop.baseline_manager import BaselineManager
from llm_ir_dt.recovery_loop.action_provider import (
    LocalModelActionProvider,
    MockServerSSHActionProvider,
)
from llm_ir_dt.recovery_loop.command_agent import DeepSeekCommandAgent
from llm_ir_dt.recovery_loop.command_agent import MockCommandAgent
from llm_ir_dt.recovery_loop.command_agent import OpenAICommandAgent
from llm_ir_dt.recovery_loop.command_safety import CommandSafetyValidator
from llm_ir_dt.recovery_loop.orchestrator import (
    RecoveryLoopConfig,
    RecoveryLoopOrchestrator,
)
from llm_ir_dt.recovery_loop.plan_store import PlanStore
from llm_ir_dt.recovery_loop.recovery_executor import RecoveryExecutor
from llm_ir_dt.recovery_loop.state_verifier import make_state_verifier


DEFAULT_SYSTEM = (
    "The llm_ir_dt_new digital twin contains a client attacker host "
    "10.0.1.11, a gateway IDS/router, and server_ssh at 10.0.2.11."
)
DEFAULT_LOGS = (
    "Snort observed ICMP reconnaissance and repeated SSH connection attempts "
    "from 10.0.1.11 to 10.0.2.11, including SSH brute-force alerts."
)
DEFAULT_INCIDENT = (
    "The SSH server at 10.0.2.11 is targeted by reconnaissance and SSH "
    "brute-force activity from 10.0.1.11."
)

TARGET_SERVER_IPS = {
    "server_ssh": "10.0.2.11",
    "server_samba": "10.0.2.12",
    "server_shellshock": "10.0.2.13",
    "server_web1": "10.0.2.14",
    "server_web2": "10.0.2.15",
}


def read_text_arg(inline_value: str | None, file_value: str | None, default_value: str) -> str:
    """Read an inline/file/default text argument."""
    if file_value:
        return Path(file_value).expanduser().read_text(encoding="utf-8").strip()
    if inline_value:
        return inline_value.strip()
    return default_value


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run command-agent recovery loop for one target server."
    )
    parser.add_argument(
        "--server",
        choices=tuple(TARGET_SERVER_IPS),
        default="server_ssh",
        help="Prioritized target server to recover.",
    )
    parser.add_argument(
        "--server-ip",
        default=None,
        help="Target server IP. Defaults to the known IP for --server.",
    )
    parser.add_argument("--attacker-ip", default="10.0.1.11")
    parser.add_argument("--num-candidates", type=int, default=3)
    parser.add_argument("--num-rollouts", type=int, default=1)
    parser.add_argument("--max-plan-steps", type=int, default=6)
    parser.add_argument("--max-rollout-depth", type=int, default=2)
    parser.add_argument(
        "--action-provider",
        choices=("mock", "local-model"),
        default="mock",
        help=(
            "Use 'local-model' to generate candidate high-level actions with "
            "the A100-backed fine-tuned model."
        ),
    )
    parser.add_argument(
        "--adapter",
        default=None,
        help="LoRA adapter or full model path for --action-provider local-model.",
    )
    parser.add_argument("--base-model", default=None)
    parser.add_argument("--device-map", default="auto")
    parser.add_argument("--torch-dtype", default="float16")
    parser.add_argument("--action-max-new-tokens", type=int, default=500)
    parser.add_argument("--action-temperature", type=float, default=0.6)
    parser.add_argument("--action-top-p", type=float, default=0.9)
    parser.add_argument(
        "--command-agent",
        choices=("mock", "openai", "deepseek"),
        default="mock",
        help="Use mock templates, OpenAI API, or DeepSeek API for command-plan generation.",
    )
    parser.add_argument("--openai-model", default="gpt-5.5")
    parser.add_argument("--openai-api-key-env", default="OPENAI_API_KEY")
    parser.add_argument("--openai-base-url", default="https://api.openai.com/v1")
    parser.add_argument("--openai-timeout-seconds", type=int, default=120)
    parser.add_argument("--deepseek-model", default="deepseek-v4-pro")
    parser.add_argument("--deepseek-api-key-env", default="DEEPSEEK_API_KEY")
    parser.add_argument("--deepseek-base-url", default="https://api.deepseek.com")
    parser.add_argument("--deepseek-timeout-seconds", type=int, default=120)
    parser.add_argument("--deepseek-max-tokens", type=int, default=4096)
    parser.add_argument("--system", default=None, help="Inline System text override.")
    parser.add_argument("--logs", default=None, help="Inline Logs text override.")
    parser.add_argument("--incident", default=None, help="Inline Incident text override.")
    parser.add_argument("--system-file", default=None, help="Path to a file containing the System section.")
    parser.add_argument("--logs-file", default=None, help="Path to a file containing the Logs section.")
    parser.add_argument("--incident-file", default=None, help="Path to a file containing the Incident section.")
    parser.add_argument(
        "--dt-context-file",
        default=None,
        help="Path to a file containing digital-twin command-generation context.",
    )
    parser.add_argument("--wait-seconds", type=int, default=15)
    parser.add_argument("--rebuild-images", action="store_true")
    parser.add_argument(
        "--artifacts-dir",
        default=str(ROOT / "artifacts" / "recovery_loop"),
    )
    args = parser.parse_args()
    server_ip = args.server_ip or TARGET_SERVER_IPS[args.server]

    context = {
        "System": read_text_arg(args.system, args.system_file, DEFAULT_SYSTEM),
        "Logs": read_text_arg(args.logs, args.logs_file, DEFAULT_LOGS),
        "Incident": read_text_arg(args.incident, args.incident_file, DEFAULT_INCIDENT),
        "TargetServer": f"{args.server} / {server_ip}",
    }
    dt_context = (
        Path(args.dt_context_file).expanduser().read_text(encoding="utf-8").strip()
        if args.dt_context_file
        else ""
    )

    if args.action_provider == "local-model":
        if not args.adapter:
            raise SystemExit("--adapter is required with --action-provider local-model")
        action_provider = LocalModelActionProvider(
            adapter_path=args.adapter,
            base_model=args.base_model,
            context=context,
            device_map=args.device_map,
            torch_dtype=args.torch_dtype,
            max_new_tokens=args.action_max_new_tokens,
            temperature=args.action_temperature,
            top_p=args.action_top_p,
        )
    else:
        action_provider = MockServerSSHActionProvider()

    if args.command_agent == "openai":
        command_agent = OpenAICommandAgent(
            model=args.openai_model,
            api_key_env=args.openai_api_key_env,
            base_url=args.openai_base_url,
            timeout_seconds=args.openai_timeout_seconds,
        )
    elif args.command_agent == "deepseek":
        command_agent = DeepSeekCommandAgent(
            model=args.deepseek_model,
            api_key_env=args.deepseek_api_key_env,
            base_url=args.deepseek_base_url,
            timeout_seconds=args.deepseek_timeout_seconds,
            max_tokens=args.deepseek_max_tokens,
        )
    else:
        command_agent = MockCommandAgent()

    executor = RecoveryExecutor()
    verifier = make_state_verifier(
        server=args.server,
        server_ip=server_ip,
        attacker_ip=args.attacker_ip,
    )
    baseline = BaselineManager(
        project_root=ROOT,
        executor=executor,
        verifier=verifier,
        wait_seconds=args.wait_seconds,
        rebuild_images=args.rebuild_images,
    )
    orchestrator = RecoveryLoopOrchestrator(
        context=context,
        config=RecoveryLoopConfig(
            server=args.server,
            server_ip=server_ip,
            attacker_ip=args.attacker_ip,
            num_candidates=args.num_candidates,
            num_rollouts=args.num_rollouts,
            max_plan_steps=args.max_plan_steps,
            max_rollout_depth=args.max_rollout_depth,
        ),
        command_agent=command_agent,
        action_provider=action_provider,
        safety=CommandSafetyValidator(),
        executor=executor,
        verifier=verifier,
        baseline_manager=baseline,
        plan_store=PlanStore(args.artifacts_dir),
        dt_context=dt_context,
    )
    selected = orchestrator.run()
    print(f"Selected {len(selected)} actions. Artifacts: {orchestrator.plan_store.run_dir}")
    for item in selected:
        print(
            f"step={item.step} action={item.high_level_action.action} "
            f"rollout_total_time_seconds={item.rollout_total_time_seconds:.3f} "
            f"state_after={item.state_after}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
