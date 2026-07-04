from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer


DEFAULT_CHECKPOINT = "/home/yu3194924316/llm-recovery-dt/models/checkpoint-850"
DEFAULT_SELECTED_PLANS_DIR = (
    "/home/yu3194924316/llm-recovery-dt/llm_ir_dt_new/artifacts/"
    "recovery_loop/runs/20260531_035253/selected_plans"
)

RECOVERY_STATE_FIELDS = [
    "is_attack_contained",
    "is_knowledge_sufficient",
    "are_forensics_preserved",
    "is_eradicated",
    "is_hardened",
    "is_recovered",
]

SERVER_MAP = {
    "server_ssh": "10.0.2.11",
    "server_samba": "10.0.2.12",
    "server_shellshock": "10.0.2.13",
    "server_web1": "10.0.2.14",
    "server_web2": "10.0.2.15",
}

INITIAL_UNRECOVERED = {"server_ssh", "server_samba", "server_shellshock"}

STATE_PROMPT_TEMPLATE = (
    "Below is a system description, a sequence of network logs (e.g., from an intrusion detection system), "
    "a description of a cybersecurity incident, the current state of the recovery from the incident, "
    "a proposed recovery action, and an instruction that describes a task.\n"
    "Write a response that appropriately completes the request.\nBefore generating the response, "
    "think carefully about the system, the logs, and the instruction, then create a step-by-step "
    "chain of thoughts to ensure a logical and accurate response.\n\n"
    "### System:\n{}\n\n"
    "### Logs:\n{}\n\n"
    "### Incident:\n{}\n\n"
    "### Target server:\n{}\n\n"
    "### State:\n{}\n"
    "The meaning of the state fields are as follows.\n"
    "is_attack_contained: Has the immediate threat been stopped from spreading?\n"
    "is_knowledge_sufficient: Have we gathered enough data to effectively contain and eradicate the attack?\n"
    "are_forensics_preserved: Has evidence been captured and stored in a forensically sound manner?\n"
    "is_eradicated: Is the adversary completely removed from the system?\n"
    "is_hardened: Has the root cause of the attack been remediated? i.e., are future attacks of the same "
    "type prevented?\n"
    "is_recovered: Are primary services restored for users?\n\n"
    "### Recovery action:\n{}\n\n"
    "### Instruction:\n"
    "You are a security operator with advanced knowledge in cybersecurity "
    "and IT systems.\nYou have been given information about a security incident, the state of recovery from "
    "the incident, "
    "and a recovery action.\nYour task is to predict what the next state of the recovery will be after applying "
    "the recovery action to the target server.\n"
    "For example, if the given recovery action effectively contains the attack and 'is_attack_contained' is "
    "'false' in the "
    "current state, then the next state should have 'is_attack_contained' set to 'true'.\nSimilarly, if "
    "'is_recovered' is 'false' "
    "in the current state and the given recovery action effectively recovers operational services of the system,"
    " then the next state "
    "should have 'is_recovered' set to 'true', etc.\nIt is also possible that multiple state properties change "
    "values from false to true. "
    "It is also possible that the state remains the same, i.e., no property changes.\nIt is important that the "
    "state only changes if the "
    "action is effective in achieving one of the recovery goals for the target server: containment, information "
    "gathering, preserving evidence, eradication, hardening, or recovery.\n"
    "Actions that only repair unrelated systems should not change the target server's recovery state.\n"
    "A state variable can only change from 'false' to 'true', it cannot be changed from "
    "'true' to 'false'.\n"
    "Return a JSON object that defines the next state and contains the Boolean fields 'is_attack_contained', "
    "'is_knowledge_sufficient', 'are_forensics_preserved', 'is_eradicated', 'is_hardened', 'is_recovered'.\n\n"
    "### Response:\n<think>"
)

ALL_SERVERS_STATE_PROMPT_TEMPLATE = (
    "Below is a system description, a sequence of network logs (e.g., from an intrusion detection system), "
    "a description of a cybersecurity incident, the current recovery state for each server, "
    "a proposed recovery action, and an instruction that describes a task.\n"
    "Write a response that appropriately completes the request.\nBefore generating the response, "
    "think carefully about the system, the logs, and the instruction, then create a step-by-step "
    "chain of thoughts to ensure a logical and accurate response.\n\n"
    "### System:\n{}\n\n"
    "### Logs:\n{}\n\n"
    "### Incident:\n{}\n\n"
    "### Server recovery states:\n{}\n"
    "The meaning of the state fields are as follows.\n"
    "is_attack_contained: Has the immediate threat been stopped from spreading?\n"
    "is_knowledge_sufficient: Have we gathered enough data to effectively contain and eradicate the attack?\n"
    "are_forensics_preserved: Has evidence been captured and stored in a forensically sound manner?\n"
    "is_eradicated: Is the adversary completely removed from the system?\n"
    "is_hardened: Has the root cause of the attack been remediated? i.e., are future attacks of the same "
    "type prevented?\n"
    "is_recovered: Are primary services restored for users?\n\n"
    "### Recovery action:\n{}\n\n"
    "### Instruction:\n"
    "You are a security operator with advanced knowledge in cybersecurity and IT systems.\n"
    "You have been given information about a security incident, the per-server state of recovery from the "
    "incident, and a recovery action.\n"
    "Your task is to predict the next recovery state for every listed server after applying the recovery "
    "action.\n"
    "For each server, only change a state field from 'false' to 'true' if the recovery action is effective "
    "for that specific server in achieving one of the recovery goals: containment, information gathering, "
    "preserving evidence, eradication, hardening, or recovery.\n"
    "Actions that repair server_ssh should not automatically change server_samba, server_shellshock, "
    "server_web1, or server_web2 unless the action explicitly and effectively addresses those servers too.\n"
    "It is possible that multiple state properties change values from false to true. It is also possible "
    "that a server's state remains the same, i.e., no property changes.\n"
    "A state variable can only change from 'false' to 'true', it cannot be changed from 'true' to 'false'.\n"
    "Even if the recovery action mainly targets one server, you must still return the next state for all "
    "five listed servers, grouped by server name.\n"
    "Return a JSON object with one property per server: 'server_ssh', 'server_samba', "
    "'server_shellshock', 'server_web1', and 'server_web2'. Each server property must contain the Boolean "
    "fields 'is_attack_contained', 'is_knowledge_sufficient', 'are_forensics_preserved', 'is_eradicated', "
    "'is_hardened', and 'is_recovered'.\n\n"
    "### Response:\n<think>"
)


def load_text(path: str) -> str:
    return Path(path).read_text(encoding="utf-8").strip()


def initial_state(is_recovered: bool) -> dict[str, bool]:
    return {field: bool(is_recovered) for field in RECOVERY_STATE_FIELDS}


def load_selected_actions(selected_plans_dir: str) -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = []
    for path in sorted(Path(selected_plans_dir).glob("step_*.json")):
        obj = json.loads(path.read_text(encoding="utf-8"))
        plan = obj.get("plan", {})
        action = str(plan.get("high_level_action", "")).strip()
        explanation = str(plan.get("high_level_action_explanation", "")).strip()
        if action:
            actions.append(
                {
                    "step": obj.get("step"),
                    "source_file": str(path),
                    "action": action,
                    "explanation": explanation,
                }
            )
    return actions


def load_model_and_tokenizer(
    checkpoint_path: str,
    dtype: torch.dtype,
) -> tuple[AutoTokenizer, AutoModelForCausalLM]:
    adapter_config_path = Path(checkpoint_path) / "adapter_config.json"
    if adapter_config_path.exists():
        adapter_meta = json.loads(adapter_config_path.read_text(encoding="utf-8"))
        base_model_name = str(adapter_meta["base_model_name_or_path"])
        tokenizer = AutoTokenizer.from_pretrained(base_model_name, use_fast=True)
        base_model = AutoModelForCausalLM.from_pretrained(
            base_model_name,
            device_map="auto",
            torch_dtype=dtype,
        )
        model = PeftModel.from_pretrained(base_model, checkpoint_path)
    else:
        tokenizer = AutoTokenizer.from_pretrained(checkpoint_path, use_fast=True)
        model = AutoModelForCausalLM.from_pretrained(
            checkpoint_path,
            device_map="auto",
            torch_dtype=dtype,
        )

    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    model.eval()
    return tokenizer, model


def build_prompt(
    *,
    system_text: str,
    logs_text: str,
    incident_text: str,
    server_name: str,
    server_ip: str,
    state: dict[str, bool],
    action: str,
) -> str:
    target = f"{server_name} ({server_ip})"
    state_text = json.dumps(
        {field: bool(state.get(field, False)) for field in RECOVERY_STATE_FIELDS},
        indent=2,
        ensure_ascii=True,
    )
    return STATE_PROMPT_TEMPLATE.format(
        system_text,
        logs_text,
        incident_text,
        target,
        state_text,
        action.strip(),
    ).rstrip()


def build_all_servers_prompt(
    *,
    system_text: str,
    logs_text: str,
    incident_text: str,
    states: dict[str, dict[str, bool]],
    action: str,
    action_target_server: str,
) -> str:
    server_states = {
        server_name: {
            "ip": SERVER_MAP[server_name],
            "state": {
                field: bool(states[server_name].get(field, False))
                for field in RECOVERY_STATE_FIELDS
            },
        }
        for server_name in SERVER_MAP
    }
    states_text = json.dumps(server_states, indent=2, ensure_ascii=True)
    return ALL_SERVERS_STATE_PROMPT_TEMPLATE.format(
        system_text,
        logs_text,
        incident_text,
        states_text,
        (
            f"{action.strip()}\n\n"
            f"Action target server: {action_target_server} "
            f"({SERVER_MAP[action_target_server]})."
        ),
    ).rstrip()


def generate_once(
    *,
    model: AutoModelForCausalLM,
    tokenizer: AutoTokenizer,
    prompt: str,
    max_new_tokens: int,
    temperature: float,
    top_p: float,
) -> str:
    inputs = tokenizer(prompt, return_tensors="pt")
    inputs = {key: value.to(model.device) for key, value in inputs.items()}
    do_sample = temperature > 0.0

    with torch.no_grad():
        output_ids = model.generate(
            **inputs,
            max_new_tokens=max_new_tokens,
            do_sample=do_sample,
            temperature=temperature if do_sample else None,
            top_p=top_p if do_sample else None,
            pad_token_id=tokenizer.pad_token_id,
            eos_token_id=tokenizer.eos_token_id,
        )

    decoded = tokenizer.decode(output_ids[0], skip_special_tokens=True)
    if decoded.startswith(prompt):
        decoded = decoded[len(prompt):]
    return decoded.strip()


def extract_json_object(text: str) -> dict[str, Any] | None:
    decoder = json.JSONDecoder()
    for match in re.finditer(r"\{", text):
        try:
            obj, _ = decoder.raw_decode(text[match.start():])
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            return obj
    return None


def omit_logs_section(prompt: str, logs_text: str) -> str:
    placeholder = (
        "[LOGS OMITTED FROM PRINTED PROMPT: "
        f"{len(logs_text)} characters, {len(logs_text.splitlines())} lines]"
    )
    return prompt.replace(
        f"### Logs:\n{logs_text}\n\n",
        f"### Logs:\n{placeholder}\n\n",
    )


def normalize_next_state(
    current_state: dict[str, bool],
    predicted: dict[str, Any] | None,
) -> dict[str, bool]:
    next_state: dict[str, bool] = {}
    for field in RECOVERY_STATE_FIELDS:
        current_value = bool(current_state.get(field, False))
        predicted_value = bool(predicted.get(field, current_value)) if predicted else current_value
        next_state[field] = current_value or predicted_value
    return next_state


def _predicted_state_for_server(
    predicted: dict[str, Any] | None,
    server_name: str,
) -> dict[str, Any] | None:
    if not isinstance(predicted, dict):
        return None
    candidates = [
        predicted.get(server_name),
        predicted.get(SERVER_MAP[server_name]),
    ]
    for wrapper_key in ("servers", "Servers", "states", "States", "next_state", "Next state"):
        wrapped = predicted.get(wrapper_key)
        if isinstance(wrapped, dict):
            candidates.extend([wrapped.get(server_name), wrapped.get(SERVER_MAP[server_name])])
    for candidate in candidates:
        if isinstance(candidate, dict):
            if isinstance(candidate.get("state"), dict):
                return candidate["state"]
            return candidate
    transposed = {}
    for field in RECOVERY_STATE_FIELDS:
        field_value = predicted.get(field)
        if isinstance(field_value, dict) and server_name in field_value:
            transposed[field] = field_value[server_name]
    if transposed:
        return transposed
    return None


def _is_flat_state_object(predicted: dict[str, Any] | None) -> bool:
    if not isinstance(predicted, dict):
        return False
    return any(field in predicted for field in RECOVERY_STATE_FIELDS)


def normalize_all_server_next_states(
    current_states: dict[str, dict[str, bool]],
    predicted: dict[str, Any] | None,
    action_target_server: str,
) -> dict[str, dict[str, bool]]:
    if _is_flat_state_object(predicted):
        return {
            server_name: normalize_next_state(
                current_states[server_name],
                predicted if server_name == action_target_server else None,
            )
            for server_name in SERVER_MAP
        }
    return {
        server_name: normalize_next_state(
            current_states[server_name],
            _predicted_state_for_server(predicted, server_name),
        )
        for server_name in SERVER_MAP
    }


def run_all_servers_per_action(
    *,
    args: argparse.Namespace,
    system_text: str,
    logs_text: str,
    incident_text: str,
    actions: list[dict[str, Any]],
    tokenizer: AutoTokenizer | None,
    model: AutoModelForCausalLM | None,
) -> dict[str, Any]:
    initial_states = {
        name: initial_state(name not in INITIAL_UNRECOVERED)
        for name in SERVER_MAP
    }
    states = {name: dict(state) for name, state in initial_states.items()}
    transitions = []

    for action_item in actions:
        prompt = build_all_servers_prompt(
            system_text=system_text,
            logs_text=logs_text,
            incident_text=incident_text,
            states=states,
            action=action_item["action"],
            action_target_server=args.action_target_server,
        )
        if args.print_prompts:
            print(f"\n===== PROMPT all_servers step={action_item['step']} =====")
            if args.omit_logs_when_printing:
                print(omit_logs_section(prompt, logs_text))
            else:
                print(prompt)
            print(f"===== END PROMPT all_servers step={action_item['step']} =====\n")
            if args.print_prompts_only:
                transitions.append(
                    {
                        "step": action_item["step"],
                        "action": action_item["action"],
                        "states_before": states,
                        "raw_output": None,
                        "parsed_state": None,
                        "states_after": states,
                    }
                )
                continue

        if model is None or tokenizer is None:
            raise RuntimeError("Model was not loaded.")
        raw_output = generate_once(
            model=model,
            tokenizer=tokenizer,
            prompt=prompt,
            max_new_tokens=args.max_new_tokens,
            temperature=args.temperature,
            top_p=args.top_p,
        )
        parsed = extract_json_object(raw_output)
        next_states = normalize_all_server_next_states(
            states,
            parsed,
            args.action_target_server,
        )
        transitions.append(
            {
                "step": action_item["step"],
                "action": action_item["action"],
                "states_before": states,
                "raw_output": raw_output,
                "parsed_state": parsed,
                "states_after": next_states,
            }
        )
        states = next_states

    server_results = {
        server_name: {
            "server_ip": SERVER_MAP[server_name],
            "initial_state": initial_states[server_name],
            "final_state": states[server_name],
        }
        for server_name in SERVER_MAP
    }
    return {
        "mode": "all_servers_per_action",
        "checkpoint": args.checkpoint,
        "system_file": args.system_file,
        "logs_file": args.logs_file,
        "incident_file": args.incident_file,
        "selected_plans_dir": args.selected_plans_dir,
        "actions": actions,
        "action_transitions": transitions,
        "servers": server_results,
    }


def run_predictions(args: argparse.Namespace) -> dict[str, Any]:
    system_text = load_text(args.system_file)
    logs_text = load_text(args.logs_file)
    incident_text = load_text(args.incident_file)
    actions = load_selected_actions(args.selected_plans_dir)

    tokenizer = None
    model = None
    if not args.print_prompts_only:
        dtype = getattr(torch, args.dtype)
        tokenizer, model = load_model_and_tokenizer(args.checkpoint, dtype)

    runs = []
    for run_idx in range(1, args.num_runs + 1):
        run_result = run_single_prediction(
            args=args,
            system_text=system_text,
            logs_text=logs_text,
            incident_text=incident_text,
            actions=actions,
            tokenizer=tokenizer,
            model=model,
            run_idx=run_idx,
        )
        runs.append(run_result)

    if args.num_runs == 1:
        return runs[0]

    target_success_count = 0
    target_field_counts = {field: 0 for field in RECOVERY_STATE_FIELDS}
    for run_result in runs:
        target_state = run_result["servers"][args.action_target_server]["final_state"]
        if all(bool(target_state.get(field, False)) for field in RECOVERY_STATE_FIELDS):
            target_success_count += 1
        for field in RECOVERY_STATE_FIELDS:
            if bool(target_state.get(field, False)):
                target_field_counts[field] += 1

    return {
        "mode": "multi_run",
        "num_runs": args.num_runs,
        "checkpoint": args.checkpoint,
        "system_file": args.system_file,
        "logs_file": args.logs_file,
        "incident_file": args.incident_file,
        "selected_plans_dir": args.selected_plans_dir,
        "action_target_server": args.action_target_server,
        "target_terminal_count": target_success_count,
        "target_terminal_ratio": target_success_count / args.num_runs,
        "target_field_counts": target_field_counts,
        "target_field_ratios": {
            field: count / args.num_runs for field, count in target_field_counts.items()
        },
        "runs": runs,
    }


def run_single_prediction(
    *,
    args: argparse.Namespace,
    system_text: str,
    logs_text: str,
    incident_text: str,
    actions: list[dict[str, Any]],
    tokenizer: AutoTokenizer | None,
    model: AutoModelForCausalLM | None,
    run_idx: int,
) -> dict[str, Any]:
    if args.all_servers_per_action:
        result = run_all_servers_per_action(
            args=args,
            system_text=system_text,
            logs_text=logs_text,
            incident_text=incident_text,
            actions=actions,
            tokenizer=tokenizer,
            model=model,
        )
        result["run"] = run_idx
        return result

    server_states = {
        name: initial_state(name not in INITIAL_UNRECOVERED)
        for name in SERVER_MAP
    }
    server_results: dict[str, Any] = {}

    for server_name, server_ip in SERVER_MAP.items():
        state = dict(server_states[server_name])
        transitions = []
        for action_item in actions:
            prompt = build_prompt(
                system_text=system_text,
                logs_text=logs_text,
                incident_text=incident_text,
                server_name=server_name,
                server_ip=server_ip,
                state=state,
                action=action_item["action"],
            )
            if args.print_prompts:
                print(f"\n===== PROMPT server={server_name} step={action_item['step']} =====")
                if args.omit_logs_when_printing:
                    print(omit_logs_section(prompt, logs_text))
                else:
                    print(prompt)
                print(f"===== END PROMPT server={server_name} step={action_item['step']} =====\n")
                if args.print_prompts_only:
                    next_state = state
                    transitions.append(
                        {
                            "step": action_item["step"],
                            "action": action_item["action"],
                            "state_before": state,
                            "raw_output": None,
                            "parsed_state": None,
                            "state_after": next_state,
                        }
                    )
                    state = next_state
                    continue
            if model is None or tokenizer is None:
                raise RuntimeError("Model was not loaded.")
            raw_output = generate_once(
                model=model,
                tokenizer=tokenizer,
                prompt=prompt,
                max_new_tokens=args.max_new_tokens,
                temperature=args.temperature,
                top_p=args.top_p,
            )
            parsed = extract_json_object(raw_output)
            next_state = normalize_next_state(state, parsed)
            transitions.append(
                {
                    "step": action_item["step"],
                    "action": action_item["action"],
                    "state_before": state,
                    "raw_output": raw_output,
                    "parsed_state": parsed,
                    "state_after": next_state,
                }
            )
            state = next_state
        server_results[server_name] = {
            "server_ip": server_ip,
            "initial_state": server_states[server_name],
            "final_state": state,
            "transitions": transitions,
        }

    return {
        "run": run_idx,
        "mode": "one_server_per_action",
        "checkpoint": args.checkpoint,
        "system_file": args.system_file,
        "logs_file": args.logs_file,
        "incident_file": args.incident_file,
        "selected_plans_dir": args.selected_plans_dir,
        "actions": actions,
        "servers": server_results,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Predict per-server six-state recovery transitions after applying "
            "selected high-level recovery actions."
        )
    )
    parser.add_argument("--checkpoint", default=DEFAULT_CHECKPOINT)
    parser.add_argument("--system-file", required=True)
    parser.add_argument("--logs-file", required=True)
    parser.add_argument("--incident-file", required=True)
    parser.add_argument("--selected-plans-dir", default=DEFAULT_SELECTED_PLANS_DIR)
    parser.add_argument("--output-json")
    parser.add_argument("--max-new-tokens", type=int, default=1200)
    parser.add_argument("--num-runs", type=int, default=1)
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--top-p", type=float, default=0.9)
    parser.add_argument(
        "--all-servers-per-action",
        action="store_true",
        help="Predict all server states in one model call per recovery action.",
    )
    parser.add_argument(
        "--action-target-server",
        choices=sorted(SERVER_MAP),
        default="server_ssh",
        help="Server that the selected high-level recovery actions are intended to recover.",
    )
    parser.add_argument(
        "--print-prompts",
        action="store_true",
        help="Print the full prompt for every server/action prediction.",
    )
    parser.add_argument(
        "--print-prompts-only",
        action="store_true",
        help="Print prompts and skip model generation.",
    )
    parser.add_argument(
        "--omit-logs-when-printing",
        action="store_true",
        help="When printing prompts, replace the Logs body with a short placeholder.",
    )
    parser.add_argument(
        "--dtype",
        choices=["float16", "bfloat16", "float32"],
        default="float16",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.print_prompts_only:
        args.print_prompts = True
    result = run_predictions(args)

    if args.num_runs == 1:
        summary = {
            server_name: server_result["final_state"]
            for server_name, server_result in result["servers"].items()
        }
    else:
        summary = {
            "num_runs": result["num_runs"],
            "action_target_server": result["action_target_server"],
            "target_terminal_count": result["target_terminal_count"],
            "target_terminal_ratio": result["target_terminal_ratio"],
            "target_field_counts": result["target_field_counts"],
            "target_field_ratios": result["target_field_ratios"],
            "final_states": [
                {
                    "run": run_result["run"],
                    args.action_target_server: run_result["servers"][args.action_target_server][
                        "final_state"
                    ],
                }
                for run_result in result["runs"]
            ],
        }
    print(json.dumps(summary, indent=2, ensure_ascii=False))

    if args.output_json:
        Path(args.output_json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output_json).write_text(
            json.dumps(result, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        print(f"Saved detailed results to {args.output_json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
