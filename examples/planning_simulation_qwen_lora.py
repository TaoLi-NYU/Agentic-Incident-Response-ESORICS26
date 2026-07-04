import argparse
import json
import random
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

import torch
from peft import PeftConfig, PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer

from llm_recovery.decision_transformer.planner import (
    IncidentResponsePlanner,
    PlannerConfig,
    RECOVERY_STATE_FIELDS,
    TERMINAL_STATE,
)


ACTION_PROMPT_TEMPLATE = (
    "Below is a system description, a sequence of network logs (e.g., from an intrusion detection system), "
    "a description of a cybersecurity incident, the current state of the recovery from the incident, "
    "a list of previously executed recovery actions, "
    "and an instruction that describes a task.\n"
    "Write a response that appropriately completes the request.\nBefore generating the response, "
    "think carefully about the system, the logs, and the instruction, then create a step-by-step "
    "chain of thoughts to ensure a logical and accurate response.\n\n"
    "### System:\n{}\n\n"
    "### Logs:\n{}\n\n"
    "### Incident:\n{}\n\n"
    "### State:\n{}\n"
    "The meaning of the state fields are as follows.\n"
    "is_attack_contained: Has the immediate threat been stopped from spreading?\n"
    "is_knowledge_sufficient: Have we gathered enough data to effectively contain and eradicate the attack?\n"
    "are_forensics_preserved: Has evidence been captured and stored in a forensically sound manner?\n"
    "is_eradicated: Is the adversary completely removed from the system?\n"
    "is_hardened: Has the root cause of the attack been remediated? i.e., are future attacks of the same "
    "type prevented?\n"
    "is_recovered: Are primary services restored for users?\n\n"
    "### Previous recovery actions:\n{}\n\n"
    "### Instruction:\n"
    "You are a security operator with advanced knowledge in cybersecurity "
    "and IT systems. You have been given information about a security incident and should"
    " generate the next suitable action for recovering the system from the incident. "
    "Your suggested action should be based on the logs, the system description only, the current state, and the "
    "previous recovery actions.\n"
    "Make sure that the suggested recovery action is consistent with the system description and the logs and that "
    "you do not repeat any action that has already been performed.\n"
    "The goal when selecting the recovery action is to change the state so that one of the state-properties that "
    "is currently 'false' "
    "becomes 'true'. The ideal recovery action sequence is: 1. contain the attack 2. gather information 3. "
    "preserve evidence "
    "4. eradicate the attacker 5. harden the system 6. recover operational services.\n"
    "When selecting the recovery action, make sure that it is concrete and actionable and minimizes unnecessary "
    "service disruptions. "
    "Vague or unnecessary actions will not change the state and should be avoided.\n"
    "Return a JSON object with two properties: 'Action' and 'Explanation', both of which should be strings.\n"
    "The property 'Action' should be a string that concisely describes the concrete recovery action.\n"
    "The property 'Explanation' should be a string that concisely explains why you selected the recovery action "
    "and motivates why the action is needed.\n\n"
    "### Response:\n<think>"
)

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
    "the recovery action.\n"
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
    "action is effective in achieving one of the recovery goals: containment, information gathering, preserving "
    "evidence, eradication, "
    "hardening, or recovery.\nA state variable can only change from 'false' to 'true', it cannot be changed from "
    "'true' to 'false'.\n"
    "Return a JSON object that defines the next state and contains the Boolean fields 'is_attack_contained', "
    "'is_knowledge_sufficient', 'are_forensics_preserved', 'is_eradicated', 'is_hardened', 'is_recovered'.\n\n"
    "### Response:\n<think>"
)

CLASSIFICATION_PROMPT_TEMPLATE = (
    "Below is a system description and an instruction that describes a task. "
    "Write a response that appropriately completes the request. "
    "Before generating the response, think carefully about the system and the instruction "
    "to ensure a logical and accurate response.\n\n"
    "### System:\n{}\n\n"
    "### Instruction:\n"
    "Generate fields produced by an intrusion detection system (e.g., Snort) during a cyberattack by an attacker "
    "following this MITRE ATT&CK tactic: {}.\n\n"
    "### Response:\n<think>"
)

def _format_state_json(state: Sequence[bool]) -> str:
    return json.dumps(
        {field: bool(state[i]) for i, field in enumerate(RECOVERY_STATE_FIELDS)},
        ensure_ascii=True,
    )


def build_action_prompt(
    context: Dict[str, str],
    state: Sequence[bool],
    previous_actions: Sequence[str],
) -> str:
    state_json = _format_state_json(state)
    if previous_actions:
        prev_actions = "\n".join(f"- {a}" for a in previous_actions).strip()
    else:
        prev_actions = "None."
    return ACTION_PROMPT_TEMPLATE.format(
        context.get("System", "").strip(),
        context.get("Logs", "").strip(),
        context.get("Incident", "").strip(),
        state_json,
        prev_actions,
    ).rstrip()


def build_state_prompt(
    context: Dict[str, str],
    state: Sequence[bool],
    action: str,
) -> str:
    state_json = _format_state_json(state)
    return STATE_PROMPT_TEMPLATE.format(
        context.get("System", "").strip(),
        context.get("Logs", "").strip(),
        context.get("Incident", "").strip(),
        state_json,
        action.strip(),
    ).rstrip()


def build_classification_prompt(system: str, tactic: str) -> str:
    return CLASSIFICATION_PROMPT_TEMPLATE.format(system.strip(), tactic).rstrip()


def _extract_unique_pairs(text: str) -> List[Tuple[str, str]]:
    import re

    pairs = re.findall(
        r"\[Classification:\s*([^\]]+)\]\s*\[Priority:\s*([^\]]+)\]",
        text,
        flags=re.IGNORECASE,
    )
    seen: set[Tuple[str, str]] = set()
    unique_pairs: List[Tuple[str, str]] = []
    for cls, pri in pairs:
        pair = (cls.strip(), pri.strip())
        if pair not in seen:
            seen.add(pair)
            unique_pairs.append(pair)
    return unique_pairs


def _normalize_classification(text: str) -> str:
    import re

    normalized = re.sub(r"[^a-z0-9]+", " ", text.lower())
    normalized = re.sub(r"\s+", " ", normalized).strip()
    return normalized


def _compute_precision_recall_unique_pairs(
    pred_text: str, label_text: str
) -> Tuple[float, float]:
    pred_pairs = _extract_unique_pairs(pred_text)
    label_pairs = _extract_unique_pairs(label_text)

    pred_set = {
        (_normalize_classification(cls), pri)
        for cls, pri in pred_pairs
        if _normalize_classification(cls)
    }
    label_set = {
        (_normalize_classification(cls), pri)
        for cls, pri in label_pairs
        if _normalize_classification(cls)
    }

    if not pred_set or not label_set:
        return 0.0, 0.0
    overlap = len(pred_set & label_set)
    precision = overlap / len(pred_set) if pred_set else 0.0
    recall = overlap / len(label_set) if label_set else 0.0
    return precision, recall


 


def _start_label_object() -> Dict[str, object]:
    return {
        "System": "",
        "Logs": [],
        "Incident": "",
        "Incident description": "",
        "Recovery actions": [],
    }


def _normalize_label_key(key: str) -> str:
    if key == "system":
        return "System"
    return key


def _parse_labels_file(path: str) -> List[Dict[str, object]]:
    lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    objects: List[Dict[str, object]] = []
    cur: Optional[Dict[str, object]] = None

    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        if stripped.startswith("{"):
            cur = _start_label_object()
            i += 1
            continue
        if stripped.startswith("}"):
            if cur is not None:
                objects.append(cur)
            cur = None
            i += 1
            continue
        if cur is None:
            i += 1
            continue

        if stripped.startswith('"') and ":" in stripped:
            key_part, rest = stripped.split(":", 1)
            key = _normalize_label_key(key_part.strip().strip('"'))
            rest = rest.strip()

            if key == "Logs":
                if "[" in rest:
                    i += 1
                    while i < len(lines):
                        item_line = lines[i].strip()
                        if item_line.startswith("]"):
                            break
                        if item_line.startswith('"'):
                            item = item_line.rstrip(",")
                            if item.startswith('"') and item.endswith('"'):
                                item = item[1:-1]
                            cur["Logs"].append(item)
                        i += 1
                    i += 1
                    continue

            if key == "Recovery actions":
                if rest.startswith("[]"):
                    cur["Recovery actions"] = []
                    i += 1
                    continue
                if rest.startswith("["):
                    i += 1
                    while i < len(lines):
                        item_line = lines[i].strip()
                        if item_line.startswith("]"):
                            break
                        if item_line.startswith('"'):
                            item = item_line.rstrip(",")
                            if item.startswith('"') and item.endswith('"'):
                                item = item[1:-1]
                            cur["Recovery actions"].append(item)
                        i += 1
                    i += 1
                    continue

            if rest.startswith('"'):
                if rest.count('"') >= 2 and rest.endswith('"'):
                    value = rest.rstrip(",")[1:-1]
                    cur[key] = value
                    i += 1
                    continue
                buf = [rest.lstrip('"')]
                i += 1
                while i < len(lines):
                    next_line = lines[i]
                    if next_line.strip().startswith('"') and ":" in next_line:
                        i -= 1
                        break
                    buf.append(next_line)
                    if next_line.rstrip().endswith('"'):
                        break
                    i += 1
                value = "\n".join(buf).rstrip(",")
                if value.endswith('"'):
                    value = value[:-1]
                cur[key] = value
                i += 1
                continue

        i += 1

    return objects


def build_planner(
    adapter_path: str,
    base_model: Optional[str],
    device_map: str,
    torch_dtype: str,
    config: PlannerConfig,
    context: Dict[str, str],
) -> Tuple[IncidentResponsePlanner, List[str]]:
    peft_cfg = PeftConfig.from_pretrained(adapter_path)
    base_name = base_model or peft_cfg.base_model_name_or_path
    dtype = getattr(torch, torch_dtype)

    tokenizer = AutoTokenizer.from_pretrained(base_name, use_fast=True)
    base = AutoModelForCausalLM.from_pretrained(
        base_name,
        device_map=device_map,
        torch_dtype=dtype,
    )
    model = PeftModel.from_pretrained(base, adapter_path)

    history: List[str] = []
    action_builder = lambda logs, state: build_action_prompt(
        context, state, history
    )
    state_builder = lambda logs, state, action: build_state_prompt(
        context, state, action
    )
    planner = IncidentResponsePlanner(
        model,
        tokenizer,
        config=config,
        action_prompt_builder=action_builder,
        state_prompt_builder=state_builder,
    )
    return planner, history


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Simulate the planning algorithm using a LoRA fine-tuned LLM."
    )
    parser.add_argument(
        "--adapter",
        required=False,
        default=None,
        help="Path to the LoRA adapter checkpoint directory.",
    )
    parser.add_argument(
        "--base-model",
        default=None,
        help="Base model name/path (optional; inferred from LoRA config if omitted).",
    )
    parser.add_argument(
        "--labels",
        default=None,
        help="Optional labels.json path; if provided, sample Incident=Yes from it.",
    )
    parser.add_argument(
        "--labels-seed",
        type=int,
        default=None,
        help="Random seed for labels.json sampling.",
    )
    parser.add_argument(
        "--labels-index",
        type=int,
        default=None,
        help="Optional index for Incident=Yes entries (overrides random sampling).",
    )
    parser.add_argument(
        "--print-selected-sample",
        action="store_true",
        help="Print selected System/Logs/Incident description and exit.",
    )
    parser.add_argument(
        "--tactic",
        default=None,
        help="Optional tactic label selected externally (e.g., from GPT).",
    )
    parser.add_argument(
        "--tactics",
        nargs="+",
        default=None,
        help="Optional list of tactics (space-separated). If set, AP is computed for each before planning.",
    )
    parser.add_argument(
        "--ap-threshold",
        type=float,
        default=0.7,
        help="AP threshold to continue planning when tactics are provided.",
    )
    parser.add_argument(
        "--ap-continue-on-fail",
        action="store_true",
        help="Continue planning even if no tactic meets the AP threshold.",
    )
    parser.add_argument("--cls-max-new-tokens", type=int, default=256)
    parser.add_argument("--cls-temperature", type=float, default=0.0)
    parser.add_argument("--cls-top-p", type=float, default=1.0)
    parser.add_argument("--num-candidates", type=int, default=3)
    parser.add_argument("--num-rollouts", type=int, default=3)
    parser.add_argument("--max-plan-steps", type=int, default=10)
    parser.add_argument("--max-rollout-depth", type=int, default=10)
    parser.add_argument("--max-new-tokens", type=int, default=500)
    parser.add_argument("--temperature", type=float, default=0.6)
    parser.add_argument("--top-p", type=float, default=0.9)
    parser.add_argument("--device-map", default="auto")
    parser.add_argument("--torch-dtype", default="float16")
    parser.add_argument(
        "--show-progress",
        action="store_true",
        help="Print per-step planning progress and rollout scores.",
    )
    parser.add_argument(
        "--show-rollout-progress",
        action="store_true",
        help="Print per-rollout progress for each candidate action.",
    )
    args = parser.parse_args()

    context = {}
    if args.labels:
        if args.labels_seed is not None:
            random.seed(args.labels_seed)
        labels = _parse_labels_file(args.labels)
        incident_yes = [
            obj
            for obj in labels
            if str(obj.get("Incident", "")).strip().lower() == "yes"
        ]
        if not incident_yes:
            raise SystemExit("No Incident=Yes entries found in labels.json")
        if args.labels_index is not None:
            idx = max(0, min(args.labels_index, len(incident_yes) - 1))
            sample = incident_yes[idx]
        else:
            sample = random.choice(incident_yes)
        context = {
            "System": str(sample.get("System", "")).strip(),
            "Logs": "\n".join(sample.get("Logs", [])).strip(),
            "Incident": str(sample.get("Incident description", "")).strip(),
        }
    if not context:
        raise SystemExit("No context provided. Pass --labels to supply input data.")
    if args.print_selected_sample:
        print("Selected sample (Incident=Yes):")
        print("\n### System:\n" + context.get("System", ""))
        print("\n### Logs:\n" + context.get("Logs", ""))
        print("\n### Incident description:\n" + context.get("Incident", ""))
        return
    if not args.adapter:
        raise SystemExit("--adapter is required unless --print-selected-sample is used.")

    config = PlannerConfig(
        num_candidates=args.num_candidates,
        num_rollout_samples=args.num_rollouts,
        max_plan_steps=args.max_plan_steps,
        max_rollout_depth=args.max_rollout_depth,
        action_max_new_tokens=args.max_new_tokens,
        state_max_new_tokens=args.max_new_tokens,
        candidate_temperature=args.temperature,
        candidate_top_p=args.top_p,
        rollout_temperature=args.temperature,
        rollout_top_p=args.top_p,
    )

    planner, history = build_planner(
        adapter_path=args.adapter,
        base_model=args.base_model,
        device_map=args.device_map,
        torch_dtype=args.torch_dtype,
        config=config,
        context=context,
    )

    if args.tactic and not args.tactics:
        args.tactics = [args.tactic]
    ap_failed = False
    if args.tactics:
        label_text = context.get("Logs", "")
        print("\n=== AP check (unique pairs) ===")
        passed = False
        for tactic in args.tactics:
            prompt = build_classification_prompt(context.get("System", ""), tactic)
            inputs = planner.tokenizer(prompt, return_tensors="pt")
            inputs = {k: v.to(planner.llm.device) for k, v in inputs.items()}
            with torch.no_grad():
                output_ids = planner.llm.generate(
                    **inputs,
                    max_new_tokens=args.cls_max_new_tokens,
                    do_sample=args.cls_temperature > 0.0,
                    temperature=args.cls_temperature,
                    top_p=args.cls_top_p,
                    pad_token_id=planner.tokenizer.pad_token_id,
                    eos_token_id=planner.tokenizer.eos_token_id,
                )
            pred = planner.tokenizer.decode(output_ids[0], skip_special_tokens=True)
            if pred.startswith(prompt):
                pred = pred[len(prompt) :]
            precision, recall = _compute_precision_recall_unique_pairs(pred, label_text)
            print(f"Tactic: {tactic}")
            print(f"  Average precision (unique pairs): {precision:.4f}")
            print(f"  Average recall (unique pairs): {recall:.4f}")
            if precision >= args.ap_threshold:
                passed = True
        if not passed:
            msg = (
                f"\nAP check failed (threshold={args.ap_threshold:.2f}). "
                "No tactic met the threshold."
            )
            if args.ap_continue_on_fail:
                print(msg + " Continuing planning anyway.")
            else:
                print(msg + " Planning will run one step and stop.")
                ap_failed = True

    state: Tuple[bool, ...] = tuple(False for _ in RECOVERY_STATE_FIELDS)
    plan: List[str] = []
    t = 0

    while state != TERMINAL_STATE and t < config.max_plan_steps:
        if args.show_progress:
            print(f"\n[Step {t+1}] Current state: {state}")
        actions = planner._sample_actions("", state, config.num_candidates)
        if not actions:
            break
        scores = []
        for idx_action, action in enumerate(actions, start=1):
            if args.show_rollout_progress:
                print(f"  Rollouts for candidate {idx_action}/{len(actions)}")
            samples = []
            for r in range(config.num_rollout_samples):
                if args.show_rollout_progress:
                    print(f"    rollout {r+1}/{config.num_rollout_samples}")
                samples.append(planner._recovery_time("", state, action, depth=0))
            score = float(sum(samples)) / float(len(samples))
            scores.append(score)
        best_idx = min(range(len(actions)), key=lambda i: scores[i])
        best_action = actions[best_idx]
        if args.show_progress:
            for i, (a, s) in enumerate(zip(actions, scores), start=1):
                print(f"  Candidate {i}: score={s:.3f} action={a}")
            print(f"  चुosen action: {best_action}")
        plan.append(best_action)
        history.append(best_action)

        next_state = planner._predict_state("", state, best_action)
        if next_state is None:
            break
        if args.show_progress:
            print(f"  Next state: {next_state}")
        state = next_state
        t += 1
        if ap_failed:
            break
    print("Generated plan:")
    for idx, action in enumerate(plan, start=1):
        print(f"{idx}. {action}")
    print("\nFinal state:")
    print(
        json.dumps(
            {field: bool(state[i]) for i, field in enumerate(RECOVERY_STATE_FIELDS)},
            ensure_ascii=True,
            indent=2,
        )
    )
    if state == TERMINAL_STATE:
        print("\nReached terminal state (all ones).")
    else:
        print(f"\nStopped at step {t} before reaching terminal state.")


if __name__ == "__main__":
    main()
