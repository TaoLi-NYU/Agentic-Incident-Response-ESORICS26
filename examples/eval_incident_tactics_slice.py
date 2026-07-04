from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

import torch
from datasets import load_dataset
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer


DEFAULT_HF_DATASET = "kimhammar/CSLE-IncidentResponse-V1"
DEFAULT_HF_DATA_FILE = "incident_examples.json"

ATTACK_TACTIC_ORDER = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

TACTIC_ORDER_INDEX = {tactic: idx for idx, tactic in enumerate(ATTACK_TACTIC_ORDER)}

TACTIC_ID_TO_NAME = {
    "TA0043": "Reconnaissance",
    "TA0042": "Resource Development",
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0011": "Command and Control",
    "TA0010": "Exfiltration",
    "TA0040": "Impact",
}

TACTIC_TEXT_ALIASES = {
    "reconnaissance": "Reconnaissance",
    "resource development": "Resource Development",
    "initial access": "Initial Access",
    "initial_access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege escalation": "Privilege Escalation",
    "defense evasion": "Defense Evasion",
    "defense_evasion": "Defense Evasion",
    "credential access": "Credential Access",
    "credential_access": "Credential Access",
    "discovery": "Discovery",
    "lateral movement": "Lateral Movement",
    "lateral_movement": "Lateral Movement",
    "collection": "Collection",
    "command and control": "Command and Control",
    "command_and_control": "Command and Control",
    "command control": "Command and Control",
    "c2": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}


def load_incident_examples(path: Path) -> tuple[list[str], list[str]]:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("incident_examples.json must be an object.")
    instructions = data.get("instructions")
    answers = data.get("answers")
    if not isinstance(instructions, list) or not isinstance(answers, list):
        raise ValueError("incident_examples.json must contain instructions and answers lists.")
    if len(instructions) != len(answers):
        raise ValueError(
            f"instructions and answers length mismatch: {len(instructions)} != {len(answers)}"
        )
    return [str(x) for x in instructions], [str(x) for x in answers]


def load_incident_examples_from_hf(
    dataset_name: str,
    data_file: str,
) -> tuple[list[str], list[str]]:
    dataset = load_dataset(dataset_name, data_files=data_file)
    row = dataset["train"][0]
    instructions = row.get("instructions")
    answers = row.get("answers")
    if not isinstance(instructions, list) or not isinstance(answers, list):
        raise ValueError(
            f"{dataset_name}/{data_file} must contain instructions and answers lists."
        )
    if len(instructions) != len(answers):
        raise ValueError(
            f"instructions and answers length mismatch: {len(instructions)} != {len(answers)}"
        )
    return [str(x) for x in instructions], [str(x) for x in answers]


def extract_json_object(text: str) -> dict[str, Any] | None:
    decoder = json.JSONDecoder()
    for match in re.finditer(r"\{", text):
        try:
            obj, _ = decoder.raw_decode(text[match.start() :])
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            return obj
    return None


def canonicalize_tactic(raw_tactic: Any) -> str | None:
    raw = str(raw_tactic).strip()
    if not raw:
        return None

    tactic_id_match = re.search(r"\bTA\d{4}\b", raw, flags=re.IGNORECASE)
    if tactic_id_match:
        tactic_id = tactic_id_match.group(0).upper()
        if tactic_id in TACTIC_ID_TO_NAME:
            return TACTIC_ID_TO_NAME[tactic_id]

    lowered = raw.lower().replace("&", "and")
    lowered = re.sub(r"[\(\)\[\]\{\}:,/-]+", " ", lowered)
    lowered = re.sub(r"\s+", " ", lowered).strip()
    if lowered in TACTIC_TEXT_ALIASES:
        return TACTIC_TEXT_ALIASES[lowered]

    compact = lowered.replace(" ", "_")
    if compact in TACTIC_TEXT_ALIASES:
        return TACTIC_TEXT_ALIASES[compact]

    for alias, canonical in TACTIC_TEXT_ALIASES.items():
        alias_tokens = alias.replace("_", " ")
        if re.search(rf"\b{re.escape(alias_tokens)}\b", lowered):
            return canonical

    return None


def sort_tactics(tactics: set[str]) -> list[str]:
    return sorted(
        tactics,
        key=lambda tactic: (
            TACTIC_ORDER_INDEX.get(tactic, len(ATTACK_TACTIC_ORDER)),
            tactic,
        ),
    )


def extract_tactics(obj: dict[str, Any] | None) -> list[str]:
    if not isinstance(obj, dict):
        return []

    raw_tactics: list[Any] = []
    tactics = obj.get("MITRE ATT&CK Tactics", [])
    if isinstance(tactics, list):
        raw_tactics.extend(tactics)

    tactic_chains = obj.get("MITRE ATT&CK Tactic Chains", [])
    if isinstance(tactic_chains, list):
        for chain_obj in tactic_chains:
            if isinstance(chain_obj, dict) and isinstance(chain_obj.get("chain"), list):
                raw_tactics.extend(chain_obj["chain"])

    normalized: set[str] = set()
    for item in raw_tactics:
        tactic = canonicalize_tactic(item)
        if tactic:
            normalized.add(tactic)
    return sort_tactics(normalized)


def normalize_incident_label(obj: dict[str, Any] | None) -> str:
    if not isinstance(obj, dict):
        return "Invalid"
    value = str(obj.get("Incident", "")).strip().lower()
    if value == "yes":
        return "Yes"
    if value == "no":
        return "No"
    return "Invalid"


def compare_tactics(predicted: list[str], gold: list[str]) -> dict[str, Any]:
    pred_set = set(predicted)
    gold_set = set(gold)
    tp = pred_set & gold_set
    fp = pred_set - gold_set
    fn = gold_set - pred_set

    precision = len(tp) / len(pred_set) if pred_set else (1.0 if not gold_set else 0.0)
    recall = len(tp) / len(gold_set) if gold_set else (1.0 if not pred_set else 0.0)
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    union = pred_set | gold_set
    jaccard = len(tp) / len(union) if union else 1.0

    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "jaccard": jaccard,
        "exact_set_match": pred_set == gold_set,
        "true_positive": sort_tactics(tp),
        "false_positive": sort_tactics(fp),
        "false_negative": sort_tactics(fn),
    }


def compute_per_tactic_metrics(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    observed_tactics: set[str] = set(ATTACK_TACTIC_ORDER)
    for item in results:
        observed_tactics.update(item.get("gold_tactics", []))
        observed_tactics.update(item.get("predicted_tactics", []))

    rows: list[dict[str, Any]] = []
    for tactic in sort_tactics(observed_tactics):
        tp = fp = fn = tn = 0
        gold_positive_indices: list[int] = []
        missed_gold_positive_indices: list[int] = []
        false_positive_indices: list[int] = []

        for item in results:
            index = int(item["index"])
            gold_has = tactic in set(item.get("gold_tactics", []))
            pred_has = tactic in set(item.get("predicted_tactics", []))

            if gold_has:
                gold_positive_indices.append(index)

            if gold_has and pred_has:
                tp += 1
            elif not gold_has and pred_has:
                fp += 1
                false_positive_indices.append(index)
            elif gold_has and not pred_has:
                fn += 1
                missed_gold_positive_indices.append(index)
            else:
                tn += 1

        support_gold = tp + fn
        support_predicted = tp + fp
        precision = tp / support_predicted if support_predicted else None
        recall = tp / support_gold if support_gold else None
        f1 = (
            2 * precision * recall / (precision + recall)
            if precision is not None
            and recall is not None
            and precision + recall > 0.0
            else None
        )
        gold_positive_accuracy = recall

        rows.append(
            {
                "tactic": tactic,
                "true_positive": tp,
                "false_positive": fp,
                "false_negative": fn,
                "true_negative": tn,
                "support_gold": support_gold,
                "support_predicted": support_predicted,
                "precision": precision,
                "recall": recall,
                "f1": f1,
                "gold_positive_accuracy": gold_positive_accuracy,
                "gold_positive_indices": gold_positive_indices,
                "missed_gold_positive_indices": missed_gold_positive_indices,
                "false_positive_indices": false_positive_indices,
            }
        )
    return rows


def format_metric(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.3f}"


def print_per_tactic_table(rows: list[dict[str, Any]]) -> None:
    print("\n=== Per-Tactic Metrics ===")
    print(
        f"{'Tactic':<24} {'TP':>4} {'FP':>4} {'FN':>4} "
        f"{'Gold':>5} {'Pred':>5} {'Precision':>9} {'Recall':>7} "
        f"{'F1':>7} {'GoldAcc':>7}"
    )
    print("-" * 86)
    for row in rows:
        print(
            f"{row['tactic']:<24} "
            f"{row['true_positive']:>4} "
            f"{row['false_positive']:>4} "
            f"{row['false_negative']:>4} "
            f"{row['support_gold']:>5} "
            f"{row['support_predicted']:>5} "
            f"{format_metric(row['precision']):>9} "
            f"{format_metric(row['recall']):>7} "
            f"{format_metric(row['f1']):>7} "
            f"{format_metric(row['gold_positive_accuracy']):>7}"
        )


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
    inputs = {k: v.to(model.device) for k, v in inputs.items()}

    with torch.no_grad():
        output_ids = model.generate(
            **inputs,
            max_new_tokens=max_new_tokens,
            do_sample=temperature > 0.0,
            temperature=temperature,
            top_p=top_p,
            pad_token_id=tokenizer.pad_token_id,
            eos_token_id=tokenizer.eos_token_id,
        )

    decoded = tokenizer.decode(output_ids[0], skip_special_tokens=True)
    if decoded.startswith(prompt):
        decoded = decoded[len(prompt) :]
    return decoded.strip()


def average(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Evaluate incident_examples.json samples by comparing only MITRE ATT&CK tactics "
            "as multi-label sets."
        )
    )
    parser.add_argument(
        "--dataset",
        default=None,
        help=(
            "Optional local path to incident_examples.json. If omitted, the script downloads "
            "kimhammar/CSLE-IncidentResponse-V1 incident_examples.json from HuggingFace."
        ),
    )
    parser.add_argument("--hf-dataset", default=DEFAULT_HF_DATASET)
    parser.add_argument("--hf-data-file", default=DEFAULT_HF_DATA_FILE)
    parser.add_argument("--checkpoint", required=True, help="Model or LoRA checkpoint path.")
    parser.add_argument("--start-index", type=int, default=17000)
    parser.add_argument("--end-index", type=int, default=17019)
    parser.add_argument(
        "--dtype",
        choices=("float16", "bfloat16"),
        default="float16",
    )
    parser.add_argument("--max-new-tokens", type=int, default=1024)
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--top-p", type=float, default=1.0)
    parser.add_argument("--output-json", default=None)
    parser.add_argument("--print-raw-output", action="store_true")
    args = parser.parse_args()

    if args.dataset:
        dataset_source = str(Path(args.dataset))
        instructions, answers = load_incident_examples(Path(args.dataset))
    else:
        dataset_source = f"{args.hf_dataset}/{args.hf_data_file}"
        instructions, answers = load_incident_examples_from_hf(
            args.hf_dataset,
            args.hf_data_file,
        )
    if args.start_index < 0 or args.end_index < args.start_index:
        raise ValueError("--start-index and --end-index define an invalid range.")
    if args.end_index >= len(instructions):
        raise ValueError(
            f"--end-index {args.end_index} is out of range for dataset length {len(instructions)}."
        )

    dtype = torch.float16 if args.dtype == "float16" else torch.bfloat16
    tokenizer, model = load_model_and_tokenizer(args.checkpoint, dtype=dtype)

    results: list[dict[str, Any]] = []
    for sample_index in range(args.start_index, args.end_index + 1):
        prompt = instructions[sample_index]
        gold_obj = extract_json_object(answers[sample_index])
        gold_tactics = extract_tactics(gold_obj)
        tactics_label_available = bool(gold_tactics)

        generated = generate_once(
            model=model,
            tokenizer=tokenizer,
            prompt=prompt,
            max_new_tokens=args.max_new_tokens,
            temperature=args.temperature,
            top_p=args.top_p,
        )
        pred_obj = extract_json_object(generated)
        gold_incident = normalize_incident_label(gold_obj)
        predicted_incident = normalize_incident_label(pred_obj)
        incident_correct = predicted_incident == gold_incident
        predicted_tactics = extract_tactics(pred_obj)
        metrics = compare_tactics(predicted_tactics, gold_tactics)

        item = {
            "index": sample_index,
            "gold_incident": gold_incident,
            "predicted_incident": predicted_incident,
            "incident_correct": incident_correct,
            "tactics_label_available": tactics_label_available,
            "gold_tactics": gold_tactics,
            "predicted_tactics": predicted_tactics,
            "metrics": metrics,
            "parsed_prediction": pred_obj,
        }
        if args.print_raw_output:
            item["raw_output"] = generated
        results.append(item)

        print(
            f"[{sample_index}] "
            f"Incident={predicted_incident}/{gold_incident} "
            f"incident_correct={incident_correct} "
            f"P={metrics['precision']:.3f} "
            f"R={metrics['recall']:.3f} "
            f"F1={metrics['f1']:.3f} "
            f"J={metrics['jaccard']:.3f} "
            f"exact={metrics['exact_set_match']} "
            f"gold_tactics_available={tactics_label_available}"
        )
        print(f"  gold: {gold_tactics}")
        print(f"  pred: {predicted_tactics}")
        if metrics["false_positive"]:
            print(f"  extra: {metrics['false_positive']}")
        if metrics["false_negative"]:
            print(f"  missing: {metrics['false_negative']}")

    labeled_tactic_results = [x for x in results if x["tactics_label_available"]]
    per_tactic_metrics = compute_per_tactic_metrics(results)

    summary = {
        "dataset": dataset_source,
        "checkpoint": args.checkpoint,
        "start_index": args.start_index,
        "end_index": args.end_index,
        "num_samples": len(results),
        "tactic_labeled_sample_count": len(labeled_tactic_results),
        "empty_gold_tactics_count": len(results) - len(labeled_tactic_results),
        "macro_precision": average([x["metrics"]["precision"] for x in results]),
        "macro_recall": average([x["metrics"]["recall"] for x in results]),
        "macro_f1": average([x["metrics"]["f1"] for x in results]),
        "macro_jaccard": average([x["metrics"]["jaccard"] for x in results]),
        "exact_set_match_rate": average(
            [1.0 if x["metrics"]["exact_set_match"] else 0.0 for x in results]
        ),
        "macro_precision_labeled_tactics_only": average(
            [x["metrics"]["precision"] for x in labeled_tactic_results]
        ),
        "macro_recall_labeled_tactics_only": average(
            [x["metrics"]["recall"] for x in labeled_tactic_results]
        ),
        "macro_f1_labeled_tactics_only": average(
            [x["metrics"]["f1"] for x in labeled_tactic_results]
        ),
        "macro_jaccard_labeled_tactics_only": average(
            [x["metrics"]["jaccard"] for x in labeled_tactic_results]
        ),
        "exact_set_match_rate_labeled_tactics_only": average(
            [
                1.0 if x["metrics"]["exact_set_match"] else 0.0
                for x in labeled_tactic_results
            ]
        ),
        "incident_correct_count": sum(1 for x in results if x["incident_correct"]),
        "incident_wrong_count": sum(1 for x in results if not x["incident_correct"]),
        "incident_accuracy": average(
            [1.0 if x["incident_correct"] else 0.0 for x in results]
        ),
    }
    output = {
        "summary": summary,
        "per_tactic_metrics": per_tactic_metrics,
        "results": results,
    }

    print("\n=== Summary ===")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print_per_tactic_table(per_tactic_metrics)

    if args.output_json:
        Path(args.output_json).write_text(
            json.dumps(output, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        print(f"\nSaved detailed results to {args.output_json}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
