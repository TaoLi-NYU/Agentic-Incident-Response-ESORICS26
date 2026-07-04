from __future__ import annotations

import argparse
import json
import random
import re
import time
from pathlib import Path

import torch
from datasets import load_dataset
from transformers import AutoTokenizer, AutoModelForCausalLM
from peft import PeftModel, PeftConfig

from llm_recovery.evaluation import exact_match_accuracy
from llm_recovery.evaluation.exact_match import REQUIRED_FIELDS
from llm_recovery.evaluation.f1_score import multilabel_f1_from_texts


TASK_TAG_STATE = "[TASK:CSLE_STATE]"
TASK_TAG_CLS_PRI = "[TASK:CLS_PRI]"


def extract_unique_pairs(text: str) -> list[tuple[str, str]]:
    pairs = re.findall(
        r"\[Classification:\s*([^\]]+)\]\s*\[Priority:\s*([^\]]+)\]",
        text,
        flags=re.IGNORECASE,
    )
    seen: set[tuple[str, str]] = set()
    unique_pairs: list[tuple[str, str]] = []
    for cls, pri in pairs:
        pair = (cls.strip(), pri.strip())
        if pair not in seen:
            seen.add(pair)
            unique_pairs.append(pair)
    return unique_pairs


def normalize_classification(text: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", " ", text.lower())
    normalized = re.sub(r"\s+", " ", normalized).strip()
    return normalized


def has_empty_classification(text: str) -> bool:
    return re.search(r"^\[Classification:\]$", text, flags=re.MULTILINE) is not None


def set_seed(seed: int) -> None:
    random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


def load_model(adapter_dir: str):
    peft_cfg = PeftConfig.from_pretrained(adapter_dir)
    tokenizer = AutoTokenizer.from_pretrained(peft_cfg.base_model_name_or_path, use_fast=True)
    tokenizer.pad_token = tokenizer.eos_token
    device_map = {"": 0}
    base = AutoModelForCausalLM.from_pretrained(peft_cfg.base_model_name_or_path, device_map=device_map)
    model = PeftModel.from_pretrained(base, adapter_dir)
    model.eval()
    return tokenizer, model, peft_cfg.base_model_name_or_path


def generate_predictions(tokenizer, model, instructions, max_new_tokens: int):
    preds = []
    total_start = time.time()
    with torch.no_grad():
        for i, instr in enumerate(instructions):
            inputs = tokenizer(instr, return_tensors="pt").to(model.device)
            out = model.generate(
                **inputs,
                max_new_tokens=max_new_tokens,
                do_sample=False,
                pad_token_id=tokenizer.eos_token_id,
                eos_token_id=tokenizer.eos_token_id,
            )
            text = tokenizer.decode(out[0], skip_special_tokens=True)
            preds.append(text)
            if (i + 1) % 10 == 0 or (i + 1) == len(instructions):
                total_elapsed = time.time() - total_start
                print(f"Processed {i + 1}/{len(instructions)} in total {total_elapsed:.2f}s", flush=True)
    return preds


def evaluate_cls_pri(preds, labels):
    # Build normalized classification frequency map from labels.
    label_class_counts: dict[str, int] = {}
    for label in labels:
        if not label:
            continue
        for cls, _pri in extract_unique_pairs(label):
            norm_cls = normalize_classification(cls)
            if not norm_cls:
                continue
            label_class_counts[norm_cls] = label_class_counts.get(norm_cls, 0) + 1

    recalls: list[float] = []
    precisions: list[float] = []
    for idx, (pred, label) in enumerate(zip(preds, labels), start=1):
        if label and has_empty_classification(label):
            print("\n(drop: empty classification)\n")
            continue

        pred_pairs = extract_unique_pairs(pred)
        label_pairs = extract_unique_pairs(label)
        pred_pairs_norm = [
            (normalize_classification(cls), pri)
            for cls, pri in pred_pairs
            if normalize_classification(cls)
        ]
        label_pairs_norm = [
            (normalize_classification(cls), pri)
            for cls, pri in label_pairs
            if normalize_classification(cls)
        ]

        # Filter out low-frequency classifications (< 50) based on label distribution.
        pred_set = {
            (cls, pri)
            for cls, pri in pred_pairs_norm
            if label_class_counts.get(cls, 0) >= 50
        }
        label_set = {
            (cls, pri)
            for cls, pri in label_pairs_norm
            if label_class_counts.get(cls, 0) >= 50
        }

        if not label_set:
            print("\n(drop: empty label_set after filtering)\n")
            continue
        if not pred_set:
            print("\n(drop: empty pred_set after filtering)\n")
            continue

        overlap = len(pred_set & label_set)
        recall = overlap / len(label_set)
        precision = overlap / len(pred_set)
        recalls.append(recall)
        precisions.append(precision)

    if not recalls:
        return {"avg_recall": 0.0, "avg_precision": 0.0, "num_scored": 0}
    return {
        "avg_recall": sum(recalls) / len(recalls),
        "avg_precision": sum(precisions) / len(precisions),
        "num_scored": len(recalls),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate mixed tasks with task tags.")
    parser.add_argument(
        "--adapter",
        default="/content/drive/MyDrive/llm_recovery_runs-continue-twodatasets/checkpoint-680",
        help="LoRA adapter checkpoint path",
    )
    parser.add_argument(
        "--states-limit",
        type=int,
        default=200,
        help="How many CSLE state samples to evaluate",
    )
    parser.add_argument(
        "--states-start",
        type=int,
        default=50000,
        help="Start index for CSLE state samples",
    )
    parser.add_argument(
        "--cls-pri-dataset",
        default="/content/drive/MyDrive/transformed_dataset_cls_pri_all2preprocessing.json",
        help="Path to classification/priority dataset JSON",
    )
    parser.add_argument(
        "--cls-pri-limit",
        type=int,
        default=200,
        help="How many classification/priority samples to evaluate",
    )
    parser.add_argument(
        "--random",
        action="store_true",
        help="Sample classification/priority data points randomly",
    )
    parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility")
    parser.add_argument("--max-new-tokens", type=int, default=256)
    args = parser.parse_args()

    set_seed(args.seed)

    tokenizer, model, base_name = load_model(args.adapter)
    print("peft base:", base_name)

    # Dataset 1: CSLE states
    ds_states = load_dataset("kimhammar/CSLE-IncidentResponse-V1", data_files="states_examples.json")
    sample = ds_states["train"][0]
    start = args.states_start
    end = args.states_start + args.states_limit if args.states_limit else None
    instructions_states = [
        f"{TASK_TAG_STATE} {instr}" for instr in sample["instructions"][start:end]
    ]
    labels_states = sample["answers"][start:end]
    states_start_time = time.time()
    preds_states = generate_predictions(tokenizer, model, instructions_states, args.max_new_tokens)
    states_elapsed = time.time() - states_start_time
    print(f"CSLE states total time: {states_elapsed:.2f}s")
    label_texts = [json.dumps(l) if isinstance(l, dict) else l for l in labels_states]
    acc = exact_match_accuracy(preds_states, label_texts)
    f1 = multilabel_f1_from_texts(preds_states, label_texts)
    print(f"\nCSLE states exact-match accuracy: {acc:.4f}")
    print(f"CSLE states Micro-F1: {f1['micro_f1']:.4f}")
    print(f"CSLE states Macro-F1: {f1['macro_f1']:.4f}")
    print("CSLE states Per-state F1:")
    for i, key in enumerate(REQUIRED_FIELDS):
        print(f"  {key}: {f1['per_label_f1'][i]:.4f}")

    # Dataset 2: classification/priority
    cls_data = json.loads(Path(args.cls_pri_dataset).read_text(encoding="utf-8"))
    if not isinstance(cls_data, list):
        raise ValueError("Classification/priority dataset JSON must be a list of objects")
    if args.random:
        if args.cls_pri_limit and args.cls_pri_limit > 0:
            cls_data = random.sample(cls_data, k=min(args.cls_pri_limit, len(cls_data)))
        else:
            random.shuffle(cls_data)
    else:
        cls_data = cls_data[: args.cls_pri_limit] if args.cls_pri_limit else cls_data
    instructions_cls = [f"{TASK_TAG_CLS_PRI} {row['instruction']}" for row in cls_data]
    labels_cls = [row["output"] for row in cls_data]
    preds_cls = generate_predictions(tokenizer, model, instructions_cls, args.max_new_tokens)
    cls_metrics = evaluate_cls_pri(preds_cls, labels_cls)
    print(f"\nCLS/PRI avg recall (unique pairs): {cls_metrics['avg_recall']:.4f}")
    print(f"CLS/PRI avg precision (unique pairs): {cls_metrics['avg_precision']:.4f}")
    print(f"CLS/PRI num scored: {cls_metrics['num_scored']}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
