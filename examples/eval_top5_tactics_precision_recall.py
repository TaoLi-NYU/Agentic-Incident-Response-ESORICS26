from __future__ import annotations

import argparse
import json
import random
import re
from collections import Counter
from pathlib import Path

import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer


def load_dataset(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError("Dataset JSON must be a list of objects")
    return data


def set_seed(seed: int) -> None:
    random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


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


def build_label_class_counts(data: list[dict]) -> dict[str, int]:
    label_class_counts: dict[str, int] = {}
    for item in data:
        label = item.get("output", "")
        if not label:
            continue
        for cls, _pri in extract_unique_pairs(label):
            norm_cls = normalize_classification(cls)
            if not norm_cls:
                continue
            label_class_counts[norm_cls] = label_class_counts.get(norm_cls, 0) + 1
    return label_class_counts


def extract_tactic(instruction: str) -> str | None:
    match = re.search(r"MITRE ATT&CK tactic:\s*([^\n\r\.]+)", instruction)
    if not match:
        return None
    return match.group(1).strip()


def compute_precision_recall(
    pred_text: str,
    label_text: str,
    label_class_counts: dict[str, int],
    min_class_frequency: int,
) -> tuple[float, float]:
    pred_pairs = extract_unique_pairs(pred_text)
    label_pairs = extract_unique_pairs(label_text)

    pred_set = {
        (normalize_classification(cls), pri)
        for cls, pri in pred_pairs
        if normalize_classification(cls)
        and (
            min_class_frequency <= 0
            or label_class_counts.get(normalize_classification(cls), 0) >= min_class_frequency
        )
    }
    label_set = {
        (normalize_classification(cls), pri)
        for cls, pri in label_pairs
        if normalize_classification(cls)
        and (
            min_class_frequency <= 0
            or label_class_counts.get(normalize_classification(cls), 0) >= min_class_frequency
        )
    }

    if not pred_set or not label_set:
        return 0.0, 0.0
    overlap = len(pred_set & label_set)
    precision = overlap / len(pred_set) if pred_set else 0.0
    recall = overlap / len(label_set) if label_set else 0.0
    return precision, recall


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compute precision/recall/F1 for top tactics, sampling up to 100 items per tactic."
    )
    parser.add_argument(
        "--model",
        required=True,
        help="Path or HF id for the model checkpoint",
    )
    parser.add_argument(
        "--dataset",
        required=True,
        help="Path to transformed_dataset_cls_pri_all2preprocessing.json",
    )
    parser.add_argument("--max-new-tokens", type=int, default=512)
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--top-p", type=float, default=1.0)
    parser.add_argument("--top-tactics", type=int, default=5)
    parser.add_argument("--per-tactic", type=int, default=100)
    parser.add_argument(
        "--min-class-frequency",
        type=int,
        default=50,
        help=(
            "Filter out normalized classifications whose label frequency is below this "
            "threshold. Set to 0 to disable low-frequency filtering."
        ),
    )
    parser.add_argument(
        "--stats-only",
        action="store_true",
        help=(
            "Only print tactic-chain and classification-frequency statistics, "
            "then exit before loading the model."
        ),
    )
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    set_seed(args.seed)

    dataset_path = Path(args.dataset)
    data = load_dataset(dataset_path)
    label_class_counts = build_label_class_counts(data)

    tactic_counts: Counter[str] = Counter()
    for item in data:
        instruction = item.get("instruction", "")
        tactic = extract_tactic(instruction)
        if tactic:
            tactic_counts[tactic] += 1

    total_tactic_labeled = sum(tactic_counts.values())
    top_tactics = tactic_counts.most_common(args.top_tactics)
    print(f"Dataset samples: {len(data)}")
    print(f"Tactic-chain labeled samples: {total_tactic_labeled}")
    print(f"Top {args.top_tactics} tactic-chain categories by frequency:")
    for tactic, count in top_tactics:
        ratio = count / total_tactic_labeled if total_tactic_labeled else 0.0
        print(f"- {tactic}: count={count}, ratio={ratio:.4f}")
    if args.min_class_frequency > 0:
        kept_classes = [
            cls
            for cls, count in label_class_counts.items()
            if count >= args.min_class_frequency
        ]
        print(
            f"Low-frequency classification filter: keeping {len(kept_classes)} "
            f"classes with label frequency >= {args.min_class_frequency}"
        )
    else:
        print("Low-frequency classification filter: disabled")
    if args.stats_only:
        return 0

    adapter_config = Path(args.model) / "adapter_config.json"
    if adapter_config.exists():
        with adapter_config.open("r", encoding="utf-8") as f:
            adapter_meta = json.load(f)
        base_model = adapter_meta.get("base_model_name_or_path")
        if not base_model:
            raise ValueError("adapter_config.json missing base_model_name_or_path")
        tokenizer = AutoTokenizer.from_pretrained(base_model, use_fast=True)
    else:
        base_model = None
        tokenizer = AutoTokenizer.from_pretrained(args.model, use_fast=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    if base_model:
        base = AutoModelForCausalLM.from_pretrained(
            base_model, device_map="auto", torch_dtype=torch.bfloat16
        )
        model = PeftModel.from_pretrained(base, args.model)
    else:
        model = AutoModelForCausalLM.from_pretrained(
            args.model, device_map="auto", torch_dtype=torch.bfloat16
        )
    model.eval()

    for tactic, total_count in top_tactics:
        candidates = [
            item
            for item in data
            if extract_tactic(item.get("instruction", "")) == tactic
        ]
        if not candidates:
            print(f"\nTactic: {tactic}")
            print("  No samples found.")
            continue

        sample_n = min(args.per_tactic, len(candidates))
        sample = random.sample(candidates, k=sample_n)

        precisions: list[float] = []
        recalls: list[float] = []

        for idx, item in enumerate(sample, start=1):
            prompt = item.get("instruction", "")
            label = item.get("output", "")
            if not prompt or not label:
                print(f"  Completed: {idx}/{sample_n} (skipped empty sample)", flush=True)
                continue

            inputs = tokenizer(prompt, return_tensors="pt")
            inputs = {k: v.to(model.device) for k, v in inputs.items()}
            with torch.no_grad():
                output_ids = model.generate(
                    **inputs,
                    max_new_tokens=args.max_new_tokens,
                    do_sample=args.temperature > 0.0,
                    temperature=args.temperature,
                    top_p=args.top_p,
                    pad_token_id=tokenizer.pad_token_id,
                )
            pred = tokenizer.decode(output_ids[0], skip_special_tokens=True)
            if pred.startswith(prompt):
                pred = pred[len(prompt) :]

            precision, recall = compute_precision_recall(
                pred,
                label,
                label_class_counts=label_class_counts,
                min_class_frequency=args.min_class_frequency,
            )
            precisions.append(precision)
            recalls.append(recall)
            print(f"  Completed: {idx}/{sample_n}", flush=True)

        avg_precision = sum(precisions) / len(precisions) if precisions else 0.0
        avg_recall = sum(recalls) / len(recalls) if recalls else 0.0
        avg_f1 = (
            2 * avg_precision * avg_recall / (avg_precision + avg_recall)
            if avg_precision + avg_recall
            else 0.0
        )

        print(f"\nTactic: {tactic}")
        print(f"  Data points in dataset: {total_count}")
        print(f"  Dataset ratio: {total_count / total_tactic_labeled if total_tactic_labeled else 0.0:.4f}")
        print(f"  Evaluated samples: {sample_n}")
        print(f"  Average precision (unique pairs): {avg_precision:.4f}")
        print(f"  Average recall (unique pairs): {avg_recall:.4f}")
        print(f"  F1 (from average precision/recall): {avg_f1:.4f}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
