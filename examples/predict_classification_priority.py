from __future__ import annotations

import argparse
import json
import random
import re
from pathlib import Path

import torch
from transformers import AutoTokenizer, AutoModelForCausalLM
from peft import PeftModel


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


def has_empty_classification(text: str) -> bool:
    return re.search(r"^\[Classification:\]$", text, flags=re.MULTILINE) is not None


VALID_CLASSES = {
    "a network trojan was detected",
    "attempted administrator privilege gain",
    "attempted denial of service",
    "attempted information leak",
    "attempted user privilege gain",
    "bad unknown",
    "misc activity",
    "policy violation",
    "potential corporate privacy violation",
    "potentially bad traffic",
    "trojan activity",
    "web application attack",
}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run model inference on instruction field and print prediction + label"
    )
    parser.add_argument(
        "--model",
        default=r"D:\RA Project\AI Agent&Cybersecurity paper\llm_recovery\transformed-updated-dataset-lora\checkpoint-3631",
        help="Path or HF id for the model checkpoint",
    )
    parser.add_argument(
        "--dataset",
        default=r"D:\RA Project\AI Agent&Cybersecurity paper\updated_data\transformed_dataset_cls_pri_all2.json",
        help="Path to dataset JSON (list of {instruction, output})",
    )
    parser.add_argument("--max-new-tokens", type=int, default=512)
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--top-p", type=float, default=1.0)
    parser.add_argument("--limit", type=int, default=200, help="How many samples to run (0 = all)")
    parser.add_argument("--random", action="store_true", help="Sample data points randomly")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility")
    args = parser.parse_args()

    set_seed(args.seed)

    model_path = args.model
    dataset_path = Path(args.dataset)

    adapter_config = Path(model_path) / "adapter_config.json"
    if adapter_config.exists():
        with adapter_config.open("r", encoding="utf-8") as f:
            adapter_meta = json.load(f)
        base_model = adapter_meta.get("base_model_name_or_path")
        if not base_model:
            raise ValueError("adapter_config.json missing base_model_name_or_path")
        tokenizer = AutoTokenizer.from_pretrained(base_model, use_fast=True)
    else:
        base_model = None
        tokenizer = AutoTokenizer.from_pretrained(model_path, use_fast=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    if base_model:
        base = AutoModelForCausalLM.from_pretrained(
            base_model, device_map="auto", torch_dtype=torch.float16
        )
        model = PeftModel.from_pretrained(base, model_path)
    else:
        model = AutoModelForCausalLM.from_pretrained(
            model_path, device_map="auto", torch_dtype=torch.float16
        )
    model.eval()

    data = load_dataset(dataset_path)
    if args.random:
        if args.limit and args.limit > 0:
            data = random.sample(data, k=min(args.limit, len(data)))
        else:
            random.shuffle(data)
    else:
        if args.limit and args.limit > 0:
            data = data[: args.limit]

    recalls: list[float] = []
    precisions: list[float] = []
    for i, item in enumerate(data, start=1):
        prompt = item.get("instruction", "")
        label = item.get("output", "")
        if not prompt:
            continue
        if label and has_empty_classification(label):
            print(f"=== Sample {i} ===")
            print("instruction:")
            print(prompt)
            print("\nlabel:")
            print(label)
            print("\n(drop: empty classification)\n")
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

        print(f"=== Sample {i} ===")
        print("instruction:")
        print(prompt)
        print("\nprediction:")
        print(pred.strip())
        print("\nlabel:")
        print(label)
        pred_pairs = extract_unique_pairs(pred)
        label_pairs = extract_unique_pairs(label)
        print("\nunique prediction pairs:")
        if pred_pairs:
            for cls, pri in pred_pairs:
                print(f"- [Classification: {cls}] [Priority: {pri}]")
        else:
            print("- (none)")
        print("\nunique label pairs:")
        if label_pairs:
            for cls, pri in label_pairs:
                print(f"- [Classification: {cls}] [Priority: {pri}]")
        else:
            print("- (none)")

        # Normalize classifications to ignore formatting differences.
        pred_pairs_norm = [
            (normalize_classification(cls), pri) for cls, pri in pred_pairs if normalize_classification(cls)
        ]
        label_pairs_norm = [
            (normalize_classification(cls), pri) for cls, pri in label_pairs if normalize_classification(cls)
        ]
        print("\nnormalized prediction pairs:")
        if pred_pairs_norm:
            for cls, pri in pred_pairs_norm:
                print(f"- [Classification: {cls}] [Priority: {pri}]")
        else:
            print("- (none)")
        print("\nnormalized label pairs:")
        if label_pairs_norm:
            for cls, pri in label_pairs_norm:
                print(f"- [Classification: {cls}] [Priority: {pri}]")
        else:
            print("- (none)")

        # Filter out low-frequency classifications (precomputed from full dataset).
        pred_set = {
            (cls, pri)
            for cls, pri in pred_pairs_norm
            if cls in VALID_CLASSES
        }
        label_set = {
            
            (cls, pri)
            for cls, pri in label_pairs_norm
            if cls in VALID_CLASSES
        }

        if not label_set:
            print('\n(drop: empty label_set after filtering)\n')
            continue
        if not pred_set:
            print('\n(drop: empty pred_set after filtering)\n')
            continue

        overlap = len(pred_set & label_set)
        recall = (overlap / len(label_set)) if label_set else 0.0
        precision = (overlap / len(pred_set)) if pred_set else 0.0
        recalls.append(recall)
        precisions.append(precision)
        print(f"\nrecall (unique pairs): {recall:.4f}")
        print(f"precision (unique pairs): {precision:.4f}")
        print()

    if recalls:
        avg_recall = sum(recalls) / len(recalls)
        avg_precision = sum(precisions) / len(precisions)
        print(f"Average recall (unique pairs): {avg_recall:.4f}")
        print(f"Average precision (unique pairs): {avg_precision:.4f}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
