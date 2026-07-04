from __future__ import annotations

import argparse
from collections import Counter
import json
import re
from pathlib import Path
from typing import Any

import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer


DEFAULT_CHECKPOINT = "/content/drive/MyDrive/llm_recovery_runs-FOURdatasets/checkpoint-850"
DEFAULT_GOLD_PRIORITY = "1"

DEFAULT_SYSTEM = """The testbed is a Dockerized incident response digital twin designed for autonomous incident response research. It emulates a small segmented IT infrastructure with two networks: a client network (10.0.1.0/24) and a server network (10.0.2.0/24). These two networks are connected through a gateway host that functions both as a router and as a Snort IDS sensor.

The gateway has IP address 10.0.1.10 on the client network and 10.0.2.10 on the server network. A client host with IP 10.0.1.11 resides on the client network and serves as the attack platform. The server network contains five servers: an SSH server at 10.0.2.11, a Samba server at 10.0.2.12, a Shellshock-vulnerable web server at 10.0.2.13, and two normal web servers at 10.0.2.14 and 10.0.2.15.

The gateway runs Snort IDS and iptables and monitors traffic flowing between the two network segments. The client container includes common offensive security tools such as nmap, hydra, curl, smbclient, and sshpass, which are used to generate attack traffic for experimentation. Among the servers, three are intentionally vulnerable: the SSH server uses weak credentials, the Samba server is configured to emulate CVE-2017-7494, and the Shellshock server is configured to emulate CVE-2014-6271. The remaining two web servers are normal hosts and serve as benign comparison systems."""

DEFAULT_TACTICS = [
    "Reconnaissance",
    "Discovery",
    "Credential Access",
    "Initial Access",
    "Execution",
    "Lateral Movement",
]

DEFAULT_GOLD_ALERTS = """2026-04-09 19:39:29,621 [    INFO] Alert: [1:1000001:1] ICMP traffic detected (run_attack.py:107)
2026-04-09 19:39:29,622 [    INFO] Alert: [1:1000006:1] HTTP traffic detected (run_attack.py:107)
2026-04-09 19:39:29,632 [    INFO] Alert: [1:1000003:1] SMB traffic to Samba server (run_attack.py:107)
2026-04-09 19:39:29,633 [    INFO] Alert: [1:1000007:1] SSH connection attempt (run_attack.py:107)
2026-04-09 19:39:29,633 [    INFO] Alert: [1:1000002:1] Potential SSH brute force attack (run_attack.py:107)
2026-04-09 19:39:29,633 [    INFO] Alert: [1:1000004:1] SMB traffic to Samba server (NetBIOS) (run_attack.py:107)
2026-04-09 19:39:29,646 [    INFO] Alert: [1:1000005:1] Shellshock attack attempt (run_attack.py:107)"""

DEFAULT_GOLD_CLASSIFICATION_PRIORITY = [
    {
        "sid": "1000001",
        "message": "ICMP traffic detected",
        "classification": "Network Scan",
        "priority": "2",
    },
    {
        "sid": "1000002",
        "message": "Potential SSH brute force attack",
        "classification": "Attempted Admin Privilege Gain",
        "priority": "1",
    },
    {
        "sid": "1000003",
        "message": "SMB traffic to Samba server",
        "classification": "Attempted Reconnaissance",
        "priority": "2",
    },
    {
        "sid": "1000004",
        "message": "SMB traffic to Samba server (NetBIOS)",
        "classification": "Attempted Reconnaissance",
        "priority": "2",
    },
    {
        "sid": "1000005",
        "message": "Shellshock attack attempt",
        "classification": "Web Application Attack",
        "priority": "1",
    },
    {
        "sid": "1000006",
        "message": "HTTP traffic detected",
        "classification": "Misc activity",
        "priority": "3",
    },
    {
        "sid": "1000007",
        "message": "SSH connection attempt",
        "classification": "Attempted Reconnaissance",
        "priority": "2",
    },
]

PROMPT_TEMPLATE = """Below is a system description and an instruction that describes a task. Write a response that appropriately completes the request. Before generating the response, think carefully about the system and the instruction to ensure a logical and accurate response.

### System:
{system}

### Instruction:
Generate fields produced by an intrusion detection system (e.g., Snort) during a cyberattack by an attacker following these MITRE ATT&CK tactics: {tactics}.

### Response:
<think>"""


def load_text_arg(inline_value: str | None, file_value: str | None, default_value: str) -> str:
    if file_value:
        return Path(file_value).read_text(encoding="utf-8")
    if inline_value:
        return inline_value
    return default_value


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


def build_prompt(system_text: str, tactics: list[str]) -> str:
    return PROMPT_TEMPLATE.format(
        system=system_text.strip(),
        tactics=", ".join(tactics),
    )


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
        decoded = decoded[len(prompt):]
    return decoded.strip()


def normalize_classification(text: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", " ", text.lower())
    normalized = re.sub(r"\s+", " ", normalized).strip()
    return normalized


def extract_predicted_pairs(text: str) -> list[tuple[str, str]]:
    pairs = re.findall(
        r"\[Classification:\s*([^\]]+)\]\s*\[Priority:\s*([^\]]+)\]",
        text,
        flags=re.IGNORECASE,
    )
    seen: set[tuple[str, str]] = set()
    unique_pairs: list[tuple[str, str]] = []
    for cls, pri in pairs:
        pair = (normalize_classification(cls), pri.strip())
        if pair[0] and pair not in seen:
            seen.add(pair)
            unique_pairs.append(pair)
    return unique_pairs


def extract_gold_pairs(text: str, default_priority: str) -> list[tuple[str, str]]:
    pattern = re.compile(
        r"Alert:\s*\[\d+:(\d+):(\d+)\]\s*(.+?)\s*\(run_attack\.py:\d+\)",
        flags=re.IGNORECASE,
    )
    seen: set[tuple[str, str]] = set()
    unique_pairs: list[tuple[str, str]] = []
    for sid, rev, message in pattern.findall(text):
        _ = sid
        _ = rev
        pair = (normalize_classification(message), default_priority.strip())
        if pair[0] and pair not in seen:
            seen.add(pair)
            unique_pairs.append(pair)
    return unique_pairs


def extract_gold_pairs_from_mapping(
    mapping: list[dict[str, str]],
) -> list[tuple[str, str]]:
    seen: set[tuple[str, str]] = set()
    unique_pairs: list[tuple[str, str]] = []
    for item in mapping:
        classification = normalize_classification(item.get("classification", ""))
        priority = str(item.get("priority", "")).strip()
        pair = (classification, priority)
        if classification and priority and pair not in seen:
            seen.add(pair)
            unique_pairs.append(pair)
    return unique_pairs


def compute_precision_recall(
    predicted_pairs: list[tuple[str, str]],
    gold_pairs: list[tuple[str, str]],
) -> dict[str, Any]:
    pred_set = set(predicted_pairs)
    gold_set = set(gold_pairs)
    overlap = pred_set & gold_set
    precision = len(overlap) / len(pred_set) if pred_set else 0.0
    recall = len(overlap) / len(gold_set) if gold_set else 0.0
    return {
        "precision": precision,
        "recall": recall,
        "matched_pairs": sorted(overlap),
        "predicted_pair_count": len(pred_set),
        "gold_pair_count": len(gold_set),
        "matched_pair_count": len(overlap),
        "exact_match": pred_set == gold_set,
    }


def summarize_pair_counts(
    runs: list[list[tuple[str, str]]],
) -> list[dict[str, Any]]:
    counts: Counter[tuple[str, str]] = Counter()
    for pairs in runs:
        counts.update(set(pairs))

    summary: list[dict[str, Any]] = []
    for (classification, priority), count in counts.most_common():
        summary.append(
            {
                "classification": classification,
                "priority": priority,
                "count": count,
                "formatted": f"[Classification: {classification}] [Priority: {priority}] x {count}",
            }
        )
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Generate IDS classification/priority fields for a custom multi-tactic prompt "
            "and compare them against raw alert logs using unique (classification, priority) pairs."
        )
    )
    parser.add_argument("--checkpoint", default=DEFAULT_CHECKPOINT)
    parser.add_argument(
        "--dtype",
        choices=("float16", "bfloat16"),
        default="float16",
    )
    parser.add_argument("--max-new-tokens", type=int, default=512)
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--top-p", type=float, default=1.0)
    parser.add_argument("--num-runs", type=int, default=10)
    parser.add_argument("--system", default=None)
    parser.add_argument("--system-file", default=None)
    parser.add_argument("--tactics", nargs="+", default=DEFAULT_TACTICS)
    parser.add_argument("--gold-alerts", default=None)
    parser.add_argument("--gold-alerts-file", default=None)
    parser.add_argument(
        "--use-provisional-gold-mapping",
        action="store_true",
        help=(
            "Use the provisional SID->classification->priority mapping defined in this script "
            "instead of deriving gold pairs from raw alert logs."
        ),
    )
    parser.add_argument(
        "--gold-default-priority",
        default=DEFAULT_GOLD_PRIORITY,
        help=(
            "Priority value assigned to raw gold alerts. "
            "Use this only because the supplied raw logs do not contain explicit Priority fields."
        ),
    )
    parser.add_argument(
        "--print-prompt",
        action="store_true",
        help="Print the final prompt before generation.",
    )
    args = parser.parse_args()

    dtype = torch.float16 if args.dtype == "float16" else torch.bfloat16
    system_text = load_text_arg(args.system, args.system_file, DEFAULT_SYSTEM)
    gold_alerts_text = load_text_arg(args.gold_alerts, args.gold_alerts_file, DEFAULT_GOLD_ALERTS)
    prompt = build_prompt(system_text, args.tactics)

    if args.print_prompt:
        print("=== Prompt ===")
        print(prompt)
        print()

    tokenizer, model = load_model_and_tokenizer(args.checkpoint, dtype=dtype)
    run_outputs: list[dict[str, Any]] = []
    predicted_pairs_by_run: list[list[tuple[str, str]]] = []
    aggregated_predicted_pairs: set[tuple[str, str]] = set()
    for run_index in range(1, args.num_runs + 1):
        generated = generate_once(
            model=model,
            tokenizer=tokenizer,
            prompt=prompt,
            max_new_tokens=args.max_new_tokens,
            temperature=args.temperature,
            top_p=args.top_p,
        )
        predicted_pairs = extract_predicted_pairs(generated)
        predicted_pairs_by_run.append(predicted_pairs)
        aggregated_predicted_pairs.update(predicted_pairs)
        run_outputs.append(
            {
                "run": run_index,
                "generated_answer": generated,
                "predicted_pairs": predicted_pairs,
            }
        )

    if args.use_provisional_gold_mapping:
        gold_pairs = extract_gold_pairs_from_mapping(
            DEFAULT_GOLD_CLASSIFICATION_PRIORITY
        )
        gold_source: dict[str, Any] = {
            "type": "provisional_mapping",
            "mapping": DEFAULT_GOLD_CLASSIFICATION_PRIORITY,
            "note": (
                "This mapping is being used as a temporary evaluation reference. "
                "Its accuracy may need further verification later."
            ),
        }
    else:
        gold_pairs = extract_gold_pairs(
            gold_alerts_text,
            default_priority=args.gold_default_priority,
        )
        gold_source = {
            "type": "raw_alert_logs",
            "assumption": (
                "Raw gold alerts do not contain explicit [Priority: x] fields. "
                f"Gold pairs were therefore normalized as (alert_message, priority={args.gold_default_priority})."
            ),
        }
    predicted_pairs = sorted(aggregated_predicted_pairs)
    pair_frequency_summary = summarize_pair_counts(predicted_pairs_by_run)
    metrics = compute_precision_recall(predicted_pairs, gold_pairs)

    result = {
        "checkpoint": args.checkpoint,
        "num_runs": args.num_runs,
        "tactics": args.tactics,
        "gold_source": gold_source,
        "prompt": prompt,
        "runs": run_outputs,
        "predicted_pairs": predicted_pairs,
        "predicted_pair_frequency_summary": pair_frequency_summary,
        "gold_pairs": gold_pairs,
        "metrics": metrics,
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
