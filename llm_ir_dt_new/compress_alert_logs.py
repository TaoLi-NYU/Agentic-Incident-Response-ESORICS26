from __future__ import annotations

import argparse
import re
from collections import Counter, defaultdict
from pathlib import Path


ALERT_RE = re.compile(
    r"Alert:\s+\[pri=(?P<priority>[^\s]+)\s+cls=(?P<classification>[^\]]+)\]\s+"
    r"\{(?P<protocol>[^}]+)\}\s+"
    r"(?P<source>\S+)\s+->\s+(?P<destination>\S+)\s+"
    r"(?P<message>.*)$"
)

SERVER_NAMES = {
    "10.0.2.11": "server_ssh",
    "10.0.2.12": "server_samba",
    "10.0.2.13": "server_shellshock",
    "10.0.2.14": "server_web1",
    "10.0.2.15": "server_web2",
}


def strip_port(endpoint: str) -> str:
    return endpoint.rsplit(":", 1)[0] if re.search(r":\d+$", endpoint) else endpoint


def parse_alerts(lines: list[str]) -> tuple[list[str], list[dict[str, str]]]:
    preamble: list[str] = []
    alerts: list[dict[str, str]] = []
    for line in lines:
        match = ALERT_RE.search(line)
        if not match:
            if line.strip() and not alerts:
                preamble.append(line.rstrip())
            continue

        alert = match.groupdict()
        alert["raw"] = line.rstrip()
        alert["source_ip"] = strip_port(alert["source"])
        alert["destination_ip"] = strip_port(alert["destination"])
        alerts.append(alert)
    return preamble, alerts


def add_limited_example(
    examples: dict[str, list[str]],
    key: str,
    raw: str,
    *,
    examples_per_key: int,
) -> None:
    bucket = examples[key]
    if raw not in bucket and len(bucket) < examples_per_key:
        bucket.append(raw)


def build_summary(
    preamble: list[str],
    alerts: list[dict[str, str]],
    *,
    examples_per_key: int,
    max_alert_lines: int,
) -> str:
    classification_counts: Counter[tuple[str, str]] = Counter()
    protocol_counts: Counter[str] = Counter()
    endpoint_counts: Counter[tuple[str, str, str]] = Counter()
    destination_counts: Counter[str] = Counter()
    server_counts: dict[str, Counter[tuple[str, str, str]]] = defaultdict(Counter)
    examples_by_server: dict[str, list[str]] = defaultdict(list)
    examples_by_classification: dict[str, list[str]] = defaultdict(list)

    for alert in alerts:
        classification = alert["classification"]
        priority = alert["priority"]
        protocol = alert["protocol"]
        source_ip = alert["source_ip"]
        destination_ip = alert["destination_ip"]
        message = alert["message"]

        classification_counts[(classification, priority)] += 1
        protocol_counts[protocol] += 1
        endpoint_counts[(source_ip, destination_ip, protocol)] += 1
        destination_counts[destination_ip] += 1

        if destination_ip in SERVER_NAMES:
            server_counts[destination_ip][(protocol, classification, message)] += 1
            add_limited_example(
                examples_by_server,
                destination_ip,
                alert["raw"],
                examples_per_key=examples_per_key,
            )

        add_limited_example(
            examples_by_classification,
            f"{classification} / priority {priority}",
            alert["raw"],
            examples_per_key=examples_per_key,
        )

    output: list[str] = []
    output.append("Compressed IDS alert summary for planning.")
    output.append("This file preserves counts, endpoints, priorities, and representative alerts while removing repeated duplicate alert lines.")
    output.append("")

    if preamble:
        output.append("Original narrative summary:")
        output.extend(f"- {line}" for line in preamble[:12])
        output.append("")

    output.append(f"Total parsed alerts: {len(alerts)}")
    output.append("")

    output.append("Alert counts by classification and priority:")
    for (classification, priority), count in classification_counts.most_common():
        output.append(f"- priority={priority} classification={classification}: count={count}")
    output.append("")

    output.append("Alert counts by protocol:")
    for protocol, count in protocol_counts.most_common():
        output.append(f"- {protocol}: count={count}")
    output.append("")

    output.append("Destination endpoint counts:")
    for destination, count in destination_counts.most_common():
        name = SERVER_NAMES.get(destination, "non-server-or-gateway")
        output.append(f"- {destination} ({name}): count={count}")
    output.append("")

    output.append("Top source -> destination endpoint flows:")
    for (source, destination, protocol), count in endpoint_counts.most_common(30):
        destination_name = SERVER_NAMES.get(destination, "")
        suffix = f" ({destination_name})" if destination_name else ""
        output.append(f"- {source} -> {destination}{suffix} protocol={protocol}: count={count}")
    output.append("")

    output.append("Per-server evidence:")
    for server_ip, server_name in SERVER_NAMES.items():
        output.append(f"{server_name} / {server_ip}:")
        if not server_counts.get(server_ip):
            output.append("- No parsed alerts with this server as destination.")
            output.append("")
            continue
        for (protocol, classification, message), count in server_counts[server_ip].most_common():
            output.append(
                f"- count={count} protocol={protocol} priority/classification={classification} message={message}"
            )
        output.append("- Representative alerts:")
        for raw in examples_by_server.get(server_ip, []):
            output.append(f"  {raw}")
        output.append("")

    output.append("Representative alerts by classification:")
    emitted = 0
    for classification_key, examples in examples_by_classification.items():
        if emitted >= max_alert_lines:
            break
        output.append(f"{classification_key}:")
        for raw in examples:
            if emitted >= max_alert_lines:
                break
            output.append(f"- {raw}")
            emitted += 1
    output.append("")

    return "\n".join(output).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compress repeated IDS alert logs into a concise planner-friendly summary."
    )
    parser.add_argument("--input", required=True, help="Input log file.")
    parser.add_argument("--output", required=True, help="Output summary file.")
    parser.add_argument("--examples-per-key", type=int, default=3)
    parser.add_argument("--max-alert-lines", type=int, default=80)
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)
    lines = input_path.read_text(encoding="utf-8").splitlines()
    preamble, alerts = parse_alerts(lines)
    summary = build_summary(
        preamble,
        alerts,
        examples_per_key=args.examples_per_key,
        max_alert_lines=args.max_alert_lines,
    )
    output_path.write_text(summary, encoding="utf-8")
    print(f"Read {len(lines)} lines from {input_path}")
    print(f"Parsed {len(alerts)} alerts")
    print(f"Wrote compressed summary to {output_path}")
    print(f"Output bytes: {len(summary.encode('utf-8'))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
