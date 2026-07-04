"""
Export Snort alerts with protocol and endpoint fields for planner inputs.

The recovery planner needs enough network context to infer which server was
targeted. Snort's fast alert lines include protocol and source/destination
endpoints, but short summaries often drop them. This script preserves those
fields in a compact text format that can be passed as --logs-file.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from llm_ir_dt.docker_manager.docker_manager import DockerManager


def _endpoint_ip(endpoint: str) -> str:
    """Return the IP portion from a Snort endpoint string."""
    value = endpoint.strip()
    if ":" in value:
        return value.rsplit(":", 1)[0]
    return value


def _format_alert(alert: dict[str, str]) -> str:
    priority = alert.get("priority", "-")
    classification = alert.get("classification", "-")
    protocol = alert.get("protocol", "-")
    source = alert.get("source", "-")
    destination = alert.get("destination", "-")
    message = alert.get("message", alert.get("raw", "-"))
    return (
        f"Alert: [pri={priority} cls={classification}] "
        f"{{{protocol}}} {source} -> {destination} {message}"
    )


def build_text(alerts: list[dict[str, str]]) -> str:
    """Build a planner-friendly alert text block."""
    destination_counts = Counter(
        _endpoint_ip(alert.get("destination", ""))
        for alert in alerts
        if alert.get("destination")
    )
    class_counts = Counter(
        (
            alert.get("classification", "-"),
            alert.get("priority", "-"),
        )
        for alert in alerts
    )

    lines: list[str] = []
    lines.append(
        "The IDS alert stream below includes protocol, source endpoint, and "
        "destination endpoint so targeted servers can be inferred."
    )
    lines.append("")
    lines.append("Destination endpoint counts:")
    for destination, count in destination_counts.most_common():
        lines.append(f"- {destination}: {count}")
    lines.append("")
    lines.append("Classification counts:")
    for (classification, priority), count in class_counts.most_common():
        lines.append(f"- cls={classification} pri={priority}: {count}")
    lines.append("")
    lines.append("Alerts:")
    for alert in alerts:
        lines.append(_format_alert(alert))
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Export Snort alerts with protocol/source/destination fields."
    )
    parser.add_argument(
        "--output",
        default=str(ROOT / "inputs" / "logs_with_endpoints.txt"),
        help="Output text file path.",
    )
    parser.add_argument(
        "--json-output",
        default=None,
        help="Optional JSON file path for structured alerts.",
    )
    args = parser.parse_args()

    data = DockerManager.read_alerts()
    alerts = data["alerts"]
    output_path = Path(args.output).expanduser()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(build_text(alerts), encoding="utf-8")

    if args.json_output:
        json_path = Path(args.json_output).expanduser()
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(
            json.dumps({"alerts": alerts, "raw": data["raw"]}, indent=2),
            encoding="utf-8",
        )

    print(f"Exported {len(alerts)} alerts to {output_path}")
    if args.json_output:
        print(f"Exported structured alerts to {args.json_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
