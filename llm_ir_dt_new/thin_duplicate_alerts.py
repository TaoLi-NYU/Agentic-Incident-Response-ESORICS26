from __future__ import annotations

import argparse
import math
from collections import Counter
from pathlib import Path


def alert_key(line: str) -> str | None:
    marker = "Alert:"
    if marker not in line:
        return None
    return line[line.index(marker) :].strip()


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Reduce repeated alert lines while preserving original log text. "
            "Non-alert lines are copied unchanged."
        )
    )
    parser.add_argument("--input", required=True, help="Input log file.")
    parser.add_argument("--output", required=True, help="Output log file.")
    parser.add_argument(
        "--keep-fraction",
        type=float,
        default=0.5,
        help="Fraction of each duplicate alert group to keep. Default: 0.5.",
    )
    args = parser.parse_args()

    if args.keep_fraction <= 0.0 or args.keep_fraction > 1.0:
        raise ValueError("--keep-fraction must be greater than 0 and at most 1.")

    input_path = Path(args.input)
    output_path = Path(args.output)
    lines = input_path.read_text(encoding="utf-8").splitlines()

    total_by_key: Counter[str] = Counter()
    for line in lines:
        key = alert_key(line)
        if key is not None:
            total_by_key[key] += 1

    kept_by_key: Counter[str] = Counter()
    output_lines: list[str] = []
    for line in lines:
        key = alert_key(line)
        if key is None:
            output_lines.append(line)
            continue

        keep_limit = max(1, math.ceil(total_by_key[key] * args.keep_fraction))
        if kept_by_key[key] < keep_limit:
            output_lines.append(line)
            kept_by_key[key] += 1

    output_path.write_text("\n".join(output_lines) + "\n", encoding="utf-8")

    original_alerts = sum(total_by_key.values())
    kept_alerts = sum(kept_by_key.values())
    print(f"Read lines: {len(lines)}")
    print(f"Original alert lines: {original_alerts}")
    print(f"Kept alert lines: {kept_alerts}")
    print(f"Wrote: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
