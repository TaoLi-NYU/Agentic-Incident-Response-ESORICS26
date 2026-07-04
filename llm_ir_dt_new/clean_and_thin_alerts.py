from __future__ import annotations

import argparse
import math
import re
from collections import Counter
from pathlib import Path


RUN_ATTACK_SUFFIX_RE = re.compile(r"\s+\(run_attack\.py:113\)\s*$")


def clean_line(line: str) -> str:
    return RUN_ATTACK_SUFFIX_RE.sub("", line.rstrip())


def alert_key(line: str) -> str | None:
    marker = "Alert:"
    if marker not in line:
        return None
    return line[line.index(marker) :].strip()


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Remove run_attack.py source suffixes and thin duplicate alert lines "
            "while preserving original alert text otherwise."
        )
    )
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--keep-fraction", type=float, default=0.5)
    parser.add_argument(
        "--alerts-only",
        action="store_true",
        help="Write only Alert: lines and drop all non-alert text.",
    )
    args = parser.parse_args()

    if args.keep_fraction <= 0.0 or args.keep_fraction > 1.0:
        raise ValueError("--keep-fraction must be greater than 0 and at most 1.")

    input_path = Path(args.input)
    output_path = Path(args.output)
    lines = [clean_line(line) for line in input_path.read_text(encoding="utf-8").splitlines()]

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
            if not args.alerts_only:
                output_lines.append(line)
            continue

        keep_limit = max(1, math.ceil(total_by_key[key] * args.keep_fraction))
        if kept_by_key[key] < keep_limit:
            output_lines.append(line)
            kept_by_key[key] += 1

    output_path.write_text("\n".join(output_lines) + "\n", encoding="utf-8")

    print(f"Read lines: {len(lines)}")
    print(f"Original alert lines: {sum(total_by_key.values())}")
    print(f"Kept alert lines: {sum(kept_by_key.values())}")
    print(f"Wrote: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
