"""Utilities for parsing model-generated high-level actions."""

from __future__ import annotations

import json
import re
from typing import Any

from llm_ir_dt.recovery_loop.schemas import HighLevelAction


def _extract_json_objects(text: str) -> list[dict[str, Any]]:
    decoder = json.JSONDecoder()
    objects: list[dict[str, Any]] = []
    for match in re.finditer(r"\{", text):
        try:
            obj, _ = decoder.raw_decode(text[match.start():])
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            objects.append(obj)
    return objects


def parse_high_level_action(raw_output: str) -> HighLevelAction:
    """
    Parse one model output into a clean action plus explanation.

    The local model is prompted to emit JSON with ``Action`` and ``Explanation``.
    If JSON parsing fails, the raw output is used as the action text.
    """
    raw = raw_output.strip()
    for obj in reversed(_extract_json_objects(raw)):
        action = str(obj.get("Action") or obj.get("action") or "").strip()
        explanation = str(
            obj.get("Explanation") or obj.get("explanation") or ""
        ).strip()
        if action:
            return HighLevelAction(
                action=action,
                explanation=explanation,
                raw_model_output=raw_output,
            )

    return HighLevelAction(action=raw, explanation="", raw_model_output=raw_output)


def deduplicate_actions(actions: list[HighLevelAction]) -> list[HighLevelAction]:
    """Deduplicate actions by normalized action text, preserving order."""
    seen: set[str] = set()
    deduped: list[HighLevelAction] = []
    for action in actions:
        key = re.sub(r"\s+", " ", action.action.strip().lower())
        if key and key not in seen:
            seen.add(key)
            deduped.append(action)
    return deduped
