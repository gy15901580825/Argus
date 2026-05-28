"""Extract a JSON object from the tail of an LLM phase output."""
from __future__ import annotations

import json
import re

_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)
_BARE_RE = re.compile(r"(\{.*\})\s*$", re.DOTALL)


def extract_json_tail(text: str) -> dict:
    """Parse the LAST ```json ... ``` fenced block, or a trailing bare object.

    Returns {} on any failure — phase runner decides whether that is fatal.
    """
    if not text:
        return {}

    fences = _FENCE_RE.findall(text)
    if fences:
        try:
            return json.loads(fences[-1])
        except json.JSONDecodeError:
            pass

    m = _BARE_RE.search(text.strip())
    if m:
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            pass

    return {}
