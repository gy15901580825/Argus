"""Stable id of what a run tests (target and probe set), so a baseline only matches like with like."""
from __future__ import annotations

import hashlib
import json

_SECRET_WORDS = ("key", "token", "secret", "password", "auth", "header", "cookie")


def _clean(value):
    if isinstance(value, dict):
        return {k: _clean(v) for k, v in value.items() if not any(w in str(k).lower() for w in _SECRET_WORDS)}
    if isinstance(value, list):
        return [_clean(v) for v in value]
    return value


def baseline_key(target: dict, probe_ids: list[str]) -> str:
    payload = {"target": _clean(target), "probes": sorted(probe_ids) or ["all"]}
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()[:32]
