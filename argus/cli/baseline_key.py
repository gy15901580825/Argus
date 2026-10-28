"""Stable id of the target a run tests, so a baseline only matches runs against the same target."""
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


# Where browser_use's trap page listens is a deployment detail, not the target's identity.
_DEPLOYMENT_KEYS = ("trap_host", "trap_port", "trap_public_url")


def baseline_key(target: dict) -> str:
    target = {k: v for k, v in target.items() if k not in _DEPLOYMENT_KEYS}
    return hashlib.sha256(json.dumps(_clean(target), sort_keys=True).encode()).hexdigest()[:32]
