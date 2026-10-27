"""run.json: a versioned, redacted record of one run. Field list and rules: docs/run-json.md."""
from __future__ import annotations

import json
from datetime import date, datetime
from importlib.metadata import PackageNotFoundError, version
from typing import Any, Iterable
from uuid import UUID

SCHEMA_VERSION = "argus.run/1"
MASK = "***"
_SECRET_KEY_SUFFIXES = ("_key", "token", "secret", "password")


def _default(obj: Any) -> Any:
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, UUID):
        return str(obj)
    if isinstance(obj, (bytes, bytearray)):
        return bytes(obj).decode("utf-8", "replace")
    return str(obj)  # never lose a finished run over an odd evidence type


def _is_secret_key(key: str) -> bool:
    return key == "api_key" or key.endswith(_SECRET_KEY_SUFFIXES)


def _is_header_key(key: str) -> bool:
    return key == "headers" or key.endswith("_headers")


def _mask_headers(value: Any) -> Any:
    # Keep header names, mask every value: {"Name": v} or [["Name", v], ...].
    if isinstance(value, dict):
        return {k: MASK for k in value}
    if isinstance(value, list):
        return [[item[0], *([MASK] * (len(item) - 1))] if isinstance(item, (list, tuple)) and item else MASK
                for item in value]
    return MASK


def redact(spec: dict) -> dict:
    """Mask secret-named keys and header values in a target spec. Returns a new dict."""
    def walk(value: Any) -> Any:
        if isinstance(value, dict):
            out = {}
            for k, v in value.items():
                if isinstance(k, str) and _is_secret_key(k):
                    out[k] = MASK
                elif isinstance(k, str) and _is_header_key(k):
                    out[k] = _mask_headers(v)
                else:
                    out[k] = walk(v)
            return out
        if isinstance(value, list):
            return [walk(v) for v in value]
        return value
    return walk(spec)


def _scrub(value: Any, secrets: list[str]) -> Any:
    """Replace every secret value inside every string (dict keys included), longest first."""
    if isinstance(value, str):
        for s in secrets:
            value = value.replace(s, MASK)
        return value
    if isinstance(value, dict):
        return {_scrub(k, secrets): _scrub(v, secrets) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub(v, secrets) for v in value]
    return value


def _argus_version() -> str:
    try:
        return version("argus-probe")
    except PackageNotFoundError:  # running from a source tree that was never installed
        return "unknown"


def render_json(run: dict, secret_values: Iterable[str] = ()) -> str:
    # Key-name rule first, so scrubbing a key name cannot hide it from that rule.
    run = {**run, "target_spec": redact(run.get("target_spec") or {})}
    plain = json.loads(json.dumps(run, default=_default))
    secrets = sorted({s for s in secret_values if s}, key=len, reverse=True)
    plain = _scrub(plain, secrets)
    record = {
        # Fixed values are set after scrubbing so a short env value (say "1") cannot corrupt them.
        "schema_version": SCHEMA_VERSION,
        "id": plain.get("id"),
        "status": plain.get("status"),
        "started_at": plain.get("started_at"),
        "finished_at": plain.get("finished_at"),
        "argus_version": _argus_version(),
        "target_spec": plain["target_spec"],
        "coverage": plain.get("coverage"),
        "findings": plain.get("findings", []),
    }
    return json.dumps(record, indent=2, ensure_ascii=False)
