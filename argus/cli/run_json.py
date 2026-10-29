"""run.json: a versioned, redacted record of one run. Field list and rules: docs/run-json.md."""
from __future__ import annotations

import json
from datetime import date, datetime
from importlib.metadata import PackageNotFoundError, version
from typing import Any, Iterable
from uuid import UUID

SCHEMA_VERSION = "argus.run/1"
MASK = "***"
# Matched against the key lowercased with "_" and "-" removed, so apiKey, API_KEY and api-key
# all match. Ending in "token" masks accessToken but not max_tokens.
_SECRET_KEY_SUFFIXES = ("key", "token", "authheader")
_SECRET_KEY_PARTS = ("secret", "password", "authorization", "credential", "cookie")
# Engine-generated fields put back after the scrub, so a short env value cannot mangle them.
_RUN_FIELDS = ("id", "status", "started_at", "finished_at", "coverage")
_FINDING_FIELDS = ("id", "probe_id", "verdict", "severity", "probed_at", "created_at",
                   "confidence", "target_latency_ms", "atlas_id", "owasp_id", "nist_id", "eu_ai_act_id",
                   "judge_model", "escalated_model", "remediation")


def _default(obj: Any) -> Any:
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, UUID):
        return str(obj)
    if isinstance(obj, (bytes, bytearray)):
        return bytes(obj).decode("utf-8", "replace")
    return str(obj)  # never lose a finished run over an odd evidence type


def _is_secret_key(key: str) -> bool:
    k = key.lower().replace("_", "").replace("-", "")
    return k.endswith(_SECRET_KEY_SUFFIXES) or any(p in k for p in _SECRET_KEY_PARTS)


def _is_header_key(key: str) -> bool:
    return key.lower().endswith("headers")


def _strings(value: Any, out: list[str]) -> None:
    """Collect every string inside a masked value, plus the credential after a scheme like "Bearer "."""
    if isinstance(value, str):
        out.append(value)
        if " " in value.strip():
            out.append(value.strip().split(" ", 1)[1].strip())
    elif isinstance(value, dict):
        for v in value.values():
            _strings(v, out)
    elif isinstance(value, (list, tuple)):
        for v in value:
            _strings(v, out)


def _mask_headers(value: Any, masked: list[str]) -> Any:
    # Keep header names, mask every value: {"Name": v} or [["Name", v], ...].
    if isinstance(value, dict):
        _strings(list(value.values()), masked)
        return {k: MASK for k in value}
    if isinstance(value, list):
        out = []
        for item in value:
            if isinstance(item, (list, tuple)) and item:
                _strings(list(item[1:]), masked)
                out.append([item[0], *([MASK] * (len(item) - 1))])
            else:
                _strings(item, masked)
                out.append(MASK)
        return out
    _strings(value, masked)
    return MASK


def _redact(spec: dict) -> tuple[dict, list[str]]:
    masked: list[str] = []

    def walk(value: Any) -> Any:
        if isinstance(value, dict):
            out = {}
            for k, v in value.items():
                if isinstance(k, str) and _is_header_key(k):
                    out[k] = _mask_headers(v, masked)
                elif isinstance(k, str) and _is_secret_key(k):
                    _strings(v, masked)
                    out[k] = MASK
                else:
                    out[k] = walk(v)
            return out
        if isinstance(value, list):
            return [walk(v) for v in value]
        return value
    return walk(spec), masked


def redact(spec: dict) -> dict:
    """Mask secret-named keys and header values in a target spec. Returns a new dict."""
    return _redact(spec)[0]


def _ordered(values: Iterable[str]) -> list[str]:
    # Longest first, so a secret that contains another is masked whole.
    return sorted({s for s in values if s and s != MASK}, key=len, reverse=True)


def mask_text(text: str, secrets: list[str]) -> str:
    """Replace every value of `secrets` (as returned by run_secrets) inside `text`."""
    for s in secrets:
        text = text.replace(s, MASK)
    return text


def run_secrets(target_spec: dict, secret_values: Iterable[str] = ()) -> list[str]:
    """Every value scrub_run masks for this spec: `secret_values` plus the spec's secret-named literals."""
    return _ordered((*secret_values, *_redact(target_spec or {})[1]))


def _scrub(value: Any, secrets: list[str], keys: bool = False) -> Any:
    """Replace every secret value inside every string, longest first. Dict keys too when `keys`."""
    if isinstance(value, str):
        return mask_text(value, secrets)
    if isinstance(value, dict):
        out: dict = {}
        for k, v in value.items():
            new_k = _scrub(k, secrets) if keys and isinstance(k, str) else k
            base, n = new_k, 1
            while new_k in out:  # two keys that mask to the same text: keep both
                n += 1
                new_k = f"{base}#{n}"
            out[new_k] = _scrub(v, secrets, keys)
        return out
    if isinstance(value, list):
        return [_scrub(v, secrets, keys) for v in value]
    return value


def _restore(dst: dict, src: dict, fields: tuple[str, ...]) -> None:
    for f in fields:
        if f in src:
            dst[f] = src[f]


def scrub_run(run: dict, secret_values: Iterable[str] = ()) -> dict:
    """Return a plain-JSON copy of `run` with secrets masked. Every report format renders from this.

    Masks secret-named keys and header values in target_spec, then every occurrence of those
    literal values and of `secret_values` in every string of the run."""
    spec, literal = _redact(run.get("target_spec") or {})
    plain = json.loads(json.dumps({**run, "target_spec": spec}, default=_default))
    secrets = _ordered((*secret_values, *literal))
    out = _scrub(plain, secrets)
    # Evidence is free-form and may key on a secret; schema keys elsewhere must stay intact.
    for f in out.get("findings") or []:
        if isinstance(f, dict) and "evidence" in f:
            f["evidence"] = _scrub(f["evidence"], secrets, keys=True)
    _restore(out, plain, _RUN_FIELDS)
    _restore(out["target_spec"], plain["target_spec"], ("kind",))
    for clean, orig in zip(out.get("findings") or [], plain.get("findings") or []):
        if isinstance(clean, dict) and isinstance(orig, dict):
            _restore(clean, orig, _FINDING_FIELDS)
    return out


def _argus_version() -> str:
    try:
        return version("argus-probe")
    except PackageNotFoundError:  # running from a source tree that was never installed
        return "unknown"


def render_json(run: dict, secret_values: Iterable[str] = (), include_notes: bool = False) -> str:
    """`include_notes`: `run` writes its few run notes; scan-mcp's notes list every tool and stay out."""
    plain = scrub_run(run, secret_values)
    record = {
        "schema_version": SCHEMA_VERSION,
        "id": plain.get("id"),
        "status": plain.get("status"),
        # Optional keys (format version 1 only grows): present only when they say something.
        **({"incomplete_reason": plain["incomplete_reason"]} if plain.get("incomplete_reason") else {}),
        "started_at": plain.get("started_at"),
        "finished_at": plain.get("finished_at"),
        "argus_version": _argus_version(),
        "target_spec": plain["target_spec"],
        "coverage": plain.get("coverage"),
        "findings": plain.get("findings", []),
        **({"notes": plain["notes"]} if include_notes and plain.get("notes") else {}),
    }
    return json.dumps(record, indent=2, ensure_ascii=False)
