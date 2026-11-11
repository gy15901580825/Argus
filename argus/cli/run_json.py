"""run.json: a versioned, redacted record of one run. Field list and rules: docs/run-json.md."""
from __future__ import annotations

import json
from datetime import date, datetime
from importlib.metadata import PackageNotFoundError, version
from typing import Any, Iterable
from uuid import UUID

from argus.redaction import (
    MASK, _SECRET_KEY_SUFFIXES, _SECRET_KEY_PARTS, _is_secret_key, _is_header_key, _strings, _mask_headers,
    _redact, redact, _ordered, mask_text, run_secrets, _scrub,
)
from argus.coverage import build_summary
from argus.deep_thread import THREAD_STRUCTURE_FIELDS, ROUND_STRUCTURE_FIELDS, ROUND_FIELDS, is_deep_finding
from argus.events import EVENT_STRUCTURE_FIELDS, normalize_redacted_event

SCHEMA_VERSION = "argus.run/1"
# Engine-generated fields put back after the scrub, so a short env value cannot mangle them.
_RUN_FIELDS = ("id", "status", "started_at", "finished_at", "coverage", "baseline_key", "baseline")
_FINDING_FIELDS = ("id", "probe_id", "verdict", "severity", "probed_at", "created_at",
                   "confidence", "target_latency_ms", "atlas_id", "owasp_id", "owasp_agentic", "nist_id", "eu_ai_act_id",
                   "judge_model", "escalated_model", "remediation", "remediation_actions")

_EVENT_FIELDS = EVENT_STRUCTURE_FIELDS


def _default(obj: Any) -> Any:
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, UUID):
        return str(obj)
    if isinstance(obj, (bytes, bytearray)):
        return bytes(obj).decode("utf-8", "replace")
    return str(obj)  # never lose a finished run over an odd evidence type


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
    if isinstance(plain.get("deep"), dict):
        _restore(out, plain, ("deep",))
    _restore(out["target_spec"], plain["target_spec"], ("kind",))
    for clean, orig in zip(out.get("findings") or [], plain.get("findings") or []):
        if isinstance(clean, dict) and isinstance(orig, dict):
            _restore(clean, orig, _FINDING_FIELDS)
            evidence = orig.get("evidence")
            if is_deep_finding(orig):
                freeform = {k: v for k, v in evidence.items() if k not in (*THREAD_STRUCTURE_FIELDS, "transcript")}
                preserved = _scrub(freeform, secrets, keys=True)
                _restore(preserved, evidence, THREAD_STRUCTURE_FIELDS)
                preserved["transcript"] = []
                for row in evidence["transcript"]:
                    if isinstance(row, dict):
                        safe = {key: _scrub(row[key], secrets) for key in ROUND_FIELDS if key in row}
                        _restore(safe, row, ROUND_STRUCTURE_FIELDS)
                        preserved["transcript"].append(safe)
                clean["evidence"] = preserved
            for clean_event, orig_event in zip(clean.get("events") or [], orig.get("events") or []):
                if isinstance(clean_event, dict) and isinstance(orig_event, dict):
                    _restore(clean_event, orig_event, _EVENT_FIELDS)
                    clean_event.update(normalize_redacted_event(clean_event))
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
        # Count after redaction restores verdict/severity, so short secrets cannot corrupt summary labels.
        "summary": build_summary(plain.get("findings", [])),
        "findings": plain.get("findings", []),
        **({"notes": plain["notes"]} if include_notes and plain.get("notes") else {}),
        **({"judge": plain["judge"]} if plain.get("judge") else {}),
        **({"target_cleanup": plain["target_cleanup"]} if plain.get("target_cleanup") is not None else {}),
        **({"deep": plain["deep"]} if plain.get("deep") is not None else {}),
        **({"baseline_key": plain["baseline_key"]} if "baseline_key" in plain else {}),
        **({"baseline": plain["baseline"]} if "baseline" in plain else {}),
    }
    return json.dumps(record, indent=2, ensure_ascii=False)
