"""Read a local run record and compare probe outcomes without a server."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable

import click

from argus.cli import run_json
from argus.cli.baseline_key import baseline_key
from argus.cli.severity import SEVERITY_ORDER


def load_baseline(file: str, spec: dict, mode: str, secret_values: Iterable[str] = ()) -> dict:
    """Validate the baseline before starting a target or making a paid call."""
    try:
        record = json.loads(Path(file).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise click.UsageError(f"--baseline {file}: cannot read run.json ({exc})") from None

    def invalid(reason: str) -> None:
        raise click.UsageError(f"--baseline {file}: {reason}")

    if not isinstance(record, dict) or record.get("schema_version") != run_json.SCHEMA_VERSION:
        invalid(f"expected schema_version {run_json.SCHEMA_VERSION!r}")
    if not isinstance(record.get("target_spec"), dict):
        invalid("target_spec must be an object")
    if not isinstance(record.get("id"), str) or not isinstance(record.get("finished_at"), str):
        invalid("id and finished_at must be strings")
    findings = record.get("findings")
    if not isinstance(findings, list) or any(
        not isinstance(f, dict) or not isinstance(f.get("probe_id"), str) or not f["probe_id"]
        or not isinstance(f.get("verdict"), str) or f.get("severity") not in SEVERITY_ORDER
        for f in findings
    ):
        invalid("findings must contain probe_id, verdict and severity for each result")
    if "deep" in record and not isinstance(record["deep"], dict):
        invalid("deep must be an object")
    baseline_mode = "deep" if "deep" in record else "static"
    if baseline_mode != mode:
        invalid(f"mode mismatch: baseline is {baseline_mode}, current run is {mode}")

    if "baseline_key" in record:
        key = record["baseline_key"]
        if not isinstance(key, str) or not re.fullmatch(r"[0-9a-f]{32}", key):
            invalid("baseline_key must be a 32-character hexadecimal string")
        same_target = key == baseline_key(spec)
    else:
        # 1.9.0 has no stored key. Apply its redaction to the current spec too:
        # an expanded env value can be masked inside an otherwise public field.
        redacted = run_json.scrub_run({"target_spec": spec}, secret_values)["target_spec"]
        same_target = baseline_key(record["target_spec"]) in {baseline_key(spec), baseline_key(redacted)}
    if not same_target:
        invalid("target mismatch: the baseline tests a different target")
    return record


def _by_probe(findings: list[dict]) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = {}
    for finding in findings:
        grouped.setdefault(finding["probe_id"], []).append(finding)
    return grouped


def _failures(grouped: dict[str, list[dict]]) -> dict[str, str]:
    failures = {}
    for pid, findings in grouped.items():
        failing = [f for f in findings if f.get("verdict") == "fail"]
        if failing:
            failures[pid] = max(
                (f.get("severity", "info") for f in failing),
                key=lambda s: SEVERITY_ORDER.index(s) if s in SEVERITY_ORDER else 0,
            )
    return failures


def compare_baseline(baseline: dict, findings: list[dict]) -> dict:
    """One outcome per probe; failing trials win over passes and errors."""
    head = _by_probe(findings)
    old_failing = _failures(_by_probe(baseline["findings"]))
    new_failing = _failures(head)
    result = {"id": baseline["id"], "finished_at": baseline["finished_at"],
              "new": [], "fixed": [], "still_failing": [], "not_run": []}
    for pid in sorted(old_failing.keys() | new_failing.keys()):
        if pid in new_failing:
            category = "still_failing" if pid in old_failing else "new"
            severity = new_failing[pid]
        else:
            category = "fixed" if pid in head and all(f.get("verdict") in {"pass", "warn"} for f in head[pid]) else "not_run"
            severity = old_failing[pid]
        result[category].append({"probe_id": pid, "severity": severity})
    return result


def comparison_summary(comparison: dict) -> str:
    return (f"new: {len(comparison['new'])}, fixed: {len(comparison['fixed'])}, "
            f"still failing: {len(comparison['still_failing'])}, not run: {len(comparison['not_run'])}")


def new_failure_findings(comparison: dict) -> list[dict]:
    return [{"verdict": "fail", **item} for item in comparison["new"]]
