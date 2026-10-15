"""Severity ranking for --fail-on."""
from __future__ import annotations

SEVERITY_ORDER: tuple[str, ...] = ("info", "low", "medium", "high", "critical")


def _rank(severity) -> int:
    # Anything the server did not label (None, unknown string) ranks lowest, so a
    # gate on "low" or above never trips on an unlabelled finding.
    try:
        return SEVERITY_ORDER.index(severity)
    except ValueError:
        return 0


def findings_at_or_above(findings: list[dict], threshold: str) -> list[dict]:
    """Findings with verdict "fail" whose severity ranks at or above `threshold`."""
    floor = SEVERITY_ORDER.index(threshold)
    return [
        f for f in findings
        if f.get("verdict") == "fail" and _rank(f.get("severity")) >= floor
    ]
