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


def incomplete_lines(findings: list[dict], stopped_by: str | None = None) -> list[str]:
    """Why a run is incomplete, for the console and the report; empty when it is complete.

    Keys off `error` findings and an early stop only: blocked, skipped and
    aborted_cost probes are outcomes, not probes that failed to run.
    """
    lines: list[str] = []
    errors = [f for f in findings if f.get("verdict") == "error"]
    if errors:
        probes = {f.get("probe_id") for f in findings}
        errored = {f.get("probe_id") for f in errors}
        lines.append(f"{len(errored)} of {len(probes)} probes errored; run incomplete")
        reasons = list(dict.fromkeys(str(f.get("reasoning") or "no reason given") for f in errors))
        lines += [f"  {r}" for r in reasons[:3]]
    if stopped_by:
        lines.append(f"Run stopped early: {stopped_by}. The report covers only the probes that ran.")
    return lines
