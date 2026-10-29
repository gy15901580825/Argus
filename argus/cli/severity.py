"""Severity ranking for --fail-on."""
from __future__ import annotations

import re
from collections import Counter

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

    Keys off `error` and `aborted_cost` findings and an early stop only: blocked
    and skipped probes are outcomes, not probes that failed to run.
    """
    lines: list[str] = []
    aborted = {f.get("probe_id") for f in findings if f.get("verdict") == "aborted_cost"}
    if aborted:
        lines.append(f"{len(aborted)} probe(s) stopped at the cost cap; run incomplete")
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


def hit_cost_cap(findings: list[dict]) -> bool:
    """An iterative probe that hit the cap records `aborted_cost` and the run goes on; it still exits 4."""
    return any(f.get("verdict") == "aborted_cost" for f in findings)


_BLOCKED_CODE = re.compile(r"target returned HTTP (\d+) to the attack prompt")


def blocked_warning(findings: list[dict]) -> str | None:
    """A warning when nearly every finding was blocked with one status code.

    A target that answers every prompt with the same 4xx is usually rejecting the
    request format, not the attack. The verdicts and the exit code stay as they are.
    """
    codes = Counter(m.group(1) for f in findings if f.get("verdict") == "blocked_by_target"
                    and (m := _BLOCKED_CODE.search(str(f.get("reasoning") or ""))))
    if not codes:
        return None
    code, n = codes.most_common(1)[0]
    if n < 5 or n < 0.9 * len(findings):
        return None
    every = "every" if n == len(findings) else "almost every"
    return f"{every} probe was blocked with HTTP {code}; check the request format"
