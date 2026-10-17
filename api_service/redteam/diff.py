"""Compare two runs' findings by probe: what newly fails, what got fixed."""
from __future__ import annotations

SEVERITY_ORDER: tuple[str, ...] = ("info", "low", "medium", "high", "critical")


def _rank(severity) -> int:
    try:
        return SEVERITY_ORDER.index(severity)
    except ValueError:
        return 0


def failing_probes(findings: list[dict]) -> dict[str, str]:
    """probe_id -> highest severity among its `fail` findings."""
    out: dict[str, str] = {}
    for f in findings:
        if f.get("verdict") != "fail":
            continue
        pid = f.get("probe_id")
        sev = f.get("severity") if f.get("severity") in SEVERITY_ORDER else "info"
        if pid not in out or _rank(sev) > _rank(out[pid]):
            out[pid] = sev
    return out


def compare(base: list[dict] | None, head: list[dict]) -> dict:
    head_fail = failing_probes(head)
    base_fail = failing_probes(base or [])
    head_ran = {f.get("probe_id") for f in head}

    def items(ids, sev_from):
        return [{"probe_id": p, "severity": sev_from[p]} for p in sorted(ids)]

    return {
        "new": items(set(head_fail) - set(base_fail), head_fail),
        "fixed": items({p for p in base_fail if p in head_ran and p not in head_fail}, base_fail),
        "still_failing": items(set(head_fail) & set(base_fail), head_fail),
        "not_run": items({p for p in base_fail if p not in head_ran}, base_fail),
    }
