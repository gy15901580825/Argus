"""What a scan did and did not test, per standard.

The findings answer "what broke". This answers the question a customer cannot
check for themselves: "what did you not look at?" A library of 193 probes can
still leave a control category with one probe in it, and a run can skip a whole
category because the target class did not match — neither fact appears anywhere
in a findings list.

Two axes, deliberately not merged into one status:

  library_status  what the probe library holds, independent of any run
  run_status      what happened to those probes this time

A cell with `library_status: thin` is a cell we can barely speak about; a cell
with `run_status: skipped` is one we said nothing about today. Collapsing them
would let a rich library hide behind a skipped run, or the reverse.
"""

from __future__ import annotations

from collections import Counter
from typing import Iterable

THIN_THRESHOLD = 2

OWASP_LLM_TOP10 = (
    ("LLM01", "Prompt Injection"),
    ("LLM02", "Sensitive Information Disclosure"),
    ("LLM03", "Supply Chain"),
    ("LLM04", "Data and Model Poisoning"),
    ("LLM05", "Improper Output Handling"),
    ("LLM06", "Excessive Agency"),
    ("LLM07", "System Prompt Leakage"),
    ("LLM08", "Vector and Embedding Weaknesses"),
    ("LLM09", "Misinformation"),
    ("LLM10", "Unbounded Consumption"),
)

# standard key -> (probe.mappings attribute, finding dict key)
_STANDARDS = (
    ("owasp-llm-top10", "owasp_llm", "owasp_id"),
    ("mitre-atlas", "atlas", "atlas_id"),
    ("nist-ai-rmf", "nist_ai_rmf", "nist_id"),
    ("eu-ai-act", "eu_ai_act", "eu_ai_act_id"),
)

_SKIPPED_ONLY_VERDICTS = {
    "skipped": "skipped",
    "blocked_by_target": "blocked_by_target",
    "aborted_cost": "aborted_cost",
}
_TESTED_VERDICTS = {"pass", "fail", "warn", "error"}


def _library_status(probes_in_library: int) -> str:
    if probes_in_library == 0:
        return "absent"
    if probes_in_library <= THIN_THRESHOLD:
        return "thin"
    return "covered"


def _run_status(verdicts: set[str]) -> str:
    if not verdicts:
        return "not_run"
    for verdict, status in _SKIPPED_ONLY_VERDICTS.items():
        if verdicts <= {verdict}:
            return status
    if verdicts <= _TESTED_VERDICTS:
        return "tested"
    return "mixed"


def _build_standard(cell_key: str, finding_key: str, probes: list, findings: list[dict] | None,
                     *, closed_universe: tuple[tuple[str, str], ...] | None) -> dict:
    library_probe_ids: dict[str, set[str]] = {}
    if closed_universe is not None:
        for cell_id, _name in closed_universe:
            library_probe_ids[cell_id] = set()

    for probe in probes:
        for cell_id in getattr(probe.mappings, cell_key):
            library_probe_ids.setdefault(cell_id, set()).add(probe.id)

    run_probe_ids: dict[str, set[str]] = {}
    run_verdicts: dict[str, Counter] = {}
    if findings is not None:
        for finding in findings:
            for cell_id in finding.get(finding_key, ()):
                run_probe_ids.setdefault(cell_id, set()).add(finding["probe_id"])
                run_verdicts.setdefault(cell_id, Counter())[finding["verdict"]] += 1

    if closed_universe is not None:
        cell_ids = [cell_id for cell_id, _name in closed_universe]
    else:
        cell_ids = sorted(set(library_probe_ids) | set(run_probe_ids))

    names = dict(closed_universe) if closed_universe is not None else {}

    cells = []
    for cell_id in cell_ids:
        probes_in_library = len(library_probe_ids.get(cell_id, ()))
        verdict_counts = run_verdicts.get(cell_id, Counter())
        cell = {
            "id": cell_id,
            "probes_in_library": probes_in_library,
            "probes_run": len(run_probe_ids.get(cell_id, ())),
            "library_status": _library_status(probes_in_library),
            "run_status": _run_status(set(verdict_counts)),
            "verdicts": dict(verdict_counts),
        }
        if cell_id in names:
            cell["name"] = names[cell_id]
        cells.append(cell)

    return {
        "universe": "closed" if closed_universe is not None else "open",
        "cells": cells,
    }


def build_coverage(probes: Iterable, findings: Iterable[dict] | None = None) -> dict:
    probes = list(probes)
    findings = list(findings) if findings is not None else None

    standards = {}
    for standard_key, mappings_attr, finding_key in _STANDARDS:
        closed_universe = OWASP_LLM_TOP10 if standard_key == "owasp-llm-top10" else None
        standards[standard_key] = _build_standard(
            mappings_attr, finding_key, probes, findings, closed_universe=closed_universe
        )

    probes_run = len({f["probe_id"] for f in findings}) if findings is not None else 0

    return {
        "thin_threshold": THIN_THRESHOLD,
        "totals": {
            "probes_in_library": len(probes),
            "probes_run": probes_run,
        },
        "standards": standards,
    }
