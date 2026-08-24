"""Scan suites derived from what a probe already declares.

Two dimensions, both reverse indexes over data the probe YAMLs already carry:
standards mappings (`owasp-llm-top10`, ...) and attack-class tags (`payments`).
A probe can join suites on both; the dimensions add, they do not partition.

A suite is a reverse index over `ProbeMappings`: a probe joins a suite when the
corresponding mapping field is non-empty. Suite ids are fixed constants, one per
mapping field — they are NOT derived from mapping values (there is one
`owasp-llm-top10` suite, not one suite per LLM0x id).

No new data and no probe YAML edits: `derive_suites` is a pure function over an
already-loaded probe list.
"""
from __future__ import annotations

from typing import Iterable

# suite id -> ProbeMappings attribute name. Order fixes the response ordering.
SUITE_MAPPING_FIELDS: dict[str, str] = {
    "owasp-llm-top10": "owasp_llm",
    "mitre-atlas": "atlas",
    "nist-ai-rmf": "nist_ai_rmf",
    "eu-ai-act": "eu_ai_act",
}

# suite id -> the attack_class tag that puts a probe in it. Standards suites
# answer "show me OWASP coverage"; these answer "run the payment tests", which
# is what a prospect asks for by name. A probe joins both — the two dimensions
# add suites, they do not partition the library.
SUITE_ATTACK_CLASSES: dict[str, str] = {
    "payments": "payment-abuse",
}

SUITE_IDS: tuple[str, ...] = tuple(SUITE_MAPPING_FIELDS) + tuple(SUITE_ATTACK_CLASSES)


def derive_suites(probes: Iterable) -> dict[str, list[str]]:
    """Reverse-index probes by which standards mappings they carry.

    Returns {suite_id: [probe_id, ...]} with probe ids sorted for stable
    ordering. A suite with zero probes is omitted entirely rather than
    returned empty, so callers can treat a present key as a runnable suite.
    """
    derived: dict[str, list[str]] = {suite_id: [] for suite_id in SUITE_IDS}
    for probe in probes:
        for suite_id, field_name in SUITE_MAPPING_FIELDS.items():
            if getattr(probe.mappings, field_name):
                derived[suite_id].append(probe.id)
        for suite_id, tag in SUITE_ATTACK_CLASSES.items():
            if tag in probe.attack_class:
                derived[suite_id].append(probe.id)
    return {suite_id: sorted(ids) for suite_id, ids in derived.items() if ids}
