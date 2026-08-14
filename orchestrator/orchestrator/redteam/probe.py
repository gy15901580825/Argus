"""Probe dataclass + YAML loader."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

import yaml


VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}
# Two vocabularies are live: the Plan 2 hyphenated names that the shipped probe
# YAMLs use, and the Plan 4 underscored names the target adapters advertise in
# `compatible_classes` (runner.py does its skip/compat check against those). The
# loader must accept both, or a probe written in the newer convention is rejected
# at load time and never reaches an adapter — see tests/test_redteam_probe.py
# ::test_valid_target_classes_covers_every_adapter, which fails if they drift.
VALID_TARGET_CLASSES = {
    # Plan 2 (probe YAMLs)
    "http-chat", "browser-using", "tool-using", "rag", "multi-agent", "http-upload",
    # Plan 4 (target adapters)
    "llm_chat", "agent_with_tools", "agent_with_rag", "browser_using_agent",
}


@dataclass(frozen=True)
class ProbeMappings:
    atlas: tuple[str, ...] = field(default_factory=tuple)
    owasp_llm: tuple[str, ...] = field(default_factory=tuple)
    nist_ai_rmf: tuple[str, ...] = field(default_factory=tuple)
    eu_ai_act: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class Probe:
    id: str
    name: str
    target_class: tuple[str, ...]
    attack_class: tuple[str, ...]
    severity: str
    prompts: tuple[str, ...]
    mappings: ProbeMappings
    judge_model: str
    # judge_rubric_path: resolution (relative path → absolute) is the judge's responsibility, not the loader's.
    judge_rubric_path: str
    # Browser-use probes carry an extra `scenario` block: kind + payload.
    # Static-prompt probes (Plan 2) leave this as None.
    scenario_kind: str | None = None
    scenario_payload: str = ""
    # When True, `prompts` are consecutive turns of ONE conversation rather than
    # independent single shots. Requires a target with supports_history=True;
    # the runner emits verdict=skipped otherwise.
    conversation: bool = False


def load_probe(path: Path) -> Probe:
    raw = yaml.safe_load(Path(path).read_text())
    try:
        if raw["severity"] not in VALID_SEVERITIES:
            raise ValueError(f"invalid severity {raw['severity']!r} in {path}")
        for tc in raw["target_class"]:
            if tc not in VALID_TARGET_CLASSES:
                raise ValueError(f"invalid target_class {tc!r} in {path}")
        scenario_kind = None
        scenario_payload = ""
        if "scenario" in raw:
            scenario_kind = raw["scenario"].get("kind")
            scenario_payload = raw["scenario"].get("payload", "")
        return Probe(
            id=raw["id"],
            name=raw["name"],
            target_class=tuple(raw["target_class"]),
            attack_class=tuple(raw["attack_class"]),
            severity=raw["severity"],
            prompts=tuple(raw["prompts"]),
            mappings=ProbeMappings(
                atlas=tuple(raw.get("mappings", {}).get("atlas", [])),
                owasp_llm=tuple(raw.get("mappings", {}).get("owasp_llm", [])),
                nist_ai_rmf=tuple(raw.get("mappings", {}).get("nist_ai_rmf", [])),
                eu_ai_act=tuple(raw.get("mappings", {}).get("eu_ai_act", [])),
            ),
            judge_model=raw.get("judge", {}).get("model", "claude-haiku-4-5-20251001"),
            judge_rubric_path=raw.get("judge", {}).get("rubric_path", "rubrics/default.md"),
            scenario_kind=scenario_kind,
            scenario_payload=scenario_payload,
            conversation=bool(raw.get("conversation", False)),
        )
    except KeyError as exc:
        raise ValueError(f"missing required key {exc.args[0]!r} in {path}") from exc


def load_all_probes(probes_dir: Path) -> Iterator[Probe]:
    for path in sorted(Path(probes_dir).rglob("*.yaml")):
        yield load_probe(path)
