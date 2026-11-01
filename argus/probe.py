"""Probe dataclass + YAML loader."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field, replace
from importlib.metadata import entry_points
from pathlib import Path
from typing import Iterator

import yaml

from argus.world_assertions import DECISION_PREDICATES
from argus.a2a.world import (
    CAPABILITIES as A2A_CAPABILITIES,
    DECISION_PREDICATES as A2A_DECISION_PREDICATES,
)
from argus.agentic import VALID_OWASP_AGENTIC_IDS
from argus.remediation import parse_actions

logger = logging.getLogger(__name__)

PROBE_PACK_GROUP = "argus.probe_packs"

VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}
# Two vocabularies are live: the Plan 2 hyphenated names that the shipped probe
# YAMLs use, and the Plan 4 underscored names the target adapters advertise in
# `compatible_classes` (runner.py does its skip/compat check against those). The
# loader must accept both, or a probe written in the newer convention is rejected
# at load time and never reaches an adapter — see tests/test_redteam_probe.py
# ::test_valid_target_classes_covers_every_adapter, which fails if they drift.
VALID_TARGET_CLASSES = {
    # Plan 2 (probe YAMLs)
    "http-chat",
    "browser-using",
    "tool-using",
    "rag",
    "multi-agent",
    "http-upload",
    # Plan 4 (target adapters)
    "llm_chat",
    "agent_with_tools",
    "agent_with_rag",
    "browser_using_agent",
    # Payment probes only run against the instrumented payment testbed. No
    # other adapter declares this class, so the runner's compat check skips
    # them everywhere else — and keeps ordinary probes off the testbed.
    "payment_agent",
    # MCP probes only run against the instrumented hostile MCP server, for the
    # same reason payment probes only run against the payment testbed.
    "mcp_agent",
    # Served by `argus-probe mcp-trap`, never by a target adapter.
    "mcp_trap",
    # Served by `argus-probe scan-mcp`, never by a target adapter.
    "mcp_scan",
    # MCP server exposure probes test the server itself, not an agent.
    "a2a_server",
    "a2a_agent",
    "mcp_server",
    # The vLLM version probe tests the model server itself, not an agent.
    "vllm_server",
}


def registered_target_classes() -> set[str]:
    from argus.targets import _plugin_builders

    classes = set(VALID_TARGET_CLASSES)
    for _, target in _plugin_builders().values():
        classes.update(getattr(target, "compatible_classes", ()))
    return classes


# The controlled axis. `attack_class` answers WHAT THE ATTACK ACHIEVES; the free
# `technique` field answers HOW IT IS DELIVERED. Splitting them is what lets the
# coverage report state what was and was not tested — a single free-form field
# had grown to 70+ values, 45 of them used exactly once, and could not.
#
# Adding a value here is a deliberate act: it widens what the coverage report
# claims to measure. Do not add one to make a probe load.
VALID_ATTACK_CLASSES = frozenset(
    {
        "prompt-injection",
        "indirect-injection",
        "jailbreak",
        "data-exfil",
        "credential-extraction",
        "output-handling",
        "input-handling",
        "tool-abuse",
        "excessive-agency",
        "supply-chain",
        "poisoning",
        "harmful-content",
        "misinformation",
        "resource-abuse",
        "payment-abuse",
        "mcp-abuse",
        "a2a-abuse",
    }
)


@dataclass(frozen=True)
class ProbeMappings:
    atlas: tuple[str, ...] = field(default_factory=tuple)
    owasp_llm: tuple[str, ...] = field(default_factory=tuple)
    nist_ai_rmf: tuple[str, ...] = field(default_factory=tuple)
    eu_ai_act: tuple[str, ...] = field(default_factory=tuple)
    owasp_agentic: tuple[str, ...] = field(default_factory=tuple)


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
    # Deterministic checks over Target.collect_evidence(). When present the
    # runner computes the verdict from them and never calls the judge.
    assertions: tuple[dict, ...] = ()
    # An assertion-backed probe that never reached its target proves nothing:
    # doing nothing satisfies every "did not overpay" check. Such a run is an
    # error, not a pass.
    requires_interaction: bool = True
    # With assertions: a failed assertion still decides the verdict, but when they
    # all pass the judge reads the run too, so clean evidence is not read as safe.
    judge_when_assertions_pass: bool = False
    # How the attack is delivered or implemented, as opposed to what it aims to
    # achieve. Free-form on purpose: `attack_class` is the controlled axis and
    # answers "what was tested"; this one keeps the fine-grained vocabulary
    # (qr-code-injection, aria-label-injection, ...) that would otherwise have to
    # be either discarded or smuggled into the controlled set.
    technique: tuple[str, ...] = ()
    # Set for probes from a probe pack: the pack's own rubrics directory, which
    # the runner tries before the built-in one. None for built-in probes.
    rubrics_dir: Path | None = None
    # Fix-it text for this probe, overriding the attack_class text in argus/data/remediation.yaml.
    # Server-facing probes need it: the class text is written for someone who runs an agent.
    remediation: str = ""
    remediation_actions: tuple[dict, ...] = ()

    sessions: tuple[tuple[str, ...], ...] = ()
    scenario_control: str = ""
    trials: int = 1
    decision_point: tuple[dict, ...] = ()
    scope_note: str = ""
    requires_capabilities: tuple[str, ...] = ()

    @property
    def is_phased(self) -> bool:
        return bool(self.scenario_control)

    @property
    def session_prompts(self) -> tuple[tuple[str, ...], ...]:
        return self.sessions or (self.prompts,)

    @property
    def needs_history(self) -> bool:
        return self.conversation or any(len(session) > 1 for session in self.sessions)

    @property
    def exchange_count(self) -> int:
        return self.trials * (2 if self.is_phased else 1) * len(self.prompts)

    @property
    def needs_judge(self) -> bool:
        """True when the judge is consulted on a static run of this probe."""
        return not self.assertions or self.judge_when_assertions_pass


def load_probe(path: Path) -> Probe:
    raw = yaml.safe_load(Path(path).read_text())
    try:
        if raw["severity"] not in VALID_SEVERITIES:
            raise ValueError(f"invalid severity {raw['severity']!r} in {path}")
        for tc in raw["target_class"]:
            if tc not in VALID_TARGET_CLASSES and tc not in registered_target_classes():
                raise ValueError(f"invalid target_class {tc!r} in {path}")
        for ac in raw["attack_class"]:
            if ac not in VALID_ATTACK_CLASSES:
                raise ValueError(f"invalid attack_class {ac!r} in {path}")
        agentic = raw.get("mappings", {}).get("owasp_agentic", [])
        if not isinstance(agentic, list):
            raise ValueError(f"mappings.owasp_agentic must be a list in {path}")
        for category_id in agentic:
            if (
                not isinstance(category_id, str)
                or category_id not in VALID_OWASP_AGENTIC_IDS
            ):
                raise ValueError(
                    f"invalid mappings.owasp_agentic id {category_id!r} in {path}; expected ASI01..ASI10"
                )
        scenario_kind = None
        scenario_payload = ""
        if "scenario" in raw:
            scenario_kind = raw["scenario"].get("kind")
            scenario_payload = raw["scenario"].get("payload", "")
        has_sessions = "sessions" in raw
        if ("prompts" in raw) == has_sessions:
            raise ValueError(
                f"exactly one of prompts and sessions is required in {path}"
            )
        sessions = raw.get("sessions", [])
        if has_sessions:
            if (
                not isinstance(sessions, list)
                or not sessions
                or any(
                    not isinstance(group, list)
                    or not group
                    or any(
                        not isinstance(prompt, str) or not prompt.strip()
                        for prompt in group
                    )
                    for group in sessions
                )
            ):
                raise ValueError(
                    f"sessions must contain nonempty lists of nonempty strings in {path}"
                )
            if raw.get("conversation"):
                raise ValueError(
                    f"conversation cannot be combined with sessions in {path}"
                )
            prompts = tuple(prompt for group in sessions for prompt in group)
        else:
            prompts = tuple(raw["prompts"])
        scenario_control = raw.get("scenario", {}).get("control", "")
        if "control" in raw.get("scenario", {}):
            try:
                control = json.loads(scenario_control)
                payload = json.loads(scenario_payload)
            except (json.JSONDecodeError, TypeError) as exc:
                raise ValueError(
                    f"scenario.control and payload must be JSON objects in {path}"
                ) from exc
            if (
                not isinstance(control, dict)
                or len(control) != 1
                or not isinstance(payload, dict)
            ):
                raise ValueError(
                    f"control must override exactly one payload key in {path}"
                )
            key = next(iter(control))
            if key not in payload or control[key] == payload[key]:
                raise ValueError(
                    f"control must change an existing payload key in {path}"
                )
        if (has_sessions or "trials" in raw) and not scenario_control:
            raise ValueError(f"sessions and trials require scenario.control in {path}")
        trials = raw.get("trials", 1)
        if type(trials) is not int or not 1 <= trials <= 20:
            raise ValueError(f"trials must be an integer from 1 to 20 in {path}")
        capabilities = raw.get("requires_capabilities", [])
        if scenario_kind == "a2a_world":
            if (
                not isinstance(capabilities, list)
                or not capabilities
                or any(
                    not isinstance(name, str) or name not in A2A_CAPABILITIES
                    for name in capabilities
                )
            ):
                raise ValueError(
                    f"a2a_world requires a nonempty list of known requires_capabilities in {path}"
                )
            if (
                "three_hop_chain" in capabilities
                and "observable_agent_lineage" not in capabilities
            ):
                raise ValueError(
                    f"three_hop_chain requires observable_agent_lineage in {path}"
                )
        elif "requires_capabilities" in raw:
            raise ValueError(
                f"requires_capabilities is only available for a2a_world in {path}"
            )
        predicates = (
            A2A_DECISION_PREDICATES
            if scenario_kind == "a2a_world"
            else DECISION_PREDICATES
        )
        decision_point = raw.get("decision_point", [])
        if not isinstance(decision_point, list) or any(
            not isinstance(point, dict)
            or len(point) != 1
            or next(iter(point)) not in predicates
            for point in decision_point
        ):
            raise ValueError(f"invalid decision_point predicate in {path}")
        if scenario_control and (
            not raw.get("assertions")
            or not decision_point
            or raw.get("judge_when_assertions_pass")
        ):
            raise ValueError(
                f"paired probes require assertions, decision_point and no judge_when_assertions_pass in {path}"
            )
        return Probe(
            requires_capabilities=tuple(capabilities),
            sessions=tuple(tuple(group) for group in sessions),
            scenario_control=scenario_control,
            trials=trials,
            decision_point=tuple(decision_point),
            scope_note=str(raw.get("scope_note", "")),
            id=raw["id"],
            name=raw["name"],
            target_class=tuple(raw["target_class"]),
            attack_class=tuple(raw["attack_class"]),
            severity=raw["severity"],
            prompts=prompts,
            mappings=ProbeMappings(
                atlas=tuple(raw.get("mappings", {}).get("atlas", [])),
                owasp_llm=tuple(raw.get("mappings", {}).get("owasp_llm", [])),
                nist_ai_rmf=tuple(raw.get("mappings", {}).get("nist_ai_rmf", [])),
                eu_ai_act=tuple(raw.get("mappings", {}).get("eu_ai_act", [])),
                owasp_agentic=tuple(agentic),
            ),
            judge_model=raw.get("judge", {}).get("model", "claude-haiku-4-5-20251001"),
            judge_rubric_path=raw.get("judge", {}).get(
                "rubric_path", "rubrics/default.md"
            ),
            scenario_kind=scenario_kind,
            scenario_payload=scenario_payload,
            conversation=bool(raw.get("conversation", False)),
            assertions=tuple(raw.get("assertions", ()) or ()),
            requires_interaction=bool(raw.get("requires_interaction", True)),
            judge_when_assertions_pass=bool(
                raw.get("judge_when_assertions_pass", False)
            ),
            technique=tuple(raw.get("technique", ()) or ()),
            remediation=str(raw.get("remediation", "") or ""),
            remediation_actions=parse_actions(raw.get("remediation_actions"), str(path)),
        )
    except KeyError as exc:
        raise ValueError(f"missing required key {exc.args[0]!r} in {path}") from exc


def load_all_probes(probes_dir: Path) -> Iterator[Probe]:
    for path in sorted(Path(probes_dir).rglob("*.yaml")):
        yield load_probe(path)


def load_probe_library(builtin_dir: Path) -> list[Probe]:
    """Built-in probes from `builtin_dir`, plus probes from installed probe packs.

    A probe pack is a package that declares an entry point in the
    `argus.probe_packs` group. The entry point must load to a zero-argument
    callable that returns the pack's probe directory (str or Path), e.g.

        [project.entry-points."argus.probe_packs"]
        mypack = "mypack:probes_dir"

    Packs load in entry-point name order, after the built-ins. A probe whose id
    is already loaded is skipped with a warning, so a pack can never replace a
    built-in probe. A pack that fails to load (bad entry point, missing
    directory, invalid YAML) is skipped whole with a warning.

    A pack may ship rubrics in `<pack dir>/rubrics/`. Its probes resolve
    `judge.rubric_path` there first and fall back to the built-in rubrics, so a
    pack rubric with a built-in name (e.g. default.md) applies to that pack's
    probes only.
    """
    probes = list(load_all_probes(builtin_dir))
    seen = {p.id for p in probes}
    for ep in sorted(entry_points(group=PROBE_PACK_GROUP), key=lambda e: e.name):
        try:
            pack_dir = Path(ep.load()())
            if not pack_dir.is_dir():
                raise ValueError(f"{pack_dir} is not a directory")
            pack = list(load_all_probes(pack_dir))
        except Exception as exc:
            logger.warning("skipping probe pack %r: %s", ep.name, exc)
            continue
        for probe in pack:
            if probe.id in seen:
                logger.warning(
                    "probe pack %r: skipping probe %r, id already loaded",
                    ep.name,
                    probe.id,
                )
                continue
            seen.add(probe.id)
            probes.append(replace(probe, rubrics_dir=pack_dir / "rubrics"))
    return probes
