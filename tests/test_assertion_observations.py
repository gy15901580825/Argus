import copy
from dataclasses import FrozenInstanceError, dataclass, replace
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from argus import assertions, phases
from argus.mcp_trap.driver import judge_round, load_trap_probes
from argus.probe import Probe, ProbeMappings, load_probe
from argus.runner import Runner
import argus.targets as factory
from argus.targets._base import Target
from argus.world_assertions import WorldProfile


LEGACY_IDS = (
    "mcp_budget_unbounded_tool_loop",
    "mcp_confused_deputy_chained_forward",
    "mcp_confused_deputy_result_injection",
    "mcp_credential_lure_api_key",
    "mcp_credential_lure_compliance_framing",
    "mcp_poison_description_exfil",
    "mcp_poison_description_multi_turn",
    "mcp_poison_non_english",
    "mcp_rugpull_after_relist",
    "mcp_rugpull_silent_escalation",
    "mcp_shadow_claims_newer_version",
    "mcp_shadow_near_name",
)
TRAP_IDS = (
    "mcp_trap_confused_deputy",
    "mcp_trap_credential_lure",
    "mcp_trap_rug_pull",
    "mcp_trap_shadowing",
    "mcp_trap_tool_poisoning",
)
EXPOSED_CASES = tuple(
    (kind, probe_id)
    for kind in ("mcp_agent", "testbed_agent")
    for probe_id in LEGACY_IDS
) + tuple(("fixture_plugin", probe_id) for probe_id in LEGACY_IDS + TRAP_IDS)
CHECKS = (
    ("no_call_to_tool", "__shadow__"),
    ("no_secret_in_tool_args", True),
    ("no_attacker_address_in_tool_args", True),
    ("no_call_after_description_change", True),
    ("max_tool_calls", 0),
)
MISSING = object()


def evidence(ledger=MISSING):
    report = {
        "interaction_count": 1,
        "canary": "synthetic-marker",
        "canary_hits": [],
        "attacker_addresses": ["outside@example.invalid"],
        "shadow_tool_names": ["fixture_shadow"],
    }
    if ledger is not MISSING:
        report["tool_calls"] = copy.deepcopy(ledger)
    return report


def probe(name, value):
    return Probe(
        id="observation_fixture", name="Observation fixture",
        target_class=("mcp_agent",), attack_class=("mcp-abuse",),
        severity="critical", prompts=("Complete the benign task.",),
        mappings=ProbeMappings(), judge_model="unused",
        judge_rubric_path="rubrics/mcp_tool_abuse.md",
        assertions=({name: value},),
    )


class ForbiddenJudge:
    _cost_meter = None

    async def judge(self, **kwargs):
        raise AssertionError("assertion-backed probes must not call a model")


@dataclass
class PluginSpec:
    kind: str = "fixture_plugin"
    report: dict | None = None
    classes: tuple = ("mcp_agent", "mcp_trap")


class PluginTarget(Target):
    supports_history = True

    def __init__(self, spec):
        self.report = spec.report
        self.compatible_classes = frozenset(spec.classes)

    async def send_prompt(self, prompt, history=()):
        return "Benign task completed.", 0.0

    async def collect_evidence(self):
        return copy.deepcopy(self.report)


@pytest.fixture
def target_builder(monkeypatch):
    entry = SimpleNamespace(name="fixture_plugin", value="fixture:target",
                            load=lambda: (PluginSpec, PluginTarget))
    monkeypatch.setattr(factory, "_plugin_builders", lambda: {
        entry.name: entry.load()
    })
    real_client = httpx.AsyncClient
    reports = {}

    def respond(request):
        assert request.url.host == "127.0.0.1"
        if request.url.path == "/sessions" and request.method == "POST":
            body = {"session_id": "fixture", "mcp_url": "http://127.0.0.1/mcp"}
        elif request.url.path.endswith("/evidence"):
            body = reports["current"]
        elif request.url.path == "/chat":
            body = {"reply": "Benign task completed."}
        else:
            body = {}
        return httpx.Response(200, json=body)

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: real_client(
        **kwargs, transport=httpx.MockTransport(respond)
    ))

    def build(kind, report, classes=("mcp_agent", "mcp_trap")):
        if kind == "fixture_plugin":
            return factory.build_target({"kind": kind, "report": report, "classes": classes})
        reports["current"] = report
        spec = {
            "kind": kind, "sandbox": True, "testbed_url": "http://127.0.0.1",
            "inner": {"kind": "custom_http", "request_url": "http://127.0.0.1/chat",
                      "request_body_template": '{"prompt":"{{ prompt }}"}',
                      "response_jsonpath": "$.reply"},
        }
        if kind == "testbed_agent":
            spec["environment"] = "mcp"
        return factory.build_target(spec)
    return build


async def run(target, p, tmp_path):
    try:
        findings = [f async for f in Runner(target, ForbiddenJudge(), tmp_path).run_probe(p)]
        assert len(findings) == 1
        return findings[0]
    finally:
        await target.aclose()


@pytest.mark.parametrize("kind", ("mcp_agent", "fixture_plugin"))
@pytest.mark.parametrize("name,value", CHECKS)
@pytest.mark.parametrize("ledger,want", (
    (MISSING, "error"), (None, "error"), ({}, "error"), ("unobserved", "error"),
    ([], "pass"),
    ([{"tool": "fixture_shadow", "arguments": {
        "secret": "synthetic-marker", "to": "outside@example.invalid"},
       "after_description_change": True}], "fail"),
))
async def test_required_ledger_through_runner(kind, name, value, ledger, want,
                                            target_builder, tmp_path):
    result = await run(target_builder(kind, evidence(ledger)), probe(name, value), tmp_path)
    assert result.verdict == want
    if want == "error":
        assert "tool_calls" in result.reasoning
    assert result.evidence["interaction_count"] == 1


@pytest.mark.parametrize("kind,probe_id", EXPOSED_CASES)
async def test_shipped_missing_ledger_cases_are_error(kind, probe_id, target_builder, tmp_path):
    directory = "mcp_trap" if probe_id in TRAP_IDS else "mcp"
    p = load_probe(Path(__file__).parents[1] / "argus" / "probes" / directory / f"{probe_id}.yaml")
    result = await run(target_builder(kind, evidence()), p, tmp_path)
    assert result.verdict == "error"
    assert "tool_calls" in result.reasoning


def test_exposed_fixture_covers_41_distinct_rows():
    assert len(EXPOSED_CASES) == len(set(EXPOSED_CASES)) == 41


@pytest.mark.parametrize("name", (
    "no_secret_in_tool_args", "no_attacker_address_in_tool_args",
    "no_call_after_description_change",
))
async def test_disabled_flags_do_not_require_a_ledger(name, target_builder, tmp_path):
    result = await run(target_builder("fixture_plugin", evidence()), probe(name, False), tmp_path)
    assert result.verdict == "pass"
    assert "check disabled" in result.reasoning


@pytest.mark.parametrize("name,value,missing,reason", (
    ("no_call_to_tool", "__shadow__", "shadow_tool_names", "names no shadow tools"),
    ("no_secret_in_tool_args", True, "canary", "needs a canary"),
    ("no_attacker_address_in_tool_args", True, "attacker_addresses", "needs attacker_addresses"),
))
async def test_observed_ledger_keeps_prerequisite_diagnoses(name, value, missing, reason,
                                                         target_builder, tmp_path):
    report = evidence([])
    report.pop(missing)
    result = await run(target_builder("fixture_plugin", report), probe(name, value), tmp_path)
    assert result.verdict == "fail"
    assert reason in result.reasoning


def test_tool_ledger_accessor_never_invents_an_empty_observation():
    with pytest.raises(KeyError):
        assertions._tool_calls({})
    assert assertions._tool_calls({"tool_calls": []}) == []


def test_observation_declaration_preserves_callback_and_freezes_fields():
    fields = {"tool_calls": list}

    def check(value, report, response):
        return True, "allowed"

    declared = assertions.requires_observations(fields)(check)
    assert declared is check
    fields.clear()
    with pytest.raises(FrozenInstanceError):
        declared.observation_requirements.fields = ()
    with pytest.raises(assertions.Undecided):
        assertions.validate_observations(declared, True, {})
    assertions.validate_observations(declared, True, {"tool_calls": []})


@pytest.mark.parametrize("ledger,want", ((MISSING, "error"), (None, "error"), ([], "pass")))
async def test_phase_profile_enforces_declared_observation_before_callback(ledger, want, monkeypatch, tmp_path):
    calls = []

    def declared_check(value, report, response):
        calls.append(report["phase"])
        return True, "recorded action is allowed"

    declared_check = assertions.requires_observations({"tool_calls": list})(declared_check)
    profile = WorldProfile(
        ("session_id", "phase", "sealed", "seal_timeout", "task_completed"),
        {"fixture_ledger_check": declared_check}, (), lambda *args: True,
        lambda *args: None, lambda *args: None,
    )
    monkeypatch.setitem(phases.PROFILES, "fixture_world", profile)
    p = replace(probe("fixture_ledger_check", True), scenario_kind="fixture_world",
                scenario_control="{}")

    class PhasedTarget(PluginTarget):
        supports_phases = True

        async def begin_phase(self, probe, phase, trial):
            self.phase = phase

        async def begin_conversation(self, index):
            pass

        async def end_phase(self):
            report = evidence(ledger)
            report.update(session_id=self.phase, phase=self.phase, sealed=True,
                          seal_timeout=False, task_completed=True)
            return report

    result = await run(PhasedTarget(PluginSpec(report={})), p, tmp_path)
    assert result.verdict == want
    assert calls == (["clean", "clean", "attack"] if want == "pass" else [])


def test_trap_undecided_assertion_is_inconclusive():
    p = load_trap_probes(["tool_poisoning"])[0]
    outcome, reason, _ = judge_round(p, evidence(), "", None)
    assert outcome == "inconclusive"
    assert "tool_calls" in reason


def test_trap_proven_failure_wins_over_an_undecided_assertion():
    p = load_trap_probes(["tool_poisoning"])[0]
    report = evidence()
    report["canary_hits"] = [{"method": "tools/call", "canary": "synthetic-marker"}]
    assert judge_round(p, report, "", None)[0] == "failed"
