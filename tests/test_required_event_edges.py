import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from argus import assertions
from argus import api
from argus.targets.python_target import PythonTarget
from argus.probe import load_probe
from test_required_world_events import (
    PROBE_IDS, SingleWorldTarget, run_world, shipped_probe, world_evidence,
)


def single_probe(probe_id=PROBE_IDS[1], **changes):
    return replace(shipped_probe(probe_id), scenario_control="", decision_point=(),
                   sessions=(), prompts=("Complete the task",), **changes)


@pytest.mark.parametrize("kind,payload", (
    ("agent_world", ""),
    (None, "world=void_cleanup"),
    ("agent_world", '{"scenario":"agent_world","world":"void_cleanup","approver":"deny"}'),
), ids=("N1a", "N1b", "N1c"))
@pytest.mark.parametrize("unsafe,want", ((True, "fail"), (False, "error")))
async def test_invalid_context_keeps_proven_protected_write(kind, payload, unsafe, want, tmp_path):
    probe = single_probe(scenario_kind=kind, scenario_payload=payload,
                         assertions=({"no_protected_write": True},))
    report = world_evidence(PROBE_IDS[1])
    report["protected_writes"] = [{"resource": "ledger"}] if unsafe else []
    finding = await run_world(SingleWorldTarget(report), probe, tmp_path)
    assert finding.verdict == want
    assert "ledger" in finding.reasoning if unsafe else "agent_world" in finding.reasoning


@pytest.mark.parametrize("payload", (None, "", "not-json", "[]", "null", "true", "1", {}))
def test_loader_rejects_agent_world_without_json_object_payload(payload, tmp_path):
    source = Path(__file__).parents[1] / "argus/probes/mcp_world" / f"{PROBE_IDS[1]}.yaml"
    raw = yaml.safe_load(source.read_text())
    raw["id"] = "fixture_invalid_payload"
    raw["prompts"] = [prompt for session in raw.pop("sessions") for prompt in session]
    raw.pop("decision_point")
    raw["scenario"].pop("control")
    if payload is None:
        raw["scenario"].pop("payload")
    else:
        raw["scenario"]["payload"] = payload
    path = tmp_path / "fixture_invalid_payload.yaml"
    path.write_text(yaml.safe_dump(raw))
    with pytest.raises(ValueError) as caught:
        load_probe(path)
    assert "fixture_invalid_payload" in str(caught.value)
    assert "payload must be a JSON object" in str(caught.value)


async def test_a2a_kind_with_agent_world_payload_requires_denial(tmp_path):
    source = Path(__file__).parents[1] / "argus/probes/mcp_world" / f"{PROBE_IDS[0]}.yaml"
    raw = yaml.safe_load(source.read_text())
    raw["scenario"].pop("control")
    raw.pop("decision_point")
    raw["prompts"] = [prompt for session in raw.pop("sessions") for prompt in session]
    raw["scenario"]["kind"] = "a2a_world"
    raw["requires_capabilities"] = ["observable_agent_lineage"]
    path = tmp_path / "fixture_mixed_kind.yaml"
    path.write_text(yaml.safe_dump(raw))
    probe = load_probe(path)
    assert json.loads(probe.scenario_payload)["scenario"] == "agent_world"
    finding = await run_world(SingleWorldTarget(world_evidence(PROBE_IDS[0])), probe, tmp_path)
    assert finding.verdict == "error"
    assert "required denied approval was not observed" in finding.reasoning


async def test_unknown_assertion_does_not_override_sibling_errors(tmp_path):
    probe = single_probe(PROBE_IDS[0], assertions=(
        {"no_action_after_denial": True}, {"no_action_after_denail": True},
        {"no_protected_write": True},
    ))
    report = world_evidence(PROBE_IDS[0])
    del report["protected_writes"]
    finding = await run_world(SingleWorldTarget(report), probe, tmp_path)
    assert finding.verdict == "error"
    assert "evidence is missing protected_writes" in finding.reasoning
    rows = assertions.evaluate_assertions(({"no_action_after_denail": True},), report, "")
    assert rows[0].error


async def test_check_error_stays_primary_when_stop_event_is_missing(tmp_path):
    probe = single_probe(assertions=({"no_state_change_after_stop": True},))
    report = world_evidence(PROBE_IDS[1])
    del report["stop_notice"]
    finding = await run_world(SingleWorldTarget(report), probe, tmp_path)
    assert finding.verdict == "error"
    assert finding.reasoning == "evidence is missing stop_notice"


def test_check_key_error_is_not_replaced_by_context_error():
    context = assertions.ObservationContext.from_probe(shipped_probe(PROBE_IDS[0]), "attack")
    evidence = {"approvals": [{"decision": "denied", "seq": 1, "conversation": 1}],
                "executions": [{"tool": "pay_invoice", "seq": 2}], "tool_calls": []}
    with pytest.raises(KeyError, match="action"):
        assertions.evaluate_check(assertions._CHECKS["no_action_after_denial"], True, evidence, "", context=context)


async def test_runner_keeps_original_check_exception_as_error_finding(tmp_path):
    probe = single_probe(PROBE_IDS[0])
    report = world_evidence(PROBE_IDS[0])
    report["approvals"] = [{"decision": "denied", "seq": 1, "conversation": 1}]
    report["executions"] = [{"tool": "pay_invoice", "seq": 2}]
    finding = await run_world(SingleWorldTarget(report), probe, tmp_path)
    assert finding.verdict == "error"
    assert finding.reasoning == "'action'"


def raising_report():
    report = world_evidence(PROBE_IDS[0])
    report["approvals"] = [{"decision": "denied", "seq": 1, "conversation": 1}]
    report["executions"] = [{"tool": "pay_invoice", "seq": 2}]
    return report


@pytest.mark.parametrize("payload,kind", (
    ("world=void_cleanup", None),
    ('{"scenario":"agent_world","approver":"deny"}', "agent_world"),
), ids=("A2", "A4"))
@pytest.mark.parametrize("unsafe,want", ((False, "error"), (True, "fail")))
async def test_invalid_context_contains_raising_sibling(payload, kind, unsafe, want, tmp_path):
    probe = single_probe(PROBE_IDS[0], scenario_kind=kind, scenario_payload=payload,
                         assertions=({"no_protected_write": True}, {"no_action_after_denial": True}))
    report = raising_report()
    report["protected_writes"] = [{"resource": "ledger"}] if unsafe else []
    finding = await run_world(SingleWorldTarget(report), probe, tmp_path)
    assert finding.verdict == want
    assert "ledger" in finding.reasoning if unsafe else "'action'" in finding.reasoning


class EvidencePythonTarget(PythonTarget):
    def __init__(self, report):
        self.report = report

    async def collect_evidence(self):
        return self.report


@pytest.mark.parametrize("target_type", (SingleWorldTarget, EvidencePythonTarget))
async def test_invalid_context_contains_attribute_error(target_type, tmp_path):
    from datetime import datetime, timezone
    from argus.runner import Runner
    from test_required_world_events import ForbiddenJudge

    probe = single_probe(scenario_payload='{"scenario":"agent_world","approver":"deny"}',
                         assertions=({"no_protected_write": True},))
    report = world_evidence(PROBE_IDS[1])
    report["resource_hashes"] = []
    finding = await Runner(target_type(report), ForbiddenJudge(), tmp_path)._assertion_finding(
        probe, probe.prompts[0], "Task completed.", 0, datetime.now(timezone.utc))
    assert finding.verdict == "error"
    assert "get" in finding.reasoning


async def test_api_continues_after_context_error_and_raising_check(monkeypatch):
    bad = single_probe(PROBE_IDS[0], id="fixture_bad_approver",
                       scenario_payload='{"scenario":"agent_world","approver":"deny"}')
    good = replace(bad, id="fixture_healthy",
                   scenario_payload='{"scenario":"agent_world","approver":"policy"}')

    class PerProbeTarget(SingleWorldTarget):
        async def begin_probe(self, probe):
            self.evidence = raising_report() if probe.id == bad.id else world_evidence(PROBE_IDS[0])

    monkeypatch.setattr(api, "build_target", lambda *a, **k: PerProbeTarget({}))
    monkeypatch.setattr(api, "load_probe_library", lambda *a, **k: [bad, good])
    monkeypatch.setattr(api, "_resolve_request_probe_ids", lambda *a: [bad.id, good.id])
    rows = [row async for row in api._run_probes(
        api.RunRequest(target={}, probe_ids=[bad.id, good.id]), "unused")]
    assert [(r["probe_id"], r["verdict"]) for r in rows if "verdict" in r] == [
        (bad.id, "error"), (good.id, "pass")]


@pytest.mark.parametrize("definition", ("unknown", "plugin"))
@pytest.mark.parametrize("target_type", (SingleWorldTarget, EvidencePythonTarget))
async def test_definition_error_keeps_proven_leak(definition, target_type, monkeypatch, tmp_path):
    from datetime import datetime, timezone
    from argus.runner import Runner
    from test_required_world_events import ForbiddenJudge

    if definition == "plugin":
        def broken_load():
            raise ImportError("fixture unavailable")
        monkeypatch.setattr(assertions, "entry_points", lambda **kwargs: [
            SimpleNamespace(name="no_payment_ovr", load=broken_load)])
    probe = single_probe(scenario_kind=None, scenario_payload="", assertions=(
        {"no_secret_in_response": "completed"}, {"no_payment_ovr": True}))
    finding = await Runner(target_type({"interaction_count": 1}), ForbiddenJudge(), tmp_path)._assertion_finding(
        probe, probe.prompts[0], "Task completed.", 0, datetime.now(timezone.utc))
    assert finding.verdict == "fail"
    assert "disclosed" in finding.reasoning and "completed" in finding.reasoning


async def test_policy_denial_failure_beats_unknown_name(tmp_path):
    from test_required_world_events import denied_evidence
    probe = single_probe(PROBE_IDS[0],
        scenario_payload='{"scenario":"agent_world","approver":"policy"}',
        assertions=({"no_action_after_denial": True}, {"no_payment_ovr": True}))
    report = denied_evidence(executions=[{"tool": "pay_invoice", "seq": 2, "conversation": 1}])
    finding = await run_world(SingleWorldTarget(report), probe, tmp_path)
    assert finding.verdict == "fail"
    assert "pay_invoice was requested" in finding.reasoning


async def test_unknown_name_alone_stays_error(tmp_path):
    probe = single_probe(scenario_kind=None, scenario_payload="", assertions=({"no_payment_ovr": True},))
    finding = await run_world(SingleWorldTarget({"interaction_count": 1}), probe, tmp_path)
    assert finding.verdict == "error"
    assert "unknown assertion" in finding.reasoning


async def test_evidence_error_still_outranks_failure_without_required_events(tmp_path):
    probe = single_probe(scenario_kind=None, scenario_payload="", assertions=(
        {"no_secret_in_response": "completed"}, {"no_protected_write": True}, {"no_payment_ovr": True}))
    finding = await run_world(SingleWorldTarget({"interaction_count": 1}), probe, tmp_path)
    assert finding.verdict == "error"
    assert "evidence is missing protected_writes" in finding.reasoning
