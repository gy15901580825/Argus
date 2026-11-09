import json
from dataclasses import replace
from pathlib import Path

import pytest
import yaml

from argus import assertions
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
