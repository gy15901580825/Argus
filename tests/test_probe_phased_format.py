import copy
import json
from pathlib import Path
from types import SimpleNamespace
import pytest
import yaml
from fastapi import HTTPException
from argus import api
from argus.probe import load_probe, load_probe_library
from argus.local import check_run, LocalRunError

BASE = {
    "id": "paired",
    "name": "Paired",
    "severity": "high",
    "target_class": ["mcp_agent"],
    "attack_class": ["excessive-agency"],
    "sessions": [["a", "b"], ["c"]],
    "scenario": {
        "kind": "agent_world",
        "payload": '{"scenario":"agent_world","world":"invoice_memory","inject":"memory_note"}',
        "control": '{"inject":null}',
    },
    "assertions": [{"no_protected_write": True}],
    "decision_point": [{"state_change": {}}],
}


def load(tmp_path, **kw):
    data = {**copy.deepcopy(BASE), **kw}
    path = tmp_path / "probe.yaml"
    path.write_text(yaml.safe_dump(data))
    return load_probe(path)


def test_sessions_flatten_into_prompts(tmp_path):
    probe = load(tmp_path)
    assert probe.prompts == ("a", "b", "c") and probe.session_prompts == (
        ("a", "b"),
        ("c",),
    )
    assert probe.needs_history and probe.is_phased


def test_prompts_and_sessions_are_mutually_exclusive(tmp_path):
    with pytest.raises(ValueError, match="probe.yaml"):
        load(tmp_path, prompts=["x"])


def test_conversation_with_sessions_rejected(tmp_path):
    with pytest.raises(ValueError):
        load(tmp_path, conversation=True)


def test_control_must_override_exactly_one_payload_key(tmp_path):
    for control in [
        "{}",
        '{"inject":null,"world":"email_memory"}',
        '{"missing":null}',
        '{"inject":"memory_note"}',
        "[]",
        "invalid",
    ]:
        with pytest.raises(ValueError, match="probe.yaml"):
            load(tmp_path, scenario={**BASE["scenario"], "control": control})


def test_sessions_or_trials_without_control_is_rejected(tmp_path):
    scenario = {k: v for k, v in BASE["scenario"].items() if k != "control"}
    with pytest.raises(ValueError):
        load(tmp_path, scenario=scenario)
    data = copy.deepcopy(BASE)
    data.pop("sessions")
    data["prompts"] = ["x"]
    data["scenario"] = scenario
    data["trials"] = 1
    path = tmp_path / "probe.yaml"
    path.write_text(yaml.safe_dump(data))
    with pytest.raises(ValueError):
        load_probe(path)


def test_phased_probe_requires_assertions_and_decision_point_and_no_judge(tmp_path):
    for kw in [
        {"assertions": []},
        {"decision_point": []},
        {"judge_when_assertions_pass": True},
    ]:
        with pytest.raises(ValueError):
            load(tmp_path, **kw)


def test_unknown_decision_point_predicate_rejected(tmp_path):
    with pytest.raises(ValueError):
        load(tmp_path, decision_point=[{"unknown": {}}])


def test_trials_bounds(tmp_path):
    for value in [0, 21, "3", True]:
        with pytest.raises(ValueError):
            load(tmp_path, trials=value)
    assert (
        load(tmp_path, trials=1).trials == 1 and load(tmp_path, trials=20).trials == 20
    )


def test_exchange_count_multiplies_trials_phases_prompts(tmp_path):
    assert load(tmp_path, trials=3).exchange_count == 18


def test_estimate_exchanges_scales_with_trials(tmp_path, monkeypatch):
    probe = load(tmp_path, trials=3)
    monkeypatch.setattr(api, "load_probe_library", lambda *a: [probe])
    req = api.RunRequest(target={}, probe_ids=["paired"])
    assert (
        api._estimate_exchanges(req, ["paired"]) == 18
        and api._judged_exchanges(req, ["paired"]) == 0
    )


def test_deep_mode_refuses_phased_probe_api_422(tmp_path, monkeypatch):
    probe = load(tmp_path)
    monkeypatch.setattr(api, "load_probe_library", lambda *a: [probe])
    with pytest.raises(HTTPException) as exc:
        api._resolve_request_probe_ids(
            api.RunRequest(target={}, probe_ids=["paired"], mode="deep")
        )
    assert exc.value.status_code == 422 and "paired-run" in exc.value.detail


def test_deep_mode_refuses_phased_probe_local_input_error(tmp_path, monkeypatch):
    probe = load(tmp_path)
    monkeypatch.setattr(api, "load_probe_library", lambda *a: [probe])
    spec = {
        "kind": "mcp_agent",
        "testbed_url": "http://127.0.0.1:9",
        "sandbox": True,
        "inner": {
            "kind": "openai_compat",
            "endpoint_url": "http://127.0.0.1:9/v1/chat/completions",
            "model": "demo",
        },
    }
    with pytest.raises(LocalRunError) as exc:
        check_run(spec, ["paired"], mode="deep", env={})
    assert exc.value.code == "input"


def test_compatible_probe_ids_respects_multi_turn_sessions(tmp_path, monkeypatch):
    probe = load(tmp_path)
    monkeypatch.setattr(api, "load_probe_library", lambda *a: [probe])
    assert (
        api.compatible_probe_ids(
            SimpleNamespace(supports_history=False, compatible_classes={"mcp_agent"})
        )
        == []
    )
    assert api.compatible_probe_ids(
        SimpleNamespace(supports_history=True, compatible_classes={"mcp_agent"})
    ) == ["paired"]


def test_existing_library_loads_unchanged():
    library = load_probe_library(api.PROBES_DIR)
    assert len(library) == 236
    assert all(not p.is_phased and p.exchange_count == len(p.prompts) for p in library)
