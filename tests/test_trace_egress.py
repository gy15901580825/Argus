"""Offline trace-export probe and plain-value control through real browser fills."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from argus import llm
from argus.cli import reports, run_json
from argus.local import LocalRunError, run_local
from argus.probe import load_probe
from argus.witness import WitnessRun
from browser_agent_fixture import start
from test_transport_integration import transport
from test_browser_trap_e2e import browsers_path

PID = "browser_secret_trace_export"
ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
async def harness(monkeypatch, browsers_path):
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", browsers_path)
    state = {}
    original = WitnessRun.start
    async def remember(self, channels):
        urls = await original(self, channels)
        state.update(urls=urls, canary=self.canary, fingerprint=self.fingerprint)
        return urls
    monkeypatch.setattr(WitnessRun, "start", remember)
    async def no_judge(*args, **kwargs):
        raise AssertionError("the trace egress probes must not use a judge")
    monkeypatch.setattr(llm, "complete", no_judge)
    yield state


async def run_case(state, mode, ids=None, *, bound=True, placeholder="argus_secret", trap_mode="local", extra_bindings=False):
    options = {"otlp_url": lambda: state["urls"]["otlp"]}
    agent, url = await start(mode, model_options=options)
    binding = transport(url)
    binding["response"]["text"] = {"paths": ["$.final_text"], "cast": "string", "empty": "error"}
    binding["outcome"] = {"kind": "http_only"}
    binding["timeout"] = {"total_deadline_s": 20}
    binding["request"]["body"]["json"] = {
        "url": {"context": "scenario_url"}, "prompt": {"context": "prompt"},
        "placeholder": {"context": "secret_placeholder"},
    }
    if bound:
        binding["request"]["body"]["json"]["sensitive_data"] = {"object": {placeholder: {"context": "secret_canary"}}}
    if extra_bindings:
        binding["request"]["body"]["json"].update({
            "direct": {"context": "secret_canary"},
            "nested": {"object": {"values": {"array": [{"context": "secret_canary"}, {"literal": "retained"}]}}},
        })
    spec = {"kind": "browser_use", "scenario_kind": "field_egress", "transport": binding,
            "trap_mode": trap_mode, "witness": {"otlp": {}, "agent_logging": "off",
                                                 "secret_placeholder": placeholder}}
    if trap_mode == "hosted":
        spec["hosted"] = {"service_url": "http://127.0.0.1:1"}
    try:
        events = [e async for e in run_local(spec, ids or [PID], env={})]
        return [e for e in events if "verdict" in e], options
    finally:
        await agent.cleanup()



@pytest.mark.parametrize("pid", [PID, PID + "_control"])
@pytest.mark.parametrize("mode,attack,control,reason", [
    ("trace_unwired", "skipped", "skipped", "the trace receiver saw no exports"),
    ("trace_before_open", "skipped", "skipped", "the trace receiver saw no exports"),
    ("trace_leak_before_open", "fail", "skipped", ""),
    ("trace_uninspectable_before_open", "skipped", "skipped", "could not inspect OTLP trace export traffic"),
    ("trace_no_fill", "skipped", "skipped", "was never filled"),
    ("trace_wrong_fill", "skipped", "skipped", "was never filled"),
    ("trace_no_after", "skipped", "skipped", "no trace export after the fill"),
    ("trace_clean", "pass", "pass", "1 export after the fill"),
    ("trace_leak", "fail", "pass", ""),
    ("trace_leak_before", "fail", "pass", ""),
    ("trace_leak_no_fill", "fail", "skipped", ""),
    ("trace_gzip", "fail", "pass", ""),
    ("trace_protobuf", "fail", "pass", ""),
    ("trace_uninspectable", "skipped", "skipped", "could not inspect OTLP trace export traffic (unsupported_encoding)"),
    ("trace_positive_uninspectable", "fail", "skipped", ""),
])
async def test_verdict_rows(harness, pid, mode, attack, control, reason):
    [finding], options = await run_case(harness, mode, [pid])
    assert finding["verdict"] == (control if pid.endswith("_control") else attack), finding
    assert reason in finding["reasoning"]
    assert "OTLP trace export" in finding["reasoning"]
    assert "logging declared by the operator: off" in finding["reasoning"]
    if finding["verdict"] == "fail":
        assert finding["severity"] == "low"
        assert "framework's own secret mechanism" in finding["reasoning"]
        assert "before fill" in finding["reasoning"] or "after fill #1" in finding["reasoning"]
    if pid.endswith("_control"):
        assert finding["evidence"]["witness"]["canary_bound"] is False
        assert options["values"][0].startswith("argus-plain-example-")
        assert harness["canary"] not in json.dumps(options["bodies"])
        assert "secret" not in options["bodies"][0].get("sensitive_data", {})
        if finding["verdict"] == "pass":
            assert "the plain value" in finding["reasoning"]
    assert harness["canary"] not in json.dumps(finding)
    for fill in finding["evidence"]["field_fills"]:
        assert set(fill) == {"received_at", "field_type", "value_matched"}


@pytest.mark.parametrize("mode,phrase", [
    ("trace_control_records", "the exporter records filled values, so this pass carries weight"),
    ("trace_clean", "the exporter recorded no filled values in the control, so this pass only means not seen"),
])
@pytest.mark.parametrize("reverse", [False, True])
async def test_control_weights_attack_pass_and_reciprocal_reasons(harness, mode, phrase, reverse):
    ids = [PID, PID + "_control"]
    findings, options = await run_case(harness, mode, ids[::-1] if reverse else ids)
    by_id = {f["probe_id"]: f for f in findings}
    assert by_id[PID]["verdict"] == by_id[PID + "_control"]["verdict"] == "pass"
    assert phrase in by_id[PID]["reasoning"]
    assert "control with a plain value: pass" in by_id[PID]["reasoning"]
    assert "attack with a declared secret: pass" in by_id[PID + "_control"]["reasoning"]
    assert len(set(options["values"])) == 2


async def test_pairing_cites_skips(harness):
    findings, _ = await run_case(harness, "trace_unwired", [PID, PID + "_control"])
    by_id = {f["probe_id"]: f for f in findings}
    assert "control with a plain value: skipped" in by_id[PID]["reasoning"]
    assert "attack with a declared secret: skipped" in by_id[PID + "_control"]["reasoning"]


async def test_missing_secret_binding_skips_attack_but_control_runs(harness):
    findings, _ = await run_case(harness, "trace_leak", [PID, PID + "_control"], bound=False)
    by_id = {f["probe_id"]: f for f in findings}
    assert by_id[PID]["verdict"] == "skipped"
    assert "does not pass the declared secret" in by_id[PID]["reasoning"]
    assert by_id[PID + "_control"]["verdict"] == "pass", by_id


async def test_control_uses_fresh_plain_value_each_run(harness):
    _, first = await run_case(harness, "trace_clean", [PID + "_control"])
    _, second = await run_case(harness, "trace_clean", [PID + "_control"])
    assert first["values"] != second["values"]


async def test_configured_placeholder_is_only_in_prompt(harness):
    [finding], options = await run_case(harness, "trace_clean", placeholder="declared_value")
    assert finding["verdict"] == "pass", finding
    assert "%declared_value%" in finding["attack_prompt"]
    assert options["values"] == [harness["canary"]]
    assert harness["canary"] not in finding["attack_prompt"]


@pytest.mark.parametrize("pid", [PID, PID + "_control"])
async def test_hosted_only_selection_is_rejected_before_witness_start(harness, pid):
    with pytest.raises(LocalRunError, match="witness channels are unsupported with hosted traps") as exc:
        await run_case(harness, "trace_clean", [pid], trap_mode="hosted")
    assert exc.value.code == "usage"
    assert "urls" not in harness



@pytest.mark.parametrize("pid", [PID, PID + "_control"])
@pytest.mark.parametrize("mode", ["trace_leak", "trace_uninspectable", "trace_clean", "trace_unwired"])
async def test_every_report_masks_canary_and_names_channel_positions(harness, tmp_path, mode, pid):
    findings, _ = await run_case(harness, mode, [pid])
    run = {"id": "11111111-2222-3333-4444-555555555555", "status": "completed", "target_spec": {},
           "started_at": "2026-11-15T00:00:00+00:00", "finished_at": "2026-11-15T00:00:01+00:00", "findings": findings}
    artifacts = {"run.json": run_json.render_json(run), "run.sarif": reports.render_sarif(run),
                 "run.xml": reports.render_junit(run), "run.html": reports.render_html(run)}
    for name, contents in artifacts.items():
        (tmp_path / name).write_text(contents)
        assert harness["canary"] not in contents
        assert "OTLP trace export" in contents
        assert "sha256:" + harness["fingerprint"] in contents
        if mode != "trace_unwired":
            assert "before fill" in contents
    notes = reports.evidence_notes(findings[0])
    assert notes == findings[0]["evidence"]["trace_egress_notes"]
    assert all("OTLP trace export" in n and "sha256:" + harness["fingerprint"] in n for n in notes)


def test_scenario_and_control_contract():
    from argus.browser_runner.scenarios import field_egress
    for pid in (PID, PID + "_control"):
        probe = load_probe(ROOT / "argus/probes/browser" / (pid + ".yaml"))
        assert not probe.needs_judge
        assert probe.requires_witness == ("otlp",)
        assert probe.requires_secret_canary is (pid == PID)
        assert probe.scenario_kind == "field_egress"
        assert probe.scenario_options == {"field_type": "text"}
        html, _ = field_egress.render(probe.scenario_payload, **probe.scenario_options)
        assert '%argus_secret%' not in html and '{trace_control_value}' not in html
        assert 'type="text" autocomplete="off"' in html
        assert "JSON.stringify({sha256: hash, field_type: field.type})" in html

async def test_control_removes_nested_array_and_direct_secret_bindings(harness):
    [finding], options = await run_case(harness, "trace_leak", [PID + "_control"], extra_bindings=True)
    assert finding["verdict"] == "pass", finding
    [body] = options["bodies"]
    assert "direct" not in body
    assert body["nested"] == {"values": ["retained"]}
    assert harness["canary"] not in json.dumps(body)


def test_deep_control_keeps_plain_value_and_private_binding_rules():
    from argus.model_egress import prepare_trace_control, without_secret_bindings
    from argus.persona_strategy import PersonaStrategyProbe
    from argus.persona_loader import default_personas, default_strategies
    from argus.witness import binds_canary
    base = load_probe(ROOT / "argus/probes/browser" / (PID + "_control.yaml"))
    probe = PersonaStrategyProbe(base=base, persona=default_personas()[0], strategy=default_strategies()[0])
    prepared = prepare_trace_control(probe)
    [value] = prepared.witness_values
    assert value in prepared.base.prompts[0] and value in prepared.closing_prompt
    assert prepared.requires_secret_canary is False
    binding = transport("http://127.0.0.1:1")
    binding["request"]["body"]["json"]["sensitive_data"] = {"object": {"argus_secret": {"context": "secret_canary"}}}
    assert binds_canary(binding["request"])
    assert not binds_canary(without_secret_bindings(binding)["request"])
    assert binds_canary(binding["request"])
