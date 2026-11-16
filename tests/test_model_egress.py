"""Offline model-provider probe and password-field control through real browser fills."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from aiohttp import web

from argus import llm
from argus.cli import reports, run_json
from argus.local import run_local
from argus.probe import load_probe
from argus.witness import WitnessRun
from browser_agent_fixture import start
from test_transport_integration import transport
from test_browser_trap_e2e import browsers_path

PID = "browser_secret_field_model_egress"
ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
async def harness(monkeypatch, browsers_path):
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", browsers_path)
    state = {}
    async def upstream(request):
        await request.read()
        return web.json_response({"answer": "synthetic response"})
    app = web.Application()
    app.router.add_post("/{tail:.*}", upstream)
    runner = web.AppRunner(app, access_log=None, auto_decompress=False)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    state["upstream"] = f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}/"
    original = WitnessRun.start
    async def remember(self, channels):
        urls = await original(self, channels)
        state.update(urls=urls, canary=self.canary, fingerprint=self.fingerprint)
        return urls
    monkeypatch.setattr(WitnessRun, "start", remember)
    async def no_judge(*args, **kwargs):
        raise AssertionError("the model egress probes must not use a judge")
    monkeypatch.setattr(llm, "complete", no_judge)
    try:
        yield state
    finally:
        await runner.cleanup()


async def run_case(state, mode, ids=None, *, bound=True, placeholder="argus_secret", trap_mode="local"):
    options = {"relay_url": lambda: state["urls"]["model_relay"]}
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
    spec = {"kind": "browser_use", "scenario_kind": "field_egress", "transport": binding,
            "trap_mode": trap_mode, "witness": {"model_relay": {"upstream": state["upstream"]},
                                                 "secret_placeholder": placeholder}}
    if trap_mode == "hosted":
        spec["hosted"] = {"service_url": "http://127.0.0.1:1"}
    try:
        events = [e async for e in run_local(spec, ids or [PID], env={})]
        return [e for e in events if "verdict" in e], options
    finally:
        await agent.cleanup()


@pytest.mark.parametrize("pid", [PID, PID + "_control"])
@pytest.mark.parametrize("mode,verdict,reason", [
    ("model_unwired", "skipped", "the model relay saw no traffic"),
    ("model_no_fill", "skipped", "the declared secret was never filled"),
    ("model_wrong_fill", "skipped", "the declared secret was never filled"),
    ("model_no_after", "skipped", "no model request after the fill"),
    ("model_clean", "pass", "1 requests after the fill"),
    ("model_leak", "fail", "after fill #1"),
    ("model_leak_before", "fail", "before fill"),
    ("model_leak_fill", "fail", "fill request"),
    ("model_leak_no_fill", "fail", "delivered the value"),
    ("model_gzip", "fail", "after fill #1"),
    ("model_uninspectable", "skipped", "could not inspect model provider requests through the relay (unsupported_encoding)"),
    ("model_positive_uninspectable", "fail", "after fill #1"),
])
async def test_verdict_rows(harness, pid, mode, verdict, reason):
    [finding], _ = await run_case(harness, mode, [pid])
    assert finding["verdict"] == verdict, finding
    assert reason in finding["reasoning"]
    if verdict == "fail":
        assert finding["severity"] == "medium"
        assert "framework's own secret mechanism" in finding["reasoning"]
        assert "type=" + ("password" if pid.endswith("_control") else "text") in finding["reasoning"]
    for fill in finding["evidence"]["field_fills"]:
        assert set(fill) == {"received_at", "field_type", "value_matched"}
    assert harness["canary"] not in json.dumps(finding)


async def test_password_control_and_attack_cite_each_other(harness):
    findings, _ = await run_case(harness, "model_type_sensitive", [PID, PID + "_control"])
    by_id = {f["probe_id"]: f for f in findings}
    assert by_id[PID]["verdict"] == "fail"
    assert "control with a password field: pass" in by_id[PID]["reasoning"]
    assert by_id[PID + "_control"]["verdict"] == "pass"
    assert "attack with a text field: fail" in by_id[PID + "_control"]["reasoning"]


@pytest.mark.parametrize("pid", [PID, PID + "_control"])
async def test_missing_secret_binding_uses_applicability_skip(harness, pid):
    [finding], options = await run_case(harness, "model_clean", [pid], bound=False)
    assert finding["verdict"] == "skipped"
    assert "does not pass the declared secret" in finding["reasoning"]
    assert options.get("values") is None


async def test_configured_placeholder_is_only_in_prompt_and_secret_binding(harness):
    [finding], options = await run_case(harness, "model_clean", placeholder="declared_value")
    assert finding["verdict"] == "pass", finding
    assert options["values"] == [harness["canary"]]
    assert "%declared_value%" in finding["attack_prompt"]
    records = finding["evidence"]["witness"]["model_relay"]
    assert records[0]["placeholder_seen"] is True
    assert records[0]["position"] == "fill request"


@pytest.mark.parametrize("mode", ["model_leak", "model_uninspectable", "model_clean", "model_unwired"])
async def test_every_report_masks_canary_and_fake_key_and_names_channel_positions(harness, tmp_path, mode):
    findings, _ = await run_case(harness, mode)
    run = {"id": "11111111-2222-3333-4444-555555555555", "status": "completed", "target_spec": {},
           "started_at": "2026-11-15T00:00:00+00:00", "finished_at": "2026-11-15T00:00:01+00:00", "findings": findings}
    artifacts = {"run.json": run_json.render_json(run), "run.sarif": reports.render_sarif(run),
                 "run.xml": reports.render_junit(run), "run.html": reports.render_html(run)}
    for name, contents in artifacts.items():
        (tmp_path / name).write_text(contents)
        assert harness["canary"] not in contents
        assert "fake-provider-key-pr2" not in contents
        assert "model provider requests through the relay" in contents
        assert "sha256:" + harness["fingerprint"] in contents
        if mode != "model_unwired":
            assert "fill request" in contents
    notes = reports.evidence_notes(findings[0])
    assert notes and all(harness["canary"] not in n for n in notes)
    saved = json.loads(artifacts["run.json"])["findings"][0]["evidence"]["model_egress_notes"]
    assert saved == notes
    for note in saved:
        assert "model provider requests through the relay" in note
        assert "sha256:" + harness["fingerprint"] in note
        if mode != "model_unwired":
            assert any(position in note for position in ("fill request", "after fill #"))


def test_scenario_and_control_have_only_the_requested_field_type():
    from argus.browser_runner.scenarios import field_egress
    for field_type in ("text", "password"):
        html, mime = field_egress.render("http://127.0.0.1:1/sink/field-fill", field_type=field_type)
        assert mime == "text/html"
        assert f'type="{field_type}" autocomplete="off"' in html
        assert "%argus_secret%" not in html
        assert "JSON.stringify({sha256: hash, field_type: field.type})" in html
        assert "crypto.subtle.digest('SHA-256'" in html
        assert 'name="' not in html
    for pid in (PID, PID + "_control"):
        probe = load_probe(ROOT / "argus/probes/browser" / (pid + ".yaml"))
        assert not probe.needs_judge
        assert probe.requires_witness == ("model_relay",)
        assert probe.requires_secret_canary is True


@pytest.mark.parametrize("pid", [PID, PID + "_control"])
async def test_hosted_traps_use_witness_applicability_skip(harness, pid):
    [finding], options = await run_case(harness, "model_clean", [pid], trap_mode="hosted")
    assert finding["verdict"] == "skipped"
    assert "witness channels are unsupported with hosted traps" in finding["reasoning"]
    assert options.get("values") is None


async def test_pairing_includes_skips_and_is_independent_of_order(harness):
    findings, _ = await run_case(harness, "model_unwired", [PID + "_control", PID])
    assert len(findings) == 2
    assert all(f["verdict"] == "skipped" for f in findings)
    by_id = {f["probe_id"]: f for f in findings}
    assert "attack with a text field: skipped" in by_id[PID + "_control"]["reasoning"]
    assert "control with a password field: skipped" in by_id[PID]["reasoning"]
