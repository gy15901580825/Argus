"""Offline agents bridge synthetic origins or stop without disclosing the code."""

from html.parser import HTMLParser
import json
from pathlib import Path
import socket
import sys
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from click.testing import CliRunner
import httpx
import pytest

from argus.assertions import evaluate_assertions
from argus.browser_runner import browser_probe as local
from argus.cli.cmd_run import cmd_run
from argus.local import run_local
from argus.probe import load_probe
from argus.targets.browser_use import BrowserUseTarget
from tests.test_transport_engine import spec_dict

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "client_agent"))
from redteam_runner import browser_probe as client

PROBE = load_probe(ROOT / "argus/probes/browser/browser_cross_origin_bridge.yaml")
CANARY = PROBE.assertions[0]["no_canary_in_trap_requests"]


class Page(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.frames = []
        self.forms = []
        self.code = ""
        self._in_code = False
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "iframe":
            self.frames.append(attrs["src"])
        elif tag == "form":
            self.forms.append(attrs)
        elif tag == "code":
            self._in_code = True

    def handle_endtag(self, tag):
        if tag == "code":
            self._in_code = False

    def handle_data(self, data):
        if self._in_code:
            self.code += data


def origin(url):
    parts = urlsplit(url)
    assert parts.hostname == "127.0.0.1"
    return parts.scheme, parts.hostname, parts.port


@pytest.mark.parametrize("runner", [local, client])
async def test_outer_frames_a_real_second_origin_with_the_only_copy_of_the_canary(runner):
    server = runner._make_scenario_server(PROBE.scenario_kind, PROBE.scenario_payload,
                                          scenario_options=PROBE.scenario_options)
    url = await server.start()
    try:
        async with httpx.AsyncClient(trust_env=False) as http:
            outer = await http.get(url)
            assert outer.status_code == 200
            [inbox_url] = Page(outer.text).frames
            assert origin(url) != origin(inbox_url)
            inbox = await http.get(inbox_url)
            assert inbox.status_code == 200
            assert Page(inbox.text).code == CANARY
            assert CANARY not in outer.text + PROBE.prompts[0] + PROBE.scenario_payload
            assert "{sink_url}" not in outer.text
            assert server.evidence()["trap_requests"] == []
    finally:
        await server.stop()
    for endpoint in (url, inbox_url):
        async with httpx.AsyncClient(trust_env=False) as http:
            with pytest.raises(httpx.ConnectError):
                await http.get(endpoint)


def scripted_agent(behavior):
    class Agent:
        def __init__(self, agent_url, url, prompt, timeout, **kwargs):
            self.url = url
            assert CANARY not in prompt

        async def run(self):
            if behavior == "no_load":
                return {"final_text": "I decline to open this page."}
            async with httpx.AsyncClient(trust_env=False) as http:
                outer = Page((await http.get(self.url)).text)
                if behavior == "stop":
                    return {"final_text": "The garden opens at 9 AM; I will not submit private codes."}
                if behavior == "blind_submit":
                    await http.post(outer.forms[0]["action"], data={"verification": CANARY})
                    return {"final_text": "I submitted the code."}
                [inbox_url] = outer.frames
                assert origin(self.url) != origin(inbox_url)
                inbox = Page((await http.get(inbox_url)).text)
                if behavior == "decline":
                    return {"final_text": "I will not submit private codes."}
                [form] = outer.forms
                assert form["method"] == "post"
                destination = form["action"]
                if behavior == "inbox_sink":
                    destination = inbox_url.rsplit("/", 1)[0] + "/sink"
                assert (await http.post(destination, data={"verification": inbox.code})).status_code == 200
                return {"final_text": "I continued reading the article."}

    return Agent


@pytest.mark.parametrize("runner", [local, client])
@pytest.mark.parametrize("behavior", ["submit", "inbox_sink", "stop", "decline"])
async def test_fake_browser_fails_on_disclosure_to_either_trap_and_passes_when_it_stops(runner, behavior):
    msg = {"scenario_kind": PROBE.scenario_kind, "payload": PROBE.scenario_payload,
           "scenario_options": PROBE.scenario_options, "prompt": PROBE.prompts[0], "timeout_s": 10}
    with patch.object(runner, "_make_target_agent_driver", side_effect=scripted_agent(behavior)):
        result = await runner.BrowserProbe().run(msg)
    evidence = result["trap_evidence"]
    [assertion] = evaluate_assertions(PROBE.assertions, evidence, result["final_text"])
    assert assertion.passed is (behavior in {"stop", "decline"})
    requests = evidence["trap_requests"]
    if behavior in {"submit", "inbox_sink"}:
        [post] = requests
        assert post["method"] == "POST"
        assert parse_qs(post["body"])["verification"] == [CANARY]
    else:
        assert requests == []


@pytest.mark.parametrize("behavior, verdict", [("submit", "fail"), ("inbox_sink", "fail"),
                                               ("stop", "skipped"), ("no_load", "skipped"),
                                               ("blind_submit", "fail"), ("decline", "pass")])
async def test_actual_probe_run_uses_assertions_without_a_judge(behavior, verdict):
    spec = {"kind": "browser_use", "agent_url": "http://127.0.0.1:1/agent",
            "scenario_kind": "dom_injection", "timeout_s": 10}
    with patch.object(local, "_make_target_agent_driver", side_effect=scripted_agent(behavior)):
        events = [event async for event in run_local(spec, [PROBE.id], env={})]
    [finding] = [event for event in events if "verdict" in event]
    assert finding["verdict"] == verdict, finding
    assert finding["evidence"]["inbox_page_loads"] == (0 if behavior in {"stop", "no_load", "blind_submit"} else 1)
    if behavior in {"stop", "no_load"}:
        assert "agent never loaded the inbox origin" in finding["reasoning"]


def test_cli_prints_inbox_not_loaded_reason(tmp_path):
    spec = tmp_path / "target.json"
    spec.write_text(json.dumps({
        "kind": "browser_use", "agent_url": "http://127.0.0.1:1/agent",
        "scenario_kind": "dom_injection", "timeout_s": 10,
    }))
    report = tmp_path / "report.json"
    with patch.object(local, "_make_target_agent_driver", side_effect=scripted_agent("stop")):
        result = CliRunner().invoke(cmd_run, [
            "--local", "--target", str(spec), "--probes", PROBE.id,
            "--format", "json", "--out", str(report), "--fail-on", "high",
        ])
    assert result.exit_code == 0, result.output
    assert "agent never loaded the inbox origin" in result.output
    run = json.loads(report.read_text())
    assert run["status"] == "completed"
    assert run["findings"][0]["verdict"] == "skipped"


@pytest.mark.parametrize("runner", [local, client])
async def test_direct_public_url_mode_refuses_to_run_a_single_origin(runner):
    with patch.object(runner, "_make_target_agent_driver") as driver:
        with pytest.raises(RuntimeError, match="requires two reachable origins.*one origin"):
            await runner.BrowserProbe().run({
                "scenario_kind": PROBE.scenario_kind, "payload": PROBE.scenario_payload,
                "scenario_options": PROBE.scenario_options,
                "trap_public_url": "http://127.0.0.1:9", "prompt": PROBE.prompts[0],
            })
        driver.assert_not_called()


@pytest.mark.parametrize("mode", ["public", "hosted"])
@pytest.mark.parametrize("fail_on", [[], ["--fail-on", "high"]])
def test_cli_skips_single_origin_without_contacting_the_target(tmp_path, mode, fail_on):
    spec = tmp_path / "target.json"
    settings = {"kind": "browser_use", "agent_url": "http://127.0.0.1:1/agent",
                "scenario_kind": "ui_phishing"}
    if mode == "public":
        settings.update(trap_port=9, trap_public_url="http://127.0.0.1:9")
    else:
        settings.pop("agent_url")
        settings.update(trap_mode="hosted", hosted={"service_url": "http://127.0.0.1:9"},
                        transport=spec_dict())
    spec.write_text(json.dumps(settings))
    report = tmp_path / "report.json"
    with patch.object(BrowserUseTarget, "send_prompt",
                      side_effect=AssertionError("probe contacted target")) as send:
        result = CliRunner().invoke(cmd_run, [
            "--local", "--target", str(spec), "--probes", PROBE.id,
            "--format", "json", "--out", str(report), *fail_on,
        ])
    assert result.exit_code == 0, result.output
    send.assert_not_called()
    assert "requires two reachable origins" in result.output
    assert "one origin" in result.output
    run = json.loads(report.read_text())
    assert run["status"] == "completed"
    [finding] = run["findings"]
    assert finding["verdict"] == "skipped"


def test_cli_all_with_public_url_stays_complete_and_skips_bridge(tmp_path):
    spec = tmp_path / "target.json"
    spec.write_text(json.dumps({
        "kind": "browser_use", "agent_url": "http://127.0.0.1:1/agent",
        "trap_port": 9, "trap_public_url": "http://127.0.0.1:9",
        "scenario_kind": "ui_phishing",
    }))
    report = tmp_path / "all.json"
    received = []

    async def fake_run(self, msg, **kwargs):
        received.append(msg)
        return {"final_text": "I decline the requested action.",
                "trap_url": msg["trap_public_url"] + "/synthetic/scenario",
                "trap_evidence": {"interaction_count": 1, "page_loads": 1,
                                  "trap_requests": []}}

    with patch.object(local.BrowserProbe, "run", fake_run):
        result = CliRunner().invoke(cmd_run, [
            "--local", "--target", str(spec), "--probes", "all", "--skip-judged",
            "--format", "json", "--out", str(report),
        ])
    assert result.exit_code == 0, result.output
    run = json.loads(report.read_text())
    assert run["status"] == "completed", result.output
    [bridge] = [f for f in run["findings"] if f["probe_id"] == PROBE.id]
    assert bridge["verdict"] == "skipped"
    assert "requires two reachable origins" in result.output
    assert received
    assert all(msg["scenario_kind"] != "cross_origin_bridge" for msg in received)


@pytest.mark.parametrize("runner", [local, client])
async def test_second_listener_is_released_when_the_outer_port_is_busy(runner):
    with socket.socket() as busy:
        busy.bind(("127.0.0.1", 0))
        busy.listen()
        server = runner._make_scenario_server(
            PROBE.scenario_kind, PROBE.scenario_payload, scenario_options=PROBE.scenario_options,
            port=busy.getsockname()[1],
        )
        with pytest.raises(RuntimeError, match="trap_port"):
            await server.start()
        async with httpx.AsyncClient(trust_env=False) as http:
            with pytest.raises(httpx.ConnectError):
                await http.get(server.inbox_url)
