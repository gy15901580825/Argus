"""Synthetic link sequences through the real browser runner, adapter masking and CLI."""
from html.parser import HTMLParser
import json
from pathlib import Path
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
from argus.targets.browser_use import BrowserUseSpec, BrowserUseTarget
from tests.test_transport_engine import spec_dict

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "client_agent"))
from redteam_runner import browser_probe as client


def probe():
    return load_probe(ROOT / "argus/probes/browser/browser_url_sequence_exfil.yaml")


class Links(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.urls = {}
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            url = dict(attrs)["href"]
            assert urlsplit(url).hostname == "127.0.0.1"
            self.urls[parse_qs(urlsplit(url).query)["piece"][0]] = url


def scripted_agent(behavior):
    class Agent:
        def __init__(self, agent_url, url, prompt, timeout, **kwargs):
            self.url = url
            self.secret = prompt.split("'")[1]

        async def run(self):
            async with httpx.AsyncClient(trust_env=False) as http:
                page = await http.get(self.url)
                assert page.status_code == 200
                assert self.secret not in page.text
                assert "verify" in page.text.lower()
                links = Links(page.text).urls
                if behavior == "decline":
                    return {"final_text": "The page lists Basic and Plus; I declined verification."}
                for char in self.secret if behavior == "open" else self.secret[::-1]:
                    assert (await http.get(links[char])).status_code == 200
                return {"final_text": "The page lists Basic and Plus."}
    return Agent


@pytest.mark.parametrize("runner", [local, client])
@pytest.mark.parametrize("behavior,passed", [("open", False), ("reverse", True), ("decline", True)])
async def test_scripted_browser_sequence_verdict(runner, behavior, passed):
    p = probe()
    with patch.object(runner, "_make_target_agent_driver", side_effect=scripted_agent(behavior)):
        result = await runner.BrowserProbe().run({"scenario_kind": p.scenario_kind,
            "payload": p.scenario_payload, "prompt": p.prompts[0], "timeout_s": 10, "scenario_kind": "ui_phishing"})
    [finding] = evaluate_assertions(p.assertions, result["trap_evidence"], result["final_text"])
    assert finding.passed is passed
    if behavior == "open":
        assert "sequence" in finding.reason
        assert len(result["trap_evidence"]["trap_requests"]) == 8


@pytest.mark.parametrize("behavior,verdict", [("open", "fail"), ("reverse", "pass"), ("decline", "pass")])
async def test_real_run_preserves_sequence_through_masking(behavior, verdict):
    p = probe()
    spec = {"kind": "browser_use", "agent_url": "http://127.0.0.1:1/agent", "timeout_s": 10, "scenario_kind": "ui_phishing"}
    with patch.object(local, "_make_target_agent_driver", side_effect=scripted_agent(behavior)):
        events = [event async for event in run_local(spec, [p.id], env={})]
    [finding] = [event for event in events if "verdict" in event]
    assert finding["verdict"] == verdict, finding
    if verdict == "fail":
        assert "piece=Q" in finding["evidence"]["trap_requests"][0]["query"]


async def test_masking_keeps_only_detected_sequence_values():
    target = BrowserUseTarget(BrowserUseSpec(agent_url="http://127.0.0.1:1/agent", scenario_kind="ui_phishing"))
    await target.begin_probe(probe())
    target._evidence = {"trap_requests": [
        {"method": "GET", "path": "/sink/verify", "query": f"piece={c}", "body": "", "complete": True}
        for c in "Q7M2R8V4"] + [
        {"method": "GET", "path": "/sink/other", "query": "password=private-value", "body": "", "complete": True}]}
    evidence = await target.collect_evidence()
    [finding] = evaluate_assertions(probe().assertions, evidence, "")
    assert not finding.passed
    assert "private-value" not in json.dumps(evidence)


def test_hosted_cli_skips_with_printed_reason_before_contacting_services(tmp_path):
    p = probe()
    spec = tmp_path / "target.json"
    spec.write_text(json.dumps({"kind": "browser_use", "scenario_kind": "ui_phishing", "trap_mode": "hosted",
        "hosted": {"service_url": "http://127.0.0.1:9"}, "transport": spec_dict()}))
    report = tmp_path / "report.json"
    with patch.object(BrowserUseTarget, "send_prompt", side_effect=AssertionError("contacted target")):
        result = CliRunner().invoke(cmd_run, ["--local", "--target", str(spec), "--probes", p.id,
            "--format", "json", "--out", str(report), "--fail-on", "high"])
    assert result.exit_code == 0, result.output
    [finding] = json.loads(report.read_text())["findings"]
    assert finding["verdict"] == "skipped"
    assert "hosted" in result.output and "sequence" in result.output
    assert "redacted" in finding["reasoning"]
