import json
import logging
import time
from contextlib import asynccontextmanager
from dataclasses import asdict
from html.parser import HTMLParser
from pathlib import Path
from unittest.mock import AsyncMock
from urllib.parse import urlsplit

import httpx
import jwt
import pytest
from aiohttp import web
from cryptography.hazmat.primitives.asymmetric import rsa

pytest.importorskip("argus")

from argus.targets.hosted_trap import render_hosted_scenario
from argus.cli.run_json import render_json
from argus.probe import load_all_probes
from argus.runner import Runner
from argus.targets.browser_use import BrowserUseSpec, BrowserUseTarget, local_browser_mode
from argus_transport import local_transport_mode
from argus_transport.security import Redactor, redacted_transport_logs
from testbed.app import SafeAppRunner, create_app, ORIGIN as ORIGIN_KEY
from testbed.auth import OwnerVerifier
from testbed.memory import MemoryStore
from testbed.service import HostedService, Rejected, validate_page

ORIGIN = "https://hosted-trap.example"
PROBES = Path(__file__).resolve().parents[2] / "argus/probes/browser"


class FormAction(HTMLParser):
    def __init__(self):
        super().__init__()
        self.action = None

    def handle_starttag(self, tag, attrs):
        if tag == "form" and self.action is None:
            self.action = dict(attrs).get("action")


class CapturingService(HostedService):
    def __init__(self):
        super().__init__(MemoryStore())
        self.capabilities = []

    def create_run(self, *args, **kwargs):
        result = super().create_run(*args, **kwargs)
        self.capabilities.extend(result[key] for key in ("public_token", "evidence_token") if key in result)
        return result


@asynccontextmanager
async def hosted_runtime(monkeypatch):
    tenant = "11111111-1111-1111-1111-111111111111"
    audience = "api://synthetic-hosted-service"
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    owner = jwt.encode({"iss": f"https://login.microsoftonline.com/{tenant}/v2.0", "tid": tenant,
                       "aud": audience, "oid": "22222222-2222-2222-2222-222222222222", "exp": int(time.time()) + 300,
                       "roles": ["HostedRun.Create", "HostedRun.Control"]}, key, algorithm="RS256", headers={"kid": "synthetic-key"})
    monkeypatch.setenv("ARGUS_TEST_HOSTED_OWNER", owner)
    service = CapturingService()
    verifier = OwnerVerifier(tenant, audience, key_resolver=lambda _: key.public_key())
    runner = SafeAppRunner(create_app(service, verifier, public_origin=ORIGIN))
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    hosted_url = f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}"
    runner.app[ORIGIN_KEY] = hosted_url
    try:
        yield hosted_url, service, owner
    finally:
        await runner.cleanup()


@asynccontextmanager
async def vendor(hosted_url, canary, mode):
    calls = []

    async def handle(request):
        task = await request.json()
        parts = urlsplit(task["url"])
        if parts.scheme + "://" + parts.netloc != hosted_url:
            raise AssertionError("fake vendor requires the synthetic advertised origin")
        public = parts.path.split("/")[2]
        redactor = Redactor((public,))
        calls.append({"loaded": mode != "unloaded", "submitted": mode == "vulnerable"})
        with redacted_transport_logs(redactor):
            async with httpx.AsyncClient(trust_env=False) as client:
                if mode != "unloaded":
                    response = await client.get(hosted_url + parts.path, headers={"Purpose": "prefetch"} if mode == "prefetch" else {})
                    if response.status_code != 200:
                        raise AssertionError("fake vendor could not load the hosted page")
                    form = FormAction()
                    form.feed(response.text)
                    if mode == "vulnerable":
                        action = urlsplit(form.action)
                        if action.scheme + "://" + action.netloc != hosted_url:
                            raise AssertionError("form action changed the advertised origin")
                        if canary not in task["goal"]:
                            raise AssertionError("fake vendor did not receive the existing probe canary")
                        submitted = await client.post(hosted_url + action.path, data={"api_key": canary})
                        if submitted.status_code != 204:
                            raise AssertionError("fake vendor could not submit the synthetic marker")
        return web.json_response({"final_text": task["url"]})

    app = web.Application()
    app.router.add_post("/run", handle)
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    try:
        yield f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}/run", calls
    finally:
        await runner.cleanup()


def transport(url):
    return {"version": 1,
            "request": {"method": "POST", "url": url, "headers": {}, "body": {"json": {"url": {"context": "scenario_url"}, "goal": {"context": "prompt"}}}},
            "auth": {"kind": "none"},
            "response": {"format": "json", "text": {"paths": ["$.final_text"], "cast": "string", "empty": "error"}, "metadata": {}},
            "outcome": {"kind": "http_only"}, "delivery": {"kind": "sync"},
            "timeout": {"total_deadline_s": 3, "read_s": 3}, "session": {"mode": "none"}, "limits": {}}


@pytest.mark.parametrize("mode,verdict", [("vulnerable", "fail"), ("safe", "pass"), ("prefetch", "error"), ("unloaded", "error")])
async def test_existing_probe_through_hosted_http_and_engine(monkeypatch, tmp_path, caplog, mode, verdict):
    caplog.set_level(logging.INFO)
    probe = next(probe for probe in load_all_probes(PROBES) if probe.id == "browser_ui_phishing_api_key")
    canary = probe.assertions[0]["no_canary_in_trap_requests"]
    async with hosted_runtime(monkeypatch) as (hosted_url, service, owner):
        async with vendor(hosted_url, canary, mode) as (vendor_url, calls):
            spec = BrowserUseSpec(transport=transport(vendor_url), scenario_kind="ui_phishing", trap_mode="hosted",
                                  hosted={"service_url": hosted_url, "owner_token_env": "ARGUS_TEST_HOSTED_OWNER"})
            target = BrowserUseTarget(spec)
            judge = AsyncMock()
            judge._cost_meter = None
            try:
                with local_browser_mode(), local_transport_mode():
                    findings = [finding async for finding in Runner(target=target, judge=judge, rubrics_dir=tmp_path).run_probe(probe)]
            finally:
                await target.aclose()
            [finding] = findings
            assert finding.verdict == verdict
            assert calls == [{"loaded": mode != "unloaded", "submitted": mode == "vulnerable"}]
            assert judge.judge.call_count == 0
            assert all(run.deleted for run in service.store.runs.values())
            report = render_json({"id": "synthetic-run", "status": "completed", "target_spec": asdict(spec), "findings": [asdict(finding)]})
            output = tmp_path / "run.json"
            output.write_text(report)
            for capability in (owner, *service.capabilities):
                assert capability not in output.read_text()
                assert capability not in caplog.text
            if mode == "vulnerable":
                assert finding.evidence["trap_requests"][0]["marker_hits"] == [{"marker_id": "c1", "location": "body"}]
            if mode == "prefetch":
                assert "never loaded the hosted page" in finding.reasoning
            if mode == "unloaded":
                assert "target never reached its testbed" in finding.reasoning


def test_supported_pages_pass_service_gate():
    probes = list(load_all_probes(PROBES))
    supported = [probe for probe in probes if probe.scenario_kind not in {"visual_injection", "cross_origin_bridge"}
                 and probe.id not in {"browser_ui_phishing_login_redirect", "browser_url_sequence_exfil"}]
    assert supported
    failures = []
    for probe in supported:
        content = render_hosted_scenario(probe.scenario_kind, probe.scenario_payload, **probe.scenario_options)
        try:
            validate_page(content, "html")
        except Rejected as error:
            failures.append((probe.id, len(content.encode()), error.code))
    assert failures == []


def test_cross_origin_probe_requires_two_local_origins():
    from argus.targets.hosted_trap import UnsupportedHostedScenario

    probe = next(probe for probe in load_all_probes(PROBES) if probe.id == "browser_cross_origin_bridge")
    with pytest.raises(UnsupportedHostedScenario, match="requires two reachable origins.*one origin"):
        render_hosted_scenario(probe.scenario_kind, probe.scenario_payload, **probe.scenario_options)


@pytest.mark.parametrize("mode", ["safe", "unloaded"])
async def test_click_swap_is_skipped_on_scriptless_hosted_traps(monkeypatch, mode):
    probe = next(probe for probe in load_all_probes(PROBES) if probe.id == "browser_click_swap_toctou")
    async with hosted_runtime(monkeypatch) as (hosted_url, service, owner):
        async with vendor(hosted_url, "", mode) as (vendor_url, calls):
            target = BrowserUseTarget(BrowserUseSpec(
                transport=transport(vendor_url), scenario_kind="click_swap", trap_mode="hosted",
                hosted={"service_url": hosted_url, "owner_token_env": "ARGUS_TEST_HOSTED_OWNER"},
            ))
            judge = AsyncMock()
            judge._cost_meter = None
            try:
                with local_browser_mode(), local_transport_mode():
                    findings = [finding async for finding in Runner(
                        # The probe has a judge for its warn case, so it needs its real rubric.
                        target=target, judge=judge, rubrics_dir=PROBES.parents[1] / "rubrics",
                    ).run_probe(probe)]
            finally:
                await target.aclose()
    assert len(findings) == 1
    assert findings[0].verdict == "skipped"
    assert "Content-Security-Policy disables scripts" in findings[0].reasoning
    assert calls == [{"loaded": mode != "unloaded", "submitted": False}]
    judge.judge.assert_not_called()
