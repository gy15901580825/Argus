import asyncio
import json
import os
import sys
from contextlib import asynccontextmanager

import pytest
from aiohttp import web

from argus.targets.browser_use import BrowserUseSpec, BrowserUseTarget, local_browser_mode
from argus_transport import local_transport_mode
from tests.test_hosted_client import OWNER, PUBLIC, EVIDENCE
from tests.test_hosted_traps import page, sink
from tests.test_transport_browser import browser_spec


@asynccontextmanager
async def target_services(*, expired=None, permanent=False, delete_failure=False, delay=0, probe_delay=0, merge_overflow=False, scenario_origin=None, delete_status=200):
    calls = []
    seen = asyncio.Event()
    runs = 0
    probes = 0
    evidence_rounds = 0

    async def control(request):
        nonlocal runs, probes, evidence_rounds
        body = await request.json() if request.can_read_body else None
        calls.append((request.method, request.path, body))
        if request.path == "/vendor":
            seen.set()
            if delay:
                await asyncio.sleep(delay)
            return web.json_response({"status": "COMPLETED", "result": {"result": body["url"]}})
        if request.method == "DELETE":
            if delete_status == 204:
                return web.Response(status=204)
            return web.json_response({"error": PUBLIC}, status=503 if delete_failure else delete_status)
        if request.path == "/v1/runs":
            runs += 1
            data = {"run_id": f"r{runs}", "public_token": PUBLIC, "evidence_token": EVIDENCE, "expires_at": 9999999999}
        elif request.path.endswith("/probes"):
            probes += 1
            if probe_delay:
                seen.set()
                await asyncio.sleep(probe_delay)
            if expired and (probes == 1 or permanent):
                return web.json_response({"error": "run_expired"}, status=expired)
            origin = scenario_origin(request) if scenario_origin else f"{request.scheme}://{request.host}"
            data = {"probe_id": f"p{probes}", "scenario_url": origin + "/r/" + PUBLIC + f"/p/p{probes}/scenario"}
        elif request.path.endswith("/seal"):
            data = {"sealed": True, "seal_revision": 1}
        else:
            evidence_rounds += 1
            data = page([sink(False)] * 50 if merge_overflow and evidence_rounds == 1 else [sink(True)])
        return web.json_response(data)

    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", control)
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    try:
        yield f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}", calls, seen
    finally:
        await runner.cleanup()


def target(url, kind="ui_phishing", deadline=3):
    return BrowserUseTarget(BrowserUseSpec(
        transport=browser_spec(url + "/vendor", deadline), scenario_kind=kind,
        trap_mode="hosted", hosted={"service_url": url, "owner_token_env": "ARGUS_TEST_HOSTED_OWNER"},
    ))


@pytest.mark.parametrize("delete_failure", [False, True])
async def test_hosted_cleanup_report_survives_close(monkeypatch, delete_failure):
    monkeypatch.setenv("ARGUS_TEST_HOSTED_OWNER", OWNER)
    async with target_services(expired=410, delete_failure=delete_failure) as (url, calls, _):
        browser = target(url)
        with local_browser_mode(), local_transport_mode():
            text, _ = await browser.send_prompt("Read the page")
        await browser.aclose()
        report = browser.cleanup_report()
        await browser.aclose()
        assert browser.cleanup_report() == report
    assert text
    assert [call[1] for call in calls if call[0] == "DELETE"] == ["/v1/runs/r1", "/v1/runs/r2"]
    assert report == {
        "complete": not delete_failure, "done": 0 if delete_failure else 2,
        "open": [{
            "scope": "run", "step": f"r{index}", "status": "failed",
            "method": "DELETE", "url": url + f"/v1/runs/r{index}", "http_status": 503,
        } for index in (1, 2)] if delete_failure else [],
        "stop_reason": None, "leftover": [],
    }
    for token in (OWNER, PUBLIC, EVIDENCE):
        assert token not in json.dumps(report)


@pytest.mark.parametrize("foreign", [
    lambda request: f"https://{request.host}",
    lambda request: f"http://localhost:{request.url.port}",
    lambda request: "http://127.0.0.1:1",
    lambda request: "//" + request.host,
    lambda request: f"http://{request.host}:invalid",
    lambda request: f"http://foreign.invalid\\@{request.host}",
    lambda request: f"http://{request.host}/\\foreign.invalid",
    lambda request: f"http://{request.host}/\x00",
    lambda request: f"http://{request.host}/\t",
    lambda request: f"http://{request.host}:0",
])
async def test_foreign_scenario_origin_never_reaches_agent(monkeypatch, foreign):
    from argus.targets.hosted_trap import HostedTrapError

    monkeypatch.setenv("ARGUS_TEST_HOSTED_OWNER", OWNER)
    async with target_services(scenario_origin=foreign) as (url, calls, _):
        browser = target(url)
        try:
            with local_browser_mode(), local_transport_mode():
                with pytest.raises(HostedTrapError):
                    await browser.send_prompt("Read the page")
        finally:
            await browser.aclose()
    assert not [call for call in calls if call[1] == "/vendor"]
    assert [call[1] for call in calls if call[0] == "DELETE"] == ["/v1/runs/r1"]


async def test_nonhosted_cleanup_report_remains_none():
    from dataclasses import replace

    browser = target("http://127.0.0.1:1")
    browser = type(browser)(replace(browser.spec, trap_mode="local", hosted=None))
    assert getattr(browser, "cleanup_report", lambda: None)() is None
    await browser.aclose()
    assert getattr(browser, "cleanup_report", lambda: None)() is None


async def test_empty_delete_response_and_client_close_failure_keep_cleanup(monkeypatch):
    monkeypatch.setenv("ARGUS_TEST_HOSTED_OWNER", OWNER)
    async with target_services(delete_status=204) as (url, calls, _):
        browser = target(url)
        with local_browser_mode(), local_transport_mode():
            text, _ = await browser.send_prompt("Read the page")
        client = browser._hosted_client
        close = client.aclose

        async def fail_after_close():
            await close()
            raise RuntimeError(PUBLIC)

        monkeypatch.setattr(client, "aclose", fail_after_close)
        await browser.aclose()
        await browser.aclose()
        report = browser.cleanup_report()
    assert text
    assert report == {"complete": True, "done": 1, "open": [], "stop_reason": None, "leftover": []}
    assert [call[1] for call in calls if call[0] == "DELETE"] == ["/v1/runs/r1"]


@pytest.mark.parametrize("delete_failure", [False, True])
async def test_native_cli_run_json_contains_hosted_cleanup(monkeypatch, tmp_path, delete_failure):
    monkeypatch.setenv("ARGUS_TEST_HOSTED_OWNER", OWNER)
    async with target_services(delete_failure=delete_failure) as (url, calls, _):
        spec = target(url).spec
        target_file = tmp_path / "target.json"
        target_file.write_text(json.dumps({
            "kind": spec.kind, "transport": browser_spec(url + "/vendor"),
            "scenario_kind": spec.scenario_kind, "trap_mode": spec.trap_mode,
            "hosted": {"service_url": url, "owner_token_env": "ARGUS_TEST_HOSTED_OWNER"},
        }))
        output = tmp_path / "run.json"
        process = await asyncio.create_subprocess_exec(
            sys.executable, "-m", "argus.cli", "run", "--local", "--target", str(target_file),
            "--probes", "browser_ui_phishing_api_key", "--format", "json", "--out", str(output),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
            env={key: value for key, value in os.environ.items()
                 if not key.endswith("_API_KEY") and key not in {"ARGUS_API_URL", "ARGUS_API_TOKEN"}},
        )
        try:
            stdout, _ = await asyncio.wait_for(process.communicate(), 30)
        finally:
            if process.returncode is None:
                process.kill()
                await process.wait()
        assert process.returncode == (1 if delete_failure else 0), stdout.decode()
        record = json.loads(output.read_text())
    report = record["target_cleanup"]
    assert record["status"] == ("incomplete" if delete_failure else "completed")
    assert record["findings"][0]["verdict"] == "fail"
    assert report["complete"] is not delete_failure
    assert report["done"] == (0 if delete_failure else 1)
    assert len(report["open"]) == int(delete_failure)
    if delete_failure:
        assert report["open"][0]["http_status"] == 503
    assert [call[1] for call in calls if call[0] == "DELETE"] == ["/v1/runs/r1"]
    for token in (OWNER, PUBLIC, EVIDENCE):
        assert token not in output.read_text()
        assert token not in stdout.decode()


async def test_shared_run_cap_rotation_and_delete_every_run(monkeypatch):
    monkeypatch.setenv("ARGUS_TEST_HOSTED_OWNER", OWNER)
    async with target_services() as (url, calls, _):
        browser = target(url)
        try:
            with local_browser_mode(), local_transport_mode():
                for _ in range(101):
                    await browser.send_prompt("Read the page")
        finally:
            await browser.aclose()
    creates = [call for call in calls if call[1] == "/v1/runs"]
    assert len(creates) == 2
    uploads = [call for call in calls if call[1].endswith("/probes")]
    assert len(uploads) == 101
    assert uploads[99][1] == "/v1/runs/r1/probes"
    assert uploads[100][1] == "/v1/runs/r2/probes"
    assert uploads[0][2]["ttl_seconds"] == 65
    assert [call[1] for call in calls if call[0] == "DELETE"] == ["/v1/runs/r1", "/v1/runs/r2"]


@pytest.mark.parametrize("status", [404, 410])
async def test_expired_run_rotates_and_retries_once(monkeypatch, status):
    monkeypatch.setenv("ARGUS_TEST_HOSTED_OWNER", OWNER)
    async with target_services(expired=status) as (url, calls, _):
        browser = target(url)
        try:
            with local_browser_mode(), local_transport_mode():
                await browser.send_prompt("Read the page")
        finally:
            await browser.aclose()
    assert len([call for call in calls if call[1] == "/v1/runs"]) == 2
    assert len([call for call in calls if call[1].endswith("/probes")]) == 2
    assert len([call for call in calls if call[1] == "/vendor"]) == 1
    assert len([call for call in calls if call[0] == "DELETE"]) == 2


async def test_expired_retry_is_bounded(monkeypatch):
    from argus.targets.hosted_trap import HostedTrapError

    monkeypatch.setenv("ARGUS_TEST_HOSTED_OWNER", OWNER)
    async with target_services(expired=410, permanent=True) as (url, calls, _):
        browser = target(url)
        try:
            with local_browser_mode(), local_transport_mode():
                with pytest.raises(HostedTrapError):
                    await browser.send_prompt("Read the page")
        finally:
            await browser.aclose()
    assert len([call for call in calls if call[1] == "/v1/runs"]) == 2
    assert not [call for call in calls if call[1] == "/vendor"]


async def test_echoed_url_reply_run_json_and_delete_warning_hide_tokens(monkeypatch, caplog):
    from argus.cli.run_json import scrub_run

    monkeypatch.setenv("ARGUS_TEST_HOSTED_OWNER", OWNER)
    async with target_services(delete_failure=True) as (url, calls, _):
        browser = target(url)
        browser._canaries = ("sk-test-abc123def456", "sk-test-abc123def456")
        try:
            with local_browser_mode(), local_transport_mode():
                text, _ = await browser.send_prompt("Read the page")
                await browser.send_prompt("Read the page")
            evidence = await browser.collect_evidence()
        finally:
            await browser.aclose()
    run_json = json.dumps(scrub_run({"findings": [{"response_text": text, "evidence": evidence}]}))
    assert len(evidence["hosted"]["rounds"]) == 2
    assert evidence["hosted"]["markers"] == {"c1": "sk-test-abc123def456"}
    assert evidence["trap_requests"][0]["marker_hits"] == [{"marker_id": "c1", "location": "body"}]
    assert "<redacted>" in text
    assert "could not delete hosted run" in caplog.text
    for token in (OWNER, PUBLIC, EVIDENCE):
        assert token not in text
        assert token not in run_json
        assert token not in caplog.text


async def test_hosted_visual_rejected_before_any_network(monkeypatch):
    from argus.targets.hosted_trap import UnsupportedHostedScenario

    monkeypatch.setenv("ARGUS_TEST_HOSTED_OWNER", OWNER)
    async with target_services() as (url, calls, _):
        browser = target(url, kind="visual_injection")
        try:
            with local_browser_mode(), local_transport_mode():
                with pytest.raises(UnsupportedHostedScenario):
                    await browser.send_prompt("Read the page")
        finally:
            await browser.aclose()
        assert calls == []


async def test_cancellation_seals_timeout_and_attaches_safe_evidence(monkeypatch):
    from argus.browser_runner.browser_probe import BrowserProbe
    from argus.targets.hosted_trap import HostedTrap
    from tests.test_hosted_client import make_client
    from argus_transport import ExecutionPolicy, TransportSpec

    monkeypatch.setenv("ARGUS_TEST_HOSTED_OWNER", OWNER)
    async with target_services(delay=0.2) as (url, calls, seen):
        client = make_client(url)
        try:
            trap = HostedTrap(client, await client.create_run(), {}, 75, html="<p>Neutral page</p>")
            transport = browser_spec(url + "/vendor")
            task = asyncio.create_task(BrowserProbe().run(
                {"scenario_kind": "ui_phishing", "payload": "Neutral page", "prompt": "Read the page", "transport": transport},
                policy=ExecutionPolicy.local(TransportSpec.from_dict(transport)), trap=trap,
            ))
            await asyncio.wait_for(seen.wait(), 2)
            task.cancel()
            with pytest.raises(asyncio.CancelledError) as caught:
                await task
        finally:
            await client.aclose()
    assert [call[2] for call in calls if call[1].endswith("/seal")] == [{"reason": "timeout"}]
    assert caught.value.trap_evidence["hosted"]["rounds"][0]["complete"] is False
    for token in (OWNER, PUBLIC, EVIDENCE):
        assert token not in caught.value.trap_url
        assert token not in json.dumps(caught.value.trap_evidence)


async def test_probe_name_is_preserved_in_hosted_request(monkeypatch):
    from types import SimpleNamespace

    monkeypatch.setenv("ARGUS_TEST_HOSTED_OWNER", OWNER)
    async with target_services() as (url, calls, _):
        browser = target(url)
        try:
            await browser.begin_probe(SimpleNamespace(id="browser_ui_phishing_api_key", assertions=(), scenario_kind="ui_phishing", scenario_payload="Neutral page"))
            with local_browser_mode(), local_transport_mode():
                await browser.send_prompt("Read the page")
        finally:
            await browser.aclose()
    [upload] = [call[2] for call in calls if call[1].endswith("/probes")]
    assert upload["scenario_id"] == "browser_ui_phishing_api_key"


async def test_oversized_marker_rejected_before_network(monkeypatch):
    from argus.targets.hosted_trap import HostedTrapError

    monkeypatch.setenv("ARGUS_TEST_HOSTED_OWNER", OWNER)
    async with target_services() as (url, calls, _):
        browser = target(url)
        browser._canaries = ("sk-test-abc123def456" * 30,)
        try:
            with local_browser_mode(), local_transport_mode():
                with pytest.raises(HostedTrapError, match="at most 512 bytes"):
                    await browser.send_prompt("Read the page")
        finally:
            await browser.aclose()
        assert calls == []


async def test_cancellation_during_open_has_no_unassigned_agent_error(monkeypatch):
    from argus.browser_runner.browser_probe import BrowserProbe
    from argus.targets.hosted_trap import HostedTrap
    from tests.test_hosted_client import make_client
    from argus_transport import ExecutionPolicy, TransportSpec

    monkeypatch.setenv("ARGUS_TEST_HOSTED_OWNER", OWNER)
    async with target_services(probe_delay=0.2) as (url, calls, seen):
        client = make_client(url)
        try:
            trap = HostedTrap(client, await client.create_run(), {}, 75, html="<p>Neutral page</p>")
            spec = browser_spec(url + "/vendor")
            task = asyncio.create_task(BrowserProbe().run(
                {"scenario_kind": "ui_phishing", "payload": "Neutral page", "prompt": "Read the page", "transport": spec},
                policy=ExecutionPolicy.local(TransportSpec.from_dict(spec)), trap=trap,
            ))
            await asyncio.wait_for(seen.wait(), 2)
            task.cancel()
            with pytest.raises(asyncio.CancelledError) as caught:
                await task
        finally:
            await client.aclose()
    assert caught.value.trap_evidence == {}
    assert caught.value.trap_url == ""
    assert not [call for call in calls if call[1] == "/vendor"]


async def test_delete_failures_do_not_skip_later_runs(monkeypatch, caplog):
    monkeypatch.setenv("ARGUS_TEST_HOSTED_OWNER", OWNER)
    async with target_services(expired=410, delete_failure=True) as (url, calls, _):
        browser = target(url)
        try:
            with local_browser_mode(), local_transport_mode():
                await browser.send_prompt("Read the page")
        finally:
            await browser.aclose()
    assert [call[1] for call in calls if call[0] == "DELETE"] == ["/v1/runs/r1", "/v1/runs/r2"]
    assert caplog.text.count("could not delete hosted run") == 2
    assert PUBLIC not in caplog.text


async def test_marker_hit_after_fifty_earlier_requests_is_preserved(monkeypatch):
    from argus.assertions import evaluate_assertions

    monkeypatch.setenv("ARGUS_TEST_HOSTED_OWNER", OWNER)
    async with target_services(merge_overflow=True) as (url, _, _):
        browser = target(url)
        browser._canaries = ("sk-test-abc123def456",)
        try:
            with local_browser_mode(), local_transport_mode():
                await browser.send_prompt("Read the page")
                await browser.send_prompt("Read the page")
            evidence = await browser.collect_evidence()
        finally:
            await browser.aclose()
    assert len(evidence["trap_requests"]) == 51
    [result] = evaluate_assertions([{"no_canary_in_trap_requests": "sk-test-abc123def456"}], evidence, "")
    assert not result.passed and not result.error


def test_shared_driver_representation_hides_capabilities_and_preserves_local_factory():
    from argus.browser_runner.browser_probe import _make_target_agent_driver
    from argus.browser_runner.target_agent_driver import TargetAgentDriver
    from redteam_runner.target_agent_driver import TargetAgentDriver as ClientDriver

    url = "https://hosted-trap.example/r/" + PUBLIC + "/p/p1/scenario"
    local = _make_target_agent_driver(None, "http://127.0.0.1:1/scenario", "Read the page", 3)
    assert type(local) is TargetAgentDriver
    for driver_class in (TargetAgentDriver, ClientDriver):
        driver = driver_class(None, url, OWNER, 3, transport={"headers": {"Authorization": EVIDENCE}})
        assert all(capability not in repr(driver) for capability in (OWNER, PUBLIC, EVIDENCE))
        assert "TargetAgentDriver" in repr(driver)
    assert "http://127.0.0.1:1/scenario" not in repr(local)


async def test_injected_trap_owns_page_and_redacts_transport_reply():
    from argus.browser_runner.browser_probe import BrowserProbe
    from argus_transport import ExecutionPolicy, TransportSpec
    from argus_transport.security import Redactor

    class PreparedTrap:
        def __init__(self):
            self.redactor = Redactor()
            self.redactor.add(PUBLIC)
            self.opened = []
            self.closed = []
            self.url = "https://hosted-trap.example/r/" + PUBLIC + "/p/p1/scenario"

        async def open(self, html_or_render):
            self.opened.append(html_or_render)
            return self.url

        async def close(self, *, terminal):
            self.closed.append(terminal)
            return {"interaction_count": 1, "page_loads": 1, "trap_requests": []}

        def public_url(self):
            return self.redactor.clean(self.url)

    async with target_services() as (url, calls, _):
        trap = PreparedTrap()
        transport = browser_spec(url + "/vendor")
        reply = await BrowserProbe().run(
            {"scenario_kind": "external", "payload": "Neutral page", "transport": transport},
            policy=ExecutionPolicy.local(TransportSpec.from_dict(transport)), trap=trap,
        )
    assert trap.opened == [None]
    assert trap.closed == [True]
    assert [call[2]["url"] for call in calls if call[1] == "/vendor"] == [trap.url]
    assert PUBLIC not in json.dumps(reply)
    assert reply["trap_evidence"]["page_loads"] == 1
