import json
from contextlib import asynccontextmanager

import pytest
from aiohttp import web

OWNER = "synthetic-owner-capability"
PUBLIC = "synthetic-public-capability"
EVIDENCE = "synthetic-evidence-capability"


@asynccontextmanager
async def hosted_service(status=200, error="not_authorized"):
    calls = []

    async def handle(request):
        body = await request.json() if request.can_read_body else None
        calls.append((request.method, request.path, dict(request.query), dict(request.headers), body))
        if status != 200:
            return web.json_response({"error": error}, status=status)
        if request.path == "/v1/runs":
            return web.json_response({"run_id": "r1", "public_token": PUBLIC, "evidence_token": EVIDENCE, "expires_at": 9999999999})
        if request.path.endswith("/probes"):
            return web.json_response({"probe_id": "p1", "scenario_url": f"{request.scheme}://{request.host}/r/" + PUBLIC + "/p/p1/scenario"})
        if request.path.endswith("/evidence"):
            return web.json_response({"summary": {"complete": True}, "events": [], "next_cursor": None, "late_events": [], "late_cursor": None})
        return web.json_response({"sealed": True, "seal_revision": 1})

    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", handle)
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    try:
        yield f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}", calls
    finally:
        await runner.cleanup()


def make_client(url):
    from argus.targets.hosted_trap import HostedClient
    from argus.targets.browser_use import HostedTrapSpec

    return HostedClient(HostedTrapSpec(url, owner_token_env="ARGUS_TEST_HOSTED_OWNER", run_ttl_s=900))


async def test_hosted_request_contract_and_refreshed_owner(monkeypatch, caplog):
    monkeypatch.setenv("ARGUS_TEST_HOSTED_OWNER", OWNER)
    async with hosted_service() as (url, calls):
        client = make_client(url)
        try:
            run = await client.create_run()
            probe_id, scenario_url = await client.create_probe(run, payload='<form action="{sink_url}/api-key"></form>', markers={"c1": "sk-test-abc123def456"}, lease_s=75)
            monkeypatch.setenv("ARGUS_TEST_HOSTED_OWNER", OWNER + "-refreshed")
            await client.seal(run, probe_id, "vendor_terminal")
            await client.evidence(run, probe_id, cursor="next", late_cursor="audit")
            await client.delete_run(run)
        finally:
            await client.aclose()
    assert calls[0][0:3] == ("POST", "/v1/runs", {})
    assert calls[0][4] == {"schema_version": 1, "ttl_seconds": 900}
    assert calls[0][3]["Authorization"] == "Bearer " + OWNER
    assert len(calls[0][3]["Idempotency-Key"]) == 36
    assert calls[1][0:3] == ("POST", "/v1/runs/r1/probes", {})
    uploaded = calls[1][4]
    assert uploaded == {
        "kind": "browser", "scenario_id": uploaded["scenario_id"], "page_format": "html",
        "payload": '<form action="{sink_url}/api-key"></form>', "public_token": PUBLIC,
        "synthetic_markers": [{"marker_id": "c1", "value": "sk-test-abc123def456"}], "ttl_seconds": 75,
    }
    assert len(uploaded["scenario_id"]) <= 64
    assert calls[2][0:3] == ("POST", "/v1/runs/r1/probes/p1/seal", {})
    assert calls[2][4] == {"reason": "vendor_terminal"}
    assert calls[2][3]["Authorization"] == "Bearer " + OWNER + "-refreshed"
    assert calls[3][0:3] == ("GET", "/v1/runs/r1/evidence", {"probe_id": "p1", "limit": "100", "cursor": "next", "late_cursor": "audit"})
    assert calls[3][3]["Authorization"] == "Bearer " + EVIDENCE
    assert calls[4][0:3] == ("DELETE", "/v1/runs/r1", {})
    assert probe_id == "p1" and scenario_url.endswith("/p/p1/scenario")
    for secret in (OWNER, PUBLIC, EVIDENCE):
        assert secret not in repr(run)
        assert secret not in caplog.text


async def test_missing_owner_stops_before_network(monkeypatch):
    from argus.targets.hosted_trap import HostedTrapError

    monkeypatch.delenv("ARGUS_TEST_HOSTED_OWNER", raising=False)
    async with hosted_service() as (url, calls):
        client = make_client(url)
        try:
            with pytest.raises(HostedTrapError, match="set ARGUS_TEST_HOSTED_OWNER"):
                await client.create_run()
        finally:
            await client.aclose()
        assert calls == []


@pytest.mark.parametrize("status", [401, 403, 429, 503])
async def test_control_errors_are_safe_and_actionable(monkeypatch, status):
    from argus.targets.hosted_trap import HostedTrapError

    monkeypatch.setenv("ARGUS_TEST_HOSTED_OWNER", OWNER)
    async with hosted_service(status) as (url, calls):
        client = make_client(url)
        try:
            with pytest.raises(HostedTrapError) as caught:
                await client.create_run()
        finally:
            await client.aclose()
    assert str(status) in str(caught.value)
    assert "not_authorized" in str(caught.value)
    assert OWNER not in str(caught.value)
    assert caught.value.__cause__ is None
    assert len(calls) == 1


async def test_error_labels_cannot_echo_capability(monkeypatch):
    from argus.targets.hosted_trap import HostedTrapError

    monkeypatch.setenv("ARGUS_TEST_HOSTED_OWNER", OWNER)
    async with hosted_service(401, OWNER) as (url, _):
        client = make_client(url)
        try:
            with pytest.raises(HostedTrapError) as caught:
                await client.create_run()
        finally:
            await client.aclose()
    assert OWNER not in str(caught.value)


@pytest.mark.parametrize("status", [429, 500])
async def test_unreadable_evidence_does_not_raise(monkeypatch, status):
    from argus.targets.hosted_trap import HostedRun

    monkeypatch.setenv("ARGUS_TEST_HOSTED_OWNER", OWNER)
    async with hosted_service(status) as (url, _):
        client = make_client(url)
        try:
            page = await client.evidence(HostedRun("r1", PUBLIC, EVIDENCE, 9999999999), "p1")
        finally:
            await client.aclose()
    assert page["summary"]["complete"] is False
    assert page["unreadable"] is True
    assert page["reason"] == "evidence_unreadable"
