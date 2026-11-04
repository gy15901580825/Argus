from contextlib import asynccontextmanager

import pytest
from aiohttp import web

from tests.test_hosted_client import OWNER, PUBLIC, EVIDENCE, make_client


def sink(hit=False):
    return {"kind": "sink_request", "route_class": "/sink/other", "method": "POST", "complete": True,
            "canary_hits": [{"marker_id": "c1", "location": "body"}] if hit else []}


def page(events=(), late=(), cursor=None, late_cursor=None):
    return {"probe_id": "p1", "seal_revision": 1, "snapshot_hash": "synthetic-snapshot",
            "summary": {"interaction_count": 3, "page_loads": 2, "prefetch_count": 0, "complete": True, "dropped_events": 0},
            "events": list(events), "late_events": list(late), "late_count": 2,
            "next_cursor": cursor, "late_cursor": late_cursor}


@asynccontextmanager
async def paged_service(mode="paged"):
    requests = []

    async def handler(request):
        body = await request.json() if request.can_read_body else None
        requests.append((request.method, request.path, dict(request.query), body))
        if request.path == "/v1/runs":
            data = {"run_id": "r1", "public_token": PUBLIC, "evidence_token": EVIDENCE, "expires_at": 9999999999}
        elif request.path.endswith("/probes"):
            data = {"probe_id": "p1", "scenario_url": f"{request.scheme}://{request.host}/r/" + PUBLIC + "/p/p1/scenario"}
        elif request.path.endswith("/seal"):
            data = {"sealed": True, "seal_revision": 1}
        else:
            offset = int(request.query.get("cursor", "0"))
            if mode == "unreadable" and offset:
                return web.json_response({"error": "rate_limit"}, status=429)
            if mode == "capped":
                data = page([sink(offset == 0)], cursor=str(offset + 1), late_cursor=None)
            elif offset == 0:
                data = page([sink(True)], [sink(True)], cursor="1", late_cursor="1")
            elif offset == 1:
                data = page([sink(False)], [sink(False)], late_cursor="2")
            else:
                data = page([], [sink(False)])
            if request.query.get("late_cursor") == "2":
                data = page([sink(True)], [sink(False)])
        return web.json_response(data)

    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", handler)
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    try:
        yield f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}", requests
    finally:
        await runner.cleanup()


@pytest.mark.parametrize("terminal,reason", [(True, "vendor_terminal"), (False, "timeout")])
async def test_hosted_seal_and_independent_cursor_collection(monkeypatch, terminal, reason):
    from argus.targets.hosted_trap import HostedTrap
    from argus.targets.browser_use import _valid_evidence

    monkeypatch.setenv("ARGUS_TEST_HOSTED_OWNER", OWNER)
    async with paged_service() as (url, requests):
        client = make_client(url)
        try:
            trap = HostedTrap(client, await client.create_run(), {"c1": "sk-test-abc123def456"}, 75)
            scenario_url = await trap.open("<p>Synthetic page</p>")
            evidence = await trap.close(terminal=terminal)
            assert await trap.close(terminal=terminal) == evidence
        finally:
            await client.aclose()
    assert _valid_evidence(evidence)
    assert scenario_url.endswith("/p/p1/scenario")
    assert PUBLIC not in trap.public_url()
    assert len(evidence["trap_requests"]) == 2
    assert evidence["trap_requests"][0]["marker_hits"] == [{"marker_id": "c1", "location": "body"}]
    assert all(r["query"] == r["body"] == "" for r in evidence["trap_requests"])
    [round_] = evidence["hosted"]["rounds"]
    assert round_["late_marker_hits"] == 1
    assert round_["complete"] is terminal
    assert round_["unreadable"] is False
    assert requests[2][3] == {"reason": reason}
    evidence_queries = [r[2] for r in requests if r[1].endswith("/evidence")]
    assert len(evidence_queries) == 3
    assert evidence_queries[-1] == {"probe_id": "p1", "limit": "100", "late_cursor": "2"}


@pytest.mark.parametrize("mode,reads", [("unreadable", 2), ("capped", 10)])
async def test_hits_survive_unreadable_or_unfinished_pagination(monkeypatch, mode, reads):
    from argus.targets.hosted_trap import HostedTrap
    from argus.assertions import evaluate_assertions

    monkeypatch.setenv("ARGUS_TEST_HOSTED_OWNER", OWNER)
    async with paged_service(mode) as (url, requests):
        client = make_client(url)
        try:
            trap = HostedTrap(client, await client.create_run(), {"c1": "sk-test-abc123def456"}, 75)
            await trap.open("<p>Synthetic page</p>")
            evidence = await trap.close(terminal=True)
        finally:
            await client.aclose()
    [round_] = evidence["hosted"]["rounds"]
    assert round_["complete"] is False
    assert round_["unreadable"] is True
    assert len([r for r in requests if r[1].endswith("/evidence")]) == reads
    [result] = evaluate_assertions([{"no_canary_in_trap_requests": "sk-test-abc123def456"}], evidence, "")
    assert not result.passed and not result.error


async def test_visual_content_rejected_before_probe_request(monkeypatch):
    from argus.targets.hosted_trap import HostedTrap
    from argus.targets.hosted_trap import HostedRun, UnsupportedHostedScenario

    monkeypatch.setenv("ARGUS_TEST_HOSTED_OWNER", OWNER)
    async with paged_service() as (url, requests):
        client = make_client(url)
        try:
            trap = HostedTrap(client, HostedRun("r1", PUBLIC, EVIDENCE, 9999999999), {}, 75)
            with pytest.raises(UnsupportedHostedScenario):
                await trap.open(b"synthetic image")
        finally:
            await client.aclose()
        assert requests == []
