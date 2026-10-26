"""The mcp_server adapter and its probes (GHSA-mvf5-2qqv-rg3c): foreign Origin, no auth, sensitive tools."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from orchestrator.redteam.assertions import evaluate_assertions
from orchestrator.redteam.probe import load_probe
from orchestrator.redteam.runner import Runner
from orchestrator.redteam.targets import build_target
from orchestrator.redteam.targets.mcp_server import FOREIGN_ORIGIN

PROBES = Path(__file__).resolve().parents[1] / "orchestrator" / "redteam" / "probes" / "mcp_server"
TOKEN = "Bearer good"


def _server(*, check_origin: bool, need_auth: bool, tools: list[dict] | None, sse: bool = False, log=None):
    """A Streamable HTTP MCP server. Vulnerable: no Origin check, CORS *, no auth (the advisory's shape)."""
    def handler(req: httpx.Request) -> httpx.Response:
        if log is not None:
            log.append(req)
        origin = req.headers.get("origin")
        cors = {"access-control-allow-origin": "*"} if not check_origin else {}
        if req.method == "OPTIONS":
            return httpx.Response(204, headers=cors)
        if check_origin and origin and origin != "http://localhost":
            return httpx.Response(403, json={"error": "origin not allowed"})
        if need_auth and req.headers.get("authorization") != TOKEN:
            return httpx.Response(401, json={"error": "unauthorized"})
        msg = json.loads(req.content)
        if "id" not in msg:
            return httpx.Response(202, headers=cors)
        if msg["method"] == "initialize":
            result = {"protocolVersion": "2025-06-18", "capabilities": {}, "serverInfo": {"name": "s", "version": "1"}}
        elif msg["method"] == "tools/list" and tools is not None:
            result = {"tools": tools}
        else:
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": msg["id"], "error": {"code": -32601}})
        body = {"jsonrpc": "2.0", "id": msg["id"], "result": result}
        if sse:
            return httpx.Response(200, headers={**cors, "content-type": "text/event-stream", "mcp-session-id": "s1"},
                                  text=f"event: message\ndata: {json.dumps(body)}\n\n")
        return httpx.Response(200, headers={**cors, "mcp-session-id": "s1"}, json=body)
    return httpx.MockTransport(handler)


GET_ENV = {"name": "get-env", "description": "Returns all environment variables"}
ECHO = {"name": "echo", "description": "Echoes back the input"}


def _target(transport, headers=()):
    t = build_target({"kind": "mcp_server", "url": "http://127.0.0.1:3001/mcp", "headers": list(headers)})
    t._transport = transport
    return t


async def _evidence(transport, headers=()):
    t = _target(transport, headers)
    await t.send_prompt("ignored")
    return await t.collect_evidence()


def test_url_is_required():
    with pytest.raises(ValueError, match="url"):
        build_target({"kind": "mcp_server", "url": ""})


@pytest.mark.asyncio
async def test_vulnerable_server_fails_all_three_checks():
    ev = await _evidence(_server(check_origin=False, need_auth=False, tools=[GET_ENV, ECHO]))
    assert ev["foreign_origin_initialized"] and ev["cors_allows_foreign_origin"] and ev["unauthenticated_initialized"]
    res = {r.name: r for r in evaluate_assertions(
        ({"mcp_rejects_foreign_origin": True}, {"mcp_requires_auth": True},
         {"mcp_no_sensitive_tools": ["env", "shell", "file"]}), ev, "")}
    assert not res["mcp_rejects_foreign_origin"].passed and "any web page" in res["mcp_rejects_foreign_origin"].reason
    assert not res["mcp_requires_auth"].passed
    assert not res["mcp_no_sensitive_tools"].passed and "get-env (env)" in res["mcp_no_sensitive_tools"].reason
    assert "echo" not in res["mcp_no_sensitive_tools"].reason


@pytest.mark.asyncio
async def test_hardened_server_passes_all_three_checks():
    ev = await _evidence(_server(check_origin=True, need_auth=True, tools=[ECHO]),
                         headers=[("Authorization", TOKEN)])
    assert ev["foreign_origin_initialized"] is False and ev["cors_allows_foreign_origin"] is False
    assert ev["unauthenticated_initialized"] is False and ev["tools"] == [ECHO]
    res = evaluate_assertions(({"mcp_rejects_foreign_origin": True}, {"mcp_requires_auth": True},
                               {"mcp_no_sensitive_tools": ["env", "shell", "file"]}), ev, "")
    assert all(r.passed for r in res), [r.reason for r in res]


@pytest.mark.asyncio
async def test_sse_replies_are_parsed():
    ev = await _evidence(_server(check_origin=False, need_auth=False, tools=[GET_ENV], sse=True))
    assert ev["unauthenticated_initialized"] and ev["tools"] == [GET_ENV]


@pytest.mark.asyncio
async def test_foreign_origin_without_cors_is_still_a_failure_dns_rebinding():
    def handler(req):
        if req.method == "OPTIONS":
            return httpx.Response(204)
        msg = json.loads(req.content)
        if "id" not in msg:
            return httpx.Response(202)
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": msg["id"], "result": {"tools": []}})
    ev = await _evidence(httpx.MockTransport(handler))
    assert ev["foreign_origin_initialized"] and not ev["cors_allows_foreign_origin"]
    (r,) = evaluate_assertions(({"mcp_rejects_foreign_origin": True},), ev, "")
    assert not r.passed and "DNS rebinding" in r.reason


@pytest.mark.asyncio
async def test_unlisted_tools_fail_closed():
    """Credentials missing: tools/list never answers. Unseen is not absent."""
    ev = await _evidence(_server(check_origin=True, need_auth=True, tools=[ECHO]))
    assert ev["tools"] is None
    (r,) = evaluate_assertions(({"mcp_no_sensitive_tools": ["env"]},), ev, "")
    assert not r.passed and "cannot be ruled out" in r.reason


@pytest.mark.asyncio
async def test_unreachable_server_records_no_interaction():
    def handler(req):
        raise httpx.ConnectError("refused")
    ev = await _evidence(httpx.MockTransport(handler))
    assert ev["interaction_count"] == 0 and ev["tools"] is None and ev["errors"]


@pytest.mark.asyncio
async def test_never_calls_a_tool_and_keeps_credentials_off_the_hostile_requests():
    log: list[httpx.Request] = []
    await _evidence(_server(check_origin=False, need_auth=False, tools=[GET_ENV], log=log),
                    headers=[("Authorization", TOKEN)])
    methods = [json.loads(r.content).get("method") for r in log if r.content]
    assert "tools/call" not in methods and "tools/list" in methods
    for r in log:
        if r.headers.get("origin") == FOREIGN_ORIGIN:
            assert "authorization" not in r.headers
    assert any(json.loads(r.content).get("method") == "initialize" and "authorization" not in r.headers
               and "origin" not in r.headers for r in log if r.content)


@pytest.mark.parametrize("value", [None, [], ["nope"], 3])
def test_bad_family_value_fails_closed(value):
    (r,) = evaluate_assertions(({"mcp_no_sensitive_tools": value},), {"tools": [GET_ENV]}, "")
    assert not r.passed and "must name families" in r.reason


@pytest.mark.parametrize("name,desc,family", [
    ("run_command", "Run a shell command", "shell"), ("read_file", "Read a file", "file"),
    ("printEnv", "Print the environment variables", "env"),
])
def test_sensitive_families_match(name, desc, family):
    (r,) = evaluate_assertions(({"mcp_no_sensitive_tools": [family]},),
                               {"tools": [{"name": name, "description": desc}]}, "")
    assert not r.passed


class _NoJudge:
    async def judge(self, **kw):
        raise AssertionError("assertions decide these probes")


@pytest.mark.asyncio
@pytest.mark.parametrize("vulnerable,want", [(True, "fail"), (False, "pass")])
async def test_shipped_probes_end_to_end(tmp_path, vulnerable, want):
    probes = [load_probe(p) for p in sorted(PROBES.glob("*.yaml"))]
    assert {p.id for p in probes} == {"mcp_server_foreign_origin", "mcp_server_no_auth", "mcp_server_sensitive_tools"}
    srv = _server(check_origin=not vulnerable, need_auth=not vulnerable, tools=[GET_ENV] if vulnerable else [ECHO])
    target = _target(srv, headers=[("Authorization", TOKEN)])
    runner = Runner(target=target, judge=_NoJudge(), rubrics_dir=tmp_path)
    for probe in probes:
        findings = [f async for f in runner.run_probe(probe)]
        assert [f.verdict for f in findings] == [want], (probe.id, findings)
