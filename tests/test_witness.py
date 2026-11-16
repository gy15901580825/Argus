"""Offline witness behavior and artifact safety through local execution."""
import asyncio
import hashlib
import gzip
import json
import logging
import re
import time
from dataclasses import asdict, replace
from pathlib import Path
from unittest.mock import AsyncMock, patch
from urllib.parse import urlsplit

import pytest
from aiohttp import ClientSession, web
from yarl import URL

from argus.witness import WitnessRun, WitnessSpec, witness_scope
from argus.targets.browser_use import BrowserUseSpec, BrowserUseTarget, local_browser_mode
from argus_transport import TransportContext, TransportSpec, local_transport_mode
from test_transport_integration import transport
from test_redteam_targets_browser_use import _browser_probe

FAKE_KEY = "fake-key-witness-123456789"


@pytest.fixture
async def upstream():
    state = {"requests": [], "chunks": [b'{"answer":"ok"}'], "status": 200, "content_type": "application/json"}
    async def handle(request):
        state["requests"].append((request.method, request.raw_path, request.headers.get("Authorization"), await request.read(), request.headers.get("X-Private-Hop")))
        response = web.StreamResponse(status=state["status"], headers={"Content-Type": state["content_type"]})
        await response.prepare(request)
        for chunk in state["chunks"]:
            await response.write(chunk)
        await response.write_eof()
        return response
    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", handle)
    server = web.AppRunner(app, access_log=None, auto_decompress=False)
    await server.setup()
    site = web.TCPSite(server, "127.0.0.1", 0)
    await site.start()
    state["url"] = f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}"
    try:
        yield state
    finally:
        await server.cleanup()


@pytest.fixture
async def witness(upstream):
    run = WitnessRun(WitnessSpec(model_relay={"upstream": upstream["url"] + "/v1"}, otlp={}))
    await run.start(["model_relay", "otlp"])
    try:
        yield run
    finally:
        await run.aclose()


def test_canary_generation_and_safe_repr():
    runs = [WitnessRun(WitnessSpec()) for _ in range(20)]
    assert len({r.canary for r in runs}) == len(runs)
    for run in runs:
        assert re.fullmatch(r"ARGUS-CANARY-NOTAKEY-[A-Z2-7]{10}", run.canary)
        assert run.fingerprint == hashlib.sha256(run.canary.encode()).hexdigest()[:8]
        assert run.canary not in repr(run)
        assert run.canary not in repr(TransportContext(prompt="hello", secret_canary=run.canary))


@pytest.mark.parametrize("stream", [False, True])
async def test_relay_preserves_bytes_headers_method_path_and_query(witness, upstream, stream):
    if stream:
        upstream.update(chunks=[b'data: {"delta":"a"}\n\n', b'data: {"delta":"b"}\n\n', b'data: [DONE]\n\n'], content_type="text/event-stream")
    body = b'opaque bytes \x00\xff'
    encoding = {}
    if not stream:
        body = gzip.compress(body)
        encoding = {"Content-Encoding": "gzip"}
    async with ClientSession(auto_decompress=False) as client:
        async with client.patch(URL(witness.urls["model_relay"] + "chat/completions?mode=a%2Fb&n=2", encoded=True), data=body,
                                headers={"Authorization": "Bearer " + FAKE_KEY, "Connection": "X-Private-Hop", "X-Private-Hop": "drop", **encoding}) as response:
            assert await response.read() == b"".join(upstream["chunks"])
            assert response.headers["Content-Type"] == upstream["content_type"]
    assert upstream["requests"] == [("PATCH", "/v1/chat/completions?mode=a%2Fb&n=2", "Bearer " + FAKE_KEY, body, None)]


async def test_sse_is_streamed_before_upstream_finishes():
    release = asyncio.Event()
    async def handle(request):
        response = web.StreamResponse(headers={"Content-Type": "text/event-stream"})
        await response.prepare(request)
        await response.write(b"data: first\n\n")
        await release.wait()
        await response.write(b"data: last\n\n")
        return response
    app = web.Application()
    app.router.add_post("/v1/chat", handle)
    server = web.AppRunner(app, access_log=None)
    await server.setup()
    site = web.TCPSite(server, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    run = WitnessRun(WitnessSpec(model_relay={"upstream": f"http://127.0.0.1:{port}/v1"}))
    try:
        await run.start(["model_relay"])
        async with ClientSession() as client:
            async with client.post(run.urls["model_relay"] + "chat") as response:
                assert await asyncio.wait_for(response.content.readexactly(13), 2) == b"data: first\n\n"
                release.set()
                assert await response.read() == b"data: last\n\n"
    finally:
        release.set()
        await run.aclose()
        await server.cleanup()


@pytest.mark.parametrize("channel", ["model_relay", "otlp"])
async def test_run_token_is_required(witness, upstream, channel):
    base = witness.urls[channel].split("/r/", 1)[0]
    async with ClientSession() as client:
        for path in ["/", "/v1/traces", "/chat", "/r/wrong/v1/traces"]:
            async with client.post(base + path, data=b"not forwarded") as response:
                assert response.status == 404
    assert upstream["requests"] == []
    assert witness.relay_records == [] and witness.export_records == []


async def test_flags_masked_excerpt_and_record_allowlist(witness):
    bodies = [b"no match", b"%argus_secret%", witness.canary.encode(),
              ("x" * 200 + "%argus_secret% " + FAKE_KEY + " " + witness.canary + "z" * 200).encode()]
    async with ClientSession() as client:
        for body in bodies:
            async with client.post(witness.urls["model_relay"] + "chat", data=body, headers={"Authorization": "Bearer " + FAKE_KEY}) as response:
                await response.read()
    records = [asdict(r) for r in witness.relay_records]
    assert [(r["placeholder_seen"], r["canary_seen"]) for r in records] == [(False, False), (True, False), (False, True), (True, True)]
    assert records[0]["excerpt"] is None
    assert records[2]["excerpt"] == witness.marker
    assert witness.marker in records[3]["excerpt"]
    for record in records:
        assert set(record) == {"index", "received_at", "path", "body_size", "placeholder_seen", "canary_seen", "excerpt", "status", "error", "inspected", "inspection_error"}
        assert record["excerpt"] is None or len(record["excerpt"]) <= 160
        assert witness.canary not in json.dumps(record) and FAKE_KEY not in json.dumps(record)


@pytest.mark.parametrize("content_type", ["application/json", "application/x-protobuf"])
async def test_otlp_canary_values_span_count_and_empty_body(witness, content_type):
    witness.register_values(["plain-control-value", "absent"])
    if content_type == "application/json":
        body = json.dumps({"resourceSpans": [{"scopeSpans": [{"spans": [
            {"attributes": [{"key": "filled", "value": {"stringValue": witness.canary}}]},
            {"name": "plain-control-value"}]}]}]}).encode()
    else:
        value = witness.canary.encode()
        body = b"\x0a" + bytes([len(value)]) + value + b"plain-control-value"
    async with ClientSession() as client:
        for data in [body, b""]:
            async with client.post(witness.urls["otlp"] + "v1/traces", data=data, headers={"Content-Type": content_type}) as response:
                assert response.status == 200
                assert response.content_type == content_type
                assert await response.read() == (b"{}" if content_type == "application/json" else b"")
    first, empty = witness.export_records
    assert first.canary_seen is True and first.values_seen == (True, False)
    assert first.span_count == (2 if content_type == "application/json" else None)
    assert empty.canary_seen is False and empty.values_seen == (False, False)
    assert empty.span_count == (0 if content_type == "application/json" else None)
    assert set(asdict(first)) == {"index", "received_at", "content_type", "size", "canary_seen", "values_seen", "span_count", "inspected", "inspection_error"}
    assert witness.canary not in json.dumps(asdict(first))


async def test_upstream_failure_retains_no_body_or_exception_text(witness, upstream, caplog):
    upstream.update(status=503, chunks=[(FAKE_KEY + witness.canary).encode()])
    with caplog.at_level(logging.DEBUG):
        async with ClientSession() as client:
            async with client.post(witness.urls["model_relay"] + "chat", data=witness.canary.encode(), headers={"Authorization": "Bearer " + FAKE_KEY}) as response:
                assert response.status == 503
                assert await response.text() == "upstream HTTP failure"
    assert witness.relay_records[0].status == 503
    assert FAKE_KEY not in caplog.text and witness.canary not in caplog.text
    run = WitnessRun(WitnessSpec(model_relay={"upstream": "http://127.0.0.1:1"}))
    try:
        await run.start(["model_relay"])
        async with ClientSession() as client:
            async with client.post(run.urls["model_relay"] + "chat") as response:
                assert response.status == 502
                assert await response.text() == "upstream transport failure"
        assert run.relay_records[0].error == "upstream_transport_error"
    finally:
        await run.aclose()


@pytest.mark.parametrize("raw", [
    {"model_relay": {"upstream": "ftp://model.example.test/v1"}},
    {"model_relay": {"upstream": "http://model.example.test/v1"}},
    {"model_relay": {"upstream": "https://name:fake-password@model.example.test"}},
    {"model_relay": {"upstream": "https://model.example.test/v1?param=value"}},
    {"model_relay": {"upstream": "https://model.example.test/#fragment"}},
    {"model_relay": {"upstream": None}},
    {"model_relay": {"upstream": "https://model.example.test", "unknown": True}},
    {"otlp": {"unknown": True}}, {"unknown": True}, {"secret_canary_env": "FAKE"},
    {"secret_placeholder": "%bad%"}, {"bind": "not an address"},
])
def test_invalid_witness_is_rejected_when_target_loads(raw):
    with pytest.raises(ValueError):
        BrowserUseSpec(transport=transport("http://127.0.0.1:1/run"), scenario_kind="dom_injection", witness=raw)


def test_secret_context_bindings_and_binding_presence():
    spec = transport("http://127.0.0.1:1/run")
    spec["request"]["body"]["json"].update(sensitive_data={"object": {"argus_secret": {"context": "secret_canary"}}}, name={"context": "secret_placeholder"})
    loaded = BrowserUseSpec(transport=spec, scenario_kind="dom_injection")
    assert loaded.binds_secret_canary is True
    assert BrowserUseSpec(transport=transport("http://127.0.0.1:1/run"), scenario_kind="dom_injection").binds_secret_canary is False
    literal = transport("http://127.0.0.1:1/run")
    literal["request"]["body"]["json"] = {"data": {"literal": {"context": "secret_canary"}}}
    assert BrowserUseSpec(transport=literal, scenario_kind="dom_injection").binds_secret_canary is False
    literal["request"]["body"]["json"] = {"literal": {"context": "secret_canary"}}
    assert BrowserUseSpec(transport=literal, scenario_kind="dom_injection").binds_secret_canary is True
    literal["request"]["body"] = {"text": {"context": "secret_canary"}}
    assert BrowserUseSpec(transport=literal, scenario_kind="dom_injection").binds_secret_canary is True


@pytest.mark.parametrize("mode", ["server", "hosted", "missing_channel", "missing_binding"])
async def test_witness_requirements_skip_unsupported_execution(mode, witness):
    spec = transport("http://127.0.0.1:1/run")
    options = {"witness": witness.spec}
    if mode == "hosted":
        options.update(trap_mode="hosted", hosted={"service_url": "https://trap.example.test"})
    run = witness if mode != "missing_channel" else WitnessRun(WitnessSpec())
    with witness_scope(run):
        target = BrowserUseTarget(BrowserUseSpec(transport=spec, scenario_kind="dom_injection", **options))
    probe = replace(_browser_probe(), requires_witness=("model_relay",), requires_secret_canary=mode == "missing_binding")
    from argus.targets._base import ProbeNotApplicable
    from argus.runner import Runner
    runner = Runner(target, AsyncMock(), Path(__file__).resolve().parents[1] / "argus/rubrics")
    if mode == "server":
        findings = [r async for r in runner.run_probe(probe)]
    else:
        with local_browser_mode():
            findings = [r async for r in runner.run_probe(probe)]
    assert findings[0].verdict == "skipped"
    assert {"server": "server mode", "hosted": "hosted", "missing_channel": "configure", "missing_binding": "declared secret"}[mode] in findings[0].reasoning


async def test_probe_windows_and_value_registration_reset(witness):
    with witness_scope(witness):
        target = BrowserUseTarget(BrowserUseSpec(transport=transport("http://127.0.0.1:1/run"), scenario_kind="dom_injection", witness=witness.spec))
    probe = replace(_browser_probe(), requires_witness=("otlp",), witness_values=("plain",))
    async with ClientSession() as client:
        with local_browser_mode():
            await target.begin_probe(probe)
        async with client.post(witness.urls["otlp"] + "v1/traces", data=b'{"plain":"plain"}', headers={"Content-Type": "application/json"}) as response:
            await response.read()
        first = (await target.collect_evidence())["witness"]
        assert len(first["otlp"]) == 1 and first["otlp"][0]["values_seen"] == (True,)
        with local_browser_mode():
            await target.begin_probe(replace(probe, witness_values=()))
        assert (await target.collect_evidence())["witness"]["otlp"] == []
        async with client.post(witness.urls["otlp"] + "v1/traces", data=b'{}', headers={"Content-Type": "application/json"}) as response:
            await response.read()
        second = (await target.collect_evidence())["witness"]
        assert len(second["otlp"]) == 1 and second["otlp"][0]["values_seen"] == ()
        assert len(first["otlp"]) == 1


@pytest.mark.parametrize("fixed_token", [False, True])
async def test_local_run_artifacts_never_contain_canary_or_provider_key(upstream, monkeypatch, tmp_path, caplog, fixed_token):
    from argus import api, local
    from argus.cli import reports, run_json
    token = "fake-witness-token-0123456789abcdef"
    if fixed_token:
        monkeypatch.setenv("ARGUS_WITNESS_TOKEN", token)
    state = {}
    original_start = WitnessRun.start
    async def remember_start(self, channels):
        urls = await original_start(self, channels)
        state.update(urls=urls, run=self)
        return urls
    monkeypatch.setattr(WitnessRun, "start", remember_start)
    async def agent(request):
        body = await request.json()
        canary = body["sensitive_data"]["argus_secret"]
        assert canary == state["run"].canary
        assert body["placeholder"] == "argus_secret"
        assert canary not in body["goal"]
        parts = urlsplit(body["url"])
        assert parts.scheme == "http" and parts.hostname == "127.0.0.1"
        trap_url = f"http://127.0.0.1:{int(parts.port)}{parts.path}"
        async with ClientSession() as client:
            async with client.get(trap_url, params={"echo": canary}) as response:
                await response.read()
            async with client.post(state["urls"]["model_relay"] + "chat/" + token, json={"prompt": "%argus_secret% " + canary + " " + token},
                                   headers={"Authorization": "Bearer " + FAKE_KEY}) as response:
                assert await response.read() == b"".join(upstream["chunks"])
            async with client.post(state["urls"]["otlp"] + "v1/traces", json={"resourceSpans": [{"scopeSpans": [{"spans": [{"name": canary}]}]}]}) as response:
                await response.read()
        return web.json_response({"status": "COMPLETED", "result": canary,
                                  "run_log": [{"operation": canary + token, "status": "success", "nested": {canary: canary, token: token}}]})
    app = web.Application()
    app.router.add_post("/run", agent)
    server = web.AppRunner(app, access_log=None)
    await server.setup()
    site = web.TCPSite(server, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    spec = transport(f"http://127.0.0.1:{port}/run")
    spec["request"]["body"]["json"].update(url={"context": "scenario_url"},
        sensitive_data={"object": {"argus_secret": {"context": "secret_canary"}}},
        placeholder={"context": "secret_placeholder"})
    spec["response"]["metadata"] = {"run_log": {"path": "$.run_log"}}
    target = {"kind": "browser_use", "scenario_kind": "dom_injection", "transport": spec,
              "witness": {"model_relay": {"upstream": upstream["url"] + "/v1"}, "otlp": {}}}
    probe = replace(_browser_probe(), assertions=({"no_trap_request": True},),
                    requires_witness=("model_relay", "otlp"), requires_secret_canary=True)
    monkeypatch.setattr(api, "load_probe_library", lambda _: [probe])
    monkeypatch.setattr(local, "load_probe_library", lambda _: [probe])
    captured = []
    original_collect = BrowserUseTarget.collect_evidence
    async def collect(self):
        captured.append(self.last_run_log().model_dump() if self.last_run_log() else None)
        return await original_collect(self)
    monkeypatch.setattr(BrowserUseTarget, "collect_evidence", collect)
    try:
        with caplog.at_level(logging.DEBUG):
            events = [event async for event in local.run_local(target, [probe.id], env={})]
        if fixed_token:
            assert state["run"].token == token
        assert len([e for e in events if e.get("type") == "witness"]) == 1
        findings = [e for e in events if "verdict" in e]
        assert len(findings) == 1 and findings[0]["verdict"] == "pass"
        evidence = findings[0]["evidence"]["witness"]
        assert evidence["canary_bound"] is True
        assert evidence["model_relay"][0]["canary_seen"] is True
        assert evidence["otlp"][0]["canary_seen"] is True
        run = {"id": "11111111-2222-3333-4444-555555555555", "status": "completed", "target_spec": target,
               "started_at": "2026-11-15T00:00:00+00:00", "finished_at": "2026-11-15T00:00:01+00:00", "findings": findings}
        artifacts = {"run.json": run_json.render_json(run), "run.sarif": reports.render_sarif(run),
                     "run.xml": reports.render_junit(run), "run.html": reports.render_html(run),
                     "run.log": json.dumps(captured), "access.log": caplog.text,
                     "errors.txt": json.dumps([asdict(r) for r in state["run"].relay_records])}
        assert json.loads(artifacts["run.json"])["findings"][0]["evidence"]["witness"]["canary_bound"] is True
        for name, contents in artifacts.items():
            (tmp_path / name).write_text(contents)
        for path in tmp_path.iterdir():
            assert FAKE_KEY not in path.read_text(), path.name
            assert state["run"].canary not in path.read_text(), path.name
            if fixed_token:
                assert token not in path.read_text(), path.name
        assert state["run"]._client is None and state["run"]._servers == {}
    finally:
        await server.cleanup()


async def test_delivery_error_and_run_log_scrub_use_existing_path(witness):
    with witness_scope(witness):
        target = BrowserUseTarget(BrowserUseSpec(transport=transport("http://127.0.0.1:1/run"), scenario_kind="dom_injection"))
    with patch.object(target, "_send_prompt", side_effect=OSError("delivery echoed " + witness.canary + " " + witness.token)):
        with pytest.raises(OSError) as caught:
            await target.send_prompt("hello")
    assert witness.canary not in str(caught.value)
    assert witness.fingerprint in str(caught.value)
    assert witness.token not in str(caught.value)


async def test_unused_witness_starts_no_listener(upstream, monkeypatch):
    from argus import api, local
    probe = replace(_browser_probe(), assertions=({"no_trap_request": True},))
    monkeypatch.setattr(api, "load_probe_library", lambda _: [probe])
    monkeypatch.setattr(local, "load_probe_library", lambda _: [probe])
    async def fake_run(*args, **kwargs):
        yield {"probe_id": probe.id, "verdict": "pass", "severity": "info"}
    monkeypatch.setattr(api, "_run_probes", fake_run)
    start = AsyncMock()
    monkeypatch.setattr(WitnessRun, "start", start)
    target = {"kind": "browser_use", "scenario_kind": "dom_injection", "transport": transport(upstream["url"]),
              "witness": {"model_relay": {"upstream": upstream["url"]}, "otlp": {}}}
    events = [e async for e in local.run_local(target, [probe.id], env={})]
    assert not any(e.get("type") == "witness" for e in events)
    start.assert_not_awaited()


async def test_closing_run_after_start_event_closes_listeners(upstream, monkeypatch):
    from argus import api, local
    probe = replace(_browser_probe(), assertions=({"no_trap_request": True},), requires_witness=("otlp",))
    monkeypatch.setattr(api, "load_probe_library", lambda _: [probe])
    monkeypatch.setattr(local, "load_probe_library", lambda _: [probe])
    target = {"kind": "browser_use", "scenario_kind": "dom_injection", "transport": transport(upstream["url"]), "witness": {"otlp": {}}}
    events = local.run_local(target, [probe.id], env={})
    event = await events.__anext__()
    assert event["type"] == "witness"
    url = event["urls"]["otlp"]
    await events.aclose()
    from aiohttp import ClientConnectionError
    async with ClientSession() as client:
        with pytest.raises(ClientConnectionError):
            await client.post(url + "v1/traces", json={})


def test_deep_probe_inherits_witness_requirements():
    from argus.persona_strategy import PersonaStrategyProbe
    from argus.persona_loader import default_personas, default_strategies
    base = replace(_browser_probe(), requires_witness=("otlp",), requires_secret_canary=True, witness_values=("plain",))
    probe = PersonaStrategyProbe(base=base, persona=default_personas()[0], strategy=default_strategies()[0])
    assert probe.requires_witness == ("otlp",)
    assert probe.requires_secret_canary is True
    assert probe.witness_values == ("plain",)
