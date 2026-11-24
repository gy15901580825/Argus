"""Credential providers are opt-in, isolated per run, and share transport redaction."""
import asyncio
import base64
import json
import traceback
from dataclasses import replace
from urllib.parse import quote

import httpx
import pytest
from aiohttp import web
from click.testing import CliRunner

from argus import api, local
from argus.cli.__main__ import main
from argus.cli.reports import render_html, render_junit, render_sarif
from argus.cli.run_json import render_json
from argus.probe import load_probe_library
from argus_transport import ExecutionPolicy, SecretRef, TransportContext, TransportEngine, parse_transport_spec
from argus_transport.runtime_v2 import V2Run
from argus_transport.security import execution_policy, resolve_secret
from test_transport_engine import spec_dict
from transport_v2_fakes import RecordingApp, serve

REF = {"source": "provider", "provider": "hosting", "name": "agent-auth"}
SECRET = "synthetic credential/+=="


def transport(url="http://127.0.0.1:1/run", *, version=2, auth="bearer"):
    data = spec_dict(url)
    data["version"] = version
    data["auth"] = ({"kind": "bearer", "secret": REF} if auth == "bearer" else
        {"kind": "headers", "headers": [{"name": "X-Test-Auth", "secret": REF}]})
    if version == 2:
        data["budget"] = {"stop_on": {"credential_echo": False}}
    return data


def test_parse_provider_reference():
    ref = SecretRef.from_dict(REF)
    assert (ref.source, ref.provider, ref.name) == ("provider", "hosting", "agent-auth")


@pytest.mark.parametrize("change", [
    {"provider": None}, {"provider": ""}, {"provider": 1}, {"name": None}, {"name": ""},
    {"name": 1}, {"path": "anything"}, {"strip_final_newline": False},
])
def test_invalid_provider_reference(change):
    with pytest.raises(ValueError):
        SecretRef.from_dict(REF | change)


@pytest.mark.parametrize("missing", ["provider", "name"])
def test_required_provider_fields(missing):
    with pytest.raises(ValueError):
        SecretRef.from_dict({key: value for key, value in REF.items() if key != missing})


def test_env_file_unchanged():
    assert SecretRef.from_dict({"source": "env", "name": "DUMMY"}).name == "DUMMY"
    assert SecretRef.from_dict({"source": "file", "path": "/made-up", "strip_final_newline": True}).strip_final_newline
    for ref in ({"source": "env", "path": "/made-up"}, {"source": "file", "name": "DUMMY"},
                {"source": "env", "name": "DUMMY", "provider": "hosting"}):
        with pytest.raises(ValueError):
            SecretRef.from_dict(ref)


@pytest.mark.parametrize("local_policy", [False, True])
def test_default_denies_provider(local_policy):
    spec = parse_transport_spec(transport())
    policy = ExecutionPolicy.local(spec) if local_policy else ExecutionPolicy()
    with pytest.raises(ValueError, match="^Secret reference denied$"):
        resolve_secret(spec.auth.secret, policy)
    with pytest.raises(TypeError):
        policy.secret_providers["hosting"] = lambda _: SECRET


@pytest.mark.parametrize("value", [None, 12, ""])
def test_invalid_resolver_return(value):
    policy = ExecutionPolicy(secret_providers={"hosting": lambda _: value})
    with pytest.raises(ValueError):
        resolve_secret(SecretRef.from_dict(REF), policy)


def test_resolver_exception_has_no_secret_traceback():
    def resolver(name):
        raise RuntimeError(SECRET)
    policy = ExecutionPolicy(secret_providers={"hosting": resolver})
    with pytest.raises(ValueError) as raised:
        resolve_secret(SecretRef.from_dict(REF), policy)
    assert SECRET not in "".join(traceback.format_exception(raised.value))
    assert raised.value.__cause__ is None


@pytest.mark.parametrize("version", [1, 2])
@pytest.mark.parametrize("auth", ["bearer", "headers"])
async def test_provider_request_and_echo_redaction(version, auth, tmp_path, caplog):
    forms = [SECRET, quote(SECRET, safe=""), base64.b64encode(SECRET.encode()).decode()]
    app = RecordingApp()
    async def echo(request):
        return web.json_response({"status": "COMPLETED", "result": " | ".join(forms)})
    app.route("POST", "/run", echo)
    async with serve(app) as origin:
        spec = parse_transport_spec(transport(origin + "/run", version=version, auth=auth))
        names = []
        def resolver(name):
            names.append(name)
            return SECRET
        policy = replace(ExecutionPolicy.local(spec), secret_providers={"hosting": resolver})
        if version == 1:
            result = await TransportEngine(spec, policy=policy).run(TransportContext(prompt="hello"))
        else:
            run = V2Run(spec, policy=policy)
            result = await run.attempt(TransportContext(prompt="hello"))
            await run.close()
        assert names and set(names) == {"agent-auth"}
        headers = app.calls[0][2]
        assert headers["Authorization" if auth == "bearer" else "X-Test-Auth"] == (
            "Bearer " + SECRET if auth == "bearer" else SECRET)
        assert result.response_text == "<redacted> | <redacted> | <redacted>"
        record = {"id": "provider-test", "status": "completed", "target_spec": {"kind": "custom_http"},
            "findings": [{"probe_id": "provider-echo", "verdict": "fail", "severity": "high",
                "target_response": result.response_text, "reasoning": result.response_text,
                "target_latency_ms": result.latency_ms, "probed_at": "2026-01-01T00:00:00Z",
                "evidence": result.as_dict()}]}
        encoded = render_json(record)
        (tmp_path / "run.json").write_text(encoded)
        reports = [encoded, render_html(record), render_sarif(record), render_junit(record), caplog.text]
        for report in reports:
            assert all(form not in report for form in forms)
        assert all("redacted" in report for report in reports[:-1])


@pytest.fixture
def probe_library(monkeypatch):
    base = load_probe_library(api.PROBES_DIR)[0]
    probes = [replace(base, id="provider_probe", target_class=("llm_chat",), prompts=("normal",),
        assertions=({"no_secret_in_response": "never-returned-marker"},),
        judge_when_assertions_pass=False, conversation=False, requires_interaction=False)]
    monkeypatch.setattr(api, "load_probe_library", lambda *_: probes)
    monkeypatch.setattr(local, "load_probe_library", lambda *_: probes)
    monkeypatch.setattr(api, "Judge", lambda **_: None)
    monkeypatch.setattr(api.llm, "credential_error", lambda _: None)
    return probes


def test_cli_local_does_not_enable_provider(tmp_path, probe_library):
    target = tmp_path / "target.json"
    target.write_text(json.dumps({"kind": "custom_http", "transport": transport()}))
    out = tmp_path / "run.json"
    result = CliRunner().invoke(main, ["run", "--local", "--target", str(target), "--probes",
        probe_library[0].id, "--format", "json", "--out", str(out)])
    assert result.exit_code == 1, result.output
    assert out.exists(), result.output
    assert "secret_error" in out.read_text()


async def test_server_factory_preflight_and_run(probe_library):
    from argus.server import create_app
    contexts = []
    app = RecordingApp()
    async def completed(request):
        return web.json_response({"status": "COMPLETED", "result": "done"})
    app.route("POST", "/run", completed)
    async with serve(app) as origin:
        def factory(context, spec):
            contexts.append(context)
            return replace(ExecutionPolicy.local(spec), secret_providers={"hosting": lambda _: SECRET})
        hosted = create_app(execution_policy_factory=factory)
        request = {"target": {"kind": "custom_http", "transport": transport(origin + "/run")},
            "probe_ids": [probe_library[0].id]}
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=hosted), base_url="http://test") as client:
            response = await client.post("/redteam/run/preflight", json=request)
            assert response.status_code == 200, response.text
            assert len(contexts) == 1
            response = await client.post("/redteam/run", json=request)
            assert response.status_code == 200, response.text
            assert 'event: end' in response.text
            assert len(contexts) == 2
        assert all(isinstance(context.request, api.RunRequest) for context in contexts)
        assert all(context.request.model_dump() == api.RunRequest(**request).model_dump() for context in contexts)
        assert all(context.run_id for context in contexts)
        assert contexts[0].run_id != contexts[1].run_id
        assert app.calls[0][2]["Authorization"] == "Bearer " + SECRET


async def test_concurrent_server_factories_are_isolated_and_reset(probe_library):
    from argus.server import create_app
    gate = asyncio.Event()
    received = []
    target = RecordingApp()
    async def completed(request):
        received.append(request.headers["Authorization"])
        if len(received) == 2:
            gate.set()
        await asyncio.wait_for(gate.wait(), 5)
        return web.json_response({"status": "COMPLETED", "result": "done"})
    target.route("POST", "/run", completed)
    async with serve(target) as origin:
        data = transport(origin + "/run")
        request = {"target": {"kind": "custom_http", "transport": data}, "probe_ids": [probe_library[0].id]}
        async def scan(secret):
            hosted = create_app(execution_policy_factory=lambda context, spec:
                replace(ExecutionPolicy.local(spec), secret_providers={"hosting": lambda _: secret}))
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=hosted), base_url="http://test") as client:
                assert (await client.post("/redteam/run/preflight", json=request)).status_code == 200
                # The calling task must regain its default policy after every scope.
                assert not execution_policy(parse_transport_spec(data)).secret_providers
                response = await client.post("/redteam/run", json=request)
                assert 'event: end' in response.text, response.text
                assert not execution_policy(parse_transport_spec(data)).secret_providers
        await asyncio.gather(scan("synthetic-first"), scan("synthetic-second"))
        assert sorted(received) == ["Bearer synthetic-first", "Bearer synthetic-second"]


@pytest.mark.parametrize("version", [1, 2])
async def test_resolver_exception_does_not_leak_in_server_record(version, probe_library, caplog):
    from argus.server import create_app
    def resolver(name):
        raise RuntimeError(SECRET)
    app = create_app(execution_policy_factory=lambda context, spec:
        replace(ExecutionPolicy.local(spec), secret_providers={"hosting": resolver}))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/redteam/run", json={"target": {"kind": "custom_http",
            "transport": transport(version=version)}, "probe_ids": [probe_library[0].id]})
    assert "secret_error" in response.text
    record = render_json({"id": "error-test", "notes": [response.text] }, include_notes=True)
    assert SECRET not in response.text + record + caplog.text


@pytest.mark.parametrize("version", [1, 2])
async def test_server_echo_is_masked_in_all_reports(version, probe_library, tmp_path, caplog):
    from argus.server import create_app
    probe_library[0] = replace(probe_library[0], assertions=({"no_secret_in_response": "redacted"},))
    forms = [SECRET, quote(SECRET, safe=""), base64.b64encode(SECRET.encode()).decode()]
    target = RecordingApp()
    async def echoed(request):
        return web.json_response({"status": "COMPLETED", "result": " | ".join(forms)})
    target.route("POST", "/run", echoed)
    async with serve(target) as origin:
        app = create_app(execution_policy_factory=lambda context, spec:
            replace(ExecutionPolicy.local(spec), secret_providers={"hosting": lambda _: SECRET}))
        target_spec = {"kind": "custom_http", "transport": transport(origin + "/run", version=version)}
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post("/redteam/run", json={"target": target_spec,
                "probe_ids": [probe_library[0].id]})
        payloads = [json.loads(line[6:]) for line in response.text.splitlines() if line.startswith("data: ")]
        findings = [payload for payload in payloads if "probe_id" in payload]
        assert len(findings) == 1, response.text
        assert findings[0]["target_response"] == "<redacted> | <redacted> | <redacted>"
        record = {"id": "server-echo", "status": "completed", "target_spec": target_spec, "findings": findings}
        run_json = render_json(record)
        (tmp_path / "run.json").write_text(run_json)
        for report in (run_json, render_html(record), render_sarif(record), render_junit(record), response.text):
            assert all(form not in report for form in forms)
            assert "redacted" in report
        assert all(form not in caplog.text for form in forms)
        assert target.calls[0][2]["Authorization"] == "Bearer " + SECRET
