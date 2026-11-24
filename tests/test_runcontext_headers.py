"""Incoming binding headers stay private while providers authenticate the target."""
import base64
import json
import logging
from dataclasses import FrozenInstanceError, replace
from urllib.parse import quote

import httpx
import pytest
from aiohttp import web

from argus import api
from argus.cli.reports import render_html, render_junit, render_sarif
from argus.cli.run_json import render_json
from argus_transport import ExecutionPolicy
from test_transport_secret_provider import probe_library, transport
from transport_v2_fakes import RecordingApp, serve

CREDENTIAL = "synthetic-run-binding/+=="
UNUSED_CREDENTIAL = "synthetic-unused-binding/+=="
BINDING_HEADERS = {"X-Run-Credential": CREDENTIAL, "X-Unused-Credential": UNUSED_CREDENTIAL}


def test_context_headers_are_copied_normalized_and_private():
    source = dict(BINDING_HEADERS)
    context = api.RunContext(run_id="test-run", request=api.RunRequest(target={}), headers=source)
    source["X-Run-Credential"] = "changed"
    assert context.headers["x-run-credential"] == CREDENTIAL
    assert "X-Run-Credential" not in context.headers
    with pytest.raises(TypeError):
        context.headers["x-run-credential"] = "changed"
    with pytest.raises(FrozenInstanceError):
        context.headers = {}
    for value in BINDING_HEADERS.values():
        assert value not in repr(context)
        assert value not in str(context)


@pytest.mark.parametrize("endpoint", ["/redteam/run/preflight", "/redteam/run"])
async def test_factory_receives_immutable_incoming_headers(endpoint, probe_library):
    from argus.server import create_app
    contexts = []

    def factory(context, spec):
        contexts.append(context)
        assert context.headers["x-run-credential"] == CREDENTIAL
        assert context.headers["x-unused-credential"] == UNUSED_CREDENTIAL
        with pytest.raises(TypeError):
            context.headers["x-run-credential"] = "changed"
        return ExecutionPolicy.local(spec)

    app = create_app(execution_policy_factory=factory)
    data = transport()
    data["auth"] = {"kind": "none"}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(endpoint, headers=BINDING_HEADERS, json={
            "target": {"kind": "custom_http", "transport": data}, "probe_ids": [probe_library[0].id]})
    assert response.status_code == 200, response.text
    assert len(contexts) == 1
    assert all(value not in repr(contexts[0]) + str(contexts[0]) for value in BINDING_HEADERS.values())


@pytest.mark.parametrize("version", [1, 2])
@pytest.mark.parametrize("target_status", [200, 500])
async def test_binding_credentials_stay_out_of_server_outputs(
    version, target_status, probe_library, tmp_path, caplog,
):
    from argus.server import create_app
    caplog.set_level(logging.DEBUG)
    probe_library[0] = replace(probe_library[0], assertions=({"no_secret_in_response": "redacted"},))
    target = RecordingApp()
    contexts, resolved_names = [], []

    async def echo_everything(request):
        echo = json.dumps({"headers": dict(request.headers), "body": await request.text()})
        echo += " | " + quote(CREDENTIAL, safe="") + " | " + base64.b64encode(CREDENTIAL.encode()).decode()
        return web.json_response({"status": "COMPLETED", "result": echo}, status=target_status)

    target.route("POST", "/run", echo_everything)
    async with serve(target) as origin:
        def factory(context, spec):
            contexts.append(context)
            credential = context.headers["x-run-credential"]

            def resolve(name):
                resolved_names.append(name)
                assert name == "agent-auth"
                return credential

            return replace(ExecutionPolicy.local(spec), secret_providers={"hosting": resolve})

        app = create_app(execution_policy_factory=factory)
        target_spec = {"kind": "custom_http", "transport": transport(origin + "/run", version=version)}
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post("/redteam/run", headers=BINDING_HEADERS, json={
                "target": target_spec, "probe_ids": [probe_library[0].id]})
            # A deliberately invalid target also exercises the HTTP error response before SSE starts.
            error = await client.post("/redteam/run", headers=BINDING_HEADERS, json={
                "target": {"kind": "custom_http", "transport": {"version": 99}},
                "probe_ids": [probe_library[0].id]})
        assert response.status_code == 200, response.text
        assert error.status_code == 422, error.text
        frames = response.text.strip().split("\n\n")
        payloads = [json.loads(line[6:]) for line in response.text.splitlines() if line.startswith("data: ")]
        findings = [payload for payload in payloads if "probe_id" in payload]
        assert len(findings) == 1, response.text
        assert resolved_names and set(resolved_names) == {"agent-auth"}
        assert target.calls[0][2]["Authorization"] == "Bearer " + CREDENTIAL
        assert all(UNUSED_CREDENTIAL not in repr(call) for call in target.calls)
        if target_status == 200:
            assert "redacted" in findings[0]["target_response"]
        else:
            assert "http_error" in json.dumps(findings[0]), response.text
        record = {"id": "binding-test", "status": "completed", "target_spec": target_spec, "findings": findings}
        path = tmp_path / "run.json"
        path.write_text(render_json(record))
        outputs = [path.read_text(), render_sarif(record), render_html(record), render_junit(record),
            caplog.text, error.text, *(repr(context) + str(context) for context in contexts), *frames]
        for value in BINDING_HEADERS.values():
            forms = [value, quote(value, safe=""), base64.b64encode(value.encode()).decode()]
            assert all(form not in output for form in forms for output in outputs)


@pytest.mark.parametrize("endpoint", ["/redteam/run/preflight", "/redteam/run"])
@pytest.mark.parametrize("exception_type", [ValueError, RuntimeError])
async def test_factory_exception_cannot_disclose_headers(endpoint, exception_type, probe_library, caplog):
    from argus.server import create_app
    caplog.set_level(logging.DEBUG)

    def factory(context, spec):
        raise exception_type(" | ".join(context.headers[name] for name in
            ("x-run-credential", "x-unused-credential")))

    app = create_app(execution_policy_factory=factory)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(endpoint, headers=BINDING_HEADERS, json={
            "target": {"kind": "custom_http", "transport": transport()},
            "probe_ids": [probe_library[0].id]})
    assert response.status_code == 422, response.text
    assert response.json() == {"detail": "Execution policy factory failed"}
    assert all(value not in response.text + caplog.text for value in BINDING_HEADERS.values())
