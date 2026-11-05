import json
from dataclasses import replace

import pytest
from aiohttp import web

from argus.drafting.draft import choose_without_model, compile_draft
from argus.drafting.openapi import load_openapi, catalog_operations
from argus_transport import ExecutionPolicy, TransportContext, TransportSpecV2
from argus_transport.runtime_v2 import V2Run
from test_draft_target import agent_document, input_file
from transport_v2_fakes import RecordingApp, serve


def sync_document(origin="http://127.0.0.1:8123"):
    doc = agent_document()
    doc["servers"] = [{"url": origin}]
    doc["paths"]["/ask"]["post"]["responses"]["200"]["content"]["application/json"]["schema"]["properties"].pop("status")
    return doc


@pytest.mark.parametrize("payload, expected", [
    ({"answer": "valid answer"}, "succeeded"),
    ({"answer": ""}, "target_error"),
    ({}, "target_error"),
    ({"answer": " \n "}, "target_error"),
    ({"answer": None}, "target_error"),
    ({"answer": 7}, "target_error"),
    ({"answer": True}, "target_error"),
    ({"answer": {}}, "target_error"),
    ({"answer": []}, "target_error"),
])
async def test_no_model_sync_reply_combination_real_loopback(tmp_path, payload, expected):
    app = RecordingApp()
    async def reply(request):
        assert await request.json() == {"question": "test question"}
        return web.json_response(payload)
    app.route("POST", "/ask", reply)
    async with serve(app) as origin:
        assert origin.startswith("http://127.0.0.1:")
        catalog = catalog_operations(load_openapi(input_file(tmp_path, sync_document(origin))))
        artifacts = compile_draft(catalog, choose_without_model(catalog))
        assert artifacts.spec is not None
        spec = TransportSpecV2.from_dict(artifacts.spec["transport"])
        run = V2Run(spec, policy=ExecutionPolicy.local(spec), env={})
        try:
            result = await run.attempt(TransportContext(prompt="test question"))
            assert result.outcome.value == expected
            assert len(app.calls) == 1
        finally:
            await run.close()


@pytest.mark.parametrize("schema", [{"type": "integer"}, {"type": "string", "writeOnly": True}])
def test_sync_presence_requires_accessible_string_reply(tmp_path, schema):
    doc = sync_document()
    doc["paths"]["/ask"]["post"]["responses"]["200"]["content"]["application/json"]["schema"]["properties"]["answer"] = schema
    catalog = catalog_operations(load_openapi(input_file(tmp_path, doc)))
    artifacts = compile_draft(catalog, choose_without_model(catalog))
    assert artifacts.spec is None
    assert any(g.code == "reply_binding_missing" and g.blocking for g in artifacts.gaps)
