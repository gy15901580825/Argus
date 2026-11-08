from pathlib import Path

import pytest
from aiohttp import web

from argus_transport import ExecutionPolicy, TransportContext, TransportSpecV2, V2Run, with_origin
from test_draft_bindings import artifacts, codes, draft
from test_transport_v2_poll import poll_spec, with_attempt_undo
from transport_v2_fakes import RecordingApp, serve


def parameter(name):
    return {"name": name, "in": "path", "required": True, "schema": {"type": "string"}}


def document(submit_path, submit_names, fields, poll_path, poll_names, *, query=False, poll_ids=()):
    reply = {"status": {"type": "string", "enum": ["PENDING", "COMPLETED", "FAILED"]},
             "result": {"type": "string"}, **{name: {"type": "string"} for name in poll_ids}}
    def response(properties, status):
        return {status: {"description": "Result", "content": {"application/json": {"schema": {
            "type": "object", "properties": properties}}}}}
    params = [parameter(name) for name in poll_names]
    if query:
        params = [{**item, "in": "query", "required": False} for item in params]
    paths = {submit_path: {"post": {"operationId": "invoke", "parameters": [parameter(n) for n in submit_names],
        "requestBody": {"required": True, "content": {"application/json": {"schema": {
            "type": "object", "required": ["question"], "properties": {"question": {"type": "string"}}}}}},
        "responses": response({name: {"type": "string"} for name in fields}, "202")}}}
    paths.setdefault(poll_path, {})["get"] = {"operationId": "get_run", "parameters": params,
                                           "responses": response(reply, "200")}
    return {"openapi": "3.0.3", "info": {"title": "Neutral identity runner", "version": "1"},
            "servers": [{"url": "http://127.0.0.1:8123"}], "paths": paths}



async def execute(data, submit_body, *, env=None):
    app = RecordingApp()
    async def submitted(request):
        return web.json_response(submit_body, status=202)
    async def polled(request):
        return web.json_response({"status": "COMPLETED", "result": "own answer"})
    app.route("POST", "/{tail:.*}", submitted)
    app.route("GET", "/{tail:.*}", polled)
    async with serve(app) as origin:
        parsed = TransportSpecV2.from_dict(with_origin(data, origin))
        runtime = V2Run(parsed, policy=ExecutionPolicy.local(parsed), environ=env or {})
        try:
            result = await runtime.attempt(TransportContext(prompt="ping"))
        finally:
            await runtime.close()
    return result, [(call[0], call[1]) for call in app.calls]


@pytest.mark.parametrize("case,doc,submitted,env,reason", [
    ("RA2", document("/agents/{agent_id}/runs", ["agent_id"], ["agent_id", "id"],
                     "/agents/{agent_id}/runs/{id}", ["agent_id", "id"]),
     {"agent_id": "ag-7", "id": "ag-7"}, {"TARGET_INPUT_AGENT_ID": "ag-7"}, "submit_parent_echo"),
    ("RA2b", document("/agents/{agent_id}/runs", ["agent_id"], ["agent_id", "run_id"],
                      "/agents/{agent_id}/runs/{run_id}", ["agent_id", "run_id"]),
     {"agent_id": "ag-9", "run_id": "r-1"}, {"TARGET_INPUT_AGENT_ID": "ag-7"}, "submit_parent_changed"),
    ("RA3", document("/agents/{agent}/messages", ["agent"], ["id", "message_id"],
                     "/sessions/{id}/messages/{message_id}", ["id", "message_id"]),
     {"id": "7", "message_id": "1"}, {"TARGET_INPUT_AGENT": "7"}, "submit_parent_echo"),
    ("RA3b", document("/agents/{agent}/messages", ["agent"], ["id", "message_id"],
                      "/sessions/{id}/messages/{message_id}", ["id", "message_id"], poll_ids=["id"]),
     {"id": "7", "message_id": "1"}, {"TARGET_INPUT_AGENT": "7"}, "submit_parent_echo"),
    ("SH1", document("/agents/{agent_id}/runs", ["agent_id"], ["agentId"], "/runs/{id}", ["id"]),
     {"agentId": "ag-7"}, {"TARGET_INPUT_AGENT_ID": "ag-7"}, "submit_parent_echo"),
    ("query", document("/agents/{agent_id}/runs", ["agent_id"], ["id"], "/runs", ["id"], query=True),
     {"id": "ag-7"}, {"TARGET_INPUT_AGENT_ID": "ag-7"}, "submit_parent_echo"),
])
async def test_draft_rejects_response_parent_identity(tmp_path, case, doc, submitted, env, reason):
    result, out = draft(tmp_path, doc, None, "--operation", "invoke", "--poll-operation", "get_run")
    target, report, _ = artifacts(out)
    assert result.exit_code == 3, result.output
    assert target is not None and codes(report, True) == []
    response, calls = await execute(target["transport"], submitted, env=env)
    assert response.outcome.value == "target_error"
    assert response.reason_code.value == reason
    assert [method for method, _ in calls] == ["POST"]


def handwritten(submit_path, poll_path, inputs, ids, *, query=None):
    data = poll_spec("http://127.0.0.1/run")
    data["request"]["url"] = "http://127.0.0.1" + submit_path
    data["let"] = {"run": {name: {"literal": value} for name, value in inputs.items()}}
    data["delivery"]["ids"] = {name: {"path": "$." + name} for name in ids}
    data["delivery"]["request"]["url"] = "http://127.0.0.1" + poll_path
    if query is not None:
        data["delivery"]["request"]["query"] = query
    return data


@pytest.mark.parametrize("query_name", ["Agent-ID", "AGENT_ID"])
@pytest.mark.parametrize("drafted", [True, False], ids=["draft", "handwritten"])
async def test_query_parent_echo_does_not_normalize_spelling(tmp_path, query_name, drafted):
    if drafted:
        doc = document("/agents/{agent_id}/runs", ["agent_id"], [query_name],
                       "/runs", [query_name], query=True)
        result, out = draft(tmp_path, doc, None, "--operation", "invoke", "--poll-operation", "get_run")
        target, report, _ = artifacts(out)
        assert result.exit_code == 3 and target is not None and codes(report, True) == []
        data = target["transport"]
    else:
        data = handwritten("/agents/{input_agent_id}/runs", "/runs", {"input_agent_id": "ag-7"},
                           ["agent_id"], query={query_name: {"var": "agent_id"}})
        data["delivery"]["ids"]["agent_id"]["path"] = "$['" + query_name + "']"
    app = RecordingApp()
    async def submitted(request):
        return web.json_response({query_name: "ag-7"}, status=202)
    async def foreign(request):
        return web.json_response({"status": "COMPLETED", "result": "foreign parent reply"})
    app.route("POST", "/{tail:.*}", submitted)
    app.route("GET", "/{tail:.*}", foreign)
    async with serve(app) as origin:
        parsed = TransportSpecV2.from_dict(with_origin(data, origin))
        runtime = V2Run(parsed, policy=ExecutionPolicy.local(parsed),
                        environ={"TARGET_INPUT_AGENT_ID": "ag-7"})
        try:
            response = await runtime.attempt(TransportContext(prompt="ping"))
        finally:
            await runtime.close()
    assert response.outcome.value == "target_error"
    assert response.reason_code.value == "submit_parent_echo"
    assert response.response_text != "foreign parent reply"
    assert [(call[0], call[1]) for call in app.calls] == [("POST", "/agents/ag-7/runs")]


@pytest.mark.parametrize("parent,captured", [("ag-7", "ag-7"), ("7", 7), ("a/b", "a/b"), ("a%2Fb", "a%2Fb")])
async def test_handwritten_cross_name_echo_uses_transmitted_identity(parent, captured):
    data = handwritten("/agents/{input_agent}/runs", "/runs/{id}", {"input_agent": parent}, ["id"])
    result, calls = await execute(data, {"id": captured})
    assert result.outcome.value == "target_error" and result.reason_code.value == "submit_parent_echo"
    assert len(calls) == 1


@pytest.mark.parametrize("query_name,parent,captured,reason", [
    ("id", "ag-7", "ag-7", "submit_parent_echo"),
    ("agent", "ag-7", "ag-9", "submit_parent_changed"),
    ("agent", "ag-7", "ag-7", "ok"),
    ("id", "ag-7", "r-1", "ok"),
])
async def test_handwritten_query_identity_agreement(query_name, parent, captured, reason):
    data = handwritten("/agents/{input_agent}/runs", "/runs", {"input_agent": parent}, ["id"],
                       query={query_name: {"var": "id"}})
    result, calls = await execute(data, {"id": captured})
    assert result.reason_code.value == reason
    assert result.outcome.value == ("succeeded" if reason == "ok" else "target_error")
    assert len(calls) == (2 if reason == "ok" else 1)


@pytest.mark.parametrize("parent,returned,reason", [("a/b", "a/b", "ok"), (7, "7", "ok"), ("a/b", "x", "submit_parent_changed")])
async def test_shared_parent_affix_and_wire_value(parent, returned, reason):
    data = handwritten("/agents/pre-{input_agent}-tail/runs", "/agents/pre-{agent}-tail/runs/{id}",
                       {"input_agent": parent}, ["agent", "id"])
    result, calls = await execute(data, {"agent": returned, "id": "r-1"})
    assert result.reason_code.value == reason
    assert result.outcome.value == ("succeeded" if reason == "ok" else "target_error")
    assert len(calls) == (2 if reason == "ok" else 1)


async def test_changed_outer_parent_cannot_hide_changed_inner_parent():
    data = handwritten("/orgs/{input_org}/agents/{input_agent}/runs", "/orgs/{org}/agents/{agent}/runs/{id}",
                       {"input_org": "o-1", "input_agent": "a-1"}, ["org", "agent", "id"])
    result, calls = await execute(data, {"org": "o-9", "agent": "a-9", "id": "r-1"})
    assert result.reason_code.value == "submit_parent_changed" and len(calls) == 1


async def test_renamed_shared_parent_still_requires_agreement():
    data = handwritten("/agents/{input_agent}/runs", "/agents/{parent}/runs/{id}", {"input_agent": "a-1"}, ["parent", "id"])
    result, calls = await execute(data, {"parent": "a-9", "id": "r-1"})
    assert result.reason_code.value == "submit_parent_changed" and len(calls) == 1


async def test_resource_capture_checks_effective_run_segment():
    data = handwritten("/agents/{input_agent}/runs", "/runs/{id}", {"input_agent": "ag-7"}, ["id"])
    data["delivery"]["ids"]["id"].update(last_segment=True, expect_prefix={"literal": "runs/"})
    result, calls = await execute(data, {"id": "runs/ag-7"})
    assert result.reason_code.value == "submit_parent_echo" and len(calls) == 1


@pytest.mark.parametrize("required", [False, True])
async def test_new_session_with_same_named_id_has_distinct_resource_context(required):
    data = handwritten("/agents/{input_id}/sessions", "/sessions/{id}/messages/{message_id}",
                       {"input_id": "7"}, ["id", "message_id"])
    if required:
        data["delivery"]["ids"]["id"]["poll"] = {"path": "$.id"}
    app = RecordingApp()
    async def submitted(request):
        return web.json_response({"id": "12", "message_id": "1"}, status=202)
    async def polled(request):
        return web.json_response({"id": "12", "message_id": "1", "status": "COMPLETED", "result": "own answer"})
    app.route("POST", "/{tail:.*}", submitted)
    app.route("GET", "/{tail:.*}", polled)
    async with serve(app) as origin:
        parsed = TransportSpecV2.from_dict(with_origin(data, origin))
        runtime = V2Run(parsed, policy=ExecutionPolicy.local(parsed))
        try:
            result = await runtime.attempt(TransportContext(prompt="ping"))
        finally:
            await runtime.close()
    assert result.outcome.value == "succeeded" and result.response_text == "own answer"
    assert [(call[0], call[1]) for call in app.calls] == [("POST", "/agents/7/sessions"), ("GET", "/sessions/12/messages/1")]


@pytest.mark.parametrize("submit_path,submit_names,fields,poll_path,poll_names", [
    ("/jobs/{job}", ["job"], ["job"], "/jobs/{job}", ["job"]),
    ("/agents/{id}/runs", ["id"], ["id"], "/runs/{id}", ["id"]),
    ("/agents/{id}/runs", ["id"], ["id", "agentId"], "/agents/{agentId}/runs/{id}", ["agentId", "id"]),
])
def test_unliftable_identity_gap_names_document_limit(tmp_path, submit_path, submit_names, fields, poll_path, poll_names):
    result, out = draft(tmp_path, document(submit_path, submit_names, fields, poll_path, poll_names), None,
                        "--operation", "invoke", "--poll-operation", "get_run")
    target, report, _ = artifacts(out)
    assert result.exit_code == 3 and target is None
    gap = next(gap for gap in report["gaps"] if gap["code"] == "poll_id_binding_missing")
    assert "document" in gap["decision"].lower() and "select" not in gap["decision"].lower()
    assert "submit path" in gap["why"]


def test_resource_parent_gap_names_mapping_entry(tmp_path):
    doc = document("/agents/{agent}/runs", ["agent"], ["agent", "run"],
                   "/agents/{agent}/runs/{run}", ["agent", "run"])
    doc["paths"]["/agents/{agent}/runs/{run}"]["get"]["responses"]["200"]["content"]["application/json"]["schema"]["properties"]["name"] = {
        "type": "string", "description": "Format: agents/{agent}/runs/{run}"}
    result, out = draft(tmp_path, doc, None, "--operation", "invoke", "--poll-operation", "get_run")
    target, report, _ = artifacts(out)
    assert result.exit_code == 3 and target is None
    gap = next(gap for gap in report["gaps"] if gap["code"] == "poll_resource_format_unsupported")
    assert "poll.parameters.agent" in gap["why"]


def test_docs_describe_parent_echo_limits():
    root = Path(__file__).resolve().parents[1]
    cli = (root / "docs/cli.md").read_text()
    reference = (root / "docs/transport-spec.md").read_text()
    assert "misspelled parent" in cli and "ids" in cli
    assert "submit_parent_echo" in reference and "submit_parent_changed" in reference
    assert "same-named query" in reference and "legitimate" in reference


@pytest.mark.parametrize("captured,reason", [("ag-7", "submit_parent_echo"), ("r-1", "submit_parent_changed")])
async def test_parent_rejection_keeps_setup_cleanup_without_arming_abort(captured, reason):
    app = RecordingApp()
    async def created(request):
        return web.json_response({"ref": "obj-1"}, status=201)
    async def submitted(request):
        return web.json_response({"id": captured, "agent": "ag-9"}, status=202)
    async def polled(request):
        return web.Response(status=404)
    async def aborted(request):
        return web.json_response({"stopped": True})
    async def deleted(request):
        return web.Response(status=204)
    app.route("POST", "/objects", created)
    app.route("POST", "/agents/{agent}/runs", submitted)
    app.route("GET", "/{tail:.*}", polled)
    app.route("DELETE", "/runs/{id}", aborted)
    app.route("DELETE", "/objects/{ref}", deleted)
    async with serve(app) as origin:
        ids = ["id"] if reason == "submit_parent_echo" else ["agent", "id"]
        poll_path = "/runs/{id}" if reason == "submit_parent_echo" else "/agents/{agent}/runs/{id}"
        data = handwritten("/agents/{input_agent}/runs", poll_path, {"input_agent": "ag-7"}, ids)
        data = with_origin(data, origin)
        with_attempt_undo(data, origin)
        data["delivery"]["abort"] = {
            "request": {"method": "DELETE", "url": origin + "/runs/{id}", "body": {"none": True}},
            "expect": {"http_status": [200], "when": {"path": "$.stopped", "equals": True}},
        }
        parsed = TransportSpecV2.from_dict(with_origin(data, origin))
        runtime = V2Run(parsed, policy=ExecutionPolicy.local(parsed))
        try:
            result = await runtime.attempt(TransportContext(prompt="ping"))
        finally:
            await runtime.close()
        report = runtime.cleanup_report()
    assert [(call[0], call[1]) for call in app.calls] == [
        ("POST", "/objects"), ("POST", "/agents/ag-7/runs"), ("DELETE", "/objects/obj-1")]
    assert report["complete"] is True and report["done"] == 1 and report["open"] == []
    assert result.outcome.value == "target_error" and result.reason_code.value == reason
