from pathlib import Path

import pytest
from aiohttp import web

from argus_transport import ExecutionPolicy, TransportContext, TransportSpecV2, V2Run, with_origin
from test_draft_bindings import artifacts, codes, draft
from test_response_parent_identity import document, handwritten
from transport_v2_fakes import RecordingApp, serve


async def execute_at_owned_path(data, submitted, owned_path, *, env=None):
    app = RecordingApp()

    async def submit(request):
        return web.json_response(submitted, status=202)

    async def poll(request):
        answer = "own answer" if request.path_qs == owned_path else "foreign answer"
        return web.json_response({"status": "COMPLETED", "result": answer})

    app.route("POST", "/{tail:.*}", submit)
    app.route("GET", "/{tail:.*}", poll)
    async with serve(app) as origin:
        spec = TransportSpecV2.from_dict(with_origin(data, origin))
        runtime = V2Run(spec, policy=ExecutionPolicy.local(spec), environ=env or {})
        try:
            result = await runtime.attempt(TransportContext(prompt="ping"))
        finally:
            await runtime.close()
    return result, [(call[0], call[1]) for call in app.calls]


@pytest.mark.parametrize("submit_path,parent_name,poll_path,returned,reason,submit_sent", [
    ("/orgs/{org}/agents/{agent_id}/runs", "agent_id", "/agents/{agent_id}/runs/{run_id}", "ag-9", "submit_parent_changed", "/orgs/o-1/agents/ag-7/runs"),
    ("/orgs/{org}/agents/{agent_id}/runs", "agent_id", "/agents/{agent_id}/runs/{run_id}", "ag-7", "ok", "/orgs/o-1/agents/ag-7/runs"),
    ("/v2/agents/{agent_id}/runs", "agent_id", "/v1/agents/{agent_id}/runs/{run_id}", "ag-9", "submit_parent_changed", "/v2/agents/ag-7/runs"),
    ("/v2/agents/{agent_id}/runs", "agent_id", "/v1/agents/{agent_id}/runs/{run_id}", "ag-7", "ok", "/v2/agents/ag-7/runs"),
    ("/agents/{agent}/runs", "agent", "/agents/{agent_id}/runs/{run_id}", "ag-7", "ok", "/agents/ag-7/runs"),
    ("/agents/{agentId}/runs", "agentId", "/agents/{agent_id}/runs/{run_id}", "ag-9", "submit_parent_changed", "/agents/ag-7/runs"),
], ids=["D1_foreign", "D1_honest", "D1c_foreign", "D1d_honest", "D2c_honest", "D2b_foreign"])
async def test_drafted_local_parent_slot(tmp_path, submit_path, parent_name, poll_path, returned, reason, submit_sent):
    names = ["org", parent_name] if "{org}" in submit_path else [parent_name]
    doc = document(submit_path, names, ["agent_id", "run_id"], poll_path, ["agent_id", "run_id"])
    result, out = draft(tmp_path, doc, None, "--operation", "invoke", "--poll-operation", "get_run")
    target, report, _ = artifacts(out)
    assert result.exit_code == 3 and target is not None and codes(report, True) == []
    owned_path = poll_path.replace("{agent_id}", "ag-7").replace("{run_id}", "r-1")
    response, calls = await execute_at_owned_path(target["transport"], {"agent_id": returned, "run_id": "r-1"}, owned_path,
        env={"TARGET_INPUT_ORG": "o-1", "TARGET_INPUT_" + parent_name.upper(): "ag-7"})
    assert response.reason_code.value == reason
    assert response.outcome.value == ("succeeded" if reason == "ok" else "target_error")
    assert calls == [("POST", submit_sent)] + ([("GET", owned_path)] if reason == "ok" else [])
    assert response.response_text == ("own answer" if reason == "ok" else None)


@pytest.mark.parametrize("resource,parent_name,run_name,parent", [
    ("jobs", "kind", "job_id", "summarize"),
    ("runs", "agent_id", "run_id", "ag-7"),
], ids=["D15", "D16"])
async def test_drafted_new_run_in_parent_slot_fails_closed(tmp_path, resource, parent_name, run_name, parent):
    doc = document(f"/{resource}/{{{parent_name}}}", [parent_name], [run_name], f"/{resource}/{{{run_name}}}", [run_name])
    result, out = draft(tmp_path, doc, None, "--operation", "invoke", "--poll-operation", "get_run")
    target, report, _ = artifacts(out)
    assert result.exit_code == 3 and target is not None and codes(report, True) == []
    response, calls = await execute_at_owned_path(target["transport"], {run_name: "r-1"}, f"/{resource}/r-1",
        env={"TARGET_INPUT_" + parent_name.upper(): parent})
    assert response.reason_code.value == "submit_parent_changed"
    assert response.outcome.value == "target_error"
    assert calls == [("POST", f"/{resource}/{parent}")]


@pytest.mark.parametrize("submit_path,poll_path,inputs,returned,owned", [
    ("/orgs/{input_org}/agents/pre-{input_agent}-tail/runs", "/agents/pre-{parent}-tail/runs/{id}",
     {"input_org": "o-1", "input_agent": "ag-7"}, {"parent": "ag-7", "id": "r-1"}, "/agents/pre-ag-7-tail/runs/r-1"),
    ("/agents/{input_agent}/runs", "/agents/{parent}/runs/{id}",
     {"input_agent": "ag-7"}, {"parent": "ag-7", "id": "r-1"}, "/agents/ag-7/runs/r-1"),
    ("/agents/{input_id}/sessions", "/sessions/{id}/messages/{message_id}",
     {"input_id": "7"}, {"id": "12", "message_id": "1"}, "/sessions/12/messages/1"),
], ids=["scoped_affix_honest", "H2_renamed_honest", "new_session_positive"])
async def test_handwritten_honest_local_slots(submit_path, poll_path, inputs, returned, owned):
    data = handwritten(submit_path, poll_path, inputs, returned)
    response, calls = await execute_at_owned_path(data, returned, owned)
    expected_submit = submit_path
    for name, value in inputs.items():
        expected_submit = expected_submit.replace("{" + name + "}", value)
    assert response.outcome.value == "succeeded" and response.reason_code.value == "ok"
    assert response.response_text == "own answer"
    assert calls == [("POST", expected_submit), ("GET", owned)]


@pytest.mark.parametrize("data,returned,reason,submit_sent,owned", [
    (handwritten("/agents/{input_agent}/runs", "/runs/{id}", {"input_agent": 3}, ["id"]),
     {"id": 3}, "submit_parent_echo", "/agents/3/runs", "/runs/3"),
    (handwritten("/orgs/{input_org}/agents/{input_agent}/runs", "/orgs/{org}/agents/{agent}/runs/{id}",
                 {"input_org": "x", "input_agent": "x"}, ["org", "agent", "id"]),
     {"org": "x", "agent": "x", "id": "r-1"}, "submit_parent_echo", "/orgs/x/agents/x/runs", "/orgs/x/agents/x/runs/r-1"),
    (handwritten("/agents/{input_id}/runs", "/runs", {"input_id": "ag-7"}, ["id"], query={"id": {"var": "id"}}),
     {"id": "r-1"}, "submit_parent_changed", "/agents/ag-7/runs", "/runs?id=r-1"),
], ids=["D7_integer_collision", "H8_duplicate_parents", "same_name_query_new_resource"])
async def test_conservative_identity_refusals(data, returned, reason, submit_sent, owned):
    response, calls = await execute_at_owned_path(data, returned, owned)
    assert response.reason_code.value == reason and response.outcome.value == "target_error"
    assert calls == [("POST", submit_sent)]


async def test_differently_spelled_changed_query_parent_is_unchecked():
    data = handwritten("/agents/{input_agent_id}/runs", "/runs", {"input_agent_id": "ag-7"}, ["agent", "run_id"],
        query={"agentId": {"var": "agent"}, "run_id": {"var": "run_id"}})
    response, calls = await execute_at_owned_path(data, {"agent": "ag-9", "run_id": "r-1"}, "/runs?agentId=ag-7&run_id=r-1")
    assert response.outcome.value == "succeeded" and response.reason_code.value == "ok"
    assert response.response_text == "foreign answer"
    assert calls == [("POST", "/agents/ag-7/runs"), ("GET", "/runs?agentId=ag-9&run_id=r-1")]


@pytest.mark.parametrize("extract,reason", [(False, "ok"), (True, "submit_parent_echo")])
async def test_resource_name_comparison_uses_extraction_only_when_configured(extract, reason):
    data = handwritten("/agents/{input_agent}/runs", "/runs/{id}", {"input_agent": "ag-7"}, ["id"])
    data["delivery"]["ids"]["id"].update(expect_prefix={"literal": "runs/"}, last_segment=extract)
    response, calls = await execute_at_owned_path(data, {"id": "runs/ag-7"}, "/runs/runs%2Fag-7")
    assert response.reason_code.value == reason
    assert response.outcome.value == ("succeeded" if reason == "ok" else "target_error")
    assert calls == [("POST", "/agents/ag-7/runs")] + ([("GET", "/runs/runs%2Fag-7")] if not extract else [])


def test_reason_function_maps_mismatched_submit_url_to_binding_error():
    from argus_transport.engine_v2 import _response_parent_reason

    data = handwritten("/agents/{input_agent}/runs", "/runs/{id}", {"input_agent": "ag-7"}, ["id"])
    spec = TransportSpecV2.from_dict(data)
    reason = _response_parent_reason(spec.request, "http://127.0.0.1/runs", spec.delivery.request, {"id": "r-1"})
    assert reason is not None
    assert reason.value == "binding_error"


def test_docs_state_local_slots_and_capture_limits():
    root = Path(__file__).resolve().parents[1]
    reference = (root / "docs/transport-spec.md").read_text()
    cli = (root / "docs/cli.md").read_text()
    for text in [reference, cli]:
        assert "preceding path segment" in text
        assert "renamed parent" in text
        assert "differently spelled query parent" in text
        assert "last_segment" in text and "full resource name" in text
        assert "/runs/{agent_id}" in text and "/runs/{run_id}" in text
    assert "https://github.com/gy15901580825/Argus/blob/main/docs/transport-spec.md#polling-with-multiple-ids" in cli
