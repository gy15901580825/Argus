import copy
import json
from dataclasses import replace

import pytest
from click.testing import CliRunner

from argus.cli.__main__ import main
from argus.drafting.draft import choose_without_model, compile_draft
from test_draft_async import blocking, catalog_for, gaps, run
from test_draft_verify_local import verify


SUBMIT = "/paths/~1v1~1questions/post"
POLL = "/paths/~1v1~1questions~1{runId}/get"
THREAD = "6f1c2a9e-3b4d-4e5f-8a7b-9c0d1e2f3a4b"
RUN = "0b9e8d7c-6a5f-4e3d-9c2b-1a0f9e8d7c6b"
RETRY_AFTER = {"Retry-After": {"description": "Seconds before the next poll.", "schema": {"type": "string"}}}


def response(description, headers=None, schema=None):
    data = {"description": description,
            "content": {"application/json": {"schema": schema or {"$ref": "#/components/schemas/Run"}}}}
    if headers:
        data["headers"] = copy.deepcopy(headers)
    return data


def nested_accepted_document():
    """A submit documenting 200 (terminal) and 202 (still running) with one body, polled by two IDs."""
    error = {"description": "Validation error", "content": {"application/json": {"schema": {
        "type": "object", "properties": {"detail": {"type": "string"}}}}}}
    return {
        "openapi": "3.1.0",
        "info": {"title": "Neutral accepted-run agent", "version": "1"},
        "servers": [{"url": "http://127.0.0.1:8123"}],
        "components": {
            "securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}},
            "schemas": {
                "RunStatus": {"type": "string", "enum": ["running", "completed", "failed", "stopped"]},
                "Run": {"type": "object", "required": ["threadId", "runId", "status"], "properties": {
                    "threadId": {"type": "string", "format": "uuid"},
                    "runId": {"type": "string", "format": "uuid"},
                    "status": {"$ref": "#/components/schemas/RunStatus"},
                    "output": {"type": ["string", "null"]},
                    "error": {"type": ["string", "null"]}}},
            },
        },
        "paths": {
            "/v1/questions": {"post": {
                "operationId": "ask_question",
                "security": [{"bearer": []}],
                "requestBody": {"required": True, "content": {"application/json": {"schema": {
                    "type": "object", "required": ["message"], "properties": {"message": {"type": "string"}}}}}},
                "responses": {
                    "200": response("Terminal run"),
                    "202": response("Run still in progress",
                                    {"Location": {"schema": {"type": "string"}}, **RETRY_AFTER}),
                    "422": error,
                },
            }},
            "/v1/questions/{threadId}/{runId}": {"get": {
                "operationId": "get_question_run",
                "security": [{"bearer": []}],
                "parameters": [
                    {"name": "threadId", "in": "path", "required": True, "schema": {"type": "string", "format": "uuid"}},
                    {"name": "runId", "in": "path", "required": True, "schema": {"type": "string", "format": "uuid"}},
                ],
                "responses": {
                    "200": response("Terminal run"),
                    "202": response("Run still in progress", RETRY_AFTER),
                    "422": error,
                },
            }},
        },
    }


def accepted_document():
    document = nested_accepted_document()
    poll = document["paths"].pop("/v1/questions/{threadId}/{runId}")["get"]
    poll["parameters"] = [parameter for parameter in poll["parameters"] if parameter["name"] == "runId"]
    document["paths"]["/v1/questions/{runId}"] = {"get": poll}
    return document


def submit_responses(document):
    return document["paths"]["/v1/questions"]["post"]["responses"]


def poll_responses(document):
    return document["paths"]["/v1/questions/{runId}"]["get"]["responses"]


def body(status, output=None):
    return {"threadId": THREAD, "runId": RUN, "status": status, "output": output, "error": None}


def scenario(submit, polls, *, outcome="succeeded", reply="pong"):
    return {
        "version": 2, "environment": {},
        "source": {"document": "independent neutral accepted-run scenario", "pointers": [SUBMIT, POLL]},
        "resources": [],
        "operations": [
            {"id": "ask_question", "method": "POST", "path": "/v1/questions", "role": "invoke", "calls": {"min": 1, "max": 1},
             "request": [{"check": "prompt_bound", "at": {"kind": "json", "pointer": "/message"}, "equals": "ping"}],
             "replies": [submit]},
            {"id": "get_question_run", "method": "GET", "path": "/v1/questions/{runId}", "role": "poll",
             "calls": {"min": len(polls), "max": max(len(polls), 1)},
             "request": [{"check": "poll_identity", "at": {"kind": "path", "name": "runId"}, "equals": RUN}],
             "replies": polls or [{"status": 200, "body": body("completed", "unused"), "effects": []}]},
        ],
        "expect": {"outcome": outcome, "reply": reply, "resources": [], "required_gaps": []},
    }


def running(status=202):
    return {"status": status, "body": body("running"), "effects": [], "headers": {"Retry-After": "0"}}


def finished(state, output=None, status=200):
    return {"status": status, "body": body(state, output), "effects": []}


def test_nested_response_ids_fill_documented_parent_and_run(tmp_path):
    result, out = run(tmp_path, nested_accepted_document())
    assert result.exit_code == 3, result.output
    assert out.exists()
    transport = json.loads(out.read_text())["transport"]
    assert transport["delivery"]["ids"] == {
        "threadid": {"path": "$.threadId", "poll": {"path": "$.threadId"}},
        "runid": {"path": "$.runId", "poll": {"path": "$.runId"}}}
    assert transport["delivery"]["request"]["url"].endswith("/v1/questions/{threadid}/{runid}")


def test_submit_documenting_200_and_202_with_one_body_compiles_a_single_id_poll(tmp_path):
    result, out = run(tmp_path, accepted_document())
    assert result.exit_code == 3, result.output
    assert "spec_written: true" in result.output
    transport = json.loads(out.read_text())["transport"]
    completed = {"id": "completed", "priority": 10, "http_status": [200],
                 "when": {"all": [{"path": "$.status", "equals": "completed"}, {"path": "$.threadId", "exists": True},
                                  {"path": "$.runId", "exists": True}]}, "outcome": "succeeded"}
    failed = {"id": "failed", "priority": 20, "http_status": [200, 202],
              "when": {"path": "$.status", "one_of": ["failed", "stopped"]}, "outcome": "target_error"}
    assert transport["delivery"] == {
        "kind": "poll",
        "ids": {"runid": {"path": "$.runId", "poll": {"path": "$.runId"}}},
        "request": {"method": "GET", "url": "http://127.0.0.1:8123/v1/questions/{runid}",
                    "headers": {"Accept": "application/json"}, "body": {"none": True}},
        "pending": {"path": "$.status", "one_of": ["running"]},
        "wait": {"from": "Retry-After", "default_s": 5, "max_s": 60},
        "max_polls": 60,
        "submit_http_status": [200, 202],
        "submit_outcome": {"kind": "rules", "unmatched": "accepted", "rules": [failed, completed]},
    }
    assert transport["outcome"] == {"kind": "rules", "unmatched": "target_error", "rules": [failed, completed]}
    assert transport["response"]["text"] == {"paths": ["$.output"], "cast": "string", "empty": "error"}
    assert transport["auth"]["kind"] == "bearer"
    report = gaps(out)
    assert report["state"] == "needs_review" and report["spec_written"] is True
    assert not blocking(out)
    codes = {gap["code"] for gap in report["gaps"]}
    assert {"poll_proposed", "poll_id_binding_proposed", "poll_status_proposed"} <= codes
    assert "poll_status_unclassified" not in codes
    provenance = json.loads(out.with_suffix(".provenance.json").read_text())["fields"]
    assert provenance["/transport/delivery/submit_outcome"]["basis"] == "proposal"
    validation = CliRunner().invoke(main, ["validate-target", "--target", str(out), "--offline"])
    assert validation.exit_code == 0, validation.output


def test_verify_local_runs_an_accepted_submit_through_pending_to_completed(tmp_path):
    path = tmp_path / "scenario.json"
    path.write_text(json.dumps(scenario(running(), [running(), finished("completed", "pong")])))
    result, out = run(tmp_path, accepted_document(), "--verify-local", "--scenario", str(path))
    assert result.exit_code == 3, result.output
    assert "local.status: verified" in result.output
    local = json.loads(out.with_suffix(".provenance.json").read_text())["validation"]["local"]
    assert local["status"] == "verified" and local["semantic_success"] is True
    assert local["execution"]["requests"]["submit"] == 1
    assert local["execution"]["requests"]["poll"] == 2
    assert local["execution"]["reply"] == "pong"


@pytest.mark.parametrize("submit, outcome, reply", [
    (finished("completed", "pong"), "succeeded", "pong"),
    (finished("failed"), "target_error", None),
], ids=["completed", "failed"])
async def test_a_terminal_200_submit_is_read_without_polling(tmp_path, submit, outcome, reply):
    catalog = catalog_for(tmp_path, accepted_document())
    spec = compile_draft(catalog, choose_without_model(catalog)).spec
    result = await verify(spec, scenario(submit, [], outcome=outcome, reply=reply), catalog=catalog)
    execution = result.as_dict()["execution"]
    assert execution["outcome"] == outcome, result.as_dict()
    assert execution["reply"] == reply
    assert execution["requests"]["submit"] == 1
    assert execution["requests"]["poll"] == 0


async def test_a_completed_run_with_no_output_is_an_error_not_a_success(tmp_path):
    catalog = catalog_for(tmp_path, accepted_document())
    spec = compile_draft(catalog, choose_without_model(catalog)).spec
    result = await verify(spec, scenario(finished("completed"), [], outcome="target_error", reply=None), catalog=catalog)
    assert result.as_dict()["execution"]["outcome"] == "target_error", result.as_dict()


async def test_a_200_submit_that_is_still_running_is_polled(tmp_path):
    catalog = catalog_for(tmp_path, accepted_document())
    spec = compile_draft(catalog, choose_without_model(catalog)).spec
    result = await verify(spec, scenario(running(200), [finished("completed", "pong")]), catalog=catalog)
    execution = result.as_dict()["execution"]
    assert execution["outcome"] == "succeeded", result.as_dict()
    assert execution["requests"]["poll"] == 1


@pytest.mark.parametrize("alter", ["other_id_shape", "sync_answer", "no_body"])
def test_submit_2xx_responses_with_different_bodies_block(tmp_path, alter):
    document = accepted_document()
    responses = submit_responses(document)
    if alter == "other_id_shape":
        responses["200"] = response("Terminal run", schema={"type": "object", "required": ["taskId", "status"], "properties": {
            "taskId": {"type": "string"}, "status": {"$ref": "#/components/schemas/RunStatus"}, "output": {"type": "string"}}})
    elif alter == "sync_answer":
        responses["200"] = response("Answer", schema={"type": "object", "properties": {"answer": {"type": "string"}}})
    else:
        responses["200"] = {"description": "Done"}
    result, out = run(tmp_path, document)
    assert result.exit_code == 3, result.output
    assert not out.exists()
    assert "async_shape_unsupported" in blocking(out)


def test_poll_2xx_responses_with_different_bodies_are_not_a_poll(tmp_path):
    document = accepted_document()
    poll_responses(document)["202"] = response("Queued", RETRY_AFTER, {"type": "object", "properties": {
        "threadId": {"type": "string"}, "runId": {"type": "string"}, "queuePosition": {"type": "integer"}}})
    result, out = run(tmp_path, document)
    assert result.exit_code == 3, result.output
    assert not out.exists()
    assert "async_poll_missing" in blocking(out)


@pytest.mark.parametrize("alter", ["no_status", "other_enum", "no_reply"])
def test_submit_without_the_poll_state_and_reply_is_always_polled(tmp_path, alter):
    document = accepted_document()
    run_schema = copy.deepcopy(document["components"]["schemas"]["Run"])
    if alter == "no_status":
        del run_schema["properties"]["status"]
        run_schema["required"] = ["threadId", "runId"]
    elif alter == "other_enum":
        run_schema["properties"]["status"] = {"type": "string", "enum": ["running", "completed"]}
    else:
        del run_schema["properties"]["output"]
    document["components"]["schemas"]["SubmittedRun"] = run_schema
    for status in ("200", "202"):
        submit_responses(document)[status]["content"]["application/json"]["schema"] = {"$ref": "#/components/schemas/SubmittedRun"}
    result, out = run(tmp_path, document)
    assert result.exit_code == 3, result.output
    delivery = json.loads(out.read_text())["transport"]["delivery"]
    assert delivery["submit_http_status"] == [200, 202]
    assert delivery["submit_outcome"] == {"kind": "rules", "unmatched": "accepted", "rules": []}


def test_retry_after_on_any_successful_poll_response_selects_wait(tmp_path):
    document = accepted_document()
    for responses in (submit_responses(document), poll_responses(document)):
        responses["202"].pop("headers")
    result, out = run(tmp_path, document)
    assert result.exit_code == 3, result.output
    delivery = json.loads(out.read_text())["transport"]["delivery"]
    assert delivery["interval_s"] == 5 and "wait" not in delivery


def test_links_on_any_successful_submit_response_block(tmp_path):
    document = accepted_document()
    submit_responses(document)["202"]["links"] = {"poll": {"operationId": "get_question_run"}}
    result, out = run(tmp_path, document)
    assert result.exit_code == 3, result.output
    assert not out.exists()
    assert "links_unsupported" in blocking(out)


def test_bindings_point_at_the_lowest_documented_status(tmp_path):
    catalog = catalog_for(tmp_path, accepted_document())
    choices = choose_without_model(catalog)
    assert choices.reply.pointer == POLL + "/responses/200/content/application~1json/schema/properties/output"
    assert compile_draft(catalog, choices).spec is not None
    moved = replace(choices.reply, pointer=choices.reply.pointer.replace("/responses/200/", "/responses/202/"))
    with pytest.raises(ValueError):
        compile_draft(catalog, replace(choices, reply=moved))


def test_several_successes_without_202_are_not_read_as_one_result(tmp_path):
    document = accepted_document()
    responses = submit_responses(document)
    responses["201"] = responses.pop("202")
    result, out = run(tmp_path, document)
    assert result.exit_code == 3, result.output
    assert not out.exists()
    assert "reply_binding_missing" in blocking(out)
