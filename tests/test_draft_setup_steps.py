import asyncio
import copy
import hashlib
import json

import pytest
from click.testing import CliRunner

from argus.cli.__main__ import main
from argus.cli.verify_local import LocalFake, StrictLoopbackPolicy, verify_local
from argus.drafting.openapi import catalog_operations, load_openapi
from argus.drafting.scenario import parse_scenario
from argus_transport import TransportSpecV2, V2Run, with_origin
from argus_transport.runtime_v2 import TargetRunStopped
from argus_transport.spec_v2 import TransportContextV2
from test_draft_bindings import artifacts, codes, draft, file_source

SERVER = "http://127.0.0.1:8123"
NOTES = "/paths/~1notes/post"


def json_body(schema):
    return {"required": True, "content": {"application/json": {"schema": schema}}}


def reply(status, schema):
    return {status: {"description": "Result", "content": {"application/json": {"schema": schema}}}}


def setup_document():
    """A notes API: create a source, add a note to it, then ask a question about the notes."""
    status = {"type": "object", "properties": {"status": {"type": "string"}}}
    return {
        "openapi": "3.0.3",
        "info": {"title": "Neutral notes", "version": "1"},
        "servers": [{"url": SERVER}],
        "paths": {
            "/sources": {"post": {
                "operationId": "create_source",
                "requestBody": json_body({"type": "object", "required": ["name"], "properties": {
                    "name": {"type": "string"}, "kind": {"type": "string", "enum": ["custom", "mail"]},
                    "serial": {"type": "integer", "readOnly": True}}}),
                "responses": reply("201", {"type": "object", "required": ["id", "name"], "properties": {
                    "id": {"type": "string"}, "name": {"type": "string"}, "secret_note": {"type": "string", "writeOnly": True}}})}},
            "/sources/{sourceId}": {"delete": {
                "operationId": "delete_source",
                "parameters": [{"name": "sourceId", "in": "path", "required": True, "schema": {"type": "string"}}],
                "responses": reply("200", status)}},
            "/notes": {
                "post": {
                    "operationId": "add_note",
                    "requestBody": json_body({"type": "object", "required": ["sourceId", "externalId", "text", "createdAt", "tags"],
                                              "properties": {
                        "sourceId": {"type": "string"},
                        "externalId": {"type": "string"},
                        "text": {"type": "string"},
                        "createdAt": {"anyOf": [{"type": "string"}, {"type": "integer"}, {"type": "number"}]},
                        "tags": {"type": "array", "minItems": 1, "items": {"type": "object", "properties": {"name": {"type": "string"}}}},
                        "owner": {"type": "object", "properties": {"id": {"anyOf": [{"type": "string"}, {"type": "null"}]}}},
                    }}),
                    "responses": reply("201", {"type": "object", "required": ["noteId", "externalId", "sourceId"], "properties": {
                        "noteId": {"type": "string"}, "externalId": {"type": "string"}, "sourceId": {"type": "string"}}})},
                "delete": {
                    "operationId": "delete_note",
                    "parameters": [{"name": "externalId", "in": "query", "required": True, "schema": {"type": "string"}},
                                   {"name": "sourceId", "in": "query", "required": True, "schema": {"type": "string"}}],
                    "responses": reply("200", status)},
            },
            "/notes/{noteId}": {"get": {
                "operationId": "get_note",
                "parameters": [{"name": "noteId", "in": "path", "required": True, "schema": {"type": "string"}}],
                "responses": reply("200", {"type": "object", "properties": {"text": {"type": "string"}}})}},
            "/ask": {"post": {
                "operationId": "ask",
                "requestBody": json_body({"type": "object", "required": ["question"], "properties": {"question": {"type": "string"}}}),
                "responses": reply("200", {"type": "object", "required": ["answer"], "properties": {"answer": {"type": "string"}}})}},
        },
    }


def source_step(**changes):
    return {"id": "source", "operation": "create_source", "scope": "run",
            "values": {"/name": {"concat": [{"literal": "argus-"}, {"generate": "uuid4"}]}},
            "capture": {"source_id": "/id"},
            "undo": {"operation": "delete_source", "parameters": {"sourceId": {"var": "source_id"}}},
            "origin": "API guide, sources", **changes}


def note_step(**changes):
    return {"id": "note", "operation": "add_note", "scope": "attempt",
            "values": {"/sourceId": {"var": "source_id"}, "/externalId": {"literal": "note-1"}, "/text": {"context": "material"},
                       "/createdAt": {"generate": "now_iso8601"}, "/tags": {"literal": [{"name": "synthetic"}]},
                       "/owner/id": {"literal": "tester"}},
            "undo": {"operation": "delete_note", "parameters": {"externalId": {"literal": "note-1"}, "sourceId": {"var": "source_id"}}},
            **changes}


def steps(*items):
    return {"steps": list(items or (source_step(), note_step()))}


def run_draft(tmp_path, bindings, *options):
    return draft(tmp_path, setup_document(), bindings, "--operation", "ask", *options)


SOURCE_SPEC = {
    "id": "source",
    "request": {"method": "POST", "url": SERVER + "/sources", "headers": {"Accept": "application/json"},
                "body": {"json": {"name": {"concat": [{"literal": "argus-"}, {"generate": "uuid4"}]}}}},
    "expect": {"http_status": [201]},
    "capture": {"source_id": {"path": "$.id"}},
    "undo": {"request": {"method": "DELETE", "url": SERVER + "/sources/{source_id}", "headers": {"Accept": "application/json"},
                         "body": {"none": True}},
             "expect": {"http_status": [200]}},
}
NOTE_SPEC = {
    "id": "note",
    "if_present": "material",
    "request": {"method": "POST", "url": SERVER + "/notes", "headers": {"Accept": "application/json"},
                "body": {"json": {"sourceId": {"var": "source_id"}, "externalId": {"literal": "note-1"},
                                  "text": {"context": "material"}, "createdAt": {"generate": "now_iso8601"},
                                  "tags": {"literal": [{"name": "synthetic"}]},
                                  "owner": {"object": {"id": {"literal": "tester"}}}}}},
    "expect": {"http_status": [201]},
    "undo": {"request": {"method": "DELETE", "url": SERVER + "/notes", "headers": {"Accept": "application/json"},
                         "query": {"externalId": {"literal": "note-1"}, "sourceId": {"var": "source_id"}}, "body": {"none": True}},
             "expect": {"http_status": [200]}},
}


def blocking(report):
    return [gap for gap in report["gaps"] if gap["blocking"]]


def unresolved(report):
    return sorted((gap["source"][0]["pointer"], gap["why"]) for gap in report["gaps"] if gap["code"] == "binding_unresolved")


def test_create_then_ingest_then_ask_compiles_the_steps_in_order_with_their_cleanup(tmp_path):
    result, out = run_draft(tmp_path, steps())
    assert result.exit_code == 3, result.output
    spec, report, provenance = artifacts(out)
    assert blocking(report) == []
    transport = spec["transport"]
    assert transport["lifecycle"] == {"run": [SOURCE_SPEC], "attempt": [NOTE_SPEC]}
    assert transport["request"]["body"] == {"json": {"question": {"context": "prompt"}}}
    assert transport["budget"]["max_requests"] == 3
    assert transport["budget"]["cleanup_reserve"] == 2
    supplied = sorted(gap["field"] for gap in report["gaps"] if gap["code"] == "binding_user_supplied")
    assert supplied == ["/transport/lifecycle/attempt/0", "/transport/lifecycle/run/0"]
    record = provenance["fields"]["/transport/lifecycle/run/0"]
    assert record["basis"] == "user_selection" and record["origin"] == "API guide, sources"
    assert record["source"][:2] == [{"file": "api.json", "pointer": "/paths/~1sources/post"}, file_source("/steps/0")]
    assert provenance["fields"]["/transport/lifecycle/run/0/capture/source_id"]["basis"] == "user_selection"
    check = CliRunner().invoke(main, ["validate-target", "--target", str(out), "--offline"])
    assert check.exit_code == 0, check.output


def test_the_ask_keeps_its_cleanup_review_row_when_every_step_has_an_undo(tmp_path):
    result, out = run_draft(tmp_path, steps())
    _, report, _ = artifacts(out)
    rows = [gap for gap in report["gaps"] if gap["code"] == "cleanup_mapping_missing"]
    assert [(gap["field"], gap["blocking"]) for gap in rows] == [("/transport/lifecycle", False)]


def test_a_union_field_reads_the_branch_the_value_fits(tmp_path):
    result, out = run_draft(tmp_path, steps())
    spec, report, provenance = artifacts(out)
    assert "operation_unsupported" not in codes(report)
    fields = NOTES + "/requestBody/content/application~1json/schema/properties"
    sources = provenance["fields"]["/transport/lifecycle/attempt/0"]["source"]
    assert {"file": "api.json", "pointer": fields + "/createdAt/anyOf/0"} in sources
    assert {"file": "api.json", "pointer": fields + "/createdAt"} not in sources


def scenario(with_note=True):
    """The independent oracle: the ask fails unless the source is live and the note holds the material."""
    note_effects = [{"resource": "note", "from": "live", "to": "live"}] if with_note else []
    operations = [
        {"id": "create_source", "method": "POST", "path": "/sources", "role": "setup", "calls": {"min": 1, "max": 1}, "request": [],
         "replies": [{"status": 201, "body": {"id": "src-1", "name": "argus-x"},
                      "effects": [{"resource": "source", "from": "absent", "to": "live"}]}]},
        {"id": "add_note", "method": "POST", "path": "/notes", "role": "setup", "calls": {"min": 1, "max": 1},
         "request": [{"check": "material_bound", "at": {"kind": "json", "pointer": "/text"}, "equals": "Argus validation sample."},
                     {"check": "resource_identity", "at": {"kind": "json", "pointer": "/sourceId"}, "equals": "src-1"}],
         "replies": [{"status": 201, "body": {"noteId": "n-1", "externalId": "note-1", "sourceId": "src-1"},
                      "effects": [{"resource": "source", "from": "live", "to": "live"},
                                  {"resource": "note", "from": "absent", "to": "live"}]}]},
        {"id": "ask", "method": "POST", "path": "/ask", "role": "invoke", "calls": {"min": 1, "max": 1},
         "request": [{"check": "prompt_bound", "at": {"kind": "json", "pointer": "/question"}, "equals": "ping"}],
         "replies": [{"status": 200, "body": {"answer": "done"},
                      "effects": [{"resource": "source", "from": "live", "to": "live"}, *note_effects]}]},
        {"id": "delete_note", "method": "DELETE", "path": "/notes", "role": "delete", "calls": {"min": 1, "max": 1},
         "request": [{"check": "resource_identity", "at": {"kind": "query", "name": "externalId"}, "equals": "note-1"},
                     {"check": "resource_identity", "at": {"kind": "query", "name": "sourceId"}, "equals": "src-1"}],
         "replies": [{"status": 200, "body": {"status": "deleted"}, "effects": [{"resource": "note", "from": "live", "to": "absent"}]}]},
        {"id": "delete_source", "method": "DELETE", "path": "/sources/{sourceId}", "role": "delete", "calls": {"min": 1, "max": 1},
         "request": [{"check": "resource_identity", "at": {"kind": "path", "name": "sourceId"}, "equals": "src-1"}],
         "replies": [{"status": 200, "body": {"status": "deleted"},
                      "effects": [{"resource": "note", "from": "absent", "to": "absent"},
                                  {"resource": "source", "from": "live", "to": "absent"}]}]},
    ]
    return {"version": 2, "environment": {}, "source": {"document": "notes.json", "pointers": ["/paths"]},
            "resources": [{"id": "source", "initial": "absent", "cleanup": "delete"}, {"id": "note", "initial": "absent", "cleanup": "delete"}],
            "operations": operations,
            "expect": {"outcome": "succeeded", "reply": "done",
                       "resources": [{"id": "source", "final": "absent"}, {"id": "note", "final": "absent"}],
                       "required_gaps": ["cleanup_mapping_missing"]}}


def verify(tmp_path, bindings, raw_scenario):
    path = tmp_path / "scenario.json"
    path.write_text(json.dumps(raw_scenario))
    return run_draft(tmp_path, bindings, "--verify-local", "--scenario", str(path))


def test_the_steps_run_before_the_ask_and_clean_up_against_an_independent_scenario(tmp_path):
    result, out = verify(tmp_path, steps(), scenario())
    assert "local.status: verified" in result.output, result.output
    local = artifacts(out)[2]["validation"]["local"]
    assert [row["operation"] for row in local["trace"]] == ["create_source", "add_note", "ask", "delete_note", "delete_source"]
    assert local["resources"] == [{"id": "source", "state": "absent", "cleanup": "delete"},
                                  {"id": "note", "state": "absent", "cleanup": "delete"}]


def test_without_the_steps_the_same_ask_fails_the_scenario(tmp_path):
    result, out = verify(tmp_path, {}, scenario())
    assert result.exit_code == 1, result.output
    local = artifacts(out)[2]["validation"]["local"]
    assert local["status"] == "failed"
    assert "resource_state_mismatch" in local["checks"]


def test_without_a_scenario_the_steps_are_reported_unverified_by_name(tmp_path):
    result, out = run_draft(tmp_path, steps(), "--verify-local")
    assert "local.status: schema_mock_only" in result.output, result.output
    assert "local.unverified: setup_step:source" in result.output
    assert "local.unverified: setup_step:note" in result.output
    local = artifacts(out)[2]["validation"]["local"]
    assert [row["operation"] for row in local["trace"]] == ["create_source", "add_note", "ask", "delete_note", "delete_source"]


async def run_spec(spec, raw_scenario, document_path):
    catalog = catalog_operations(load_openapi(document_path))
    return await verify_local(spec, catalog=catalog, scenario=parse_scenario(raw_scenario, catalog=catalog), gaps=("cleanup_mapping_missing",))


def drafted(tmp_path):
    result, out = run_draft(tmp_path, steps())
    assert result.exit_code == 3, result.output
    return artifacts(out)[0], tmp_path / "api.json"


@pytest.mark.parametrize("budget,reason,sent,unsent", [
    ({"max_requests": 2}, "request_budget", ["create_source", "add_note"], "ask"),
    ({"cleanup_reserve": 1}, "cleanup_reserve", ["create_source"], "add_note"),
])
def test_a_budget_one_short_of_the_steps_stops_before_the_request_it_cannot_afford(tmp_path, budget, reason, sent, unsent):
    spec, document = drafted(tmp_path)
    assert asyncio.run(run_spec(spec, scenario(), document)).status == "verified"
    spec["transport"]["budget"].update(budget)
    result = asyncio.run(run_spec(spec, scenario(), document))
    trace = [row["operation"] for row in result.trace]
    assert result.status == "failed"
    assert result.execution["reason"] == reason
    assert trace[:len(sent)] == sent
    assert unsent not in trace


def test_a_second_attempt_on_the_drafted_budget_stops_before_sending_anything(tmp_path):
    spec, document = drafted(tmp_path)
    catalog = catalog_operations(load_openapi(document))

    async def two_attempts():
        async with LocalFake(catalog, None) as fake:
            transport = TransportSpecV2.from_dict(with_origin(copy.deepcopy(spec["transport"]) | {"auth": {"kind": "none"}}, fake.origin))
            run = V2Run(transport, policy=StrictLoopbackPolicy(fake.origin))
            context = TransportContextV2(prompt="ping", material="Argus validation sample.")
            first = await run.attempt(context)
            sent = len(fake.trace)
            with pytest.raises(TargetRunStopped) as stopped:
                await run.attempt(context)
            after = len(fake.trace)
            await run.close()
            return first, sent, after, stopped.value.reason, [row["operation"] for row in fake.trace]

    first, sent, after, reason, trace = asyncio.run(two_attempts())
    assert first.outcome.value == "succeeded"
    assert after == sent
    assert reason in {"request_budget", "cleanup_reserve"}
    assert trace == ["create_source", "add_note", "ask", "delete_note", "delete_source"]


def test_a_poll_draft_budgets_the_steps_and_every_poll(tmp_path):
    from test_draft_async import async_document
    document = async_document()
    document["paths"]["/sources"] = setup_document()["paths"]["/sources"]
    document["paths"]["/sources/{sourceId}"] = setup_document()["paths"]["/sources/{sourceId}"]
    result, out = draft(tmp_path, document, steps(source_step()), "--operation", "submit_job")
    spec, report, _ = artifacts(out)
    assert blocking(report) == [], report
    assert spec["transport"]["budget"] == {"max_requests": 62, "cleanup_reserve": 1}


def test_a_capture_named_like_a_poll_id_blocks_instead_of_crashing(tmp_path):
    from test_draft_async import async_document
    document = async_document()
    document["paths"]["/sources"] = setup_document()["paths"]["/sources"]
    document["paths"]["/sources/{sourceId}"] = setup_document()["paths"]["/sources/{sourceId}"]
    step = source_step(capture={"job_id": "/id"}, undo={"operation": "delete_source", "parameters": {"sourceId": {"var": "job_id"}}})
    result, out = draft(tmp_path, document, steps(step), "--operation", "submit_job")
    assert result.exit_code == 3, result.output
    spec, report, _ = artifacts(out)
    assert spec is None
    assert [(gap["field"], gap["source"]) for gap in blocking(report)] == [("/transport/lifecycle", [file_source("/steps")])]


def test_an_environment_value_in_a_step_is_a_run_variable(tmp_path):
    source = source_step(values={"/name": {"env": "TARGET_INPUT_SOURCE_NAME"}})
    _, out = run_draft(tmp_path, steps(source, note_step()))
    transport = artifacts(out)[0]["transport"]
    assert transport["let"]["run"] == {"input_source_name": {"env": "TARGET_INPUT_SOURCE_NAME"}}
    assert transport["lifecycle"]["run"][0]["request"]["body"] == {"json": {"name": {"var": "input_source_name"}}}


def test_a_step_that_binds_material_is_guarded_and_one_that_does_not_is_not(tmp_path):
    other = note_step(values={**note_step()["values"], "/text": {"literal": "fixed"}})
    _, out = run_draft(tmp_path, steps(source_step(), other))
    spec = artifacts(out)[0]
    assert "if_present" not in spec["transport"]["lifecycle"]["attempt"][0]


def test_a_step_naming_an_unknown_operation_blocks(tmp_path):
    result, out = run_draft(tmp_path, steps(source_step(operation="make_source"), note_step()))
    spec, report, _ = artifacts(out)
    assert spec is None
    assert ("/steps/0/operation", "The operation is not documented.") in unresolved(report)


def test_a_capture_path_the_response_does_not_document_blocks(tmp_path):
    result, out = run_draft(tmp_path, steps(source_step(capture={"source_id": "/sourceId"}), note_step()))
    spec, report, _ = artifacts(out)
    assert spec is None
    assert [pointer for pointer, _ in unresolved(report)] == ["/steps/0/capture/source_id"]


@pytest.mark.parametrize("capture", [{"source_id": "/secret_note"}, {"source_id": "/name/first"}])
def test_a_capture_must_read_a_returned_scalar(tmp_path, capture):
    _, out = run_draft(tmp_path, steps(source_step(capture=capture), note_step()))
    assert [pointer for pointer, _ in unresolved(artifacts(out)[1])] == ["/steps/0/capture/source_id"]


@pytest.mark.parametrize("values,pointer", [
    ({"/name": {"literal": 7}}, "/steps/0/values/~1name"),
    ({"/name": {"literal": "x"}, "/kind": {"literal": "other"}}, "/steps/0/values/~1kind"),
    ({"/name": {"literal": "x"}, "/kind": {"env": "TARGET_INPUT_KIND"}}, "/steps/0/values/~1kind"),
    ({"/name": {"literal": "x"}, "/serial": {"literal": 3}}, "/steps/0/values/~1serial"),
    ({"/name": {"literal": "x"}, "/missing": {"literal": "x"}}, "/steps/0/values/~1missing"),
    ({"/name": {"literal": ["x"]}}, "/steps/0/values/~1name"),
])
def test_a_step_value_the_document_does_not_accept_blocks(tmp_path, values, pointer):
    _, out = run_draft(tmp_path, steps(source_step(values=values), note_step()))
    spec, report, _ = artifacts(out)
    assert spec is None
    assert [item for item, _ in unresolved(report)] == [pointer]


def test_a_union_field_with_no_branch_for_the_value_blocks(tmp_path):
    note = note_step(values={**note_step()["values"], "/createdAt": {"literal": True}})
    _, out = run_draft(tmp_path, steps(source_step(), note))
    assert [item for item, _ in unresolved(artifacts(out)[1])] == ["/steps/1/values/~1createdAt"]


def test_a_required_step_field_without_a_value_blocks(tmp_path):
    values = {key: value for key, value in note_step()["values"].items() if key != "/tags"}
    _, out = run_draft(tmp_path, steps(source_step(), note_step(values=values)))
    spec, report, _ = artifacts(out)
    assert spec is None
    assert unresolved(report) == [("/steps/1", "These required request fields have no value: \"tags\".")]


@pytest.mark.parametrize("undo,pointer", [
    ({"operation": "delete_source", "parameters": {"sourceId": {"literal": "src-1"}}}, "/steps/0/undo/parameters/sourceId"),
    ({"operation": "delete_source", "parameters": {}}, "/steps/0/undo"),
    ({"operation": "delete_source", "parameters": {"sourceId": {"var": "source_id"}, "force": {"literal": "yes"}}},
     "/steps/0/undo/parameters/force"),
    ({"operation": "get_note", "parameters": {"noteId": {"var": "source_id"}}}, "/steps/0/undo/operation"),
    ({"operation": "remove_source", "parameters": {}}, "/steps/0/undo/operation"),
])
def test_an_undo_the_document_cannot_express_blocks(tmp_path, undo, pointer):
    _, out = run_draft(tmp_path, steps(source_step(undo=undo), note_step()))
    spec, report, _ = artifacts(out)
    assert spec is None
    assert [item for item, _ in unresolved(report)] == [pointer]


def test_material_in_a_run_step_blocks(tmp_path):
    values = {"/name": {"context": "material"}}
    _, out = run_draft(tmp_path, steps(source_step(values=values), note_step()))
    assert [item for item, _ in unresolved(artifacts(out)[1])] == ["/steps/0"]


@pytest.mark.parametrize("change,pointer", [
    (lambda document: document["paths"]["/sources"]["post"].update(security=[{"other": []}]), "/steps/0/operation"),
    (lambda document: document["paths"]["/sources"]["post"].update(servers=[{"url": "http://127.0.0.1:9"}]), "/steps/0/operation"),
    (lambda document: document["paths"]["/sources"]["post"]["requestBody"].update(
        content={"multipart/form-data": {"schema": {"type": "object"}}}), "/steps/0/operation"),
])
def test_a_step_operation_the_draft_cannot_send_like_the_ask_blocks(tmp_path, change, pointer):
    document = setup_document()
    document["components"] = {"securitySchemes": {"other": {"type": "http", "scheme": "bearer"}}}
    change(document)
    _, out = draft(tmp_path, document, steps(), "--operation", "ask")
    spec, report, _ = artifacts(out)
    assert spec is None
    assert pointer in [item for item, _ in unresolved(report)]


def test_an_undo_is_proposed_for_the_delete_on_the_created_path(tmp_path):
    proposed = {key: value for key, value in source_step().items() if key not in {"capture", "undo"}}
    note = note_step(values={**note_step()["values"], "/sourceId": {"literal": "src-1"}},
                     undo={"operation": "delete_note", "parameters": {"externalId": {"literal": "note-1"}, "sourceId": {"literal": "src-1"}}})
    _, out = run_draft(tmp_path, steps(proposed, note))
    spec, report, provenance = artifacts(out)
    assert blocking(report) == []
    step = spec["transport"]["lifecycle"]["run"][0]
    assert step["capture"] == {"source_id": {"path": "$.id"}}
    assert step["undo"] == SOURCE_SPEC["undo"]
    [row] = [gap for gap in report["gaps"] if gap["code"] == "setup_undo_proposed"]
    assert row["field"] == "/transport/lifecycle/run/0/undo" and row["blocking"] is False
    assert provenance["fields"]["/transport/lifecycle/run/0/undo"]["basis"] == "proposal"
    assert spec["transport"]["budget"]["cleanup_reserve"] == 2


def test_a_delete_with_query_parameters_is_not_proposed_and_the_step_is_listed(tmp_path):
    note = {key: value for key, value in note_step().items() if key != "undo"}
    _, out = run_draft(tmp_path, steps(source_step(), note))
    spec, report, _ = artifacts(out)
    assert "undo" not in spec["transport"]["lifecycle"]["attempt"][0]
    assert "setup_undo_proposed" not in codes(report)
    rows = [gap for gap in report["gaps"] if gap["code"] == "cleanup_mapping_missing"]
    assert sorted((gap["field"], gap["blocking"]) for gap in rows) == [
        ("/transport/lifecycle", False), ("/transport/lifecycle/attempt/0/undo", False)]
    assert spec["transport"]["budget"]["cleanup_reserve"] == 1


def test_the_bindings_file_steps_are_hashed_into_provenance(tmp_path):
    _, out = run_draft(tmp_path, steps())
    raw = (tmp_path / "bindings.json").read_bytes()
    assert artifacts(out)[2]["inputs"][-1] == {"file": "bindings.json", "sha256": hashlib.sha256(raw).hexdigest()}


@pytest.mark.parametrize("bad", [
    {"steps": {}},
    {"steps": [{**source_step(), "extra": 1}]},
    {"steps": [{key: value for key, value in source_step().items() if key != "scope"}]},
    {"steps": [source_step(scope="once")]},
    {"steps": [source_step(id="Source")]},
    {"steps": [source_step(id="input_source")]},
    {"steps": [source_step(id="api_token")]},
    {"steps": [source_step(), note_step(id="source")]},
    {"steps": [source_step(capture={"source": "/id"})]},
    {"steps": [note_step(), source_step()]},
    {"steps": [source_step(), note_step(values={"/sourceId": {"var": "nothing"}})]},
    {"steps": [source_step(values={"/name": {"context": "prompt"}})]},
    {"steps": [source_step(values={"/name": {"env": "TARGET_INPUT_API_KEY"}})]},
    {"steps": [source_step(values={"/name": {"concat": [{"literal": "a"}, {"env": "TARGET_INPUT_NAME"}]}})]},
    {"steps": [source_step(values={"/name": {"object": {"a": {"literal": "b"}}}})]},
    {"steps": [source_step(values={"/token": {"literal": "x"}})]},
    {"steps": [source_step(values={"/name": {"literal": "x"}, "/name/first": {"literal": "y"}})]},
    {"steps": [source_step(capture={"source_id": "id"})]},
    {"steps": [source_step(undo={"operation": "delete_source", "parameters": {"sourceId": {"var": "later"}}})]},
    {"steps": [source_step(undo={"operation": "delete_source", "values": {}})]},
    {"steps": [source_step(undo={"operation": "delete_source", "parameters": {"apiKey": {"literal": "x"}}})]},
])
def test_a_malformed_step_is_a_usage_error_with_no_artifacts(tmp_path, bad):
    result, out = run_draft(tmp_path, bad)
    assert result.exit_code == 2, result.output
    assert "--bindings" in result.output
    assert not out.exists() and not out.with_suffix(".gaps.json").exists()


def test_an_input_file_with_no_steps_drafts_exactly_as_before(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    _, out_before = draft(tmp_path / "a", setup_document(), None, "--operation", "ask")
    _, out_after = draft(tmp_path / "b", setup_document(), {}, "--operation", "ask")
    spec_before, spec_after = artifacts(out_before)[0], artifacts(out_after)[0]
    assert spec_before == spec_after
    assert "lifecycle" not in spec_after["transport"]
    assert spec_after["transport"]["budget"] == {"max_requests": 1, "cleanup_reserve": 0}
