import copy
import json
from dataclasses import replace

import pytest
from click.testing import CliRunner

from argus.cli.__main__ import main
from argus.drafting.draft import Binding, IdBinding, StatusMap, choose_without_model, compile_draft
from argus.drafting.openapi import catalog_operations, load_openapi
from argus.drafting.proposal import propose_choices
from test_draft_target import input_file
from test_draft_target_model import stub_model  # noqa: F401
from test_draft_verify_local import verify


SUBMIT = "/paths/~1jobs/post"
POLL = "/paths/~1jobs~1{id}/get"
POLL_FIELDS = POLL + "/responses/200/content/application~1json/schema/properties"
STATUSES = ["PENDING", "RUNNING", "COMPLETED", "FAILED"]


def async_document(submit_status="202", result=None):
    return {
        "openapi": "3.0.3",
        "info": {"title": "Neutral async agent", "version": "1"},
        "servers": [{"url": "http://127.0.0.1:8123"}],
        "paths": {
            "/jobs": {"post": {
                "operationId": "submit_job",
                "requestBody": {"required": True, "content": {"application/json": {"schema": {
                    "type": "object", "required": ["question"], "properties": {"question": {"type": "string"}}}}}},
                "responses": {submit_status: {"description": "Accepted", "content": {"application/json": {"schema": {
                    "type": "object", "required": ["job_id"], "properties": {"job_id": {"type": "string"}}}}}}},
            }},
            "/jobs/{id}": {"get": {
                "operationId": "get_job",
                "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}],
                "responses": {"200": {"description": "Job state", "content": {"application/json": {"schema": {
                    "type": "object", "required": ["status"], "properties": {
                        "status": {"type": "string", "enum": list(STATUSES)},
                        "result": result or {"type": "object", "nullable": True}}}}}}},
            }},
        },
    }


def poll_schema(document, path="/jobs/{id}"):
    return document["paths"][path]["get"]["responses"]["200"]["content"]["application/json"]["schema"]


def run(tmp_path, document, *options):
    source = input_file(tmp_path, document)
    out = tmp_path / "target.json"
    result = CliRunner().invoke(main, ["draft-target", "--openapi", str(source), "--out", str(out), "--no-model", *options])
    return result, out


def gaps(out):
    return json.loads(out.with_suffix(".gaps.json").read_text())


def blocking(out):
    return {gap["code"] for gap in gaps(out)["gaps"] if gap["blocking"]}


def catalog_for(tmp_path, document):
    return catalog_operations(load_openapi(input_file(tmp_path, document)))


EXPECTED_DELIVERY = {
    "kind": "poll",
    "ids": {"job_id": {"path": "$.job_id"}},
    "request": {"method": "GET", "url": "http://127.0.0.1:8123/jobs/{job_id}",
                "headers": {"Accept": "application/json"}, "body": {"none": True}},
    "pending": {"path": "$.status", "one_of": ["PENDING", "RUNNING"]},
    "interval_s": 5,
    "max_polls": 60,
    "submit_http_status": [202],
    "submit_outcome": {"kind": "rules", "unmatched": "accepted", "rules": []},
}


def test_accepted_submit_and_documented_poll_compile_a_poll_draft(tmp_path):
    result, out = run(tmp_path, async_document())
    assert result.exit_code == 3, result.output
    assert "spec_written: true" in result.output
    transport = json.loads(out.read_text())["transport"]
    delivery = transport["delivery"]
    assert {key: delivery[key] for key in EXPECTED_DELIVERY} == EXPECTED_DELIVERY
    assert transport["request"]["method"] == "POST"
    assert transport["request"]["url"] == "http://127.0.0.1:8123/jobs"
    assert transport["response"]["text"] == {"paths": ["$.result"], "cast": "string_or_json", "empty": "error"}
    rules = {rule["outcome"]: rule for rule in transport["outcome"]["rules"]}
    assert set(rules) == {"succeeded", "target_error"}
    assert rules["succeeded"]["when"] == {"path": "$.status", "equals": "COMPLETED"}
    assert rules["succeeded"]["http_status"] == [200]
    assert rules["target_error"]["when"] == {"path": "$.status", "one_of": ["FAILED"]}
    assert transport["outcome"]["unmatched"] == "target_error"
    assert transport["budget"] == {"max_requests": 61, "cleanup_reserve": 0}
    report = gaps(out)
    assert report["state"] == "needs_review" and report["spec_written"] is True
    assert {"poll_proposed", "poll_id_binding_proposed", "poll_status_proposed"} <= {gap["code"] for gap in report["gaps"]}
    assert not blocking(out)
    validation = CliRunner().invoke(main, ["validate-target", "--target", str(out), "--offline"])
    assert validation.exit_code == 0, validation.output


def test_submit_returning_200_with_an_id_gives_the_same_delivery(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    accepted, accepted_out = run(tmp_path / "a", async_document("202"))
    ok, ok_out = run(tmp_path / "b", async_document("200"))
    assert accepted.exit_code == ok.exit_code == 3, ok.output
    first = json.loads(accepted_out.read_text())["transport"]["delivery"]
    second = json.loads(ok_out.read_text())["transport"]["delivery"]
    assert second.pop("submit_http_status") == [200]
    assert first.pop("submit_http_status") == [202]
    assert first == second


def test_text_result_uses_strict_string_cast(tmp_path):
    result, out = run(tmp_path, async_document(result={"type": "string"}))
    assert result.exit_code == 3, result.output
    assert json.loads(out.read_text())["transport"]["response"]["text"]["cast"] == "string"


def test_poll_limits_are_bounded_policy_defaults(tmp_path):
    result, out = run(tmp_path, async_document())
    assert result.exit_code == 3, result.output
    transport = json.loads(out.read_text())["transport"]
    delivery = transport["delivery"]
    assert delivery["max_polls"] == 60 <= 100
    assert transport["budget"]["max_requests"] == 1 + delivery["max_polls"]
    assert transport["timeout"]["total_deadline_s"] == 330
    defaults = json.loads(out.with_suffix(".provenance.json").read_text())["policy_defaults"]
    assert defaults["delivery.interval_s"] == {"value": 5, "basis": "policy_default"}
    assert defaults["delivery.max_polls"] == {"value": 60, "basis": "policy_default"}
    assert defaults["budget"]["value"]["max_requests"] == 61
    assert defaults["timeout"]["value"]["total_deadline_s"] == 330


def test_documented_retry_after_replaces_the_fixed_interval(tmp_path):
    document = async_document()
    document["paths"]["/jobs/{id}"]["get"]["responses"]["200"]["headers"] = {"Retry-After": {"schema": {"type": "integer"}}}
    result, out = run(tmp_path, document)
    assert result.exit_code == 3, result.output
    delivery = json.loads(out.read_text())["transport"]["delivery"]
    assert "interval_s" not in delivery
    assert delivery["wait"] == {"from": "Retry-After", "default_s": 5, "max_s": 60}


def scenario(tmp_path, *, result="pong"):
    data = {
        "version": 2, "environment": {},
        "source": {"document": "independent neutral async scenario", "pointers": [SUBMIT, POLL]},
        "resources": [],
        "operations": [
            {"id": "submit_job", "method": "POST", "path": "/jobs", "role": "invoke", "calls": {"min": 1, "max": 1},
             "request": [{"check": "prompt_bound", "at": {"kind": "json", "pointer": "/question"}, "equals": "ping"}],
             "replies": [{"status": 202, "body": {"job_id": "job-7"}, "effects": []}]},
            {"id": "get_job", "method": "GET", "path": "/jobs/{id}", "role": "poll", "calls": {"min": 2, "max": 2},
             "request": [{"check": "poll_identity", "at": {"kind": "path", "name": "id"}, "equals": "job-7"}],
             "replies": [{"status": 200, "body": {"status": "PENDING"}, "effects": []},
                         {"status": 200, "body": {"status": "COMPLETED", "result": result}, "effects": []}]},
        ],
        "expect": {"outcome": "succeeded", "reply": result, "resources": [], "required_gaps": []},
    }
    path = tmp_path / "scenario.json"
    path.write_text(json.dumps(data))
    return path


def test_verify_local_runs_pending_then_completed(tmp_path):
    document = async_document(result={"type": "string"})
    result, out = run(tmp_path, document, "--verify-local", "--scenario", str(scenario(tmp_path)))
    assert result.exit_code == 3, result.output
    assert "local.status: verified" in result.output
    local = json.loads(out.with_suffix(".provenance.json").read_text())["validation"]["local"]
    assert local["status"] == "verified" and local["semantic_success"] is True
    assert local["execution"]["requests"]["submit"] == 1
    assert local["execution"]["requests"]["poll"] == 2
    assert local["execution"]["reply"] == "pong"


async def test_undocumented_runtime_status_ends_as_target_error_after_one_poll(tmp_path):
    catalog = catalog_for(tmp_path, async_document(result={"type": "string"}))
    spec = compile_draft(catalog, choose_without_model(catalog)).spec
    raw = json.loads(scenario(tmp_path).read_text())
    raw["operations"][1]["calls"] = {"min": 1, "max": 1}
    raw["operations"][1]["replies"] = [{"status": 200, "body": {"status": "PAUSED"}, "effects": []}]
    raw["expect"] = {"outcome": "target_error", "reply": None, "resources": [], "required_gaps": []}
    result = await verify(spec, raw)
    assert result.status == "business_only", result.as_dict()
    execution = result.as_dict()["execution"]
    assert execution["outcome"] == "target_error"
    assert execution["reason"] != "poll_limit"
    assert execution["requests"]["poll"] == 1


def test_auto_selection_keeps_the_submit_when_a_get_poll_exists(tmp_path):
    catalog = catalog_for(tmp_path, async_document())
    choices = choose_without_model(catalog)
    assert choices.operation == "submit_job"
    assert choices.delivery.operation == "get_job"
    assert [(item.name, item.parameter, item.submit.path) for item in choices.delivery.ids] == [("job_id", "id", ("job_id",))]
    assert choices.reply.pointer == POLL_FIELDS + "/result"
    assert choices.completion == StatusMap(Binding(("status",), POLL_FIELDS + "/status", value="COMPLETED"), ("PENDING", "RUNNING"), ("FAILED",))


def test_no_poll_operation_blocks(tmp_path):
    document = async_document()
    del document["paths"]["/jobs/{id}"]
    result, out = run(tmp_path, document)
    assert result.exit_code == 3, result.output
    assert not out.exists()
    assert gaps(out)["spec_written"] is False
    assert "async_poll_missing" in blocking(out)
    assert "delivery_unsupported" not in {gap["code"] for gap in gaps(out)["gaps"]}


def second_poll(document):
    document["paths"]["/jobs/{id}/detail"] = {"get": {**copy.deepcopy(document["paths"]["/jobs/{id}"]["get"]), "operationId": "get_job_detail"}}
    return document


def test_two_poll_candidates_block_until_one_is_selected(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    result, out = run(tmp_path / "a", second_poll(async_document()))
    assert result.exit_code == 3, result.output
    assert not out.exists()
    assert "poll_ambiguous" in blocking(out)
    chosen, chosen_out = run(tmp_path / "b", second_poll(async_document()), "--poll-operation", "get_job_detail")
    assert chosen.exit_code == 3, chosen.output
    delivery = json.loads(chosen_out.read_text())["transport"]["delivery"]
    assert delivery["request"]["url"] == "http://127.0.0.1:8123/jobs/{job_id}/detail"
    assert "poll_proposed" not in {gap["code"] for gap in gaps(chosen_out)["gaps"]}


def test_unknown_poll_operation_is_a_usage_error(tmp_path):
    result, out = run(tmp_path, async_document(), "--poll-operation", "missing")
    assert result.exit_code == 2
    assert not out.with_suffix(".gaps.json").exists()


def test_unmappable_path_parameter_blocks(tmp_path):
    document = async_document()
    document["paths"]["/jobs/{ticket}"] = document["paths"].pop("/jobs/{id}")
    document["paths"]["/jobs/{ticket}"]["get"]["parameters"][0]["name"] = "ticket"
    result, out = run(tmp_path, document)
    assert result.exit_code == 3, result.output
    assert not out.exists()
    assert "poll_id_binding_missing" in blocking(out)


def test_status_enum_without_a_success_word_blocks(tmp_path):
    document = async_document()
    poll_schema(document)["properties"]["status"]["enum"] = ["PENDING", "RUNNING", "FINISHED_OK", "FAILED"]
    result, out = run(tmp_path, document)
    assert result.exit_code == 3, result.output
    assert not out.exists()
    assert "completion_missing" in blocking(out)


def test_two_success_words_are_not_a_unique_completion(tmp_path):
    document = async_document()
    poll_schema(document)["properties"]["status"]["enum"] = ["PENDING", "COMPLETED", "SUCCEEDED"]
    result, out = run(tmp_path, document)
    assert not out.exists()
    assert "completion_missing" in blocking(out)


def test_unclassified_values_are_listed_and_fall_to_target_error(tmp_path):
    document = async_document()
    poll_schema(document)["properties"]["status"]["enum"] = ["PENDING", "COMPLETED", "ON_HOLD"]
    result, out = run(tmp_path, document)
    assert result.exit_code == 3, result.output
    transport = json.loads(out.read_text())["transport"]
    assert transport["delivery"]["pending"] == {"path": "$.status", "one_of": ["PENDING"]}
    assert [rule["outcome"] for rule in transport["outcome"]["rules"]] == ["succeeded"]
    unclassified = [gap for gap in gaps(out)["gaps"] if gap["code"] == "poll_status_unclassified"]
    assert len(unclassified) == 1 and not unclassified[0]["blocking"]
    assert "ON_HOLD" in unclassified[0]["why"]


@pytest.mark.parametrize("alter", ["presence", "nested", "query", "two_successes"])
def test_unsupported_async_shapes_block(tmp_path, alter):
    document = async_document()
    if alter == "presence":
        poll_schema(document)["properties"]["status"] = {"type": "object", "properties": {"completed": {"type": "boolean"}}}
    elif alter == "nested":
        status = poll_schema(document)["properties"].pop("status")
        poll_schema(document)["properties"]["state"] = {"type": "object", "properties": {"phase": status}}
        poll_schema(document)["required"] = []
    elif alter == "query":
        document["paths"]["/jobs/{id}"]["get"]["parameters"].append(
            {"name": "view", "in": "query", "required": True, "schema": {"type": "string"}})
    else:
        responses = document["paths"]["/jobs"]["post"]["responses"]
        responses["200"] = copy.deepcopy(responses["202"])
        responses["200"]["content"]["application/json"]["schema"]["properties"] = {"task_id": {"type": "string"}}
    result, out = run(tmp_path, document)
    assert result.exit_code == 3, result.output
    assert not out.exists()
    expected = "poll_parameter_unsupported" if alter == "query" else "async_shape_unsupported"
    assert expected in blocking(out)


def test_async_draft_reads_the_poll_response_not_the_submit_response(tmp_path):
    document = async_document()
    poll_schema(document)["properties"]["result"]["format"] = "date-time"
    poll_schema(document)["properties"]["result"]["type"] = "string"
    poll_schema(document)["properties"]["result"].pop("nullable")
    result, out = run(tmp_path, document)
    assert not out.exists()
    assert "reply_binding_missing" in blocking(out)


def compiled(tmp_path):
    catalog = catalog_for(tmp_path, async_document())
    return catalog, choose_without_model(catalog)


@pytest.mark.parametrize("alter", [
    lambda c: replace(c, delivery=replace(c.delivery, ids=(IdBinding("missing_id", Binding(
        ("missing_id",), SUBMIT + "/responses/202/content/application~1json/schema/properties/missing_id"), "id"),))),
    lambda c: replace(c, delivery=replace(c.delivery, ids=(replace(c.delivery.ids[0], name="other"),))),
    lambda c: replace(c, delivery=replace(c.delivery, ids=(replace(c.delivery.ids[0], parameter="other"),))),
    lambda c: replace(c, delivery=replace(c.delivery, operation="submit_job")),
    lambda c: replace(c, completion=replace(c.completion, field=replace(c.completion.field, value="DONE"))),
    lambda c: replace(c, completion=replace(c.completion, pending=("PENDING", "PAUSED"))),
    lambda c: replace(c, completion=replace(c.completion, pending=())),
    lambda c: replace(c, completion=replace(c.completion, pending=("PENDING", "COMPLETED"))),
    lambda c: replace(c, completion=replace(c.completion, failed=("FAILED", "PENDING"))),
    lambda c: replace(c, delivery=None),
    lambda c: replace(c, completion=c.completion.field),
], ids=["id_not_documented", "id_variable_renamed", "parameter_not_in_path", "poll_not_get", "success_not_in_enum", "pending_not_in_enum",
        "pending_empty", "pending_includes_success", "failed_overlaps_pending", "status_map_without_poll", "poll_without_status_map"])
def test_compile_rejects_choices_outside_the_document(tmp_path, alter):
    catalog, choices = compiled(tmp_path)
    assert compile_draft(catalog, choices).spec is not None
    with pytest.raises(ValueError):
        compile_draft(catalog, alter(choices))


async def test_model_null_reply_keeps_the_deterministic_poll_choice(tmp_path, stub_model):
    _, output, _ = stub_model
    output["text"] = json.dumps({"operation": "submit_job",
                                 "prompt": SUBMIT + "/requestBody/content/application~1json/schema/properties/question",
                                 "reply": None, "completion": None})
    catalog = catalog_for(tmp_path, async_document())
    proposal = await propose_choices(catalog)
    assert proposal.disclosure.status == "accepted"
    artifacts = compile_draft(catalog, proposal.choices)
    expected = compile_draft(catalog, choose_without_model(catalog))
    assert artifacts.spec is not None
    assert artifacts.spec["transport"]["delivery"] == expected.spec["transport"]["delivery"]
    assert artifacts.spec["transport"]["outcome"] == expected.spec["transport"]["outcome"]


def test_a_documented_answer_keeps_a_200_submit_synchronous(tmp_path):
    document = async_document("200")
    submit = document["paths"]["/jobs"]["post"]["responses"]["200"]["content"]["application/json"]["schema"]
    submit["properties"]["answer"] = {"type": "string"}
    result, out = run(tmp_path, document)
    assert result.exit_code == 3, result.output
    assert json.loads(out.read_text())["transport"]["delivery"] == {"kind": "sync"}


def test_poll_with_different_authentication_blocks(tmp_path):
    document = async_document()
    document["components"] = {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}}
    document["security"] = [{"bearer": []}]
    document["paths"]["/jobs/{id}"]["get"]["security"] = []
    result, out = run(tmp_path, document)
    assert result.exit_code == 3, result.output
    assert not out.exists()
    assert "async_shape_unsupported" in blocking(out)


@pytest.mark.parametrize("name", ["prompt", "session_token", "author_id"])
def test_ids_that_cannot_be_transport_variables_are_not_paired(tmp_path, name):
    document = async_document()
    submit = document["paths"]["/jobs"]["post"]["responses"]["202"]["content"]["application/json"]["schema"]
    submit["properties"] = {name: {"type": "string"}}
    submit["required"] = [name]
    document["paths"]["/jobs/{" + name + "}"] = document["paths"].pop("/jobs/{id}")
    document["paths"]["/jobs/{" + name + "}"]["get"]["parameters"][0]["name"] = name
    result, out = run(tmp_path, document)
    assert result.exit_code == 3, result.output
    assert not out.exists()
    assert "poll_id_binding_missing" in blocking(out)


def test_poll_id_colliding_with_an_input_binding_blocks(tmp_path):
    document = async_document()
    operation = document["paths"]["/jobs"]["post"]
    operation["parameters"] = [{"name": "ref", "in": "query", "required": True, "schema": {"type": "string"}}]
    submit = operation["responses"]["202"]["content"]["application/json"]["schema"]
    submit["properties"] = {"input_ref": {"type": "string"}}
    document["paths"]["/jobs/{input_ref}"] = document["paths"].pop("/jobs/{id}")
    document["paths"]["/jobs/{input_ref}"]["get"]["parameters"][0]["name"] = "input_ref"
    result, out = run(tmp_path, document)
    assert result.exit_code == 3, result.output
    assert not out.exists()
    assert "parameter_collision" in blocking(out)


def test_unsafe_poll_path_blocks(tmp_path):
    document = async_document()
    document["paths"]["/jobs/{id}/%2e%2e"] = document["paths"].pop("/jobs/{id}")
    result, out = run(tmp_path, document)
    assert result.exit_code == 3, result.output
    assert not out.exists()
    assert "path_unsafe" in blocking(out)


def poll_operation(document):
    return document["paths"]["/jobs/{id}"]["get"]


@pytest.mark.parametrize("alter", ["server_override", "five_ids", "undeclared_placeholder", "label_style", "object_id", "write_only_id"])
def test_gets_that_cannot_be_a_poll_are_not_offered(tmp_path, alter):
    document = async_document()
    submit = document["paths"]["/jobs"]["post"]["responses"]["202"]["content"]["application/json"]["schema"]
    if alter == "server_override":
        poll_operation(document)["servers"] = [{"url": "http://127.0.0.1:9999"}]
    elif alter == "five_ids":
        names = ["a", "b", "c", "d", "e"]
        submit["properties"] = {name: {"type": "string"} for name in names}
        document["paths"]["/jobs/{a}/{b}/{c}/{d}/{e}"] = document["paths"].pop("/jobs/{id}")
        poll_operation_data = document["paths"]["/jobs/{a}/{b}/{c}/{d}/{e}"]["get"]
        poll_operation_data["parameters"] = [{"name": name, "in": "path", "required": True, "schema": {"type": "string"}} for name in names]
    elif alter == "undeclared_placeholder":
        document["paths"]["/jobs/{id}/{part}"] = document["paths"].pop("/jobs/{id}")
    elif alter == "label_style":
        poll_operation(document)["parameters"][0]["style"] = "label"
    elif alter == "object_id":
        submit["properties"]["job_id"] = {"type": "object"}
    else:
        submit["properties"]["job_id"]["writeOnly"] = True
    result, out = run(tmp_path, document)
    assert result.exit_code == 3, result.output
    assert not out.exists()
    assert blocking(out) & {"async_poll_missing", "poll_id_binding_missing"}


@pytest.mark.parametrize("alter", ["two_named_ids", "one_id_twice"])
def test_ids_without_a_unique_mapping_are_not_paired(tmp_path, alter):
    document = async_document()
    submit = document["paths"]["/jobs"]["post"]["responses"]["202"]["content"]["application/json"]["schema"]
    if alter == "two_named_ids":
        submit["properties"]["task_id"] = {"type": "string"}
    else:
        document["paths"]["/jobs/{job_id}/runs/{id}"] = document["paths"].pop("/jobs/{id}")
        poll_operation_data = document["paths"]["/jobs/{job_id}/runs/{id}"]["get"]
        poll_operation_data["parameters"].append({"name": "job_id", "in": "path", "required": True, "schema": {"type": "string"}})
    result, out = run(tmp_path, document)
    assert result.exit_code == 3, result.output
    assert not out.exists()
    assert "poll_id_binding_missing" in blocking(out)


@pytest.mark.parametrize("extra", [{"object": {"type": "string", "enum": ["job"]}},
                                   {"region_id": {"type": "string", "enum": ["eu", "us"]}}])
def test_type_tags_and_identifier_enums_do_not_hide_the_status(tmp_path, extra):
    document = async_document()
    poll_schema(document)["properties"].update(extra)
    result, out = run(tmp_path, document)
    assert result.exit_code == 3, result.output
    assert json.loads(out.read_text())["transport"]["delivery"]["pending"] == {"path": "$.status", "one_of": ["PENDING", "RUNNING"]}


def test_status_enum_without_a_pending_value_blocks(tmp_path):
    document = async_document()
    poll_schema(document)["properties"]["status"]["enum"] = ["COMPLETED", "FAILED"]
    result, out = run(tmp_path, document)
    assert result.exit_code == 3, result.output
    assert not out.exists()
    assert "completion_missing" in blocking(out)


def test_nullable_run_id_on_a_200_submit_pairs_with_an_id_parameter(tmp_path):
    document = async_document("200")
    document["openapi"] = "3.1.0"
    submit = document["paths"]["/jobs"]["post"]["responses"]["200"]["content"]["application/json"]["schema"]
    submit["properties"] = {"run_id": {"type": ["string", "null"]}, "error": {"type": ["string", "null"]}}
    submit["required"] = ["run_id", "error"]
    poll_schema(document)["properties"]["result"] = {"type": ["object", "null"]}
    result, out = run(tmp_path, document)
    assert result.exit_code == 3, result.output
    delivery = json.loads(out.read_text())["transport"]["delivery"]
    assert delivery["ids"] == {"run_id": {"path": "$.run_id"}}
    assert delivery["request"]["url"] == "http://127.0.0.1:8123/jobs/{run_id}"
    assert delivery["submit_http_status"] == [200]


def test_status_enum_with_a_non_string_value_is_not_a_status(tmp_path):
    document = async_document()
    poll_schema(document)["properties"]["status"] = {"type": "string", "nullable": True, "enum": ["PENDING", "COMPLETED", None]}
    result, out = run(tmp_path, document)
    assert result.exit_code == 3, result.output
    assert not out.exists()
    assert blocking(out) & {"async_shape_unsupported", "completion_missing"}


def test_cycle_under_an_opaque_object_reply_is_a_review_row(tmp_path):
    document = async_document(result={"type": "object", "additionalProperties": {"$ref": "#/components/schemas/Value"}})
    document["components"] = {"schemas": {"Value": {"type": "object", "properties": {
        "list": {"type": "array", "items": {"$ref": "#/components/schemas/Value"}}}}}}
    result, out = run(tmp_path, document)
    assert result.exit_code == 3, result.output
    transport = json.loads(out.read_text())["transport"]
    assert transport["response"]["text"] == {"paths": ["$.result"], "cast": "string_or_json", "empty": "error"}
    assert [(gap["blocking"], gap["source"]) for gap in gaps(out)["gaps"] if gap["code"] == "reference_cycle"] == [
        (False, [{"file": "api.json", "pointer": "/components/schemas/Value/properties/list/items"}])]
