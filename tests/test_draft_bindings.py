import copy
import hashlib
import json

import pytest
from click.testing import CliRunner

from argus.cli.__main__ import main
from argus.drafting.bindings import read_bindings
from argus.drafting.draft import Binding, OperationSelection, ReplyPresence, choices_from_selection, compile_draft
from test_draft_async import catalog_for, input_file
from test_draft_target import agent_document
from test_draft_target_model import proposed_document, stub_model  # noqa: F401

RUN = "/paths/~1runs/post"
RESPONSE = RUN + "/responses/200/content/application~1json/schema"
NESTED = {"prompt": {"path": "/inputs/question/text"}, "reply": {"path": "/result/text"},
          "values": {"/mode": {"literal": "MODE_DRAFT"}}}


def nested_document():
    """A run API whose question sits under a map key and whose answer sits in a nested object."""
    return {
        "openapi": "3.0.3",
        "info": {"title": "Neutral runner", "version": "1"},
        "servers": [{"url": "http://127.0.0.1:8123"}],
        "paths": {"/runs": {"post": {
            "operationId": "start_run",
            "requestBody": {"required": True, "content": {"application/json": {"schema": {
                "type": "object", "required": ["mode"],
                "properties": {
                    "inputs": {"type": "object", "additionalProperties": {"$ref": "#/components/schemas/Value"}},
                    "mode": {"type": "string", "enum": ["MODE_DRAFT", "MODE_LIVE"]},
                    "count": {"type": "integer"},
                    "label": {"type": "string"},
                }}}}},
            "responses": {"200": {"description": "Finished run", "content": {"application/json": {"schema": {
                "type": "object", "required": ["run_id", "result"],
                "properties": {
                    "run_id": {"type": "string"},
                    "result": {"type": "object", "properties": {
                        "text": {"type": "string"},
                        "updated_at": {"type": "string", "format": "date-time"},
                        "parts": {"type": "array", "items": {"type": "string"}},
                    }},
                }}}}}},
        }}},
        "components": {"schemas": {"Value": {"type": "object", "properties": {
            "text": {"type": "string"}, "number": {"type": "number"}, "child": {"$ref": "#/components/schemas/Value"},
        }}}},
    }


def draft(tmp_path, document, bindings=None, *options, raw=None):
    source = input_file(tmp_path, document)
    out = tmp_path / "target.json"
    arguments = ["draft-target", "--openapi", str(source), "--out", str(out), "--no-model", *options]
    if bindings is not None or raw is not None:
        path = tmp_path / "bindings.json"
        path.write_bytes(raw if raw is not None else json.dumps({"version": 1, **bindings}).encode())
        arguments += ["--bindings", str(path)]
    return CliRunner().invoke(main, arguments), out


def artifacts(out):
    spec = json.loads(out.read_text()) if out.exists() else None
    return (spec, json.loads(out.with_suffix(".gaps.json").read_text()),
            json.loads(out.with_suffix(".provenance.json").read_text()))


def codes(report, blocking=None):
    return sorted(gap["code"] for gap in report["gaps"] if blocking is None or gap["blocking"] is blocking)


def only(report, code):
    [gap] = [gap for gap in report["gaps"] if gap["code"] == code]
    return gap


def file_source(pointer):
    return {"file": "bindings.json", "pointer": pointer}


def test_without_a_file_the_nested_document_needs_input(tmp_path):
    result, out = draft(tmp_path, nested_document())
    assert result.exit_code == 3, result.output
    spec, report, _ = artifacts(out)
    assert spec is None
    assert codes(report, blocking=True) == ["completion_missing", "prompt_binding_missing", "reply_binding_missing"]


def test_nested_prompt_and_reply_from_a_bindings_file_draft_a_spec_that_validates(tmp_path):
    result, out = draft(tmp_path, nested_document(), NESTED)
    assert result.exit_code == 3, result.output
    spec, report, provenance = artifacts(out)
    transport = spec["transport"]
    assert transport["request"]["body"] == {"json": {
        "inputs": {"object": {"question": {"object": {"text": {"context": "prompt"}}}}},
        "mode": {"literal": "MODE_DRAFT"}}}
    assert transport["response"]["text"] == {"paths": ["$.result.text"], "cast": "string", "empty": "error"}
    assert transport["outcome"]["rules"][0]["when"] == {"all": [
        {"path": "$.result.text", "exists": True}, {"path": "$.run_id", "exists": True}, {"path": "$.result", "exists": True}]}
    assert codes(report, blocking=True) == []
    assert not {"prompt_binding_proposed", "reply_binding_proposed", "business_input_missing"} & set(codes(report))
    supplied = [gap for gap in report["gaps"] if gap["code"] == "binding_user_supplied"]
    assert sorted(gap["source"][-1]["pointer"] for gap in supplied) == ["/prompt", "/reply", "/values/~1mode"]
    assert all(gap["blocking"] is False for gap in supplied)
    fields = provenance["fields"]
    assert fields["/transport/request/body"] == {"basis": "user_selection", "source": [
        {"file": "api.json", "pointer": "/components/schemas/Value/properties/text"}, file_source("/prompt")]}
    assert fields["/transport/response/text"]["source"] == [
        {"file": "api.json", "pointer": RESPONSE + "/properties/result/properties/text"}, file_source("/reply")]
    assert fields["/transport/request/body/json/mode"]["basis"] == "user_selection"
    check = CliRunner().invoke(main, ["validate-target", "--target", str(out), "--offline"])
    assert check.exit_code == 0, check.output


def test_the_bindings_file_hash_is_in_provenance(tmp_path):
    raw = json.dumps({"version": 1, **NESTED}, indent=1).encode()
    result, out = draft(tmp_path, nested_document(), raw=raw)
    assert result.exit_code == 3, result.output
    inputs = artifacts(out)[2]["inputs"]
    assert {"file": "bindings.json", "sha256": hashlib.sha256(raw).hexdigest()} in inputs
    assert inputs[0]["file"] == "api.json"


def test_an_entry_origin_is_carried_into_provenance(tmp_path):
    bindings = copy.deepcopy(NESTED)
    bindings["values"]["/mode"]["origin"] = "vendor prose"
    result, out = draft(tmp_path, nested_document(), bindings)
    assert result.exit_code == 3, result.output
    fields = artifacts(out)[2]["fields"]
    assert fields["/transport/request/body/json/mode"]["origin"] == "vendor prose"
    assert "origin" not in fields["/transport/request/body"]


def test_a_file_that_names_nothing_changes_nothing_but_the_recorded_inputs(tmp_path):
    plain = tmp_path / "plain"
    with_file = tmp_path / "with_file"
    plain.mkdir()
    with_file.mkdir()
    first, out = draft(plain, agent_document())
    second, filed = draft(with_file, agent_document(), {})
    assert first.exit_code == second.exit_code == 3
    (spec, report, provenance), (filed_spec, filed_report, filed_provenance) = artifacts(out), artifacts(filed)
    assert spec == filed_spec and report == filed_report
    assert filed_provenance["inputs"][:-1] == provenance["inputs"]
    assert {**filed_provenance, "inputs": provenance["inputs"]} == provenance


@pytest.mark.parametrize("bindings,entry", [
    ({**NESTED, "prompt": {"path": "/payload/text"}}, "/prompt"),
    ({**NESTED, "prompt": {"path": "/inputs/question/child/text"}}, "/prompt"),
    ({**NESTED, "reply": {"path": "/result/answer"}}, "/reply"),
    ({**NESTED, "reply": {"path": "/result/parts/0"}}, "/reply"),
    ({**NESTED, "values": {**NESTED["values"], "/inputs/extra/missing": {"literal": "x"}}}, "/values/~1inputs~1extra~1missing"),
], ids=["missing_prompt", "cycle_stub_on_the_walk", "missing_reply", "array", "missing_value"])
def test_an_entry_that_does_not_resolve_blocks_and_names_the_file_pointer(tmp_path, bindings, entry):
    result, out = draft(tmp_path, nested_document(), bindings)
    assert result.exit_code == 3, result.output
    spec, report, _ = artifacts(out)
    assert spec is None
    gap = only(report, "binding_unresolved")
    assert gap["blocking"] is True and gap["source"] == [file_source(entry)]
    assert "does not name a documented field" in gap["why"]
    assert not {"prompt_binding_missing", "reply_binding_missing"} & set(codes(report))


def test_a_reference_cycle_stub_as_the_leaf_blocks(tmp_path):
    result, out = draft(tmp_path, nested_document(), {**NESTED, "prompt": {"path": "/inputs/question/child"}})
    assert result.exit_code == 3, result.output
    gap = only(artifacts(out)[1], "binding_unresolved")
    assert gap["source"] == [file_source("/prompt")] and "type is not string" in gap["why"]


def test_an_object_without_a_documented_type_is_not_walked(tmp_path):
    document = nested_document()
    del document["components"]["schemas"]["Value"]["type"]
    result, out = draft(tmp_path, document, NESTED)
    assert result.exit_code == 3, result.output
    assert only(artifacts(out)[1], "binding_unresolved")["source"] == [file_source("/prompt")]


@pytest.mark.parametrize("value", [{"literal": "MODE_OTHER"}, {"literal": 2}, {"env": "TARGET_INPUT_MODE"}],
                         ids=["outside_enum", "wrong_type", "unchecked_env"])
def test_a_value_the_enum_does_not_document_blocks(tmp_path, value):
    result, out = draft(tmp_path, nested_document(), {**NESTED, "values": {"/mode": value}})
    assert result.exit_code == 3, result.output
    spec, report, _ = artifacts(out)
    assert spec is None
    gap = only(report, "binding_unresolved")
    assert gap["blocking"] is True and gap["source"] == [file_source("/values/~1mode")]


def test_an_environment_value_for_a_field_with_a_value_set_blocks_even_when_null_is_listed(tmp_path):
    document = nested_document()
    document["paths"]["/runs"]["post"]["requestBody"]["content"]["application/json"]["schema"]["properties"]["mode"]["enum"].append(None)
    result, out = draft(tmp_path, document, {**NESTED, "values": {"/mode": {"env": "TARGET_INPUT_MODE"}}})
    assert result.exit_code == 3, result.output
    assert only(artifacts(out)[1], "binding_unresolved")["source"] == [file_source("/values/~1mode")]


@pytest.mark.parametrize("path,value", [("/count", 2), ("/inputs/question/number", 2.5), ("/label", "plain")])
def test_a_typed_literal_is_sent_as_written(tmp_path, path, value):
    bindings = {**NESTED, "values": {**NESTED["values"], path: {"literal": value}}}
    result, out = draft(tmp_path, nested_document(), bindings)
    assert result.exit_code == 3, result.output
    body = artifacts(out)[0]["transport"]["request"]["body"]["json"]
    node = body
    *parents, leaf = path.strip("/").split("/")
    for key in parents:
        node = node[key]["object"]
    assert node[leaf] == {"literal": value}


@pytest.mark.parametrize("path,value", [("/count", "2"), ("/count", 2.5), ("/count", True), ("/inputs/question/number", "x")])
def test_a_literal_of_the_wrong_type_blocks(tmp_path, path, value):
    bindings = {**NESTED, "values": {**NESTED["values"], path: {"literal": value}}}
    result, out = draft(tmp_path, nested_document(), bindings)
    assert result.exit_code == 3, result.output
    assert only(artifacts(out)[1], "binding_unresolved")["blocking"] is True


def test_an_environment_value_is_declared_as_a_run_binding(tmp_path):
    bindings = {**NESTED, "values": {**NESTED["values"], "/label": {"env": "TARGET_INPUT_RUN_LABEL"}}}
    result, out = draft(tmp_path, nested_document(), bindings)
    assert result.exit_code == 3, result.output
    transport = artifacts(out)[0]["transport"]
    assert transport["request"]["body"]["json"]["label"] == {"var": "input_run_label"}
    assert transport["let"]["run"]["input_run_label"] == {"env": "TARGET_INPUT_RUN_LABEL"}


@pytest.mark.parametrize("path,fragment", [("/run_id", "identifier"), ("/result/updated_at", "identifier")],
                         ids=["identifier", "timestamp"])
def test_a_user_supplied_identifier_or_timestamp_reply_blocks(tmp_path, path, fragment):
    result, out = draft(tmp_path, nested_document(), {**NESTED, "reply": {"path": path}})
    assert result.exit_code == 3, result.output
    spec, report, _ = artifacts(out)
    assert spec is None
    gap = only(report, "binding_unresolved")
    assert gap["blocking"] is True and gap["field"] == "/transport/response/text"
    assert fragment in gap["why"] and gap["source"] == [file_source("/reply")]


@pytest.mark.parametrize("prompt", ["/mode", "/count"], ids=["enum", "integer"])
def test_a_prompt_on_a_field_that_cannot_carry_text_blocks(tmp_path, prompt):
    result, out = draft(tmp_path, nested_document(), {**NESTED, "prompt": {"path": prompt}, "values": {}})
    assert result.exit_code == 3, result.output
    assert only(artifacts(out)[1], "binding_unresolved")["source"] == [file_source("/prompt")]


def test_a_read_only_prompt_blocks(tmp_path):
    document = nested_document()
    document["components"]["schemas"]["Value"]["properties"]["text"]["readOnly"] = True
    result, out = draft(tmp_path, document, NESTED)
    assert result.exit_code == 3, result.output
    assert only(artifacts(out)[1], "binding_unresolved")["source"] == [file_source("/prompt")]


def test_a_value_at_the_prompt_path_blocks(tmp_path):
    bindings = {**NESTED, "values": {**NESTED["values"], "/inputs/question/text": {"literal": "fixed"}}}
    result, out = draft(tmp_path, nested_document(), bindings)
    assert result.exit_code == 3, result.output
    gap = only(artifacts(out)[1], "binding_unresolved")
    assert gap["source"] == [file_source("/values/~1inputs~1question~1text")]


def test_a_required_field_inside_a_bound_object_blocks_until_supplied(tmp_path):
    document = nested_document()
    document["components"]["schemas"]["Value"]["required"] = ["number"]
    result, out = draft(tmp_path, document, NESTED)
    assert result.exit_code == 3, result.output
    spec, report, _ = artifacts(out)
    assert spec is None
    gap = only(report, "business_input_missing")
    assert gap["blocking"] is True and gap["source"][0]["pointer"] == "/components/schemas/Value"
    supplied = {**NESTED, "values": {**NESTED["values"], "/inputs/question/number": {"literal": 1}}}
    (tmp_path / "again").mkdir()
    result, out = draft(tmp_path / "again", document, supplied)
    assert artifacts(out)[0] is not None, result.output


def test_a_user_choice_equal_to_the_proposal_drops_the_proposal_row(tmp_path):
    result, out = draft(tmp_path, agent_document(), {"prompt": {"path": "/question"}})
    assert result.exit_code == 3, result.output
    _, report, provenance = artifacts(out)
    assert "prompt_binding_proposed" not in codes(report)
    assert "binding_user_supplied" not in codes(report)
    assert provenance["fields"]["/transport/request/body"]["basis"] == "user_selection"


@pytest.mark.parametrize("text", [
    {"version": 2},
    {"version": 1, "extra": {}},
    {"version": 1, "prompt": "/question"},
    {"version": 1, "prompt": {"path": "question"}},
    {"version": 1, "prompt": {"path": "/"}},
    {"version": 1, "prompt": {"path": "/a~2b"}},
    {"version": 1, "prompt": {"path": "/q", "origin": 3}},
    {"version": 1, "prompt": {"path": "/q", "literal": "x"}},
    {"version": 1, "values": {"/mode": {"literal": "a", "path": "/mode"}}},
    {"version": 1, "prompt": {"path": "/" + "/".join(["a"] * 17)}},
    {"version": 1, "values": {"/mode": {}}},
    {"version": 1, "values": {"/mode": {"literal": "a", "env": "TARGET_INPUT_A"}}},
    {"version": 1, "values": {"/mode": {"literal": None}}},
    {"version": 1, "values": {"/mode": {"literal": {"a": 1}}}},
    {"version": 1, "values": {"/mode": {"env": "OTHER_NAME"}}},
    {"version": 1, "values": {"/mode": {"env": "TARGET_INPUT_API_TOKEN"}}},
    {"version": 1, "values": {"/api_key": {"literal": "abc"}}},
    {"version": 1, "values": {"/inputs/password/text": {"literal": "abc"}}},
], ids=["version", "unknown_key", "bare_string", "relative_pointer", "empty_segment", "bad_escape", "origin_type",
        "prompt_with_a_value", "value_with_a_path", "too_deep", "no_expression", "two_expressions", "null", "object",
        "env_prefix", "env_secret_word", "credential_field", "credential_parent"])
def test_a_malformed_file_is_a_usage_error_with_no_artifacts(tmp_path, text):
    result, out = draft(tmp_path, nested_document(), raw=json.dumps(text).encode())
    assert result.exit_code == 2, result.output
    assert "--bindings" in result.output
    assert not out.exists() and not out.with_suffix(".gaps.json").exists()


@pytest.mark.parametrize("raw", [b'{"version": 1, "version": 1}', b"{version: 1}", b"\xff", b"[]"],
                         ids=["duplicate_key", "not_json", "not_utf8", "not_an_object"])
def test_an_unreadable_file_is_a_usage_error(tmp_path, raw):
    result, out = draft(tmp_path, nested_document(), raw=raw)
    assert result.exit_code == 2, result.output
    assert not out.with_suffix(".gaps.json").exists()


def test_a_model_selection_yields_to_the_file(tmp_path):
    document = agent_document()
    document["paths"]["/ask"]["post"]["requestBody"]["content"]["application/json"]["schema"]["properties"]["topic"] = {"type": "string"}
    catalog = catalog_for(tmp_path, document)
    (tmp_path / "bindings.json").write_text(json.dumps({"version": 1, "prompt": {"path": "/topic"}}))
    inputs = read_bindings(tmp_path / "bindings.json")
    ask = "/paths/~1ask/post"
    selection = OperationSelection("ask", Binding(("question",), ask + "/requestBody/content/application~1json/schema/properties/question"),
                                   Binding(("answer",), ask + "/responses/200/content/application~1json/schema/properties/answer"),
                                   ReplyPresence())
    baseline = choices_from_selection(catalog, selection, inputs=inputs)
    assert baseline.prompt.path == ("topic",) and baseline.prompt.basis == "user_selection"
    body = compile_draft(catalog, baseline).spec["transport"]["request"]["body"]["json"]
    assert body["topic"] == {"context": "prompt"} and body["question"] == {"var": "input_question"}


async def test_an_accepted_model_proposal_yields_to_the_file(tmp_path, stub_model):  # noqa: F811
    from argus.drafting.proposal import propose_choices
    document = proposed_document()
    document["paths"]["/ask"]["post"]["requestBody"]["content"]["application/json"]["schema"]["properties"]["topic"] = {"type": "string"}
    catalog = catalog_for(tmp_path, document)
    (tmp_path / "bindings.json").write_text(json.dumps({"version": 1, "prompt": {"path": "/topic"}}))
    result = await propose_choices(catalog, inputs=read_bindings(tmp_path / "bindings.json"))
    assert result.disclosure.status == "accepted"
    assert result.choices.prompt.path == ("topic",)


def test_an_unavailable_model_keeps_the_file(tmp_path, monkeypatch):
    from argus import llm
    def unavailable(): raise ValueError("no text config")
    monkeypatch.setattr(llm, "text_config", unavailable)
    source = input_file(tmp_path, nested_document())
    (tmp_path / "bindings.json").write_text(json.dumps({"version": 1, **NESTED}))
    out = tmp_path / "target.json"
    result = CliRunner().invoke(main, ["draft-target", "--openapi", str(source), "--out", str(out),
                                       "--bindings", str(tmp_path / "bindings.json")])
    assert result.exit_code == 3, result.output
    assert "model.status: unavailable" in result.output
    assert artifacts(out)[0]["transport"]["response"]["text"]["paths"] == ["$.result.text"]


def test_a_value_for_a_read_only_field_blocks(tmp_path):
    document = nested_document()
    schema = document["paths"]["/runs"]["post"]["requestBody"]["content"]["application/json"]["schema"]
    schema["properties"]["label"]["readOnly"] = True
    bindings = {**NESTED, "values": {**NESTED["values"], "/label": {"literal": "plain"}}}
    result, out = draft(tmp_path, document, bindings)
    assert result.exit_code == 3, result.output
    assert only(artifacts(out)[1], "binding_unresolved")["source"] == [file_source("/values/~1label")]


def test_a_map_key_no_transport_path_can_name_blocks(tmp_path):
    result, out = draft(tmp_path, nested_document(), {**NESTED, "prompt": {"path": "/inputs/it's/text"}})
    assert result.exit_code == 3, result.output
    assert only(artifacts(out)[1], "binding_unresolved")["source"] == [file_source("/prompt")]
