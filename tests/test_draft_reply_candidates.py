import importlib
import json

import pytest
from click.testing import CliRunner

from argus.cli.__main__ import main
from argus.drafting.draft import ReplyPresence, choices_from_selection, choose_without_model, compile_draft
from argus.drafting.openapi import catalog_operations, load_openapi
from argus.drafting.proposal import ProposalError, _reference_index, parse_proposal, propose_choices
from test_draft_bound_schemas import required_body_field, response_schema, scenario_file, verify_cli
from test_draft_target import agent_document, input_file
from test_draft_target_model import proposal_document_choices, proposed_document, stub_model  # noqa: F401


SUBMIT = "/paths/~1runs/post"
SUBMIT_PROMPT = SUBMIT + "/requestBody/content/application~1json/schema/properties/question"
SUBMIT_REPLY = SUBMIT + "/responses/200/content/application~1json/schema/properties"


def async_submit_document():
    return {
        "openapi": "3.0.3",
        "info": {"title": "Neutral async agent", "version": "1"},
        "servers": [{"url": "http://127.0.0.1:8123"}],
        "paths": {"/runs": {"post": {
            "operationId": "submit",
            "requestBody": {"required": True, "content": {"application/json": {"schema": {
                "type": "object", "required": ["question"], "properties": {"question": {"type": "string"}}}}}},
            "responses": {"200": {"description": "Run accepted", "content": {"application/json": {"schema": {
                "type": "object", "properties": {
                    "run_id": {"type": "string"},
                    "status": {"type": "string", "enum": ["queued", "running", "completed"]}}}}}}},
        }}},
    }


def catalog_for(tmp_path, document):
    return catalog_operations(load_openapi(input_file(tmp_path, document)))


def null_reply(**overrides):
    return json.dumps({"operation": "submit", "prompt": SUBMIT_PROMPT, "reply": None, "completion": None, **overrides})


def test_async_submit_offers_no_reply_or_completion_candidate(tmp_path):
    roles = _reference_index(catalog_for(tmp_path, async_submit_document()))["submit"]
    assert list(roles["prompt"]) == [SUBMIT_PROMPT]
    assert roles["reply"] == {}
    assert roles["completion"] == {}


@pytest.mark.parametrize("reply", ["run_id", "status"])
def test_model_cannot_bind_a_run_id_or_state_as_the_reply(tmp_path, reply):
    catalog = catalog_for(tmp_path, async_submit_document())
    with pytest.raises(ProposalError) as error:
        parse_proposal(null_reply(reply=SUBMIT_REPLY + "/" + reply), catalog)
    assert error.value.code == "model_field_unknown"


@pytest.mark.parametrize("name, schema", [
    ("id", {"type": "string"}), ("ID", {"type": "string"}), ("run_id", {"type": "string"}),
    ("RUN_ID", {"type": "string"}), ("runId", {"type": "string"}), ("requestID", {"type": "string"}),
    ("uuid", {"type": "string"}), ("run_uuid", {"type": "string"}),
    ("text", {"type": "string", "format": "uuid"}),
])
def test_identifier_fields_are_never_reply_or_completion_candidates(tmp_path, name, schema):
    document = proposed_document()
    fields = response_schema(document)["properties"]
    fields.pop("text")
    fields[name] = dict(schema)
    fields["done_" + name] = {**schema, "enum": ["DONE"]}
    roles = _reference_index(catalog_for(tmp_path, document))["ask"]
    assert roles["reply"] == {}
    assert roles["completion"] == {}


@pytest.mark.parametrize("name", ["text", "paid", "valid", "VALID", "android", "idea"])
def test_names_that_only_contain_id_stay_reply_candidates(tmp_path, name):
    document = proposed_document()
    fields = response_schema(document)["properties"]
    fields[name] = fields.pop("text")
    roles = _reference_index(catalog_for(tmp_path, document))["ask"]
    assert [binding.name for binding in roles["reply"].values()] == [name]


def test_no_model_never_selects_an_identifier_reply(tmp_path):
    document = agent_document()
    response_schema(document)["properties"]["answer"]["format"] = "uuid"
    catalog = catalog_for(tmp_path, document)
    artifacts = compile_draft(catalog, choose_without_model(catalog))
    assert artifacts.spec is None
    assert any(gap.code == "reply_binding_missing" and gap.blocking for gap in artifacts.gaps)


def test_no_model_never_selects_an_identifier_terminal_state(tmp_path):
    document = agent_document()
    response_schema(document)["properties"]["status"]["format"] = "uuid"
    catalog = catalog_for(tmp_path, document)
    choices = choose_without_model(catalog)
    assert choices.reply.name == "answer"
    assert choices.completion == ReplyPresence()


def test_null_reply_keeps_the_prompt_and_blocks_on_the_missing_reply(tmp_path):
    catalog = catalog_for(tmp_path, async_submit_document())
    selection = parse_proposal(null_reply(), catalog)
    assert selection.prompt.pointer == SUBMIT_PROMPT
    assert selection.reply is None and selection.completion is None
    artifacts = compile_draft(catalog, choices_from_selection(catalog, selection))
    assert artifacts.spec is None
    assert artifacts.state.value == "needs_input"
    blocking = {gap.code for gap in artifacts.gaps if gap.blocking}
    assert blocking == {"reply_binding_missing", "completion_missing"}
    assert artifacts.provenance["fields"]["/transport/request/body"]["source"][0]["pointer"] == SUBMIT_PROMPT


def test_null_reply_is_accepted_even_when_reply_fields_are_offered(tmp_path):
    catalog = catalog_for(tmp_path, proposed_document())
    selection = parse_proposal(json.dumps({**proposal_document_choices(), "reply": None}), catalog)
    artifacts = compile_draft(catalog, choices_from_selection(catalog, selection))
    assert artifacts.spec is None
    assert any(gap.code == "reply_binding_missing" and gap.blocking for gap in artifacts.gaps)


def test_null_reply_keeps_an_offered_terminal_state(tmp_path):
    document = proposed_document()
    response_schema(document)["properties"]["phase"] = {"type": "string", "enum": ["DONE"]}
    catalog = catalog_for(tmp_path, document)
    choice = {**proposal_document_choices(), "reply": None}
    choice["completion"] = proposal_document_choices()["reply"].rsplit("/", 1)[0] + "/phase"
    selection = parse_proposal(json.dumps(choice), catalog)
    assert selection.reply is None and selection.completion.name == "phase"


@pytest.mark.parametrize("reply, code", [
    (SUBMIT_REPLY + "/run_id", "model_field_unknown"),
    ("/paths/~1elsewhere", "model_field_unknown"),
    ("", "model_output_invalid"),
    (7, "model_output_invalid"),
])
def test_non_null_reply_outside_the_offered_set_is_still_rejected(tmp_path, reply, code):
    with pytest.raises(ProposalError) as error:
        parse_proposal(null_reply(reply=reply), catalog_for(tmp_path, async_submit_document()))
    assert error.value.code == code


def test_null_prompt_is_still_rejected(tmp_path):
    with pytest.raises(ProposalError) as error:
        parse_proposal(null_reply(prompt=None), catalog_for(tmp_path, async_submit_document()))
    assert error.value.code == "model_output_invalid"


async def test_model_null_reply_is_accepted_without_falling_back(tmp_path, stub_model):
    calls, output, _ = stub_model
    output["text"] = null_reply()
    catalog = catalog_for(tmp_path, async_submit_document())
    result = await propose_choices(catalog)
    assert len(calls) == 1
    assert result.disclosure.status == "accepted"
    assert result.choices.prompt.pointer == SUBMIT_PROMPT
    artifacts = compile_draft(catalog, result.choices)
    assert artifacts.spec is None
    codes = {gap.code for gap in artifacts.gaps}
    assert "reply_binding_missing" in codes and "model_output_invalid" not in codes


async def test_model_run_id_reply_falls_back_to_a_blocked_draft(tmp_path, stub_model):
    _, output, _ = stub_model
    output["text"] = null_reply(reply=SUBMIT_REPLY + "/run_id", completion=None)
    catalog = catalog_for(tmp_path, async_submit_document())
    result = await propose_choices(catalog)
    assert result.disclosure.status == "rejected"
    artifacts = compile_draft(catalog, result.choices)
    assert artifacts.spec is None
    codes = {gap.code for gap in artifacts.gaps}
    assert {"model_field_unknown", "reply_binding_missing"} <= codes


URL_SCHEMA = {"type": "string", "format": "uri", "pattern": "^https://"}


def test_bound_uri_field_with_pattern_passes_verify_local(tmp_path):
    document = agent_document()
    required_body_field(document, schema=dict(URL_SCHEMA))
    scenario = scenario_file(tmp_path, 2, {"TARGET_INPUT_URL": "https://material.invalid/doc"})
    result, local = verify_cli(tmp_path, document, scenario)
    assert local["status"] == "verified", local
    assert result.exit_code == 3, result.output
    gaps = json.loads((tmp_path / "target.gaps.json").read_text())["gaps"]
    unchecked = next(gap for gap in gaps if gap["code"] == "schema_constraints_unchecked")
    assert "format" in unchecked["why"] and "pattern" in unchecked["why"]


def test_schema_mock_accepts_constrained_reply_and_samples_its_type(tmp_path):
    document = agent_document()
    response_schema(document)["properties"]["answer"].update(URL_SCHEMA)
    out = tmp_path / "target.json"
    result = CliRunner().invoke(main, ["draft-target", "--openapi", str(input_file(tmp_path, document)),
                                       "--out", str(out), "--no-model", "--verify-local"])
    local = json.loads(out.with_suffix(".provenance.json").read_text())["validation"]["local"]
    assert local["status"] == "schema_mock_only", local
    assert local["execution"]["outcome"] == "succeeded"
    assert isinstance(local["execution"]["reply"], str)
    assert result.exit_code == 3, result.output


@pytest.mark.parametrize("keyword, value", [
    ("format", "uri"), ("pattern", "^x$"), ("exclusiveMinimum", 1), ("exclusiveMaximum", True),
    ("multipleOf", 2), ("uniqueItems", True), ("minProperties", 1), ("maxProperties", 3),
])
def test_verify_local_accepts_every_constraint_the_drafter_accepts(keyword, value):
    module = importlib.import_module("argus.cli.verify_local")
    draft = importlib.import_module("argus.drafting.draft")
    assert keyword in draft.CONSTRAINT_KEYWORDS
    schema = {"type": "string", keyword: value}
    assert module._schema_supported(schema)
    assert module._schema_supported(schema, value="sample")
    assert module._schema_valid("sample", schema)
    assert not module._schema_valid(7, schema)
