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
        run = V2Run(spec, policy=ExecutionPolicy.local(spec), environ={})
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


def proposed_document():
    doc = sync_document()
    op = doc["paths"]["/ask"]["post"]
    request = op["requestBody"]["content"]["application/json"]["schema"]
    request["properties"]["utterance"] = request["properties"].pop("question")
    request["required"] = ["utterance"]
    response = op["responses"]["200"]["content"]["application/json"]["schema"]["properties"]
    response["text"] = response.pop("answer")
    return doc


def proposal_document_choices():
    return {"operation": "ask", "prompt": "/paths/~1ask/post/requestBody/content/application~1json/schema/properties/utterance",
            "reply": "/paths/~1ask/post/responses/200/content/application~1json/schema/properties/text", "completion": None}


def test_model_catalog_references_enable_nonheuristic_business_bindings(tmp_path):
    from argus.drafting.proposal import parse_proposal
    from argus.drafting.draft import choices_from_selection
    catalog = catalog_operations(load_openapi(input_file(tmp_path, proposed_document())))
    selection = parse_proposal(json.dumps(proposal_document_choices()), catalog)
    artifacts = compile_draft(catalog, choices_from_selection(catalog, selection))
    assert artifacts.spec is not None
    assert artifacts.spec["transport"]["request"]["body"]["json"] == {"utterance": {"context": "prompt"}}
    assert artifacts.spec["transport"]["response"]["text"]["paths"] == ["$.text"]
    assert all(any(g.code == code and g.kind == "proposal" and not g.blocking for g in artifacts.gaps)
               for code in ["invoke_proposed", "prompt_binding_proposed", "reply_binding_proposed", "completion_proposed"])
    assert all(g.code not in {"prompt_binding_missing", "reply_binding_missing", "completion_missing"} for g in artifacts.gaps)


@pytest.mark.parametrize("alter, code", [
    (lambda c: c.update(url="http://outside.invalid/submit"), "model_output_invalid"),
    (lambda c: c.update(auth={"Authorization": "injected-literal"}), "model_output_invalid"),
    (lambda c: c.update(operation="unknown"), "model_operation_unknown"),
    (lambda c: c.update(prompt="/components/securitySchemes/auth"), "model_field_unknown"),
    (lambda c: c.update(reply="/paths/~1ask/post/responses/500/content/application~1json/schema/properties/text"), "model_field_unknown"),
    (lambda c: c.update(prompt=7), "model_output_invalid"),
    (lambda c: c.pop("completion"), "model_output_invalid"),
])
def test_model_contract_rejects_unknown_authority_and_references(tmp_path, alter, code):
    from argus.drafting.proposal import parse_proposal, ProposalError
    catalog = catalog_operations(load_openapi(input_file(tmp_path, proposed_document())))
    choice = proposal_document_choices(); alter(choice)
    with pytest.raises(ProposalError) as error:
        parse_proposal(json.dumps(choice), catalog)
    assert error.value.code == code
    assert "injected-literal" not in str(error.value)
    assert "outside.invalid" not in str(error.value)


@pytest.mark.parametrize("text", ["{bad json", "[]", "null", '{"operation":"ask","operation":"ask"}', '```json\n{}\n```', " " * 16385])
def test_model_contract_rejects_malformed_duplicate_and_oversized_json(tmp_path, text):
    from argus.drafting.proposal import parse_proposal, ProposalError
    catalog = catalog_operations(load_openapi(input_file(tmp_path, proposed_document())))
    with pytest.raises(ProposalError) as error:
        parse_proposal(text, catalog)
    assert error.value.code == "model_output_invalid"


@pytest.mark.parametrize("mutation", [
    lambda d: d["paths"]["/ask"]["post"]["requestBody"]["content"]["application/json"]["schema"]["properties"]["utterance"].update(enum=["fixed"]),
    lambda d: d["paths"]["/ask"]["post"]["requestBody"]["content"]["application/json"]["schema"]["properties"]["utterance"].update(readOnly=True),
    lambda d: d["paths"]["/ask"]["post"]["responses"]["200"]["content"]["application/json"]["schema"]["properties"]["text"].update(type="integer"),
    lambda d: d["paths"]["/ask"]["post"]["responses"]["200"]["content"]["application/json"]["schema"]["properties"]["text"].update(writeOnly=True),
])
def test_model_reference_index_enforces_binding_schema(tmp_path, mutation):
    from argus.drafting.proposal import parse_proposal, ProposalError
    doc = proposed_document(); mutation(doc)
    catalog = catalog_operations(load_openapi(input_file(tmp_path, doc)))
    with pytest.raises(ProposalError) as error:
        parse_proposal(json.dumps(proposal_document_choices()), catalog)
    assert error.value.code == "model_field_unknown"


def test_model_selection_preserves_unsupported_origin_and_business_gaps(tmp_path):
    from argus.drafting.proposal import parse_proposal
    from argus.drafting.draft import choices_from_selection
    doc = proposed_document()
    doc["servers"][0]["variables"] = {}
    op = doc["paths"]["/ask"]["post"]
    op["requestBody"]["content"]["application/json"]["schema"]["required"].append("organization")
    op["requestBody"]["content"]["application/json"]["schema"]["properties"]["organization"] = {"type": "string"}
    catalog = catalog_operations(load_openapi(input_file(tmp_path, doc)))
    selection = parse_proposal(json.dumps(proposal_document_choices()), catalog)
    artifacts = compile_draft(catalog, choices_from_selection(catalog, selection))
    assert artifacts.spec is None
    assert any(g.code == "server_invalid" and g.blocking for g in artifacts.gaps)


def test_model_terminal_state_is_document_singleton_not_output_literal(tmp_path):
    from argus.drafting.proposal import parse_proposal, ProposalError
    from argus.drafting.draft import choices_from_selection
    doc = proposed_document()
    fields = doc["paths"]["/ask"]["post"]["responses"]["200"]["content"]["application/json"]["schema"]["properties"]
    fields["phase"] = {"type": "string", "enum": ["DONE"]}
    catalog = catalog_operations(load_openapi(input_file(tmp_path, doc)))
    choice = proposal_document_choices(); choice["completion"] = choice["reply"].rsplit("/", 1)[0]+"/phase"
    selection = parse_proposal(json.dumps(choice), catalog)
    artifacts = compile_draft(catalog, choices_from_selection(catalog, selection))
    assert artifacts.spec["transport"]["outcome"]["rules"][0]["when"] == {"path": "$.phase", "equals": "DONE"}
    fields["phase"]["enum"].append("FAILED")
    catalog = catalog_operations(load_openapi(input_file(tmp_path, doc)))
    with pytest.raises(ProposalError) as error: parse_proposal(json.dumps(choice), catalog)
    assert error.value.code == "model_field_unknown"
