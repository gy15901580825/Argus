import json

import pytest

from argus.drafting.draft import choose_without_model, compile_draft
from argus.drafting.openapi import catalog_operations, load_openapi
from test_draft_nullable_union import NULLABLE_FORMS, drafted, sync_document, type_list
from test_draft_target import input_file
from test_draft_verify_local import verify

FORMS = {"type_list": type_list, **NULLABLE_FORMS}
STRING = {"type": "string"}


def local(out):
    return json.loads(out.with_suffix(".provenance.json").read_text())["validation"]["local"]


@pytest.mark.parametrize("fields", [lambda nullable: {"answer": nullable},
                                    lambda nullable: {"answer": STRING, "error": nullable}], ids=["reply", "sibling"])
@pytest.mark.parametrize("form", FORMS)
def test_schema_mock_fills_nullable_fields_with_their_non_null_type(tmp_path, form, fields):
    result, out = drafted(tmp_path, sync_document(**fields(FORMS[form](STRING))), "--verify-local")
    check = local(out)
    assert check["status"] == "schema_mock_only", check
    assert check["checks"] == [] and check["semantic_success"] is False
    assert check["execution"]["outcome"] == "succeeded"
    assert check["execution"]["reply"] == "schema sample"
    assert "local.status: schema_mock_only" in result.output


def test_schema_mock_samples_the_first_non_null_enum_value_of_a_nullable_reply(tmp_path):
    _, out = drafted(tmp_path, sync_document(answer={"type": ["string", "null"], "enum": [None, "ok"]}), "--verify-local")
    check = local(out)
    assert check["status"] == "schema_mock_only", check
    assert check["execution"]["reply"] == "ok"


@pytest.mark.parametrize("answer", [{"type": "null"}, {"type": ["string", "null"], "enum": [None]},
                                    {"anyOf": [{"type": "string"}, {"type": "null"}], "enum": [None]}])
async def test_schema_mock_never_accepts_a_null_reply(tmp_path, answer):
    drafted_from = catalog_operations(load_openapi(input_file(tmp_path, sync_document(answer=STRING))))
    spec = compile_draft(drafted_from, choose_without_model(drafted_from)).spec
    assert spec["transport"]["response"]["text"]["paths"] == ["$.answer"]
    catalog = catalog_operations(load_openapi(input_file(tmp_path, sync_document(answer=answer))))
    result = await verify(spec, catalog=catalog)
    assert result.status == "failed", result.as_dict()
    assert result.checks == ("mapping_error",)
    assert result.execution["outcome"] == "target_error" and result.execution["reply"] is None


def test_schema_mock_still_reads_an_untyped_schema_with_properties_as_an_object(tmp_path):
    _, out = drafted(tmp_path, sync_document(meta={"properties": {"note": FORMS["anyOf"](STRING)}}), "--verify-local")
    check = local(out)
    assert check["status"] == "schema_mock_only", check
    assert check["execution"]["reply"] == "schema sample"
