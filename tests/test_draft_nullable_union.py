import json

import pytest

from argus.drafting.openapi import catalog_operations, load_openapi
from argus.drafting.proposal import _reference_index
from test_draft_async import blocking, gaps, run
from test_draft_async_accepted import accepted_document, finished, running, scenario
from test_draft_target import agent_document, input_file


NULL = {"type": "null"}
RESPONSE = "/paths/~1ask/post/responses/200/content/application~1json/schema/properties/"
NULLABLE_FORMS = {
    "anyOf": lambda inner: {"anyOf": [inner, NULL], "title": "Nullable"},
    "oneOf": lambda inner: {"oneOf": [inner, NULL], "title": "Nullable"},
    "null_first": lambda inner: {"anyOf": [NULL, inner], "title": "Nullable"},
}


def type_list(inner):
    return {**inner, "type": [inner["type"], "null"], "title": "Nullable"}


def sync_document(**fields):
    document = agent_document("3.1.0")
    document["paths"]["/ask"]["post"]["responses"]["200"]["content"]["application/json"]["schema"]["properties"].update(fields)
    return document


def drafted(tmp_path, document, *options):
    tmp_path.mkdir(exist_ok=True)
    result, out = run(tmp_path, document, *options)
    assert result.exit_code == 3, result.output
    return result, out


@pytest.mark.parametrize("form", NULLABLE_FORMS)
def test_a_nullable_union_reply_drafts_the_same_sync_spec_as_a_type_list(tmp_path, form):
    _, expected = drafted(tmp_path / "list", sync_document(answer=type_list({"type": "string"})))
    _, out = drafted(tmp_path / "union", sync_document(answer=NULLABLE_FORMS[form]({"type": "string"})))
    assert json.loads(out.read_text()) == json.loads(expected.read_text())
    assert json.loads(out.read_text())["transport"]["response"]["text"]["paths"] == ["$.answer"]
    assert not blocking(out)


def with_union_fields(form, kind="string"):
    document = accepted_document()
    properties = document["components"]["schemas"]["Run"]["properties"]
    for name in ("output", "error"):
        properties[name] = (type_list if form == "type_list" else NULLABLE_FORMS[form])({"type": kind})
    return document


@pytest.mark.parametrize("kind, cast", [("string", "string"), ("object", "string_or_json")])
@pytest.mark.parametrize("form", ["anyOf", "oneOf"])
def test_an_async_run_with_a_nullable_union_reply_drafts_the_type_list_spec(tmp_path, form, kind, cast):
    _, expected = drafted(tmp_path / "list", with_union_fields("type_list", kind))
    _, out = drafted(tmp_path / "union", with_union_fields(form, kind))
    assert json.loads(out.read_text()) == json.loads(expected.read_text())
    assert json.loads(out.read_text())["transport"]["response"]["text"]["cast"] == cast
    report = gaps(out)
    assert report["state"] == "needs_review" and report["spec_written"] is True
    assert not blocking(out)
    assert "reply_binding_proposed" in {gap["code"] for gap in report["gaps"]}


def test_verify_local_runs_a_nullable_union_reply_through_pending_to_completed(tmp_path):
    path = tmp_path / "scenario.json"
    path.write_text(json.dumps(scenario(running(), [running(), finished("completed", "pong")])))
    result, out = drafted(tmp_path, with_union_fields("anyOf"), "--verify-local", "--scenario", str(path))
    assert "local.status: verified" in result.output
    local = json.loads(out.with_suffix(".provenance.json").read_text())["validation"]["local"]
    assert local["status"] == "verified" and local["semantic_success"] is True
    assert local["execution"]["requests"]["poll"] == 2
    assert local["execution"]["reply"] == "pong"


@pytest.mark.parametrize("answer", [
    {"anyOf": [{"type": "string"}, {"type": "integer"}]},
    {"anyOf": [{"type": "string"}, NULL, {"type": "integer"}]},
    {"anyOf": [NULL, NULL]},
    {"anyOf": [True, NULL]},
    {"anyOf": [{"type": ["string", "integer"]}, NULL]},
    {"anyOf": "xy"},
    {"oneOf": {"a": {"type": "string"}, "b": NULL}},
    {"format": "uuid", "anyOf": [{"type": "string", "format": "email"}, NULL]},
    True,
], ids=["two_non_null", "three_branches", "only_null", "boolean_branch", "inner_type_list", "not_a_list",
        "mapping", "outer_and_inner_overlap", "boolean_schema"])
def test_other_reply_schemas_stay_unsupported(tmp_path, answer):
    _, out = drafted(tmp_path, sync_document(answer=answer))
    assert not out.exists()
    assert "reply_binding_missing" in blocking(out)


@pytest.mark.parametrize("form", NULLABLE_FORMS)
@pytest.mark.parametrize("inner_format", ["uuid", "date-time"])
def test_identifier_and_timestamp_exclusions_read_the_inner_schema(tmp_path, form, inner_format):
    _, out = drafted(tmp_path, sync_document(answer=NULLABLE_FORMS[form]({"type": "string", "format": inner_format})))
    assert not out.exists()
    assert "reply_binding_missing" in blocking(out)


@pytest.mark.parametrize("form", NULLABLE_FORMS)
def test_model_index_offers_a_nullable_union_reply_but_no_excluded_field(tmp_path, form):
    nullable = NULLABLE_FORMS[form]
    document = sync_document(
        answer=nullable({"type": "string"}),
        run_id=nullable({"type": "string"}),
        status=nullable({"type": "string"}),
        mode=nullable({"type": "string", "enum": ["fast", "slow"]}),
        reference=nullable({"type": "string", "format": "uuid"}),
        finished=nullable({"type": "string", "format": "date-time"}),
    )
    catalog = catalog_operations(load_openapi(input_file(tmp_path, document)))
    assert set(_reference_index(catalog)["ask"]["reply"]) == {RESPONSE + "answer"}
