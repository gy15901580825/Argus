import json

import pytest
from click.testing import CliRunner

from argus.cli.__main__ import main
from test_draft_async import async_document, gaps, poll_schema, run
from test_draft_async_accepted import accepted_document

STATUS = {"path": "$.status", "equals": "COMPLETED"}


def requiring(*names):
    document = async_document()
    schema = poll_schema(document)
    for name in names:
        schema["properties"][name] = {"type": "string"}
    schema["required"] = ["status", *names]
    return document


def drafted(tmp_path, document):
    result, out = run(tmp_path, document)
    assert result.exit_code == 3, result.output
    succeeded = next(rule for rule in json.loads(out.read_text())["transport"]["outcome"]["rules"]
                     if rule["outcome"] == "succeeded")
    validation = CliRunner().invoke(main, ["validate-target", "--target", str(out), "--offline"])
    assert validation.exit_code == 0, validation.output
    return succeeded["when"], [gap for gap in gaps(out)["gaps"] if gap["code"] == "required_fields_unchecked"]


def checks(*names):
    return [{"path": f"$.{name}", "exists": True} for name in names]


@pytest.mark.parametrize("name", ["it's", "back\\slash", "new\nline", "carriage\rreturn", ""],
                         ids=["quote", "backslash", "newline", "carriage_return", "empty"])
def test_a_required_name_the_path_syntax_cannot_express_becomes_a_review_gap(tmp_path, name):
    when, unchecked = drafted(tmp_path, requiring("done_at", name))
    assert when == {"all": [STATUS, *checks("done_at")]}
    assert len(unchecked) == 1
    gap = unchecked[0]
    assert gap["blocking"] is False and gap["field"] == "/transport/outcome"
    assert json.dumps(name) in gap["why"]
    assert [source["pointer"] for source in gap["source"]] == [
        "/paths/~1jobs~1{id}/get/responses/200/content/application~1json/schema/required/2"]


def test_every_unexpressible_name_is_named_in_one_gap(tmp_path):
    when, unchecked = drafted(tmp_path, requiring("it's", "done_at", "back\\slash"))
    assert when == {"all": [STATUS, *checks("done_at")]}
    assert len(unchecked) == 1
    assert json.dumps("it's") in unchecked[0]["why"] and json.dumps("back\\slash") in unchecked[0]["why"]
    assert [source["pointer"].rsplit("/", 1)[1] for source in unchecked[0]["source"]] == ["1", "3"]


def test_31_required_fields_fit_the_rule_without_a_gap(tmp_path):
    names = [f"f{index}" for index in range(31)]
    when, unchecked = drafted(tmp_path, requiring(*names))
    assert when == {"all": [STATUS, *checks(*names)]}
    assert unchecked == []


def test_required_fields_past_the_rule_limit_are_named_in_a_review_gap(tmp_path):
    names = [f"f{index}" for index in range(33)]
    when, unchecked = drafted(tmp_path, requiring(*names))
    assert when == {"all": [STATUS, *checks(*names[:31])]}
    assert len(unchecked) == 1
    gap = unchecked[0]
    assert gap["blocking"] is False and gap["field"] == "/transport/outcome"
    assert json.dumps("f31") in gap["why"] and json.dumps("f32") in gap["why"]
    assert json.dumps("f30") not in gap["why"]
    assert [source["pointer"].rsplit("/", 1)[1] for source in gap["source"]] == ["32", "33"]


def test_the_limit_counts_checks_after_dropping_duplicates_and_unexpressible_names(tmp_path):
    names = [f"f{index}" for index in range(31)]
    when, unchecked = drafted(tmp_path, requiring("it's", *names, "f0"))
    assert when == {"all": [STATUS, *checks(*names)]}
    assert len(unchecked) == 1
    assert json.dumps("it's") in unchecked[0]["why"]
    assert not any(json.dumps(name) in unchecked[0]["why"] for name in names)


def test_the_submit_copy_of_an_async_rule_gets_its_own_gap(tmp_path):
    document = accepted_document()
    run_schema = document["components"]["schemas"]["Run"]
    run_schema["properties"]["it's"] = {"type": "string"}
    run_schema["required"].append("it's")
    result, out = run(tmp_path, document)
    assert result.exit_code == 3, result.output
    assert sorted(gap["field"] for gap in gaps(out)["gaps"] if gap["code"] == "required_fields_unchecked") == [
        "/transport/delivery/submit_outcome", "/transport/outcome"]
