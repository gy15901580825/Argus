import json

import pytest
from click.testing import CliRunner

from argus.cli.__main__ import main
from argus.drafting.draft import Binding, OperationSelection, ReplyPresence, choices_from_selection, compile_draft
from test_draft_async import POLL_FIELDS, SUBMIT, async_document, catalog_for, gaps, poll_schema, run, scenario
from test_draft_target import agent_document

UNWRITABLE = {"quote": "it's", "backslash": "back\\slash", "newline": "new\nline", "carriage_return": "carriage\rreturn", "empty": ""}
# Each is readable only through a bracket path: a reserved word of the path language, and a name with a space.
BRACKET_ONLY = {"reserved_word": "where", "space": "job state"}
SYNC_FIELDS = "/paths/~1ask/post/responses/200/content/application~1json/schema"


def sync_required(name):
    document = agent_document()
    schema = document["paths"]["/ask"]["post"]["responses"]["200"]["content"]["application/json"]["schema"]
    schema["properties"][name] = {"type": "string"}
    schema["required"] = ["answer", name]
    return document


def async_required(name):
    document = async_document()
    schema = poll_schema(document)
    schema["properties"][name] = {"type": "string"}
    schema["required"] = ["status", name]
    return document


def poll_status(name):
    document = async_document()
    schema = poll_schema(document)
    schema["properties"][name] = schema["properties"].pop("status")
    schema["required"] = [name]
    return document


def poll_id(name):
    document = async_document()
    submitted = document["paths"]["/jobs"]["post"]["responses"]["202"]["content"]["application/json"]["schema"]
    submitted["properties"] = {name: submitted["properties"].pop("job_id")}
    submitted["required"] = [name]
    poll = document["paths"].pop("/jobs/{id}")
    poll["get"]["parameters"][0]["name"] = name
    document["paths"]["/jobs/{" + name + "}"] = poll
    return document


def drafted(tmp_path, document):
    result, out = run(tmp_path, document)
    assert result.exit_code == 3, result.output
    return (json.loads(out.read_text())["transport"] if out.exists() else None), gaps(out)["gaps"]


def validates(out):
    result = CliRunner().invoke(main, ["validate-target", "--target", str(out), "--offline"])
    return result.exit_code == 0


def by_code(report, code):
    return [gap for gap in report if gap["code"] == code]


def rule(transport, outcome):
    return next(item for item in transport["outcome"]["rules"] if item["outcome"] == outcome)["when"]


@pytest.mark.parametrize("build", [sync_required, async_required], ids=["sync", "async"])
@pytest.mark.parametrize("name", UNWRITABLE.values(), ids=UNWRITABLE.keys())
def test_an_unwritable_required_field_is_a_non_blocking_gap(tmp_path, build, name):
    transport, report = drafted(tmp_path, build(name))
    assert transport is not None and validates(tmp_path / "target.json")
    assert all(json.dumps(name) not in json.dumps(check) for check in rule(transport, "succeeded").get("all", []))
    [gap] = by_code(report, "required_fields_unchecked")
    assert gap["blocking"] is False and json.dumps(name) in gap["why"]


@pytest.mark.parametrize("build", [sync_required, async_required], ids=["sync", "async"])
@pytest.mark.parametrize("name", BRACKET_ONLY.values(), ids=BRACKET_ONLY.keys())
def test_a_required_field_named_outside_dot_syntax_is_checked_with_a_bracket_path(tmp_path, build, name):
    transport, report = drafted(tmp_path, build(name))
    assert validates(tmp_path / "target.json")
    assert {"path": f"$['{name}']", "exists": True} in rule(transport, "succeeded")["all"]
    assert not by_code(report, "required_fields_unchecked")


@pytest.mark.parametrize("name", UNWRITABLE.values(), ids=UNWRITABLE.keys())
def test_an_unwritable_poll_status_field_blocks_with_a_gap_naming_it(tmp_path, name):
    transport, report = drafted(tmp_path, poll_status(name))
    assert transport is None
    [gap] = by_code(report, "field_path_unwritable")
    assert gap["blocking"] is True and gap["field"] == "/transport/outcome"
    assert json.dumps(name) in gap["why"]
    assert [source["pointer"] for source in gap["source"]] == [POLL_FIELDS + "/" + name]
    assert not by_code(report, "completion_missing")


@pytest.mark.parametrize("name", BRACKET_ONLY.values(), ids=BRACKET_ONLY.keys())
def test_a_poll_status_field_named_outside_dot_syntax_is_read_with_a_bracket_path(tmp_path, name):
    transport, report = drafted(tmp_path, poll_status(name))
    assert validates(tmp_path / "target.json")
    status = f"$['{name}']"
    assert transport["delivery"]["pending"] == {"path": status, "one_of": ["PENDING", "RUNNING"]}
    assert rule(transport, "succeeded") == {"path": status, "equals": "COMPLETED"}
    assert rule(transport, "target_error") == {"path": status, "one_of": ["FAILED"]}
    assert not by_code(report, "field_path_unwritable")


# An empty name cannot be a poll path parameter, so it is not a poll ID case.
@pytest.mark.parametrize("name", [name for name in UNWRITABLE.values() if name],
                         ids=[key for key, name in UNWRITABLE.items() if name])
def test_an_unwritable_poll_id_field_blocks_with_a_gap_naming_it(tmp_path, name):
    transport, report = drafted(tmp_path, poll_id(name))
    assert transport is None
    [gap] = by_code(report, "field_path_unwritable")
    assert gap["blocking"] is True and gap["field"] == "/transport/delivery/ids"
    assert json.dumps(name) in gap["why"]
    assert [source["pointer"] for source in gap["source"]] == [
        SUBMIT + "/responses/202/content/application~1json/schema/properties/" + name]
    assert not by_code(report, "poll_id_binding_missing")


@pytest.mark.parametrize("name,variable", [("where", "where"), ("job state", "job_state")], ids=BRACKET_ONLY.keys())
def test_a_poll_id_field_named_outside_dot_syntax_is_read_with_a_bracket_path(tmp_path, name, variable):
    transport, report = drafted(tmp_path, poll_id(name))
    assert validates(tmp_path / "target.json")
    assert transport["delivery"]["ids"] == {variable: {"path": f"$['{name}']"}}
    assert transport["delivery"]["request"]["url"] == "http://127.0.0.1:8123/jobs/{" + variable + "}"


def renamed_reply(name):
    document = agent_document()
    schema = document["paths"]["/ask"]["post"]["responses"]["200"]["content"]["application/json"]["schema"]
    schema["properties"] = {name: schema["properties"]["answer"]}
    return document


@pytest.mark.parametrize("name", BRACKET_ONLY.values(), ids=BRACKET_ONLY.keys())
def test_a_selected_reply_named_outside_dot_syntax_is_read_with_a_bracket_path(tmp_path, name):
    catalog = catalog_for(tmp_path, renamed_reply(name))
    reply = Binding(name, SYNC_FIELDS + "/properties/" + name)
    prompt = Binding("question", "/paths/~1ask/post/requestBody/content/application~1json/schema/properties/question")
    choices = choices_from_selection(catalog, OperationSelection("ask", prompt, reply, ReplyPresence()))
    artifacts = compile_draft(catalog, choices)
    assert artifacts.spec is not None
    transport = artifacts.spec["transport"]
    assert transport["response"]["text"]["paths"] == [f"$['{name}']"]
    assert rule(transport, "succeeded") == {"path": f"$['{name}']", "exists": True}


def renamed_scenario(tmp_path, status="status", job_id=None):
    data = json.loads(scenario(tmp_path).read_text())
    submit, poll = data["operations"]
    if job_id:
        submit["replies"][0]["body"] = {job_id: "job-7"}
        poll["path"] = "/jobs/{" + job_id + "}"
        poll["request"][0]["at"]["name"] = job_id
    for reply in poll["replies"]:
        reply["body"][status] = reply["body"].pop("status")
    path = tmp_path / "renamed-scenario.json"
    path.write_text(json.dumps(data))
    return path


@pytest.mark.parametrize("document,names", [
    (lambda: poll_status("where"), {"status": "where"}),
    (lambda: poll_status("job state"), {"status": "job state"}),
    (lambda: poll_id("where"), {"job_id": "where"}),
], ids=["status_reserved_word", "status_space", "id_reserved_word"])
def test_bracket_paths_match_a_real_poll_run(tmp_path, document, names):
    built = document()
    poll_schema(built, next(path for path in built["paths"] if path != "/jobs"))["properties"]["result"] = {"type": "string"}
    result, out = run(tmp_path, built, "--verify-local", "--scenario", str(renamed_scenario(tmp_path, **names)))
    assert result.exit_code == 3, result.output
    local = json.loads(out.with_suffix(".provenance.json").read_text())["validation"]["local"]
    assert local["status"] == "verified" and local["semantic_success"] is True
    assert local["execution"]["requests"]["poll"] == 2 and local["execution"]["reply"] == "pong"
