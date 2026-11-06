import copy
import json

import pytest
from click.testing import CliRunner

from argus.cli.__main__ import main
from argus.drafting.draft import choose_without_model, compile_draft
from argus_transport import TransportSpecV2
from argus_transport.engine import outcome_match
from argus_transport.models import SafeReasonCode, TransportOutcome
from test_draft_async import async_document, blocking, catalog_for, gaps, poll_schema, run
from test_draft_async_accepted import (accepted_document, body, finished, poll_responses, running,
                                       scenario, submit_responses)
from test_draft_target import agent_document, invoke
from test_draft_verify_local import verify


def accepted(state, output=None):
    return {"status": 202, "body": body(state, output), "effects": [], "headers": {"Retry-After": "0"}}


def transport(out):
    return json.loads(out.read_text())["transport"]


def codes(out):
    return {gap["code"] for gap in gaps(out)["gaps"]}


async def execute(tmp_path, document, submit, polls, **expect):
    catalog = catalog_for(tmp_path, document)
    spec = compile_draft(catalog, choose_without_model(catalog)).spec
    return (await verify(spec, scenario(submit, polls, **expect), catalog=catalog)).as_dict()["execution"]


async def test_a_202_submit_reporting_completed_is_polled_not_finished(tmp_path):
    execution = await execute(tmp_path, accepted_document(), accepted("completed", "early"), [finished("completed", "pong")])
    assert execution["outcome"] == "succeeded", execution
    assert execution["reply"] == "pong"
    assert execution["requests"]["poll"] == 1


async def test_a_202_submit_reporting_failed_ends_as_target_error_without_polling(tmp_path):
    execution = await execute(tmp_path, accepted_document(), accepted("failed"), [], outcome="target_error", reply=None)
    assert execution["outcome"] == "target_error", execution
    assert execution["requests"]["poll"] == 0


async def test_a_202_poll_reporting_completed_is_a_target_error_not_a_success(tmp_path):
    execution = await execute(tmp_path, accepted_document(), running(), [accepted("completed", "pong")],
                              outcome="target_error", reply=None)
    assert execution["outcome"] == "target_error", execution
    assert execution["requests"]["poll"] == 1


def test_success_rules_never_match_202_and_failure_rules_do(tmp_path):
    result, out = run(tmp_path, accepted_document())
    assert result.exit_code == 3, result.output
    spec = transport(out)
    for outcome in (spec["outcome"], spec["delivery"]["submit_outcome"]):
        rules = {rule["outcome"]: rule for rule in outcome["rules"]}
        assert rules["succeeded"]["http_status"] == [200]
        assert rules["target_error"]["http_status"] == [200, 202]


def test_a_submit_documenting_only_202_with_the_poll_body_never_succeeds_at_submit(tmp_path):
    document = accepted_document()
    del submit_responses(document)["200"]
    result, out = run(tmp_path, document)
    assert result.exit_code == 3, result.output
    delivery = transport(out)["delivery"]
    assert delivery["submit_http_status"] == [202]
    assert delivery["submit_outcome"]["rules"] == [
        {"id": "failed", "priority": 5, "http_status": [202],
         "when": {"path": "$.status", "one_of": ["failed"]}, "outcome": "target_error"}]


def test_a_poll_documenting_only_202_cannot_report_a_finished_job(tmp_path):
    document = accepted_document()
    del poll_responses(document)["200"]
    result, out = run(tmp_path, document)
    assert result.exit_code == 3, result.output
    assert not out.exists()
    assert "async_poll_missing" in blocking(out)


def test_success_requires_every_documented_required_field(tmp_path):
    document = async_document()
    schema = poll_schema(document)
    schema["properties"] = {"id": {"type": "string"}, "status": schema["properties"]["status"],
                            "output": {"type": "string"}, "generatedAt": {"type": "integer"}}
    schema["required"] = ["id", "output", "generatedAt", "undocumented", "id"]
    result, out = run(tmp_path, document)
    assert result.exit_code == 3, result.output
    succeeded = next(rule for rule in transport(out)["outcome"]["rules"] if rule["outcome"] == "succeeded")
    assert succeeded["when"] == {"all": [{"path": "$.status", "equals": "COMPLETED"}, {"path": "$.id", "exists": True},
                                         {"path": "$.output", "exists": True}, {"path": "$.generatedAt", "exists": True}]}
    assert "success_conditions_minimal" not in codes(out)
    provenance = json.loads(out.with_suffix(".provenance.json").read_text())["fields"]["/transport/outcome/rules/0"]
    assert any(source["pointer"].endswith("/schema/required") for source in provenance["source"])
    validation = CliRunner().invoke(main, ["validate-target", "--target", str(out), "--offline"])
    assert validation.exit_code == 0, validation.output


def test_a_required_list_naming_only_the_status_adds_nothing(tmp_path):
    result, out = run(tmp_path, async_document())
    assert result.exit_code == 3, result.output
    succeeded = next(rule for rule in transport(out)["outcome"]["rules"] if rule["outcome"] == "succeeded")
    assert succeeded["when"] == {"path": "$.status", "equals": "COMPLETED"}
    assert "success_conditions_minimal" not in codes(out)


@pytest.mark.parametrize("required", [None, [], "status", ["status", 1]], ids=["absent", "empty", "not_a_list", "not_names"])
def test_no_usable_required_list_keeps_the_minimal_rule_with_a_review_gap(tmp_path, required):
    document = async_document()
    schema = poll_schema(document)
    schema.pop("required")
    if required is not None:
        schema["required"] = required
    result, out = run(tmp_path, document)
    assert result.exit_code == 3, result.output
    succeeded = next(rule for rule in transport(out)["outcome"]["rules"] if rule["outcome"] == "succeeded")
    assert succeeded["when"] == {"path": "$.status", "equals": "COMPLETED"}
    gap = next(gap for gap in gaps(out)["gaps"] if gap["code"] == "success_conditions_minimal")
    assert gap["blocking"] is False and gap["field"] == "/transport/outcome"
    assert "successful response must carry" in gap["decision"]
    assert gap["source"][0]["pointer"] == "/paths/~1jobs~1{id}/get/responses/200/content/application~1json/schema"


def test_the_submit_success_rule_reads_the_submit_body_required_list(tmp_path):
    document = accepted_document()
    run_schema = document["components"]["schemas"]["Run"]
    submitted = copy.deepcopy(run_schema)
    submitted["required"] = ["threadId", "runId", "status", "output"]
    document["components"]["schemas"]["SubmittedRun"] = submitted
    run_schema.pop("required")
    for status in ("200", "202"):
        submit_responses(document)[status]["content"]["application/json"]["schema"] = {"$ref": "#/components/schemas/SubmittedRun"}
    result, out = run(tmp_path, document)
    assert result.exit_code == 3, result.output
    spec = transport(out)
    submit = next(rule for rule in spec["delivery"]["submit_outcome"]["rules"] if rule["outcome"] == "succeeded")
    poll = next(rule for rule in spec["outcome"]["rules"] if rule["outcome"] == "succeeded")
    assert submit["when"] == {"all": [{"path": "$.status", "equals": "completed"}, {"path": "$.threadId", "exists": True},
                                      {"path": "$.runId", "exists": True}, {"path": "$.output", "exists": True}]}
    assert poll["when"] == {"path": "$.status", "equals": "completed"}
    assert [gap["field"] for gap in gaps(out)["gaps"] if gap["code"] == "success_conditions_minimal"] == ["/transport/outcome"]


def generated_document(name):
    document = accepted_document()
    run_schema = document["components"]["schemas"]["Run"]
    run_schema["properties"][name] = {"type": ["integer", "null"]}
    run_schema["required"].append(name)
    return document


@pytest.mark.parametrize("name, path", [("generatedAt", "$.generatedAt"), ("generated-at", "$['generated-at']")])
async def test_a_completed_body_missing_a_required_field_is_a_target_error(tmp_path, name, path):
    document = generated_document(name)
    catalog = catalog_for(tmp_path, document)
    spec = compile_draft(catalog, choose_without_model(catalog)).spec
    rule = next(rule for rule in spec["transport"]["outcome"]["rules"] if rule["outcome"] == "succeeded")
    assert {"path": path, "exists": True} in rule["when"]["all"]
    documented = {**body("completed", "pong"), name: None}
    run_state = running() | {"body": {**body("running"), name: None}}
    complete = (await verify(spec, scenario(run_state, [finished("completed") | {"body": documented}]), catalog=catalog)).as_dict()
    assert complete["execution"]["outcome"] == "succeeded", complete
    # The local fake refuses to send a body that breaks its document, so the missing field is checked on the rule itself.
    outcome = TransportSpecV2.from_dict(spec["transport"]).outcome
    assert outcome_match(outcome, 200, documented)[0] == TransportOutcome.SUCCEEDED
    assert outcome_match(outcome, 200, body("completed", "pong"))[:3] == (TransportOutcome.TARGET_ERROR, None, SafeReasonCode.UNKNOWN_STATUS)


def test_sync_success_requires_documented_required_fields(tmp_path):
    document = agent_document()
    schema = document["paths"]["/ask"]["post"]["responses"]["200"]["content"]["application/json"]["schema"]
    schema["properties"]["request_id"] = {"type": "string"}
    schema["required"] = ["answer", "request_id"]
    result, out = invoke(tmp_path, document)
    assert result.exit_code == 3, result.output
    rule = transport(out)["outcome"]["rules"][0]
    assert rule["when"] == {"all": [{"path": "$.status", "equals": "completed"}, {"path": "$.answer", "exists": True},
                                    {"path": "$.request_id", "exists": True}]}
    assert "success_conditions_minimal" not in codes(out)


def test_sync_reply_presence_does_not_repeat_the_reply(tmp_path):
    document = agent_document()
    schema = document["paths"]["/ask"]["post"]["responses"]["200"]["content"]["application/json"]["schema"]
    schema["properties"].pop("status")
    schema["required"] = ["answer"]
    result, out = invoke(tmp_path, document)
    assert result.exit_code == 3, result.output
    assert transport(out)["outcome"]["rules"][0]["when"] == {"path": "$.answer", "exists": True}


def test_sync_without_a_required_list_gets_the_review_gap(tmp_path):
    result, out = invoke(tmp_path, agent_document())
    assert result.exit_code == 3, result.output
    assert transport(out)["outcome"]["rules"][0]["when"] == {"path": "$.status", "equals": "completed"}
    gap = next(gap for gap in gaps(out)["gaps"] if gap["code"] == "success_conditions_minimal")
    assert gap["blocking"] is False


PRESENCE_STATE = {"type": "object", "properties": {"completed": {"type": "object"}, "running": {"type": "object"}}}


def unrelated_enum_document(stage, state):
    document = async_document()
    schema = poll_schema(document)
    schema["properties"] = {"stage": {"type": "string", "enum": stage}, "state": state, "result": {"type": "string"}}
    schema["required"] = ["stage"]
    return document


def test_an_unrelated_enum_without_a_success_word_never_hides_a_presence_state(tmp_path):
    result, out = run(tmp_path, unrelated_enum_document(["STAGE_DRAFT", "STAGE_PUBLISHED"], PRESENCE_STATE))
    assert result.exit_code == 3, result.output
    assert not out.exists()
    assert blocking(out) & {"async_shape_unsupported", "completion_missing"}


@pytest.mark.parametrize("state", [PRESENCE_STATE, {"type": "string"}], ids=["presence_object", "plain_string"])
def test_an_unrelated_enum_with_success_words_is_not_read_as_the_run_state(tmp_path, state):
    result, out = run(tmp_path, unrelated_enum_document(["pending", "done"], state))
    assert result.exit_code == 3, result.output
    assert not out.exists()
    assert "async_shape_unsupported" in blocking(out)

