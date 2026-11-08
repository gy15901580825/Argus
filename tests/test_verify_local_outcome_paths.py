import copy
import json

import pytest
from click.testing import CliRunner

from argus.cli.__main__ import main
from argus.drafting.draft import choose_without_model, compile_draft
from argus.drafting.scenario import parse_scenario
from test_draft_async import SUBMIT, POLL, async_document, catalog_for, run
from test_draft_verify_local import target, verify


NOW = {"Retry-After": "0"}


def document(statuses=("PENDING", "RUNNING", "COMPLETED", "FAILED")):
    """The neutral async document with Retry-After on the poll, so scenario replies can skip the 5-second interval."""
    data = async_document(result={"type": "string"})
    poll = data["paths"]["/jobs/{id}"]["get"]["responses"]["200"]
    poll["headers"] = {"Retry-After": {"schema": {"type": "integer"}}}
    poll["content"]["application/json"]["schema"]["properties"]["status"]["enum"] = list(statuses)
    return data


def reply(status, result=None):
    body = {"status": status} if result is None else {"status": status, "result": result}
    return {"status": 200, "body": body, "effects": [], "headers": dict(NOW)}


def raw_scenario(version=2, polls=None, cases=None):
    polls = polls or [reply("PENDING"), reply("COMPLETED", "pong")]
    data = {
        "version": version,
        "source": {"document": "independent neutral async scenario", "pointers": [SUBMIT, POLL]},
        "resources": [],
        "operations": [
            {"id": "submit_job", "method": "POST", "path": "/jobs", "role": "invoke", "calls": {"min": 1, "max": 1},
             "request": [{"check": "prompt_bound", "at": {"kind": "json", "pointer": "/question"}, "equals": "ping"}],
             "replies": [{"status": 202, "body": {"job_id": "job-7"}, "effects": [], "headers": dict(NOW)}]},
            {"id": "get_job", "method": "GET", "path": "/jobs/{id}", "role": "poll",
             "calls": {"min": len(polls), "max": len(polls)},
             "request": [{"check": "poll_identity", "at": {"kind": "path", "name": "id"}, "equals": "job-7"}],
             "replies": polls},
        ],
        "expect": {"outcome": "succeeded", "reply": "pong", "resources": [], "required_gaps": []},
    }
    if version >= 2:
        data["environment"] = {}
    if version >= 3:
        data["cases"] = cases or []
    return data


def drafted(tmp_path, statuses=("PENDING", "RUNNING", "COMPLETED", "FAILED")):
    catalog = catalog_for(tmp_path, document(statuses))
    return catalog, compile_draft(catalog, choose_without_model(catalog)).spec


def rule(spec, outcome):
    return next(item for item in spec["transport"]["outcome"]["rules"] if item["outcome"] == outcome)


def failed_to_succeeded(spec):
    rule(spec, "target_error")["outcome"] = "succeeded"


def failed_to_blocked(spec):
    rule(spec, "target_error")["outcome"] = "blocked"


def success_reads_result_presence(spec):
    spec["transport"]["outcome"]["rules"].remove(rule(spec, "target_error"))
    rule(spec, "succeeded")["when"] = {"path": "$.result", "exists": True}


def pending_without(value):
    def alter(spec):
        spec["transport"]["delivery"]["pending"]["one_of"].remove(value)
    return alter


def success_also_on_failed(spec):
    success = rule(spec, "succeeded")
    success["when"] = {"path": "$.status", "one_of": ["COMPLETED", "FAILED"]}
    success["priority"] = rule(spec, "target_error")["priority"] + 1


@pytest.mark.parametrize("mutate, check, first", [
    (failed_to_succeeded, "failure_status_succeeded", "PENDING"),
    (success_reads_result_presence, "failure_status_succeeded", "PENDING"),
    (success_also_on_failed, "failure_status_succeeded", "PENDING"),
    (failed_to_blocked, "failure_status_mismatch", "PENDING"),
    (pending_without("PENDING"), "pending_status_unrecognised", "RUNNING"),
    (pending_without("RUNNING"), "pending_status_unrecognised", "PENDING"),
], ids=["failed_rule_to_succeeded", "success_on_result_presence", "success_rule_takes_failed",
        "failed_rule_to_blocked", "pending_without_PENDING", "pending_without_RUNNING"])
async def test_wrong_outcome_mapping_fails_on_a_derived_case(tmp_path, mutate, check, first):
    catalog, spec = drafted(tmp_path)
    raw = raw_scenario(polls=[reply(first), reply("COMPLETED", "pong")])
    baseline = await verify(spec, raw, catalog=catalog)
    assert baseline.status == "verified", baseline.as_dict()
    mutate(spec)
    result = await verify(spec, raw, catalog=catalog)
    assert result.status == "failed", result.as_dict()
    assert not result.semantic_success and not result.cleanup_complete
    assert check in result.checks
    assert result.execution["outcome"] == "succeeded", "the scenario's own sequence still passes"


async def test_correct_draft_passes_every_derived_case(tmp_path):
    catalog, spec = drafted(tmp_path)
    result = await verify(spec, raw_scenario(), catalog=catalog)
    assert result.status == "verified", result.as_dict()
    rows = {row["name"]: row for row in result.as_dict()["cases"]}
    assert set(rows) == {"status:PENDING", "status:RUNNING", "status:FAILED"}
    assert rows["status:FAILED"] == {"name": "status:FAILED", "origin": "document", "status": "FAILED", "class": "failed",
                                     "expected": "target_error", "outcome": "target_error", "passed": True, "checks": [],
                                     "requests": {"submit": 1, "poll": 2}}
    for name in ("status:PENDING", "status:RUNNING"):
        assert rows[name]["class"] == "pending" and rows[name]["passed"]
        assert rows[name]["expected"] == rows[name]["outcome"] == "succeeded"
        assert rows[name]["requests"] == {"submit": 1, "poll": 3}


async def test_failure_wins_when_success_also_matches_without_outranking(tmp_path):
    catalog, spec = drafted(tmp_path)
    rule(spec, "succeeded")["when"] = {"path": "$.status", "one_of": ["COMPLETED", "FAILED"]}
    result = await verify(spec, raw_scenario(), catalog=catalog)
    assert result.status == "verified", result.as_dict()
    assert result.semantic_success and result.cleanup_complete
    rows = {row["name"]: row for row in result.as_dict()["cases"]}
    assert rows["status:FAILED"]["outcome"] == "target_error"
    assert rows["status:FAILED"]["passed"] is True


async def test_failure_case_swaps_only_the_terminal_status(tmp_path):
    from argus.drafting.scenario import document_cases
    catalog, _ = drafted(tmp_path)
    scenario = parse_scenario(raw_scenario(), catalog=catalog)
    cases = {case.name: case for case in document_cases(scenario, catalog)}
    polls = {case.name: next(op for op in case.scenario.operations if op.role == "poll") for case in cases.values()}
    assert [r.body for r in polls["status:FAILED"].replies] == [{"status": "PENDING"}, {"status": "FAILED", "result": "pong"}]
    assert (polls["status:FAILED"].minimum, polls["status:FAILED"].maximum) == (2, 2)
    assert cases["status:FAILED"].scenario.outcome == "target_error" and cases["status:FAILED"].scenario.reply is None
    assert [r.body for r in polls["status:RUNNING"].replies] == [
        {"status": "PENDING"}, {"status": "RUNNING", "result": "pong"}, {"status": "COMPLETED", "result": "pong"}]
    assert (polls["status:RUNNING"].minimum, polls["status:RUNNING"].maximum) == (3, 3)
    assert cases["status:RUNNING"].scenario.outcome == "succeeded" and cases["status:RUNNING"].scenario.reply == "pong"


def test_pending_copy_has_no_effects_and_failure_keeps_them(tmp_path):
    from argus.drafting.scenario import document_cases
    catalog, _ = drafted(tmp_path)
    raw = raw_scenario()
    raw["resources"] = [{"id": "job", "initial": "absent", "cleanup": "pause"}]
    raw["expect"]["resources"] = [{"id": "job", "final": "live"}]
    raw["operations"][1]["replies"][-1]["effects"] = [{"resource": "job", "from": "absent", "to": "live"}]
    cases = {case.name: case for case in document_cases(parse_scenario(raw, catalog=catalog), catalog)}
    pending = next(op for op in cases["status:RUNNING"].scenario.operations if op.role == "poll").replies
    failed = next(op for op in cases["status:FAILED"].scenario.operations if op.role == "poll").replies
    assert [len(item.effects) for item in pending] == [0, 0, 1]
    assert [len(item.effects) for item in failed] == [0, 1]


async def test_unclassified_status_is_listed_not_asserted(tmp_path):
    catalog, spec = drafted(tmp_path, ("PENDING", "COMPLETED", "FAILED", "PAUSED"))
    result = await verify(spec, raw_scenario(), catalog=catalog)
    assert result.status == "verified", result.as_dict()
    rows = {row["name"]: row for row in result.as_dict()["cases"]}
    assert rows["status:PAUSED"]["class"] == "unclassified"
    assert rows["status:PAUSED"]["outcome"] is None and rows["status:PAUSED"]["passed"] is None
    assert "status_meaning" in result.unverified


async def test_unverified_aspects_are_named(tmp_path):
    catalog, spec = drafted(tmp_path)
    open_result = await verify(spec, raw_scenario(), catalog=catalog)
    assert open_result.unverified == ("server_origin",)
    spec["transport"]["auth"] = {"kind": "bearer", "secret": {"source": "env", "name": "UNRESOLVED_TARGET_AUTH"}}
    result = await verify(spec, raw_scenario(), catalog=catalog)
    assert result.unverified == ("auth_headers", "server_origin")
    assert result.as_dict()["unverified"] == ["auth_headers", "server_origin"]
    without_document = await verify(spec, raw_scenario())
    assert without_document.unverified == ("auth_headers", "server_origin", "documented_status_cases")
    assert without_document.cases == ()


async def test_schema_mock_also_names_unverified_aspects():
    spec = target()
    spec["transport"]["auth"] = {"kind": "bearer", "secret": {"source": "env", "name": "UNRESOLVED_TARGET_AUTH"}}
    result = await verify(spec)
    assert result.layer == "schema_mock_only"
    assert result.unverified == ("auth_headers", "server_origin")


def test_cli_prints_failed_case_and_unverified_names(tmp_path, monkeypatch):
    from argus.cli import cmd_draft_target as command
    real = command.compile_draft

    def draft_maps_failed_to_success(catalog, choices):
        artifacts = real(catalog, choices)
        failed_to_succeeded(artifacts.spec)
        return artifacts

    monkeypatch.setattr(command, "compile_draft", draft_maps_failed_to_success)
    path = tmp_path / "scenario.json"
    path.write_text(json.dumps(raw_scenario()))
    result, out = run(tmp_path, document(), "--verify-local", "--scenario", str(path))
    assert result.exit_code == 1, result.output
    assert "local.check: failure_status_succeeded" in result.output
    assert "local.case: status:FAILED failed" in result.output
    assert "local.case: status:PENDING passed" in result.output
    assert "local.unverified: server_origin" in result.output
    local = json.loads(out.with_suffix(".provenance.json").read_text())["validation"]["local"]
    assert local["version"] == 2
    assert local["unverified"] == ["server_origin"]


@pytest.mark.parametrize("version", [1, 2])
def test_older_scenarios_load_unchanged(tmp_path, version):
    catalog, _ = drafted(tmp_path)
    scenario = parse_scenario(raw_scenario(version), catalog=catalog)
    assert scenario.cases == ()
    assert [op.id for op in scenario.operations] == ["submit_job", "get_job"]
    with pytest.raises(ValueError, match="scenario_invalid"):
        parse_scenario({**raw_scenario(version), "cases": []}, catalog=catalog)


def failed_case(name="job_failed", outcome="target_error", reply_text=None, polls=None):
    polls = polls or [reply("FAILED")]
    return {"name": name, "operations": {"get_job": {"calls": {"min": len(polls), "max": len(polls)}, "replies": polls}},
            "expect": {"outcome": outcome, "reply": reply_text}}


async def test_version_3_declared_case_runs(tmp_path):
    catalog, spec = drafted(tmp_path, ("PENDING", "COMPLETED", "ERRORED"))
    raw = raw_scenario(3, cases=[failed_case(polls=[reply("ERRORED", "pong")])])
    result = await verify(spec, raw, catalog=catalog)
    assert result.status == "verified", result.as_dict()
    row = next(row for row in result.as_dict()["cases"] if row["name"] == "job_failed")
    assert row["origin"] == "scenario" and row["passed"] and row["outcome"] == "target_error"
    rule(spec, "succeeded")["when"] = {"path": "$.status", "one_of": ["COMPLETED", "ERRORED"]}
    failed = await verify(spec, raw, catalog=catalog)
    assert failed.status == "failed"
    assert "scenario_case_failed" in failed.checks
    row = next(row for row in failed.as_dict()["cases"] if row["name"] == "job_failed")
    assert row["passed"] is False and "terminal_outcome_mismatch" in row["checks"]


@pytest.mark.parametrize("alter", [
    lambda raw: raw["cases"][0]["operations"].update(unknown_op=raw["cases"][0]["operations"]["get_job"]),
    lambda raw: raw["cases"][0]["operations"].clear(),
    lambda raw: raw["cases"][0]["expect"].update(outcome="succeeded", reply=None),
    lambda raw: raw["cases"][0]["expect"].update(outcome="poll_limit"),
    lambda raw: raw["cases"].append(copy.deepcopy(raw["cases"][0])),
    lambda raw: raw["cases"].extend(failed_case(f"case_{index}") for index in range(8)),
    lambda raw: raw["cases"][0].update(name="Bad Name"),
    lambda raw: raw["cases"][0]["operations"]["get_job"].update(calls={"min": 2, "max": 2}),
    lambda raw: raw["cases"][0]["operations"].update(
        submit_job={"calls": {"min": 0, "max": 1}, "replies": raw["operations"][0]["replies"]}),
    lambda raw: raw["cases"][0]["operations"]["get_job"]["replies"][0].update(effects=[{"resource": "x", "from": "live", "to": "absent"}]),
    lambda raw: raw["cases"][0].pop("expect"),
    lambda raw: raw["cases"][0]["operations"]["get_job"].update(calls={"min": 64, "max": 64}, replies=[reply("FAILED")] * 64),
], ids=["unknown_operation", "no_operation", "success_without_reply", "unknown_outcome", "duplicate_name",
        "too_many_cases", "invalid_name", "replies_short_of_calls", "optional_invoke", "unknown_resource", "missing_expect",
        "request_limit"])
def test_version_3_case_admission_rejects(tmp_path, alter):
    catalog, _ = drafted(tmp_path)
    raw = raw_scenario(3, cases=[failed_case()])
    parse_scenario(copy.deepcopy(raw), catalog=catalog)
    alter(raw)
    with pytest.raises(ValueError, match="scenario_invalid"):
        parse_scenario(raw, catalog=catalog)


def poll_fields(catalog):
    poll = next(op for op in catalog.operations if op.id == "get_job")
    return poll.data["responses"]["200"]["content"]["application/json"]["schema"]["properties"]


def second_status_enum(catalog):
    poll_fields(catalog)["phase"] = {"type": "string", "enum": ["COMPLETED", "OTHER"]}


def too_many_statuses(catalog):
    poll_fields(catalog)["status"]["enum"] += [f"STEP_{index}" for index in range(30)]


def without_status_enum(catalog):
    poll = next(op for op in catalog.operations if op.id == "get_job")
    poll.data["responses"]["200"]["content"]["application/json"]["schema"]["properties"]["status"].pop("enum")


@pytest.mark.parametrize("alter, documented", [
    (lambda raw: raw.update(expect={**raw["expect"], "outcome": "target_error", "reply": None}), None),
    (lambda raw: raw["operations"][1]["calls"].update(min=1), None),
    (lambda raw: raw["operations"][1]["replies"][-1]["body"].update(status="UNDOCUMENTED"), None),
    (lambda raw: None, without_status_enum),
    (lambda raw: raw["operations"].pop(1), None),
    (lambda raw: raw["operations"][1]["replies"][-1]["body"].update(phase="COMPLETED"), second_status_enum),
    (lambda raw: None, too_many_statuses),
], ids=["main_not_success", "terminal_call_range_open", "terminal_status_undocumented", "no_status_enum", "no_poll",
        "two_status_enums", "too_many_statuses"])
async def test_no_derivation_without_one_documented_terminal_status(tmp_path, alter, documented):
    from argus.drafting.scenario import document_cases
    catalog, _ = drafted(tmp_path)
    raw = raw_scenario()
    assert document_cases(parse_scenario(copy.deepcopy(raw), catalog=catalog), catalog) is not None
    alter(raw)
    if documented:
        documented(catalog)
    assert document_cases(parse_scenario(raw, catalog=catalog), catalog) is None


async def test_derived_failure_case_still_requires_cleanup(tmp_path):
    data = document()
    data["paths"]["/sessions"] = {"post": {"operationId": "open_session", "responses": {"200": {
        "description": "Session", "content": {"application/json": {"schema": {
            "type": "object", "properties": {"session_id": {"type": "string"}}}}}}}}}
    data["paths"]["/sessions/{sid}"] = {"delete": {"operationId": "close_session", "parameters": [
        {"name": "sid", "in": "path", "required": True, "schema": {"type": "string"}}],
        "responses": {"204": {"description": "Closed"}}}}
    catalog = catalog_for(tmp_path, data)
    spec = compile_draft(catalog, choose_without_model(catalog, operation="submit_job")).spec
    spec["transport"]["lifecycle"] = {"attempt": [{
        "id": "session", "request": {"method": "POST", "url": "http://127.0.0.1:8123/sessions", "body": {"none": True}},
        "expect": {"http_status": [200]}, "capture": {"opened": {"path": "$.session_id"}},
        "undo": {"request": {"method": "DELETE", "url": "http://127.0.0.1:8123/sessions/{opened}",
                             "body": {"none": True}},
                 "expect": {"http_status": [204]}}}]}
    spec["transport"]["budget"] = {"max_requests": 63, "cleanup_reserve": 1}
    raw = raw_scenario()
    raw["resources"] = [{"id": "session", "initial": "absent", "cleanup": "delete"}]
    raw["expect"]["resources"] = [{"id": "session", "final": "absent"}]
    raw["operations"] += [
        {"id": "open_session", "method": "POST", "path": "/sessions", "role": "setup", "calls": {"min": 1, "max": 1},
         "request": [], "replies": [{"status": 200, "body": {"session_id": "s-1"},
                                     "effects": [{"resource": "session", "from": "absent", "to": "live"}]}]},
        {"id": "close_session", "method": "DELETE", "path": "/sessions/{sid}", "role": "delete", "calls": {"min": 1, "max": 1},
         "request": [], "replies": [{"status": 204, "body": None,
                                     "effects": [{"resource": "session", "from": "live", "to": "absent"}]}]}]
    result = await verify(spec, raw, catalog=catalog)
    assert result.status == "verified", result.as_dict()
    failed = next(row for row in result.as_dict()["cases"] if row["name"] == "status:FAILED")
    assert failed["passed"] and failed["outcome"] == "target_error"
    spec["transport"]["lifecycle"]["attempt"][0].pop("undo")
    leaked = await verify(spec, raw, catalog=catalog)
    assert leaked.status == "failed"
    assert {row["name"]: row["passed"] for row in leaked.as_dict()["cases"]} == {
        "status:PENDING": False, "status:RUNNING": False, "status:FAILED": False}
