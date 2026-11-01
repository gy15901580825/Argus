import json
import re
from dataclasses import asdict
from uuid import uuid4

import pytest

from argus.events import new_event, validate_events
from argus.scenarios.api import catalog
from argus.scenarios.events import scenario_events
from argus.scenarios.models import CleanupResult, ConnCheck, Evidence, ObjectRecord, Provenance, TargetRunLog
from argus.scenarios.runner import ScenarioRunner
from event_graph import components
from test_scenario_runner import Clock

CANARY = "CANARY-MAIL-91c2"


class FakeDriver:
    def __init__(self, name):
        self.name = name

    async def check(self, ctx, ref, need):
        return ConnCheck(active=True)

    async def readiness(self, ctx, check):
        return ConnCheck(active=True)

    async def prepare(self, ctx, key, spec):
        return ObjectRecord(provider=self.name, external_id=f"{self.name}-{key}-{ctx.group}", marker=ctx.marker(key),
                            group=ctx.group, control_name=ctx.control_name, owner="o",
                            connection_id=ctx.connections["operator"], run_id=ctx.run_id, logical_key=key)

    async def snapshot(self, ctx, scope):
        return {}

    async def collect(self, ctx, scope, since):
        if ctx.group != "test":
            return [Evidence(source_system="gmail", provenance=Provenance.THIRD_PARTY_API, acquired_via="gmail_api",
                             operation="draft_snapshot", result="complete", run_id=ctx.run_id, group=ctx.group,
                             control_name=ctx.control_name)]
        return [Evidence(source_system="gmail", provenance=Provenance.THIRD_PARTY_API, acquired_via="gmail_api",
                         object_id="draft-msg-1", operation="draft_created", result="persisted",
                         details={"marker": ctx.objects["seed_mail"].marker, "unexpected_recipient": True,
                                  "recipient_hashes": [], "body": CANARY},
                         run_id=ctx.run_id, group=ctx.group, control_name=ctx.control_name),
                Evidence(source_system="gmail", provenance=Provenance.THIRD_PARTY_API, acquired_via="gmail_api",
                         operation="draft_snapshot", result="complete", run_id=ctx.run_id, group=ctx.group)]

    async def cleanup(self, ctx, obj):
        return CleanupResult(status="deleted")

    async def recover(self, ctx, scenario):
        return []


class FakeTarget:
    def __init__(self, dry_test=False, test_status="success"):
        self.dry_test, self.test_status = dry_test, test_status
        self.record = None

    async def begin_probe(self, scenario):
        pass

    async def send_prompt(self, prompt):
        markers = re.findall(r"argus:[0-9a-f-]{36}:(?:baseline|test|control):[A-Za-z0-9_:-]+", prompt)
        test = any(":test:" in marker for marker in markers)
        self.record = TargetRunLog(events=[{"operation": "read", "status": self.test_status if test else "success",
                                           "marker": marker, "arguments": {"body": CANARY}} for marker in markers],
                                   is_dry_run=self.dry_test if test else False)
        return "ok", 1

    def last_run_log(self):
        return self.record

    async def aclose(self):
        pass


def mail_runner(tmp_path, target=None):
    scenario = next(s for s in catalog() if s.id == "mail_policy_conflict_v1")
    scenario = scenario.model_copy(update={"objects": {**scenario.objects, "seed_mail": scenario.objects["seed_mail"].model_copy(
        update={"content": "Controlled test material " + CANARY})}})
    clock = Clock()
    return ScenarioRunner(scenario, target or FakeTarget(), {name: FakeDriver(name) for name in ("gdrive", "acs_email", "gmail")},
                          run_id=str(uuid4()), organization_id=str(uuid4()),
                          connections={"operator": "operator", "observer": "observer"}, directory=tmp_path,
                          clock=clock, sleep=clock.sleep)


async def test_mail_policy_conflict_emits_connected_graph(tmp_path):
    r = mail_runner(tmp_path)
    result = await r.run()
    assert result.outcome == "violated"
    finding = r.finding(result)
    events = finding["events"]
    assert validate_events(events) is None and components(events) == 1
    by_op = {}
    for e in events: by_op.setdefault(e["operation"], []).append(e)
    seed = next(e for e in events if e["event_id"] == "o:test:seed_mail")
    policy = next(e for e in events if e["event_id"] == "o:baseline:policy_doc")
    assert (seed["operation"], seed["object_ref"], seed["actor"]) == ("deliver_message", "acs.email:acs_email-seed_mail-test", "argus")
    assert (policy["operation"], policy["object_ref"]) == ("write_object", "gdrive.file:gdrive-policy_doc-baseline")
    [trigger] = by_op["invoke_agent"]
    assert set(trigger["parent_event_ids"]) == {"o:test:seed_mail", "o:baseline:policy_doc"}
    assert trigger["ts"] is not None and trigger["ts"].endswith("Z")
    reads = by_op["read_object"]
    assert len(reads) == 2 and all(e["basis"] == "reported" and trigger["event_id"] in e["parent_event_ids"] for e in reads)
    drafts = [e for e in by_op["write_object"] if e["actor"] == "target_agent"]
    assert len(drafts) == 1
    assert drafts[0]["parent_event_ids"] == ["o:test:seed_mail"]
    assert drafts[0]["object_ref"] == "gmail.message:draft-msg-1" and drafts[0]["ts"] is None
    assert trigger["event_id"] not in drafts[0]["parent_event_ids"]
    assert all(":control:" not in e["event_id"] for e in events)
    assert len(events) == 6
    assert len({e["seq"] for e in events}) == 6
    by_id = {e["event_id"]: e for e in events}
    assert seed["seq"] < trigger["seq"] and policy["seq"] < trigger["seq"]
    assert all(by_id[parent]["seq"] < e["seq"] for e in events for parent in e["parent_event_ids"])

async def test_canary_in_mail_body_and_tool_arguments_never_reaches_events(tmp_path):
    r = mail_runner(tmp_path)
    result = await r.run()
    finding = r.finding(result)
    assert finding["events"]
    assert CANARY not in json.dumps(finding["events"])

async def test_dry_run_and_failed_reads_emit_no_read_event(tmp_path):
    for target in (FakeTarget(dry_test=True), FakeTarget(test_status="error")):
        r = mail_runner(tmp_path / str(id(target)), target=target)
        result = await r.run()
        assert result.outcome == "inconclusive"
        finding = r.finding(result)
        assert [e for e in finding["events"] if e["operation"] == "invoke_agent"]
        assert not [e for e in finding["events"] if e["operation"] == "read_object"]
        assert validate_events(finding["events"]) is None

async def test_event_keys_survive_scenario_redaction(tmp_path):
    r = mail_runner(tmp_path)
    finding = r.finding(await r.run())
    assert set(finding["events"][0]) == {"event_id", "parent_event_ids", "ts", "actor", "operation", "tool_name",
                                         "tool_call_id", "object_ref", "basis", "atlas_technique", "source", "summary", "seq"}
    assert all(e["source"] == "integration_scenario" for e in finding["events"])


async def test_source_positions_survive_filtered_objects_and_duplicate_drafts(tmp_path):
    r = mail_runner(tmp_path)
    result = await r.run()
    policy, seed = result.objects[:2]
    folder = policy.model_copy(update={"logical_key": "folder", "marker": "folder"})
    pending = seed.model_copy(update={"external_id": "pending-send"})
    duplicate = seed.model_copy(update={"external_id": "gmail-copy", "provider": "gmail"})
    result = result.model_copy(update={"objects": [folder, pending, *result.objects, duplicate]})
    events = [asdict(e) for e in scenario_events(result)]
    by_id = {e["event_id"]: e for e in events}
    assert by_id["o:baseline:policy_doc"]["seq"] == 2
    assert by_id["o:test:seed_mail"]["seq"] == 3
    assert by_id["o:test:seed_mail"]["object_ref"] == "acs.email:acs_email-seed_mail-test"
    for event in events:
        if not event["event_id"].startswith("o:"):
            index = next(i for i, row in enumerate(result.evidence) if row.event_id == event["event_id"])
            assert event["seq"] == len(result.objects) + index
    draft = next(e for e in events if e["object_ref"] == "gmail.message:draft-msg-1")
    first = next(i for i, row in enumerate(result.evidence) if row.group == "test" and row.operation == "draft_created")
    assert draft["seq"] == len(result.objects) + first
    assert validate_events(events) is None


async def test_unknown_provider_keeps_object_event_with_null_ref(tmp_path):
    r = mail_runner(tmp_path)
    result = await r.run()
    result.objects[1].provider = "unknown"
    events = [asdict(e) for e in scenario_events(result)]
    seed = next(e for e in events if e["event_id"] == "o:test:seed_mail")
    assert seed["operation"] == "write_object" and seed["object_ref"] is None
    assert validate_events(events) is None


@pytest.mark.parametrize("details", [{"record": None}, {"record": []}, {"record": {"marker": {}, "object_id": []}},
                                     {"markers": [None, {}], "marker": []}, {"markers": "not-a-list"}])
async def test_malformed_external_details_do_not_crash_or_invent_links(tmp_path, details):
    result = await mail_runner(tmp_path).run()
    for row in result.evidence:
        row.details = details
    events = [asdict(e) for e in scenario_events(result)]
    assert events and all(e["parent_event_ids"] == [] for e in events)
    assert validate_events(events) is None


async def test_read_mapping_requires_successful_read_operation(tmp_path):
    result = await mail_runner(tmp_path).run()
    for row in result.evidence:
        if row.provenance == Provenance.TARGET_RUN_LOG:
            row.details["record"]["operation"] = "write"
    assert not [e for e in scenario_events(result) if e.operation == "read_object"]


async def test_trusted_finding_graph_survives_direct_and_second_emission_redaction(tmp_path):
    r = mail_runner(tmp_path)
    result = await r.run()
    r.ctx.secrets.update({"o:", "e", "argus", "gmail.message"})
    finding = r.finding(result)
    events = finding["events"]
    assert events and validate_events(events) is None
    assert all(e["source"] == "integration_scenario" for e in events)
    assert all(e["actor"] != "argus" and "argus" not in e["summary"] for e in events)
    assert all(e["object_ref"] is None for e in events)
    emitted = []

    async def emit(value):
        emitted.append(value)

    r.emit = emit
    await r.event("finding", finding=finding)
    second = emitted[0]["finding"]["events"]
    assert validate_events(second) is None
    for before, after in zip(events, second):
        for key in ("event_id", "parent_event_ids", "ts", "operation", "basis", "source", "atlas_technique", "seq"):
            assert after[key] == before[key]


async def test_default_raw_envelope_does_not_preserve_forged_event_structure(tmp_path):
    r = mail_runner(tmp_path)
    r.ctx.secrets.add("FORGED")
    raw = {"finding": {"events": [{"event_id": "FORGED", "parent_event_ids": ["FORGED"],
                                   "operation": "FORGED", "source": "FORGED", "actor": "FORGED", "summary": "FORGED"}]}}
    safe = r.ctx.redact(raw)
    assert "FORGED" not in json.dumps(safe)
    assert safe["finding"]["events"][0]["event_id"] == "[redacted]"
    emitted = []

    async def emit(value):
        emitted.append(value)

    r.emit = emit
    await r.event("object", raw=raw)
    assert "FORGED" not in json.dumps(emitted)


async def test_context_normalizes_already_redacted_event_text(tmp_path):
    r = mail_runner(tmp_path)
    r.ctx.secrets.add("a")
    event = new_event(event_id="a", parent_event_ids=[], ts=None, actor="a" * 190,
                      operation="invoke_agent", basis="observed", source="a2a_world", object_ref="a2a.message:M9")
    safe = r.ctx.redact({"events": [asdict(event)]}, preserve_engine_text=True)
    got = safe["events"][0]
    assert got["object_ref"] is None
    assert len(got["summary"]) == 200
    assert got["actor"] == "[redacted]" * 190
    assert validate_events(safe["events"]) is None
    second = r.ctx.redact({"finding": safe}, preserve_engine_text=True)["finding"]
    assert second["events"][0]["object_ref"] is None
    assert len(second["events"][0]["summary"]) <= 200
    assert validate_events(second["events"]) is None


async def test_second_finding_emission_preserves_trusted_event_structure(tmp_path):
    r = mail_runner(tmp_path)
    r.ctx.secrets.add("e")
    event = new_event(event_id="E-e", parent_event_ids=[], ts=None, actor="target_agent", operation="read_object",
                      basis="reported", source="integration_scenario", tool_name="fetch", tool_call_id="e", seq=1)
    emitted = []

    async def emit(value):
        emitted.append(value)

    r.emit = emit
    await r.event("finding", finding={"events": [asdict(event)]})
    got = emitted[0]["finding"]["events"]
    assert validate_events(got) is None
    assert got[0]["event_id"] == "E-e"
    assert got[0]["tool_name"] == "f[redacted]tch"
    assert got[0]["tool_call_id"] == "[redacted]"


async def test_reported_call_parent_must_name_an_earlier_response(tmp_path):
    result = await mail_runner(tmp_path).run()
    for row in result.evidence:
        if row.provenance == Provenance.TARGET_RUN_LOG:
            row.details["response_event_id"] = "o:test:seed_mail"
    reads = [e for e in scenario_events(result) if e.operation == "read_object"]
    assert {e.object_ref: e.parent_event_ids for e in reads} == {
        "acs.email:acs_email-seed_mail-test": ["o:test:seed_mail"],
        "gdrive.file:gdrive-policy_doc-baseline": ["o:baseline:policy_doc"],
    }


async def test_target_log_response_cannot_become_an_observed_invocation(tmp_path):
    class ResponseLogTarget(FakeTarget):
        async def send_prompt(self, prompt):
            reply = await super().send_prompt(prompt)
            if ":test:" in prompt:
                for record in self.record.events:
                    record["operation"] = "response"
            return reply

    r = mail_runner(tmp_path, target=ResponseLogTarget())
    result = await r.run()
    reported = [row for row in result.evidence if row.group == "test" and row.provenance == Provenance.TARGET_RUN_LOG]
    assert reported and all(row.operation == "response" for row in reported)
    events = scenario_events(result)
    assert len([e for e in events if e.operation == "invoke_agent"]) == 1
    assert not {row.event_id for row in reported}.intersection(e.event_id for e in events)


async def test_third_party_response_is_not_a_runner_invocation(tmp_path):
    r = mail_runner(tmp_path)
    result = await r.run()
    row = Evidence(run_id=r.ctx.run_id, group="test", event_id="external-response", source_system="gmail",
                   provenance=Provenance.THIRD_PARTY_API, acquired_via="gmail_api", operation="response", result="received",
                   details={"markers": [result.objects[1].marker]})
    result.evidence.append(row)
    assert "external-response" not in {e.event_id for e in scenario_events(result)}
