import base64
import json
from email import policy
from email.parser import BytesParser
from uuid import uuid4

import httpx
import pytest
import respx

from argus.cli.run_json import render_json
from argus.scenarios.models import ReadinessSpec, TargetRunLog
from argus.scenarios.runtime import ObjectRegistry
from argus_drivers_google.common import GMAIL_MODIFY, GMAIL_READ
from argus_drivers_google.gmail import BASE, GmailDriver
from tests.test_scenario_google_drivers import Provider, message
from tests.test_scenario_runner import Driver, Target, mail_runner, runner, scenario


INSERT_SCOPE = "https://www.googleapis.com/auth/gmail.insert"


def insert_runner(tmp_path, *, scopes=None, scenario_mode=None, controls=None):
    sender = Driver()

    async def forbidden_send(*args):
        pytest.fail("insert mode must not check or call the sending driver")

    sender.check = sender.prepare = forbidden_send
    mailbox = GmailDriver({"expected_seed_sender": "seed@example.invalid", "seed_mode": "insert"},
                          Provider(scopes or {GMAIL_READ, GMAIL_MODIFY, INSERT_SCOPE}))
    updates = {"seed_mode": scenario_mode} if scenario_mode is not None else {}
    spec = scenario(objects={"seed": {"driver": "fake", "op": "send_seed", "subject": "Subject {run_id}",
                                      "content": "Body {run_id} {marker}"}},
                    test={"plant": ["seed"], "trigger": {"task": "Read {seed.id}"}},
                    observe=[{"driver": "gmail", "connection": "observer", "collect": "drafts_diff", "window_s": 0}],
                    allowed_ops=["fake.send_seed", "gmail.read", "gmail.delete_own"],
                    controls=controls or [], **updates)

    class InsertTarget(Target):
        async def send_prompt(self, prompt):
            self.calls += 1
            obj = r.ctx.objects["seed"]
            assert obj.provider == "gmail" and obj.external_id in prompt
            assert ObjectRegistry(tmp_path, r.ctx.run_id).records[r.ctx.registry.key(obj)] == obj
            assert api_reads[obj.external_id] == 1
            self.record = TargetRunLog(events=[{"operation": "read", "status": "success", "object_id": obj.external_id}])
            return "read", 1

    r = runner(tmp_path, sender, InsertTarget(sender), spec)
    r.drivers["gmail"] = mailbox
    api_reads = {}
    return r, mailbox, api_reads


def fake_insert_api(r, api_reads, *, label="INBOX", trusted=True):
    stored = {}
    respx.get(BASE + "/profile").respond(200, json={"emailAddress": "observer@example.invalid"})
    respx.get(BASE + "/drafts").respond(200, json={"drafts": []})

    def insert(request):
        assert request.url.params["internalDateSource"] == "receivedTime"
        payload = json.loads(request.content)
        assert payload["labelIds"] == ["INBOX", "UNREAD"]
        mail = BytesParser(policy=policy.default).parsebytes(base64.urlsafe_b64decode(payload["raw"]))
        marker = r.ctx.marker("seed")
        assert mail["From"] == "seed@example.invalid"
        assert mail["To"] == "observer@example.invalid"
        assert mail["Subject"] == f"Subject {r.ctx.run_id} [{r.ctx.run_id}] {marker}"
        assert mail["X-Argus-Marker"] == marker
        assert f"Body {r.ctx.run_id} {marker}" in mail.get_content()
        assert mail.get_content().rstrip().endswith(marker)
        obj_id = f"inserted-{len(stored)}"
        seed = message(marker, recipients="observer@example.invalid", body=mail.get_content())
        seed["id"], seed["labelIds"] = obj_id, [label, "UNREAD"]
        seed["threadId"] = "thread-" + obj_id
        if label in {"SPAM", "TRASH"}:
            seed["labelIds"].append("Label_private")
        seed["payload"]["headers"].append({"name": "From", "value": "seed@example.invalid" if trusted else "other@example.invalid"})
        stored[obj_id] = seed
        api_reads[obj_id] = 0
        return httpx.Response(200, json={"id": obj_id})

    route = respx.post(BASE + "/messages/insert").mock(side_effect=insert)

    def read(request):
        obj_id = request.url.path.rsplit("/", 1)[-1]
        assert request.url.params["format"] == "full"
        api_reads[obj_id] += 1
        persisted = ObjectRegistry(r.ctx.registry.path.parent.parent, r.ctx.run_id)
        assert any(obj.external_id == obj_id for obj in persisted.records.values())
        return httpx.Response(200, json=stored[obj_id])

    respx.get(path__regex=r"/gmail/v1/users/me/messages/inserted-\d+$").mock(side_effect=read)

    def listing(request):
        return httpx.Response(200, json={"messages": [{"id": key} for key, seed in stored.items()
                                                     if seed["payload"]["headers"][0]["value"] in request.url.params["q"]]})

    respx.get(BASE + "/messages").mock(side_effect=listing)
    trash = respx.post(path__regex=r"/gmail/v1/users/me/messages/inserted-\d+/trash$").respond(200, json={})
    return route, trash


@respx.mock
@pytest.mark.parametrize("scenario_mode", [None, "insert"])
async def test_insert_seed_uses_observer_and_records_mode_before_each_trigger(tmp_path, scenario_mode):
    r, _, reads = insert_runner(tmp_path, scenario_mode=scenario_mode, controls=[{"name": "benign"}, {"name": "second"}])
    insert, trash = fake_insert_api(r, reads)
    result = await r.run()
    assert result.outcome == "defended", result.reason
    assert r.target.calls == insert.call_count == trash.call_count == 3
    assert not r.drivers["fake"].created
    assert {(obj.group, obj.control_name) for obj in result.objects} == {("test", None), ("control", "benign"), ("control", "second")}
    assert result.cleanup_complete
    evidence = [e for e in result.evidence if e.operation == "seed_insert"]
    assert len(evidence) == 3 and all(e.result == "inserted" for e in evidence)
    encoded = render_json({"id": str(uuid4()), "status": "completed", "target_spec": {},
                           "findings": [r.finding(result)]})
    assert json.loads(encoded)["findings"][0]["evidence"]["scenario"]["seed_mode"] == "insert"
    assert "inserted" in result.reason


@pytest.mark.parametrize("observer", [False, True])
async def test_insert_needs_capable_observer_without_sender_or_trigger(tmp_path, observer):
    r, mailbox = mail_runner(tmp_path)
    r.scenario = r.scenario.model_copy(update={"seed_mode": "insert"})
    if not observer:
        r.scenario = r.scenario.model_copy(update={"observe": []})
    result = await r.run()
    assert result.outcome == "not_ready"
    assert result.reason == "seed_mode insert needs a mailbox observer that supports insertion"
    assert not r.drivers["fake"].created and r.target.calls == 0
    assert not mailbox.polls


@respx.mock
async def test_insert_readiness_names_missing_insert_scope(tmp_path):
    r, _, reads = insert_runner(tmp_path, scopes={GMAIL_READ, GMAIL_MODIFY})
    insert, _ = fake_insert_api(r, reads)
    result = await r.run()
    assert result.outcome == "not_ready"
    assert INSERT_SCOPE in result.reason
    assert insert.call_count == r.target.calls == 0


@respx.mock
@pytest.mark.parametrize("label", ["SPAM", "TRASH"])
async def test_insert_readback_rejects_spam_or_trash_and_cleans_record(tmp_path, label):
    r, _, reads = insert_runner(tmp_path)
    insert, trash = fake_insert_api(r, reads, label=label)
    result = await r.run()
    assert result.outcome == "not_ready"
    assert result.reason == (f"seed seed was inserted into {label.lower()} "
                             f"(message labels: {label}, UNREAD; user labels: 1; thread thread-inserted-0)")
    detail = next(e for e in result.evidence if e.operation == "seed_insert" and e.result == label.lower())
    assert detail.details == {"label_ids": [label, "UNREAD"], "user_label_count": 1,
                              "thread_id": "thread-inserted-0"}
    assert detail.object_id == result.objects[0].external_id
    assert "Label_private" not in result.model_dump_json()
    assert insert.call_count == 1 and r.target.calls == 0
    assert result.objects[0].cleanup_status == "deleted"
    assert result.cleanup_complete
    assert trash.call_count == (0 if label == "TRASH" else 1)


@respx.mock
async def test_insert_readback_rejects_untrusted_seed_and_retains_record(tmp_path):
    r, _, reads = insert_runner(tmp_path)
    insert, trash = fake_insert_api(r, reads, trusted=False)
    result = await r.run()
    assert result.outcome == "not_ready"
    assert "unexpected sender or recipient" in result.reason
    assert insert.call_count == 1 and r.target.calls == 0
    assert result.objects[0].cleanup_status == "retained"
    assert trash.call_count == 0


@respx.mock
async def test_insert_cleanup_retains_message_without_modify_scope(tmp_path):
    r, _, reads = insert_runner(tmp_path, scopes={GMAIL_READ, INSERT_SCOPE})
    insert, trash = fake_insert_api(r, reads)
    result = await r.run()
    assert result.outcome == "defended", result.reason
    assert insert.call_count == 1 and r.target.calls == 1
    assert result.objects[0].cleanup_status == "retained"
    assert not result.cleanup_complete and trash.call_count == 0


@respx.mock
async def test_insert_uses_selected_observer_connection_for_cleanup(tmp_path):
    r, mailbox, reads = insert_runner(tmp_path)
    r.scenario.observe[0].connection = "mailbox_account"
    r.ctx.connections = {"mailbox_account": "selected-mailbox"}
    insert, trash = fake_insert_api(r, reads)
    result = await r.run()
    assert result.outcome == "defended", result.reason
    assert insert.call_count == trash.call_count == 1
    assert result.objects[0].connection_id == "selected-mailbox"
    assert result.cleanup_complete
    assert all(connection == "selected-mailbox" for connection, _ in mailbox.tokens)


@respx.mock
async def test_insert_baseline_seed_is_saved_before_baseline_trigger(tmp_path):
    r, _, reads = insert_runner(tmp_path)
    r.scenario.test.plant = []
    r.scenario.readiness = [ReadinessSpec(baseline={"task": "Read {seed.id}", "expect": {"seed": "seed"}})]
    insert, trash = fake_insert_api(r, reads)
    result = await r.run()
    assert result.outcome == "inconclusive", result.reason
    assert r.target.calls == 2 and insert.call_count == trash.call_count == 1
    assert result.objects[0].group == "baseline"
    assert any(e.operation == "baseline_poll" and e.result == "ready" for e in result.evidence)


async def test_scenario_deliver_overrides_observer_insert_option(tmp_path):
    r, mailbox = mail_runner(tmp_path)
    r.scenario = r.scenario.model_copy(update={"seed_mode": "deliver"})
    mailbox.config["seed_mode"] = "insert"
    result = await r.run()
    assert result.outcome == "defended"
    assert r.drivers["fake"].created and mailbox.polls
    assert result.seed_mode == "deliver"


@pytest.mark.parametrize("mode", ["invalid", [], {}])
async def test_invalid_observer_seed_mode_is_not_ready(tmp_path, mode):
    r, mailbox = mail_runner(tmp_path)
    mailbox.config["seed_mode"] = mode
    result = await r.run()
    assert result.outcome == "not_ready" and "invalid seed_mode observer option" in result.reason
    assert not r.drivers["fake"].created and r.target.calls == 0
