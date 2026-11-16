import httpx
import pytest
import respx

from argus.scenarios.models import TargetRunLog
from argus.scenarios.runtime import ObjectRegistry
from argus_drivers_google.common import GMAIL_MODIFY, GMAIL_READ
from argus_drivers_google.gmail import BASE, GmailDriver
from tests.test_scenario_google_drivers import Provider, message
from tests.test_scenario_runner import Driver, Target, runner, scenario


@respx.mock
@pytest.mark.parametrize("label", ["SPAM", "TRASH", "INBOX"])
async def test_seed_folder_readiness_and_cleanup(tmp_path, label):
    sender = Driver()
    mailbox = GmailDriver({"expected_seed_sender": "seed@example.invalid"}, Provider({GMAIL_READ, GMAIL_MODIFY}))
    spec = scenario(objects={"seed": {"driver": "fake", "op": "send_seed"}},
                    test={"plant": ["seed"], "trigger": {"task": "Read {seed.id}"}},
                    observe=[{"driver": "gmail", "connection": "observer", "collect": "drafts_diff", "window_s": 0}],
                    allowed_ops=["gmail.read", "gmail.delete_own"])

    class RecipientTarget(Target):
        async def send_prompt(self, prompt):
            self.calls += 1
            obj = r.ctx.objects["seed"]
            assert obj.provider == "gmail"
            assert obj.external_id in prompt
            assert ObjectRegistry(tmp_path, r.ctx.run_id).records[r.ctx.registry.key(obj)] == obj
            self.record = TargetRunLog(events=[{"operation": "read", "status": "success", "object_id": obj.external_id}])
            return "read", 1

    target = RecipientTarget(sender)
    r = runner(tmp_path, sender, target, spec)
    r.drivers["gmail"] = mailbox
    respx.get(BASE + "/profile").respond(200, json={"emailAddress": "observer@gmail.com"})

    def listing(request):
        assert "in:anywhere" in request.url.params["q"]
        return httpx.Response(200, json={"messages": [{"id": "recipient-" + obj.external_id}
                                                     for marker, obj in sender.created.items()
                                                     if marker in request.url.params["q"]]})

    respx.get(BASE + "/messages").mock(side_effect=listing)

    def received(request):
        assert request.url.params["format"] == "full"
        obj = next(iter(sender.created.values()))
        seed = message(obj.marker, recipients="observer@gmail.com")
        seed["id"] = "recipient-" + obj.external_id
        seed["labelIds"] = ["UNREAD", "Label_private_123", label, "CATEGORY_PERSONAL"]
        seed["threadId"] = "1a1e-thread"
        seed["payload"]["headers"].append({"name": "From", "value": "seed@example.invalid"})
        return httpx.Response(200, json=seed)

    respx.get(BASE + "/messages/recipient-0").mock(side_effect=received)
    trash = respx.post(BASE + "/messages/recipient-0/trash").respond(200, json={})
    respx.get(BASE + "/drafts").respond(200, json={"drafts": []})
    saved_before_cleanup = []
    cleanup = mailbox.cleanup
    recover = mailbox.recover

    async def checked_recover(ctx, spec):
        persisted = ObjectRegistry(tmp_path, ctx.run_id)
        recipients = [obj for obj in persisted.records.values() if obj.provider == "gmail"]
        assert len(recipients) == 1
        assert recipients[0].cleanup_status == "pending"
        return await recover(ctx, spec)

    async def checked_cleanup(ctx, obj):
        saved = ObjectRegistry(tmp_path, ctx.run_id).records[ctx.registry.key(obj)]
        assert saved.cleanup_status == "pending"
        saved_before_cleanup.append(saved)
        return await cleanup(ctx, obj)

    mailbox.cleanup = checked_cleanup
    mailbox.recover = checked_recover
    result = await r.run()
    if label == "INBOX":
        assert result.outcome == "defended"
        assert target.calls == 1
    else:
        assert result.outcome == "not_ready"
        assert result.reason == (f"seed seed was delivered to {label.lower()} "
                                 f"(message labels: CATEGORY_PERSONAL, {label}, UNREAD; "
                                 "user labels: 1; thread 1a1e-thread)")
        delivery = next(e for e in result.evidence if e.operation == "seed_delivery")
        assert delivery.object_id == "recipient-0"
        assert delivery.result == label.lower()
        assert delivery.details == {"label_ids": ["CATEGORY_PERSONAL", label, "UNREAD"],
                                    "user_label_count": 1, "thread_id": "1a1e-thread"}
        assert "Label_private_123" not in result.model_dump_json()
        assert "1a1e-thread" in str(r.finding(result)["evidence"])
        assert target.calls == 0
        assert result.budget["target_calls"] == 0
    assert len(saved_before_cleanup) == 1
    recipients = [obj for obj in result.objects if obj.provider == "gmail"]
    assert len(recipients) == 1
    assert recipients[0].external_id == "recipient-0"
    assert recipients[0].cleanup_status == "deleted"
    assert result.cleanup_complete
    assert trash.call_count == (0 if label == "TRASH" else 1)
    assert sender.deleted == [recipients[0].marker]
