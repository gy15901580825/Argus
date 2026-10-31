import base64
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
import respx
from pydantic import SecretStr

from argus.scenarios.credentials import AccessToken, CredentialUnavailable
from argus.scenarios.models import BudgetSpec, ObjectRecord, ObjectSpec, ObserveSpec, now
from argus.scenarios.runtime import Budget, ObjectRegistry, RunContext
from argus_drivers_google.common import DRIVE_FILE, GMAIL_READ, GMAIL_SEND, owner_hash
from argus_drivers_google.drive import BASE as DRIVE, DriveDriver
from argus_drivers_google.gmail import BASE as GMAIL, GmailDriver


class Provider:
    def __init__(self, scopes=None):
        self.scopes = scopes or {DRIVE_FILE, GMAIL_READ}

    async def access_token(self, ref, scopes):
        if not scopes.issubset(self.scopes):
            raise CredentialUnavailable("missing scope")
        return AccessToken(value=SecretStr("test-google-token"), expires_at=now() + timedelta(hours=1), scopes=frozenset(self.scopes))


def context(tmp_path):
    run_id = str(uuid4())
    return RunContext(run_id=run_id, organization_id=str(uuid4()), scenario_id="test", connections={"operator": "op", "observer": "obs"},
                      target_identity="observer@gmail.com", allowed_ops=frozenset({"gdrive.create", "gdrive.read", "gdrive.delete_own", "gmail.read", "gmail.delete_own"}),
                      budget=Budget(BudgetSpec()), registry=ObjectRegistry(tmp_path, run_id), group="test")


def message(marker, recipients="attacker@example.invalid", *, body=None):
    return {"id": "message", "payload": {"headers": [{"name": "X-Argus-Marker", "value": marker}, {"name": "To", "value": recipients}],
                                          "body": {"data": base64.urlsafe_b64encode((body or marker).encode()).decode()}}}


@respx.mock
async def test_drive_uploads_content_and_registers_final_shared_version(tmp_path):
    ctx = context(tmp_path)
    driver = DriveDriver({}, Provider())
    respx.get(DRIVE + "/about").mock(return_value=httpx.Response(200, json={"user": {"emailAddress": "operator@gmail.com"}}))
    respx.get(DRIVE + "/files").mock(return_value=httpx.Response(200, json={"files": []}))
    respx.post(DRIVE + "/files").mock(return_value=httpx.Response(200, json={"id": "folder", "version": "1"}))
    upload = respx.post("https://www.googleapis.com/upload/drive/v3/files").mock(return_value=httpx.Response(200, json={"id": "doc", "version": "1"}))
    share = respx.post(DRIVE + "/files/doc/permissions").mock(return_value=httpx.Response(200, json={"id": "permission"}))
    respx.get(DRIVE + "/files/doc").mock(return_value=httpx.Response(200, json={"id": "doc", "version": "3"}))
    obj = await driver.prepare(ctx, "policy", ObjectSpec(driver="gdrive", op="create_doc", content="expected policy text", share_with=["target_agent"]))
    assert obj.version == "3"
    assert obj.owner == owner_hash("operator@gmail.com")
    assert b"expected policy text" in upload.calls[0].request.content
    assert b"appProperties" in upload.calls[0].request.content
    assert upload.calls[0].request.url.params["uploadType"] == "multipart"
    assert b"observer@gmail.com" in share.calls[0].request.content


@respx.mock
@pytest.mark.parametrize("change", ["version", "owner", "marker"])
async def test_drive_cleanup_preserves_modified_or_foreign_objects(tmp_path, change):
    ctx = context(tmp_path)
    ctx.cleanup_mode = True
    driver = DriveDriver({}, Provider())
    marker = ctx.marker("policy")
    obj = ObjectRecord(run_id=ctx.run_id, group="test", logical_key="policy", provider="gdrive", external_id="doc", marker=marker,
                       version="1", owner=owner_hash("operator@gmail.com"), connection_id="op")
    data = {"id": "doc", "version": "1", "owners": [{"emailAddress": "operator@gmail.com"}], "appProperties": {"argus_marker": marker}}
    if change == "version": data["version"] = "2"
    if change == "owner": data["owners"] = [{"emailAddress": "someone@example.com"}]
    if change == "marker": data["appProperties"]["argus_marker"] = "foreign"
    respx.get(DRIVE + "/about").mock(return_value=httpx.Response(200, json={"user": {"emailAddress": "operator@gmail.com"}}))
    respx.get(DRIVE + "/files/doc").mock(return_value=httpx.Response(200, json=data))
    mutation = respx.patch(DRIVE + "/files/doc").mock(return_value=httpx.Response(200, json={}))
    assert (await driver.cleanup(ctx, obj)).status == "retained"
    assert not mutation.called


@respx.mock
async def test_gmail_unrelated_new_draft_is_not_a_violation(tmp_path):
    ctx = context(tmp_path)
    driver = GmailDriver({}, Provider())
    ctx.registry.save(ObjectRecord(run_id=ctx.run_id, group="test", logical_key="seed", provider="gmail", external_id="seed", marker=ctx.marker("seed"), owner="owner", connection_id="obs"))
    respx.get(GMAIL + "/drafts").mock(return_value=httpx.Response(200, json={"drafts": [{"id": "unrelated"}, {"id": "related"}]}))
    respx.get(GMAIL + "/drafts/unrelated").mock(return_value=httpx.Response(200, json={"message": message("different-run")}))
    respx.get(GMAIL + "/drafts/related").mock(return_value=httpx.Response(200, json={"message": message(ctx.marker("seed"))}))
    records = await driver.collect(ctx, ObserveSpec(driver="gmail", collect="drafts_diff"), {})
    created = [e for e in records if e.operation == "draft_created"]
    assert len(created) == 1
    assert created[0].details["unexpected_recipient"] is True


@respx.mock
async def test_gmail_read_only_cleanup_is_retained(tmp_path):
    ctx = context(tmp_path)
    ctx.cleanup_mode = True
    driver = GmailDriver({"expected_seed_sender": "seed@test.azurecomm.net"}, Provider())
    marker = ctx.marker("seed")
    obj = ObjectRecord(run_id=ctx.run_id, group="test", logical_key="seed", provider="gmail", external_id="seed", marker=marker,
                       owner=owner_hash("observer@gmail.com"), connection_id="obs")
    respx.get(GMAIL + "/profile").mock(return_value=httpx.Response(200, json={"emailAddress": "observer@gmail.com"}))
    seed = message(marker, recipients="observer@gmail.com")
    seed["payload"]["headers"].append({"name": "From", "value": "seed@test.azurecomm.net"})
    respx.get(GMAIL + "/messages/seed").mock(return_value=httpx.Response(200, json=seed))
    trash = respx.post(GMAIL + "/messages/seed/trash").mock(return_value=httpx.Response(200, json={}))
    result = await driver.cleanup(ctx, obj)
    assert result.status == "retained"
    assert "no modification permission" in result.detail
    assert not trash.called


@respx.mock
async def test_gmail_pagination_checks_every_page_and_verifies_marker(tmp_path):
    ctx = context(tmp_path)
    driver = GmailDriver({}, Provider())
    marker = ctx.marker("seed")
    def listing(request):
        return httpx.Response(200, json={"messages": [{"id": "second"}]} if request.url.params.get("pageToken") else {"messages": [{"id": "first"}], "nextPageToken": "next"})
    respx.get(GMAIL + "/messages").mock(side_effect=listing)
    respx.get(GMAIL + "/messages/first").mock(return_value=httpx.Response(200, json=message("unrelated")))
    respx.get(GMAIL + "/messages/second").mock(return_value=httpx.Response(200, json={**message(marker), "id": "second"}))
    found = await driver.messages(ctx, ctx.connection("observer"), marker)
    assert [m["id"] for m in found] == ["second"]
    assert ctx.budget.counts["third_party_calls"] == 4


async def test_cleanup_operations_cannot_send_or_create(tmp_path):
    ctx = context(tmp_path)
    ctx.cleanup_mode = True
    ctx.allowed_ops = ctx.allowed_ops.union({"acs_email.send_seed"})
    for operation in ["gdrive.create", "acs_email.send_seed"]:
        with pytest.raises(Exception):
            ctx.authorize(operation)


@respx.mock
async def test_gmail_sender_only_permission_does_not_request_sender_read_access(tmp_path):
    ctx = context(tmp_path)
    ctx.allowed_ops = ctx.allowed_ops.union({"gmail.send_seed"})
    class ScopedProvider:
        calls = []
        async def access_token(self, ref, scopes):
            self.calls.append((ref.role, scopes))
            grants = {GMAIL_SEND} if ref.role == "operator" else {GMAIL_READ}
            if not scopes.issubset(grants):
                raise CredentialUnavailable("missing scope")
            return AccessToken(value=SecretStr(ref.role + "-token"), expires_at=now() + timedelta(hours=1), scopes=frozenset(grants))
    provider = ScopedProvider()
    driver = GmailDriver({}, provider)
    respx.get(GMAIL + "/profile").mock(return_value=httpx.Response(200, json={"emailAddress": "observer@gmail.com"}))
    respx.get(GMAIL + "/messages").mock(return_value=httpx.Response(200, json={"messages": []}))
    send = respx.post(GMAIL + "/messages/send").mock(return_value=httpx.Response(200, json={"id": "sent"}))
    obj = await driver.prepare(ctx, "seed", ObjectSpec(driver="gmail", op="send_seed", content="controlled content"))
    assert obj.external_id == "sent"
    assert send.called
    assert not any(role == "operator" and GMAIL_READ in scopes for role, scopes in provider.calls)
