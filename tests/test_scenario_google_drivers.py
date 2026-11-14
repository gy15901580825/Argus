import base64
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
import respx
from pydantic import SecretStr

from argus.scenarios.credentials import AccessToken, CredentialUnavailable
from argus.scenarios.models import BudgetSpec, ObjectRecord, ObjectSpec, ObserveSpec, now
from argus.scenarios.runtime import Budget, NotReady, ObjectRegistry, RunContext
from argus_drivers_google.common import DRIVE_FILE, GMAIL_READ, GMAIL_SEND, owner_hash
from argus_drivers_google.drive import BASE as DRIVE, DriveDriver, content_hash
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
    respx.get(DRIVE + "/files/doc").mock(return_value=httpx.Response(200, json={"id": "doc", "version": "3", "mimeType": "application/vnd.google-apps.document"}))
    export = respx.get(DRIVE + "/files/doc/export").mock(return_value=httpx.Response(200, text="expected policy text\n\n" + ctx.marker("policy") + "\n"))
    obj = await driver.prepare(ctx, "policy", ObjectSpec(driver="gdrive", op="create_doc", content="expected policy text", share_with=["target_agent"]))
    assert obj.version == "3"
    assert obj.owner == owner_hash("operator@gmail.com")
    assert b"expected policy text" in upload.calls[0].request.content
    assert b"appProperties" in upload.calls[0].request.content
    assert upload.calls[0].request.url.params["uploadType"] == "multipart"
    assert b"observer@gmail.com" in share.calls[0].request.content
    assert export.calls[0].request.url.params["mimeType"] == "text/plain"


@respx.mock
@pytest.mark.parametrize("body, accepted", [
    ("expected policy text", True),
    ("expected policy text, plus an edit", False),
])
async def test_drive_prepare_accepts_google_docs_plain_text_export(tmp_path, body, accepted):
    ctx = context(tmp_path)
    driver = DriveDriver({}, Provider())
    respx.get(DRIVE + "/about").mock(return_value=httpx.Response(200, json={"user": {"emailAddress": "operator@gmail.com"}}))
    respx.get(DRIVE + "/files").mock(return_value=httpx.Response(200, json={"files": []}))
    respx.post(DRIVE + "/files").mock(return_value=httpx.Response(200, json={"id": "folder", "version": "1"}))
    respx.post("https://www.googleapis.com/upload/drive/v3/files").mock(return_value=httpx.Response(200, json={"id": "doc", "version": "1"}))
    respx.get(DRIVE + "/files/doc").mock(return_value=httpx.Response(200, json={"id": "doc", "version": "3", "mimeType": "application/vnd.google-apps.document"}))
    # Shape of a real Docs text/plain export: UTF-8 BOM, CRLF, and one extra blank line between paragraphs.
    export = ("﻿" + body + "\r\n\r\n\r\n" + ctx.marker("policy")).encode()
    respx.get(DRIVE + "/files/doc/export").mock(return_value=httpx.Response(200, content=export))
    spec = ObjectSpec(driver="gdrive", op="create_doc", content="expected policy text")
    if accepted:
        assert (await driver.prepare(ctx, "policy", spec)).version == "3"
    else:
        with pytest.raises(NotReady, match="does not match its template"):
            await driver.prepare(ctx, "policy", spec)


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
@pytest.mark.parametrize("case, deleted", [("unedited", True), ("body_edited", False), ("other_editor", False), ("no_stored_hash", False)])
async def test_drive_cleanup_deletes_doc_whose_version_moved_without_an_edit(tmp_path, case, deleted):
    ctx = context(tmp_path)
    ctx.cleanup_mode = True
    driver = DriveDriver({}, Provider())
    marker = ctx.marker("policy")
    content = "Policy line one\nPolicy line two" + "\n\n" + marker
    obj = ObjectRecord(run_id=ctx.run_id, group="test", logical_key="policy", provider="gdrive", external_id="doc", marker=marker,
                       version="7", owner=owner_hash("operator@gmail.com"), connection_id="op")
    data = {"id": "doc", "version": "8", "mimeType": "application/vnd.google-apps.document", "owners": [{"emailAddress": "operator@gmail.com"}],
            "appProperties": {"argus_marker": marker, "argus_content_sha256": content_hash(content)}}
    export = "\ufeff" + content.replace("\n\n", "\n\n\n").replace("\n", "\r\n")
    revisions = [{"lastModifyingUser": {"me": True}}]
    if case == "body_edited": export = export.replace("two", "2")
    if case == "other_editor": revisions.append({"lastModifyingUser": {"me": False}})
    if case == "no_stored_hash": del data["appProperties"]["argus_content_sha256"]
    respx.get(DRIVE + "/about").mock(return_value=httpx.Response(200, json={"user": {"emailAddress": "operator@gmail.com"}}))
    respx.get(DRIVE + "/files/doc").mock(return_value=httpx.Response(200, json=data))
    respx.get(DRIVE + "/files/doc/revisions").mock(return_value=httpx.Response(200, json={"revisions": revisions}))
    respx.get(DRIVE + "/files/doc/export").mock(return_value=httpx.Response(200, text=export))
    trash = respx.patch(DRIVE + "/files/doc").mock(return_value=httpx.Response(200, json={}))
    result = await driver.cleanup(ctx, obj)
    assert result.status == ("deleted" if deleted else "retained")
    assert trash.called == deleted
    if deleted:
        assert trash.calls.last.request.content == b'{"trashed":true}'


def drive_doc(ctx, content, **extra):
    marker = ctx.marker("policy")
    return {"id": "doc", "version": "8", "mimeType": "application/vnd.google-apps.document", "owners": [{"emailAddress": "operator@gmail.com"}],
            "appProperties": {"argus_marker": marker, "argus_content_sha256": content_hash(content)},
            "createdTime": "2026-11-14T04:49:19.006Z", "modifiedTime": "2026-11-14T04:49:19.006Z", **extra}


@respx.mock
@pytest.mark.parametrize("case", ["unedited", "other_editor", "unknown_version"])
async def test_drive_prepare_recovery_ignores_version_bump_on_unedited_doc(tmp_path, case):
    ctx = context(tmp_path)
    driver = DriveDriver({}, Provider())
    content = "expected policy text" + "\n\n" + ctx.marker("policy")
    data = drive_doc(ctx, content)
    previous = driver.record(ctx, "policy", {**data, "version": "7"}, ctx.connection("operator"), "operator@gmail.com")
    if case == "unknown_version":
        data["modifiedTime"] = "2026-11-14T05:10:00.000Z"
    else:
        ctx.registry.save(previous)
    revisions = [{"lastModifyingUser": {"me": True}}] + ([{"lastModifyingUser": {"me": False}}] if case == "other_editor" else [])
    respx.get(DRIVE + "/about").mock(return_value=httpx.Response(200, json={"user": {"emailAddress": "operator@gmail.com"}}))
    respx.get(DRIVE + "/files").mock(return_value=httpx.Response(200, json={"files": [data]}))
    history = respx.get(DRIVE + "/files/doc/revisions").mock(return_value=httpx.Response(200, json={"revisions": revisions}))
    respx.get(DRIVE + "/files/doc/export").mock(return_value=httpx.Response(200, text=content))
    spec = ObjectSpec(driver="gdrive", op="create_doc", content="expected policy text")
    if case == "unedited":
        assert await driver.prepare(ctx, "policy", spec) is previous
    elif case == "unknown_version":
        recovered = await driver.prepare(ctx, "policy", spec)
        assert (recovered.version, recovered.cleanup_status) == ("8", "pending")
    else:
        with pytest.raises(NotReady, match="was modified"):
            await driver.prepare(ctx, "policy", spec)
        assert history.called


@respx.mock
@pytest.mark.parametrize("case, retained", [("unedited", False), ("body_edited", True)])
async def test_drive_recover_retains_only_edited_doc_of_unknown_version(tmp_path, case, retained):
    ctx = context(tmp_path)
    ctx.cleanup_mode = True
    driver = DriveDriver({}, Provider())
    content = "expected policy text" + "\n\n" + ctx.marker("policy")
    data = drive_doc(ctx, content, modifiedTime="2026-11-14T05:10:00.000Z")
    def listing(request):
        return httpx.Response(200, json={"files": [data] if ctx.marker("policy") in request.url.params["q"] else []})
    respx.get(DRIVE + "/about").mock(return_value=httpx.Response(200, json={"user": {"emailAddress": "operator@gmail.com"}}))
    respx.get(DRIVE + "/files").mock(side_effect=listing)
    respx.get(DRIVE + "/files/doc/revisions").mock(return_value=httpx.Response(200, json={"revisions": [{"lastModifyingUser": {"me": True}}]}))
    export = respx.get(DRIVE + "/files/doc/export").mock(
        return_value=httpx.Response(200, text=content.replace("text", "edited") if case == "body_edited" else content))
    scenario = SimpleNamespace(objects={"policy": ObjectSpec(driver="gdrive", op="create_doc", content="expected policy text")}, controls=[])
    recovered = await driver.recover(ctx, scenario)
    assert [(o.logical_key, o.cleanup_status) for o in recovered] == [("policy", "retained" if retained else "pending")]
    assert export.called


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
    driver = GmailDriver({"expected_seed_sender": "operator@gmail.com"}, provider)
    respx.get(GMAIL + "/profile").mock(return_value=httpx.Response(200, json={"emailAddress": "observer@gmail.com"}))
    respx.get(GMAIL + "/messages").mock(return_value=httpx.Response(200, json={"messages": []}))
    send = respx.post(GMAIL + "/messages/send").mock(return_value=httpx.Response(200, json={"id": "sent"}))
    obj = await driver.prepare(ctx, "seed", ObjectSpec(driver="gmail", op="send_seed", content="controlled content"))
    assert obj.external_id == "sent"
    assert send.called
    assert not any(role == "operator" and GMAIL_READ in scopes for role, scopes in provider.calls)


@respx.mock
async def test_drive_reads_plain_text_document_and_reports_hash_not_body(tmp_path):
    ctx = context(tmp_path)
    driver = DriveDriver({}, Provider())
    marker = ctx.marker("policy")
    obj = ObjectRecord(run_id=ctx.run_id, group="test", logical_key="policy", provider="gdrive", external_id="doc", marker=marker, owner=owner_hash("operator@gmail.com"), connection_id="op", version="1")
    ctx.objects["policy"] = obj
    data = {"id": "doc", "version": "1", "mimeType": "application/vnd.google-apps.document", "appProperties": {"argus_marker": marker}}
    respx.get(DRIVE + "/files/doc").mock(return_value=httpx.Response(200, json=data))
    export = respx.get(DRIVE + "/files/doc/export").mock(return_value=httpx.Response(200, text="PRIVATE-POLICY-BODY\n" + marker))
    respx.get(DRIVE + "/files/doc/revisions").mock(return_value=httpx.Response(200, json={"revisions": [{"id": "1", "modifiedTime": "2026-11-14T00:00:00Z"}]}))
    snapshot = await driver.snapshot(ctx, ObserveSpec(driver="gdrive", collect="object_diff", connection="operator", object="policy"))
    evidence = await driver.collect(ctx, ObserveSpec(driver="gdrive", collect="object_diff", connection="operator", object="policy"), snapshot)
    assert evidence[0].operation == "object_snapshot"
    assert evidence[0].details["marker_present"] is True
    assert "PRIVATE-POLICY-BODY" not in str(evidence[0].model_dump())
    assert export.calls[0].request.url.params["mimeType"] == "text/plain"


@respx.mock
@pytest.mark.parametrize("case, changed", [("server_version_bump", False), ("formatting_edit", True), ("body_edit", True)])
async def test_drive_diff_reports_edits_not_server_version_bumps(tmp_path, case, changed):
    ctx = context(tmp_path)
    driver = DriveDriver({}, Provider())
    marker = ctx.marker("policy")
    ctx.objects["policy"] = ObjectRecord(run_id=ctx.run_id, group="test", logical_key="policy", provider="gdrive", external_id="doc", marker=marker,
                                         owner=owner_hash("operator@gmail.com"), connection_id="op", version="7")
    meta = {"id": "doc", "mimeType": "application/vnd.google-apps.document", "appProperties": {"argus_marker": marker}}
    body = "Policy body\n\n" + marker
    first = {"revisions": [{"id": "1", "modifiedTime": "2026-11-14T04:49:19.006Z"}]}
    later = {"formatting_edit": {"revisions": [{"id": "1", "modifiedTime": "2026-11-14T04:52:00.000Z"}]}}.get(case, first)
    respx.get(DRIVE + "/files/doc").mock(side_effect=[httpx.Response(200, json={**meta, "version": "7"}), httpx.Response(200, json={**meta, "version": "8"})])
    respx.get(DRIVE + "/files/doc/export").mock(side_effect=[httpx.Response(200, text=body), httpx.Response(200, text=body.replace("body", "edited") if case == "body_edit" else body)])
    respx.get(DRIVE + "/files/doc/revisions").mock(side_effect=[httpx.Response(200, json=first), httpx.Response(200, json=later)])
    spec = ObserveSpec(driver="gdrive", collect="object_diff", connection="operator", object="policy")
    evidence = await driver.collect(ctx, spec, await driver.snapshot(ctx, spec))
    assert (evidence[0].operation, evidence[0].result) == (("object_changed", "persisted") if changed else ("object_snapshot", "unchanged"))


@respx.mock
async def test_oversized_drive_content_read_is_rejected(tmp_path):
    ctx = context(tmp_path)
    driver = DriveDriver({"max_response_bytes": 32}, Provider())
    respx.get(DRIVE + "/files/doc/export").mock(return_value=httpx.Response(200, text="x" * 64))
    with pytest.raises(RuntimeError, match="bounded content read"):
        await driver.read_content(ctx, ctx.connection("operator"), {"id": "doc", "mimeType": "application/vnd.google-apps.document"})


@respx.mock
async def test_owned_child_cleanup_precedes_folder_and_preserves_foreign_children(tmp_path):
    ctx = context(tmp_path)
    ctx.cleanup_mode = True
    driver = DriveDriver({}, Provider())
    profile = {"user": {"emailAddress": "operator@gmail.com"}}
    respx.get(DRIVE + "/about").mock(return_value=httpx.Response(200, json=profile))
    child = ObjectRecord(run_id=ctx.run_id, group="test", logical_key="policy", provider="gdrive", external_id="doc", marker=ctx.marker("policy"), owner=owner_hash("operator@gmail.com"), connection_id="op", version="1")
    folder = child.model_copy(update={"logical_key": "folder", "external_id": "folder", "marker": ctx.marker("folder")})
    respx.get(DRIVE + "/files/doc").mock(return_value=httpx.Response(200, json={"id": "doc", "version": "1", "owners": [{"emailAddress": "operator@gmail.com"}], "appProperties": {"argus_marker": child.marker}}))
    respx.get(DRIVE + "/files/folder").mock(return_value=httpx.Response(200, json={"id": "folder", "mimeType": "application/vnd.google-apps.folder", "version": "1", "owners": [{"emailAddress": "operator@gmail.com"}], "appProperties": {"argus_marker": folder.marker}}))
    respx.patch(DRIVE + "/files/doc").mock(return_value=httpx.Response(200, json={}))
    respx.get(DRIVE + "/files").mock(return_value=httpx.Response(200, json={"files": []}))
    folder_mutation = respx.patch(DRIVE + "/files/folder").mock(return_value=httpx.Response(200, json={}))
    assert (await driver.cleanup(ctx, child)).status == "deleted"
    assert (await driver.cleanup(ctx, folder)).status == "deleted"
    respx.get(DRIVE + "/files").mock(return_value=httpx.Response(200, json={"files": [{"id": "foreign-child"}]}))
    assert (await driver.cleanup(ctx, folder)).status == "retained"
    assert folder_mutation.call_count == 1
