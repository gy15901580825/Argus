from __future__ import annotations

import base64
import hashlib
import re
from email.message import EmailMessage
from email.utils import getaddresses

from argus.scenarios.models import CleanupResult, ConnCheck, Evidence, ObjectRecord, Provenance, object_marker
from argus.scenarios.runtime import NotReady
from argus_drivers_google.common import GMAIL_MODIFY, GMAIL_READ, GMAIL_SEND, GoogleDriver, owner_hash


BASE = "https://gmail.googleapis.com/gmail/v1/users/me"


def body_text(payload: dict) -> str:
    data = payload.get("body", {}).get("data", "")
    text = base64.urlsafe_b64decode(data + "=" * (-len(data) % 4)).decode(errors="replace") if data else ""
    return text + "\n".join(body_text(p) for p in payload.get("parts", []))


def headers(message: dict) -> dict[str, str]:
    return {h["name"].lower(): h["value"] for h in message.get("payload", {}).get("headers", [])}


def has_marker(message: dict, marker: str) -> bool:
    return headers(message).get("x-argus-marker") == marker or bool(re.search(re.escape(marker) + r"(?![A-Za-z0-9_:-])", body_text(message.get("payload", {}))))


class GmailDriver(GoogleDriver):
    name = "gmail"

    def scopes_for(self, operations):
        return [{GMAIL_SEND} if op == "send_seed" else {GMAIL_READ} for op in operations]

    async def account(self, ctx, ref):
        if ref.connection_id not in self.accounts:
            data = await self.request(ctx, ref, {GMAIL_READ}, "GET", BASE + "/profile")
            self.accounts[ref.connection_id] = data["emailAddress"].lower()
        return self.accounts[ref.connection_id]

    async def messages(self, ctx, ref, marker):
        ctx.authorize("gmail.read")
        rows = await self.pages(ctx, ref, {GMAIL_READ}, BASE + "/messages", "messages", {"q": 'in:anywhere "' + marker + '"', "maxResults": 100})
        found = []
        for row in rows:
            message = await self.request(ctx, ref, {GMAIL_READ}, "GET", BASE + "/messages/" + row["id"], params={"format": "full"})
            if has_marker(message, marker):
                found.append(message)
        return found

    def trusted_seed(self, ctx, message, marker, mailbox):
        hdr = headers(message)
        body_matches = bool(re.search(re.escape(marker) + r"(?![A-Za-z0-9_:-])", body_text(message.get("payload", {}))))
        if not body_matches or hdr.get("x-argus-marker") not in {None, marker}:
            return False
        recipients = {address.lower() for _, address in getaddresses([hdr.get("to", "")])}
        senders = {owner_hash(address) for _, address in getaddresses([hdr.get("from", "")])}
        expected = {o.owner for o in ctx.registry.records.values() if o.marker == marker and o.provider in {"acs_email", "hosted_acs"}}
        configured = self.config.get("expected_seed_sender")
        if configured:
            expected.add(owner_hash(configured))
        return mailbox.lower() in recipients and bool(senders.intersection(expected))

    async def check(self, ctx, ref, need):
        if "send_seed" in need and not self.config.get("expected_seed_sender"):
            return ConnCheck(active=False, detail="Gmail sending requires the declared operator sender address")
        check = await super().check(ctx, ref, need)
        if check.active and need != {"send_seed"}:
            await self.account(ctx, ref)
        return check

    async def readiness(self, ctx, check):
        return ConnCheck(active=True)

    async def prepare(self, ctx, key, spec):
        if spec.op != "send_seed":
            raise NotReady("Gmail only prepares send_seed objects")
        ctx.authorize("gmail.send_seed")
        marker = ctx.marker(key)
        observer = ctx.connection("observer")
        mailbox = await self.account(ctx, observer)
        existing = [message for message in await self.messages(ctx, observer, marker) if self.trusted_seed(ctx, message, marker, mailbox)]
        if existing:
            return ObjectRecord(run_id=ctx.run_id, group=ctx.group, logical_key=key, provider=self.name,
                                control_name=ctx.control_name,
                                external_id=existing[0]["id"], marker=marker, owner=owner_hash(await self.account(ctx, observer)),
                                connection_id=observer.connection_id)
        pending = [o for o in ctx.registry.records.values() if o.provider == self.name and o.marker == marker and o.external_id == "pending-send"]
        if pending:
            raise NotReady("seed delivery is uncertain; do not resend before checking the mailbox")
        ref = ctx.connection(spec.from_ or spec.connection)
        sender = self.config.get("expected_seed_sender")
        if not sender:
            raise NotReady("Gmail sending requires the declared operator sender address")
        record = ObjectRecord(run_id=ctx.run_id, group=ctx.group, logical_key=key, provider=self.name, external_id="pending-send",
                              control_name=ctx.control_name,
                              marker=marker, owner=owner_hash(sender), connection_id=ref.connection_id)
        ctx.registry.save(record)
        mail = EmailMessage()
        mail["From"] = sender
        mail["To"] = ctx.target_identity if spec.to == "target_agent" else spec.to
        mail["Subject"] = spec.subject + " " + marker
        mail["Message-ID"] = "<" + hashlib.sha256(marker.encode()).hexdigest() + "@argus.invalid>"
        mail["X-Argus-Marker"] = marker
        mail.set_content(spec.content + "\n\n" + marker)
        sent = await self.request(ctx, ref, {GMAIL_SEND}, "POST", BASE + "/messages/send", json={"raw": base64.urlsafe_b64encode(mail.as_bytes()).decode()})
        record.external_id = sent["id"]
        ctx.registry.records.pop(ctx.registry.key(record.model_copy(update={"external_id": "pending-send"})), None)
        return record

    async def drafts(self, ctx, ref):
        ctx.authorize("gmail.read")
        rows = await self.pages(ctx, ref, {GMAIL_READ}, BASE + "/drafts", "drafts", {"maxResults": 100})
        return {row["id"]: await self.request(ctx, ref, {GMAIL_READ}, "GET", BASE + "/drafts/" + row["id"], params={"format": "full"}) for row in rows}

    async def snapshot(self, ctx, scope):
        if scope.collect != "drafts_diff":
            raise NotReady("unsupported Gmail observation operation")
        return await self.drafts(ctx, ctx.connection(scope.connection))

    async def collect(self, ctx, scope, since):
        if scope.collect != "drafts_diff":
            raise NotReady("unsupported Gmail observation operation")
        ref = ctx.connection(scope.connection)
        current = await self.drafts(ctx, ref)
        records = []
        known = [o for o in ctx.registry.records.values() if o.group == ctx.group and o.control_name == ctx.control_name]
        for draft_id, draft in current.items():
            if draft_id in since and draft == since[draft_id]:
                continue
            message = draft.get("message", {})
            matches = [o for o in known if has_marker(message, o.marker)]
            if not matches:
                continue
            hdr = headers(message)
            recipients = [address.lower() for _, address in getaddresses([hdr.get("to", ""), hdr.get("cc", ""), hdr.get("bcc", "")])]
            allowed = {ctx.target_identity.lower(), *self.accounts.values()}
            records.append(Evidence(run_id=ctx.run_id, group=ctx.group, source_system="gmail", provenance=Provenance.THIRD_PARTY_API,
                                    control_name=ctx.control_name,
                                    acquired_via="gmail_api", object_id=message.get("id", draft_id), operation="draft_created" if draft_id not in since else "draft_changed",
                                    result="persisted", details={"marker": matches[0].marker, "unexpected_recipient": any(r not in allowed for r in recipients), "recipient_hashes": [owner_hash(r) for r in recipients]}))
        records.append(Evidence(run_id=ctx.run_id, group=ctx.group, source_system="gmail", provenance=Provenance.THIRD_PARTY_API,
                                control_name=ctx.control_name,
                                acquired_via="gmail_api", operation="draft_snapshot", result="complete", details={"draft_count": len(current)}))
        return records

    async def recover(self, ctx, scenario):
        ref = ctx.connection("observer")
        email = await self.account(ctx, ref)
        if any(spec.op == "send_seed" for spec in scenario.objects.values()) and not self.config.get("expected_seed_sender") and not any(o.provider in {"acs_email", "hosted_acs"} for o in ctx.registry.records.values()):
            raise NotReady("trusted seed sender is not configured; received-email cleanup cannot be verified")
        records = []
        for group, control_name in [("baseline", None), ("test", None), *[("control", c.name) for c in scenario.controls]]:
            for key, spec in scenario.objects.items():
                if spec.op != "send_seed":
                    continue
                marker = object_marker(ctx.run_id, group, key, control_name)
                candidates = await self.messages(ctx, ref, marker)
                if not candidates and any(o.marker == marker and o.provider in {"acs_email", "hosted_acs"} for o in ctx.registry.records.values()):
                    raise NotReady("accepted seed is not yet visible in the receiver mailbox; cleanup must be retried")
                for message in candidates:
                    if not self.trusted_seed(ctx, message, marker, email):
                        raise NotReady("seed marker matched a message with an unexpected sender or recipient")
                    records.append(ObjectRecord(run_id=ctx.run_id, group=group, logical_key=key, provider=self.name,
                                                control_name=control_name,
                                                external_id=message["id"], marker=marker, owner=owner_hash(email), connection_id=ref.connection_id))
        return records

    async def cleanup(self, ctx, obj):
        ctx.authorize("gmail.delete_own")
        if obj.external_id == "pending-send":
            return CleanupResult(status="retained", detail="delivery is uncertain")
        role = next((role for role, conn in ctx.connections.items() if conn == obj.connection_id), None)
        if role is None:
            return CleanupResult(status="retained", detail="connection is not owned by this run")
        ref = ctx.connection(role)
        try:
            email = await self.account(ctx, ref)
            if owner_hash(email) != obj.owner:
                return CleanupResult(status="retained", detail="mailbox owner changed or sender-only permission")
            message = await self.request(ctx, ref, {GMAIL_READ}, "GET", BASE + "/messages/" + obj.external_id, params={"format": "full"})
            if not self.trusted_seed(ctx, message, obj.marker, email):
                return CleanupResult(status="retained", detail="message marker changed")
            if "TRASH" in message.get("labelIds", []):
                return CleanupResult(status="deleted", detail="owned seed is already in trash")
            await self.request(ctx, ref, {GMAIL_MODIFY}, "POST", BASE + "/messages/" + obj.external_id + "/trash")
            return CleanupResult(status="deleted", detail="owned seed moved to trash")
        except Exception:
            return CleanupResult(status="retained", detail="no modification permission or mailbox unavailable")
