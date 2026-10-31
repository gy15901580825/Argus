from __future__ import annotations

import asyncio
import hashlib
import time
from collections import deque

from argus.scenarios.models import CleanupResult, ConnCheck, ObjectRecord
from argus.scenarios.runtime import NotReady
from argus.scenarios.credentials import CredentialUnavailable, _check_token


_sends: deque = deque()
_lock = asyncio.Lock()


class ACSEmailDriver:
    name = "acs_email"

    def __init__(self, config: dict, provider):
        self.config, self.provider = config, provider

    async def check(self, ctx, ref, need):
        sender = self.config.get("sender", "")
        if not sender.endswith(".azurecomm.net"):
            return ConnCheck(active=False, detail="local ACS driver requires a configured test-only Azure managed sender")
        try:
            selected = ctx.connection(self.config["connection"]) if self.config.get("connection") else ref
            token = await self.provider.access_token(selected, {"acs.email.send"})
            _check_token(token, {"acs.email.send"})
        except CredentialUnavailable:
            return ConnCheck(active=False, detail="ACS test credential is expired or unavailable")
        return ConnCheck(active=True)

    async def prepare(self, ctx, key, spec):
        ctx.authorize("acs_email.send_seed")
        marker = ctx.marker(key)
        existing = [obj for obj in ctx.registry.records.values() if obj.provider == self.name and obj.marker == marker]
        if existing:
            if existing[0].external_id == "pending-send":
                raise NotReady("ACS delivery is uncertain; do not resend without checking the target mailbox")
            return existing[0]
        ref = ctx.connection(self.config.get("connection", spec.connection))
        token = await self.provider.access_token(ref, {"acs.email.send"})
        _check_token(token, {"acs.email.send"})
        secret = token.value.get_secret_value()
        ctx.secrets.add(secret)
        sender = self.config.get("sender", "")
        if not sender.endswith(".azurecomm.net"):
            raise NotReady("local ACS driver only sends from Azure managed test domains")
        async with _lock:
            current = time.monotonic()
            while _sends and current - _sends[0] >= 3600:
                _sends.popleft()
            if len(_sends) >= 10 or sum(current - sent < 60 for sent in _sends) >= 5:
                raise NotReady("ACS managed-domain test sending quota exhausted")
            _sends.append(current)
        obj = ObjectRecord(run_id=ctx.run_id, group=ctx.group, logical_key=key, provider=self.name, external_id="pending-send",
                           control_name=ctx.control_name,
                           marker=marker, owner=hashlib.sha256(sender.strip().lower().encode()).hexdigest(), connection_id=ref.connection_id)
        ctx.registry.save(obj)
        ctx.budget.charge("third_party_calls")
        from azure.communication.email.aio import EmailClient
        message = {"senderAddress": sender, "recipients": {"to": [{"address": ctx.target_identity}]},
                   "content": {"subject": spec.subject + " " + marker, "plainText": spec.content + "\n\n" + marker},
                   "headers": {"X-Argus-Marker": marker}}
        async with EmailClient.from_connection_string(secret) as client:
            poller = await client.begin_send(message)
            delivery = await poller.result()
        if delivery.get("status") != "Succeeded":
            raise NotReady("ACS did not confirm acceptance of the seed email")
        ctx.registry.records.pop(ctx.registry.key(obj), None)
        obj.external_id = delivery["id"]
        return obj

    async def readiness(self, ctx, check):
        raise NotReady("local ACS driver does not support mailbox readiness; use an observer driver")

    async def snapshot(self, ctx, scope):
        raise NotReady("local ACS driver does not support mailbox snapshots; use an observer driver")

    async def collect(self, ctx, scope, since):
        raise NotReady("local ACS driver does not support mailbox observation; use an observer driver")

    async def recover(self, ctx, scenario):
        return []

    async def cleanup(self, ctx, obj):
        return CleanupResult(status="not_applicable", detail="ACS has no sender mailbox; observer cleanup handles the received seed")
