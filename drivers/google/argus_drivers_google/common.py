from __future__ import annotations

import hashlib
import json
from datetime import timedelta

import httpx

from argus.scenarios.credentials import CredentialUnavailable, _check_token
from argus.scenarios.models import ConnCheck, now


GMAIL_READ = "https://www.googleapis.com/auth/gmail.readonly"
GMAIL_SEND = "https://www.googleapis.com/auth/gmail.send"
GMAIL_MODIFY = "https://www.googleapis.com/auth/gmail.modify"
DRIVE_FILE = "https://www.googleapis.com/auth/drive.file"


def owner_hash(email: str) -> str:
    return hashlib.sha256(email.strip().lower().encode()).hexdigest()


class GoogleDriver:
    def __init__(self, config: dict, provider):
        self.provider = provider
        self.config = config
        self.tokens = {}
        self.accounts = {}

    async def token(self, ctx, ref, scopes: set[str]):
        key = ref.connection_id, frozenset(scopes)
        token = self.tokens.get(key)
        if token is None or token.expires_at < now() + timedelta(seconds=30):
            token = await self.provider.access_token(ref, scopes)
            _check_token(token, scopes)
            self.tokens[key] = token
        ctx.secrets.add(token.value.get_secret_value())
        return token.value.get_secret_value()

    async def request(self, ctx, ref, scopes: set[str], method: str, url: str, **kwargs):
        token = await self.token(ctx, ref, scopes)
        ctx.budget.charge("third_party_calls", cleanup=ctx.cleanup_mode)
        headers = {"Authorization": "Bearer " + token, **kwargs.pop("headers", {})}
        raw = kwargs.pop("raw", False)
        limit = min(max(int(self.config.get("max_response_bytes", 1048576)), 1), 1048576)
        async with httpx.AsyncClient(timeout=30) as client:
            async with client.stream(method, url, headers=headers, **kwargs) as response:
                if response.status_code in {401, 403}:
                    raise CredentialUnavailable("Google connection is expired or lacks required permissions")
                response.raise_for_status()
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    if len(body) + len(chunk) > limit:
                        raise RuntimeError("Google response exceeded its bounded content read")
                    body.extend(chunk)
        return bytes(body).decode("utf-8") if raw else json.loads(body) if body else {}

    async def pages(self, ctx, ref, scopes, url, key, params):
        params = dict(params)
        rows = []
        for _ in range(100):
            data = await self.request(ctx, ref, scopes, "GET", url, params=params)
            rows.extend(data.get(key, []))
            if not data.get("nextPageToken"):
                return rows
            params["pageToken"] = data["nextPageToken"]
        raise RuntimeError("Google pagination did not complete within its bound")

    async def check(self, ctx, ref, need: set[str]):
        try:
            for scopes in self.scopes_for(need):
                await self.token(ctx, ref, scopes)
            return ConnCheck(active=True)
        except CredentialUnavailable:
            return ConnCheck(active=False, detail=f"{ref.role} connection needs reauthorization or additional scopes")
