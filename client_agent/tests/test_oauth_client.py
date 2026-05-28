"""L3 tests for client_agent.OAuthClient — token request, caching, and expiry.

We mock httpx.AsyncClient so no real HTTP goes out, and freeze
`client_agent.datetime` to drive the expiry-buffer logic deterministically.
"""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import httpx
import pytest


class _FakeAsyncClient:
    """Tiny async-context httpx.AsyncClient stand-in."""

    def __init__(self, post_response=None, raise_exc=None):
        self._post_response = post_response
        self._raise_exc = raise_exc
        self.calls: list[dict] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def post(self, url, json=None, headers=None):
        self.calls.append({"url": url, "json": json, "headers": headers})
        if self._raise_exc is not None:
            raise self._raise_exc
        return self._post_response


def _ok_token_response(access="tok-1", refresh="rtok-1", expires_in=3600):
    resp = MagicMock()
    resp.status_code = 200
    resp.raise_for_status = MagicMock()
    resp.json = MagicMock(return_value={
        "access_token": access,
        "refresh_token": refresh,
        "expires_in": expires_in,
    })
    return resp


# ---------------------------------------------------------------------------
# request_token — happy path and URL shape
# ---------------------------------------------------------------------------

def test_request_token_success_stores_credentials_and_expiry():
    import client_agent

    client = client_agent.OAuthClient("http://api.invalid", "alice", "pw")
    fake = _FakeAsyncClient(post_response=_ok_token_response(expires_in=1800))

    fixed_now = datetime(2024, 1, 1, 12, 0, 0)

    class _FrozenDT(datetime):
        @classmethod
        def now(cls, tz=None):
            return fixed_now

    with patch("client_agent.httpx.AsyncClient", return_value=fake), \
         patch("client_agent.datetime", _FrozenDT):
        result = asyncio.run(client.request_token())

    assert result["access_token"] == "tok-1"
    assert client.access_token == "tok-1"
    assert client.refresh_token == "rtok-1"
    # Expiry ≈ fixed_now + 1800s
    assert client.token_expires_at == fixed_now + timedelta(seconds=1800)
    # URL was normalized to include /api/v1/auth/login
    assert fake.calls[0]["url"] == "http://api.invalid/api/v1/auth/login"
    assert fake.calls[0]["json"] == {"username": "alice", "password": "pw"}


def test_request_token_accepts_url_that_already_has_api_v1_suffix():
    import client_agent

    client = client_agent.OAuthClient("http://api.invalid/api/v1", "u", "p")
    fake = _FakeAsyncClient(post_response=_ok_token_response())

    with patch("client_agent.httpx.AsyncClient", return_value=fake):
        asyncio.run(client.request_token())

    # Should NOT double-append /api/v1
    assert fake.calls[0]["url"] == "http://api.invalid/api/v1/auth/login"


def test_request_token_raises_when_response_missing_access_token():
    import client_agent

    resp = MagicMock()
    resp.raise_for_status = MagicMock()
    resp.json = MagicMock(return_value={"refresh_token": "r"})  # no access_token
    fake = _FakeAsyncClient(post_response=resp)

    client = client_agent.OAuthClient("http://api.invalid", "u", "p")
    with patch("client_agent.httpx.AsyncClient", return_value=fake):
        with pytest.raises(Exception, match="No access_token"):
            asyncio.run(client.request_token())


def test_request_token_wraps_http_error_in_exception():
    import client_agent

    err_resp = MagicMock()
    err_resp.status_code = 401
    err_resp.text = "bad password"
    http_err = httpx.HTTPStatusError("401 Unauthorized", request=MagicMock(), response=err_resp)

    resp = MagicMock()
    resp.raise_for_status = MagicMock(side_effect=http_err)
    fake = _FakeAsyncClient(post_response=resp)

    client = client_agent.OAuthClient("http://api.invalid", "u", "p")
    with patch("client_agent.httpx.AsyncClient", return_value=fake):
        with pytest.raises(Exception, match="401"):
            asyncio.run(client.request_token())


# ---------------------------------------------------------------------------
# get_access_token — caching + refresh behavior
# ---------------------------------------------------------------------------

def test_get_access_token_returns_cached_token_when_still_valid():
    import client_agent

    client = client_agent.OAuthClient("http://api.invalid", "u", "p")
    client.access_token = "cached"
    # Token expires 1 hour from now; buffer is 5 minutes → still valid.
    client.token_expires_at = datetime.now() + timedelta(hours=1)

    # If it tries to request, this would blow up because AsyncClient isn't patched
    # to anything — so successful return proves cache hit.
    tok = asyncio.run(client.get_access_token())
    assert tok == "cached"


def test_get_access_token_refreshes_when_within_expiry_buffer():
    import client_agent

    client = client_agent.OAuthClient("http://api.invalid", "u", "p")
    client.access_token = "stale"
    # Expires in 60s — within 300s refresh buffer → must refresh.
    client.token_expires_at = datetime.now() + timedelta(seconds=60)

    fake = _FakeAsyncClient(post_response=_ok_token_response(access="fresh"))
    with patch("client_agent.httpx.AsyncClient", return_value=fake):
        tok = asyncio.run(client.get_access_token())

    assert tok == "fresh"
    assert client.access_token == "fresh"
    assert len(fake.calls) == 1


def test_get_access_token_refreshes_when_no_token_at_all():
    import client_agent

    client = client_agent.OAuthClient("http://api.invalid", "u", "p")
    assert client.access_token is None

    fake = _FakeAsyncClient(post_response=_ok_token_response(access="brand-new"))
    with patch("client_agent.httpx.AsyncClient", return_value=fake):
        tok = asyncio.run(client.get_access_token())
    assert tok == "brand-new"


# ---------------------------------------------------------------------------
# get_seconds_until_expiry
# ---------------------------------------------------------------------------

def test_seconds_until_expiry_none_when_unset():
    import client_agent

    client = client_agent.OAuthClient("http://api.invalid", "u", "p")
    assert client.get_seconds_until_expiry() is None


def test_seconds_until_expiry_positive_for_future_token():
    import client_agent

    client = client_agent.OAuthClient("http://api.invalid", "u", "p")
    client.token_expires_at = datetime.now() + timedelta(seconds=120)
    s = client.get_seconds_until_expiry()
    # Allow small jitter for scheduling
    assert s is not None and 100 < s <= 120


def test_seconds_until_expiry_clamps_to_zero_when_already_expired():
    import client_agent

    client = client_agent.OAuthClient("http://api.invalid", "u", "p")
    client.token_expires_at = datetime.now() - timedelta(seconds=60)
    assert client.get_seconds_until_expiry() == 0
