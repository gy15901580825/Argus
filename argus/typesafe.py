"""The TypeSafe System One HTTP client, shared by the Jev decider and the Jev judge."""

from __future__ import annotations

import asyncio
import os
from typing import Mapping, Optional

import httpx

DEFAULT_URL = "https://api.typesafe.ai/v1/systemone"
# TypeSafe asks clients to back off and retry on these (docs.typesafe.ai/api/errors); 5xx is transient too.
_RETRY_STATUS = frozenset({429, 529})


def api_url(env: Optional[Mapping[str, str]] = None) -> str:
    env = os.environ if env is None else env
    return (env.get("TYPESAFE_API_URL") or "").strip() or DEFAULT_URL


def api_key(env: Optional[Mapping[str, str]] = None) -> Optional[str]:
    env = os.environ if env is None else env
    return (env.get("TYPESAFE_API_KEY") or "").strip() or None


async def send(url: str, key: str, body: dict, timeout_s: float) -> httpx.Response:
    """One POST. The only place a request to TypeSafe is made, so tests can guard it."""
    async with httpx.AsyncClient(timeout=timeout_s) as client:
        return await client.post(url, json=body, headers={"Authorization": f"Bearer {key}"})


async def post_json(url: str, key: str, body: dict, *, timeout_s: float, attempts: int = 3) -> dict:
    """POST with backoff on 429/529/5xx, timeouts and transport errors; the JSON body, or the last error raised."""
    for attempt in range(attempts):
        last = attempt == attempts - 1
        try:
            # httpx timeouts are per phase; wait_for bounds the whole call.
            resp = await asyncio.wait_for(send(url, key, body, timeout_s), timeout_s)
        except (httpx.TransportError, asyncio.TimeoutError):
            if last:
                raise
        else:
            if last or not (resp.status_code in _RETRY_STATUS or resp.status_code >= 500):
                resp.raise_for_status()
                return resp.json()
        await _sleep(2 ** attempt)
    raise AssertionError("unreachable")  # pragma: no cover - the last attempt returns or raises


async def _sleep(seconds: float) -> None:
    # Indirection so tests can skip the backoff.
    await asyncio.sleep(seconds)


def choice_answer(data, question: str) -> dict:
    """The answer to one choice question: under `answers`, or at the top level as some responses put it."""
    if not isinstance(data, dict):
        raise ValueError("the response is not a JSON object")
    answers = data.get("answers")
    answer = answers.get(question) if isinstance(answers, dict) else data.get(question)
    if not isinstance(answer, dict):
        raise ValueError(f"no answer to {question!r} in the response")
    return answer
