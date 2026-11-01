"""HTTP calls restricted to the configured peer and agent origins."""

from __future__ import annotations

from urllib.parse import urlsplit

import httpx
from httpx import AsyncClient

peer_base_url = ""
agent_base_url = ""


def origin(url: str) -> tuple[str, str, int | None]:
    parsed = urlsplit(url)
    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        raise ValueError("an absolute HTTP origin without credentials is required")
    return (
        parsed.scheme,
        parsed.hostname,
        parsed.port or (443 if parsed.scheme == "https" else 80),
    )


def configure(peer_url: str) -> None:
    global peer_base_url, agent_base_url
    origin(peer_url)
    peer_base_url = peer_url.rstrip("/")
    agent_base_url = ""


def set_agent_origin(url: str) -> None:
    global agent_base_url
    origin(url)
    agent_base_url = url.rstrip("/")


async def request_json(
    method: str, url: str, credential: str, body: dict | None = None
) -> tuple[int, dict | list | None]:
    allowed = {origin(peer_base_url)}
    if agent_base_url:
        allowed.add(origin(agent_base_url))
    if origin(url) not in allowed:
        raise ValueError("outbound origin is not approved")
    headers = {
        "Authorization": credential,
        "A2A-Version": "1.0",
        "Content-Type": "application/a2a+json",
    }
    async with AsyncClient(
        timeout=15, follow_redirects=False, trust_env=False
    ) as transport:
        response = await transport.request(method, url, json=body, headers=headers)
    try:
        document = response.json()
    except ValueError:
        document = None
    return response.status_code, document


async def send(url, request: dict, credential: str) -> tuple[int, dict | None]:
    return await request_json("POST", url, credential, request)


async def get_json(url, credential) -> tuple[int, dict | None]:
    return await request_json("GET", url, credential)


async def report(kind, peer_role, message, credential, parent_message_ids=()) -> None:
    await request_json(
        "POST",
        peer_base_url + "/telemetry",
        credential,
        {
            "events": [
                {
                    "kind": kind,
                    "peer_role": peer_role,
                    "message": message,
                    "parent_message_ids": list(parent_message_ids),
                    "task_id": message.get("taskId"),
                    "context_id": message.get("contextId"),
                }
            ]
        },
    )
