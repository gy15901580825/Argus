"""Agent transport against a locally controlled A2A peer world."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import httpx

from argus.a2a.protocol import Interface, build_request, decode_response
from argus.a2a.world import CAPABILITIES
from argus.targets.testbed_agent import TestbedAgentTarget


def _http_url(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = urlsplit(value)
        parsed.port
        return (
            parsed.scheme in ("http", "https")
            and bool(parsed.hostname)
            and parsed.username is None
            and parsed.password is None
            and not parsed.fragment
        )
    except ValueError:
        return False


def validate_a2a_settings(
    *, testbed_url: str, capabilities, agent_credentials, receiver
) -> None:
    if testbed_url != "local" and (
        not _http_url(testbed_url)
        or urlsplit(testbed_url).hostname not in ("127.0.0.1", "localhost", "::1")
    ):
        raise ValueError(
            "the control interface only listens on this host; reach a remote testbed through a private channel to 127.0.0.1"
        )
    if not isinstance(capabilities, (list, tuple)) or any(
        not isinstance(c, str) or c not in CAPABILITIES for c in capabilities
    ):
        raise ValueError(
            "unknown capability in capabilities; use the documented A2A capability names"
        )
    if (
        "three_hop_chain" in capabilities
        and "observable_agent_lineage" not in capabilities
    ):
        raise ValueError("three_hop_chain requires observable_agent_lineage")
    if not isinstance(agent_credentials, dict):
        raise ValueError("agent_credentials must map roles to Authorization values")
    if any(r not in ("planner", "reviewer", "executor") for r in agent_credentials):
        raise ValueError("agent_credentials roles must be planner, reviewer, executor")
    if any(
        not isinstance(v, str) or not v.strip() or "\r" in v or "\n" in v
        for v in agent_credentials.values()
    ):
        raise ValueError(
            "agent_credentials values must be nonempty single-line credentials"
        )
    if len(set(agent_credentials.values())) != len(agent_credentials):
        raise ValueError("duplicate agent_credentials cannot prove distinct identities")
    if "observable_agent_lineage" in capabilities and not all(
        r in agent_credentials for r in ("planner", "reviewer", "executor")
    ):
        raise ValueError(
            "observable_agent_lineage requires planner, reviewer, executor credentials"
        )
    if "observable_action_sink" in capabilities and not agent_credentials:
        raise ValueError("observable_action_sink requires agent_credentials")
    if not isinstance(receiver, dict):
        raise ValueError("receiver must be an object")
    if "target_receiver" in capabilities and not _http_url(receiver.get("url")):
        raise ValueError("target_receiver requires an absolute HTTP(S) receiver.url")
    if receiver.get("url") and not _http_url(receiver["url"]):
        raise ValueError("receiver.url must be an absolute HTTP(S) URL")
    headers = receiver.get("headers", [])
    if not isinstance(headers, list) or any(
        not isinstance(row, (list, tuple))
        or len(row) != 2
        or any(not isinstance(v, str) or "\r" in v or "\n" in v for v in row)
        for row in headers
    ):
        raise ValueError("receiver.headers must be pairs of single-line strings")
    names = [
        row[0].lower()
        for row in headers
        if row[0].lower() not in ("a2a-version", "content-type")
    ]
    if len(set(names)) != len(names):
        raise ValueError("duplicate receiver header names are ambiguous")


@dataclass(frozen=True)
class A2AAgentSpec:
    kind: str = "a2a_agent"
    testbed_url: str = ""
    inner: dict[str, Any] = field(default_factory=dict)
    script: dict[str, Any] = field(default_factory=dict)
    sandbox: bool = False
    timeout_s: float = 60.0
    control_token: str = ""
    capabilities: tuple[str, ...] = ()
    agent_credentials: dict[str, str] = field(default_factory=dict)
    receiver: dict[str, Any] = field(default_factory=dict)
    peer_url: str = ""

    def __post_init__(self):
        if self.kind != "a2a_agent":
            raise ValueError("kind must be 'a2a_agent'")
        if not self.inner:
            raise ValueError("inner target spec is required")
        if self.sandbox is not True:
            raise ValueError("a2a_agent requires sandbox: true")
        validate_a2a_settings(
            testbed_url=self.testbed_url,
            capabilities=self.capabilities,
            agent_credentials=self.agent_credentials,
            receiver=self.receiver,
        )


class A2AAgentTarget(TestbedAgentTarget):
    compatible_classes = frozenset({"a2a_agent"})
    url_key = "a2a_url"
    staging_noun = "A2A peer world"
    teardown_label = "A2A testbed"
    controlled = True


async def deliver_ingress(
    spec, deliveries: list[dict], log: Callable[[dict], Awaitable[None]]
) -> None:
    iface = Interface(spec.receiver["url"], "HTTP+JSON", "")
    headers = {
        name: value
        for name, value in spec.receiver.get("headers", [])
        if name.lower() not in ("a2a-version", "content-type")
    }
    headers.update({"A2A-Version": "1.0", "Content-Type": "application/a2a+json"})
    async with httpx.AsyncClient(timeout=spec.timeout_s) as client:
        for index, delivery in enumerate(deliveries):
            request = build_request(iface, "SendMessage", delivery, index)
            row = {
                "index": index,
                "http_status": None,
                "outcome": "transport_error",
                "task_state": None,
            }
            try:
                response = await client.request(
                    request.method,
                    request.url,
                    json=request.json,
                    params=request.params,
                    headers=headers,
                )
                decoded = decode_response(
                    "HTTP+JSON", "SendMessage", response.status_code, response.content
                )
                row.update(http_status=response.status_code, outcome=decoded.outcome)
                if decoded.result_kind == "task":
                    row["task_state"] = (
                        decoded.result["task"].get("status", {}).get("state")
                    )
            except httpx.RequestError:
                pass
            await log(row)
