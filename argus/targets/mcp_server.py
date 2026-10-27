"""Target adapter for an MCP server reachable over HTTP (Streamable HTTP).

The other adapters test an agent. This one tests the server an agent connects
to, for the exposure in GHSA-mvf5-2qqv-rg3c: a server that accepts requests
from any web origin, without authentication, while offering a tool that hands
out secrets. Any page open in the developer's browser can then call it.

What it sends, and only this:
- an OPTIONS preflight and an `initialize` carrying a foreign `Origin`;
- an `initialize` without the configured credentials;
- `initialize` + `tools/list` with the configured credentials.

`serverInfo` from `initialize` is kept for the known-vulnerable-version check.

It never sends `tools/call`. Listing a tool that dumps the environment proves
the exposure; calling it would copy the customer's secrets into our evidence.
The legacy SSE transport (GET /sse + POST /message) is not covered.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import ClassVar

import httpx

from argus.targets._base import Target, Turn

FOREIGN_ORIGIN = "https://argus-origin-check.invalid"
PROTOCOL_VERSION = "2025-06-18"


def _initialize(req_id: int) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "method": "initialize",
            "params": {"protocolVersion": PROTOCOL_VERSION, "capabilities": {},
                       "clientInfo": {"name": "argus-probe", "version": "1"}}}


def _rpc_body(resp: httpx.Response) -> dict | None:
    """The JSON-RPC message in a JSON or text/event-stream reply; None if there is none."""
    text = resp.text
    if "text/event-stream" in resp.headers.get("content-type", ""):
        text = "\n".join(ln[5:].strip() for ln in text.splitlines() if ln.startswith("data:"))
    try:
        body = json.loads(text)
    except ValueError:
        return None
    return body if isinstance(body, dict) else None


def _server_info(resp: httpx.Response | None) -> dict | None:
    body = _rpc_body(resp) if resp is not None and resp.is_success else None
    info = body.get("result", {}).get("serverInfo") if body and isinstance(body.get("result"), dict) else None
    return {"name": str(info.get("name", "")), "version": str(info.get("version", ""))} \
        if isinstance(info, dict) else None


def _initialized(resp: httpx.Response) -> bool:
    body = _rpc_body(resp)
    return resp.is_success and body is not None and isinstance(body.get("result"), dict)


@dataclass(frozen=True)
class MCPServerSpec:
    kind: str = "mcp_server"
    # The Streamable HTTP endpoint, e.g. http://127.0.0.1:3001/mcp
    url: str = ""
    # Credentials a legitimate client sends. Left out of the foreign-origin and
    # no-auth requests on purpose.
    headers: tuple[tuple[str, str], ...] = ()
    timeout_s: float = 30.0

    def __post_init__(self) -> None:
        hdrs = self.headers
        if isinstance(hdrs, dict):
            object.__setattr__(self, "headers", tuple(hdrs.items()))
        elif isinstance(hdrs, list):
            object.__setattr__(self, "headers", tuple(tuple(h) for h in hdrs))
        if self.kind != "mcp_server":
            raise ValueError(f"kind must be 'mcp_server', got {self.kind!r}")
        if not self.url:
            raise ValueError("url is required")


class MCPServerTarget(Target):
    compatible_classes: ClassVar[frozenset[str]] = frozenset({"mcp_server"})

    def __init__(self, spec: MCPServerSpec) -> None:
        self.spec = spec
        self._transport: httpx.AsyncBaseTransport | None = None  # tests inject a MockTransport
        self._evidence: dict = {}

    async def begin_probe(self, probe) -> None:
        self._evidence = {}

    async def collect_evidence(self) -> dict:
        return dict(self._evidence)

    async def send_prompt(self, prompt: str, history: tuple[Turn, ...] = ()) -> tuple[str, float]:
        """Runs the passive checks once per probe; `prompt` is not sent anywhere."""
        start = time.monotonic()
        if not self._evidence:
            self._evidence = await self._check()
        return json.dumps(self._evidence, sort_keys=True), (time.monotonic() - start) * 1000.0

    async def _check(self) -> dict:
        base = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
        auth = dict(self.spec.headers)
        ev: dict = {"interaction_count": 0, "url": self.spec.url}
        async with httpx.AsyncClient(timeout=self.spec.timeout_s, transport=self._transport) as c:
            async def call(method: str, **kw) -> httpx.Response | None:
                try:
                    r = await c.request(method, self.spec.url, **kw)
                except httpx.HTTPError as e:
                    ev.setdefault("errors", []).append(f"{method}: {type(e).__name__}")
                    return None
                ev["interaction_count"] += 1
                return r

            pre = await call("OPTIONS", headers={"Origin": FOREIGN_ORIGIN, "Access-Control-Request-Method": "POST",
                                                 "Access-Control-Request-Headers": "content-type"})
            foreign = await call("POST", headers={**base, "Origin": FOREIGN_ORIGIN}, json=_initialize(1))
            acao = {(r.headers.get("access-control-allow-origin") or "") for r in (pre, foreign) if r is not None}
            ev["cors_allow_origin"] = sorted(a for a in acao if a)
            ev["cors_allows_foreign_origin"] = bool(acao & {"*", FOREIGN_ORIGIN})
            ev["foreign_origin_initialized"] = foreign is not None and _initialized(foreign)

            noauth = await call("POST", headers=base, json=_initialize(2))
            ev["unauthenticated_initialized"] = noauth is not None and _initialized(noauth)

            init = await call("POST", headers={**base, **auth}, json=_initialize(3))
            tools = None
            if init is not None and _initialized(init):
                sess = {"Mcp-Session-Id": init.headers["mcp-session-id"]} if "mcp-session-id" in init.headers else {}
                ver = {"MCP-Protocol-Version": PROTOCOL_VERSION}
                await call("POST", headers={**base, **auth, **sess, **ver},
                           json={"jsonrpc": "2.0", "method": "notifications/initialized"})
                listed = await call("POST", headers={**base, **auth, **sess, **ver},
                                    json={"jsonrpc": "2.0", "id": 4, "method": "tools/list"})
                body = _rpc_body(listed) if listed is not None else None
                if body and isinstance(body.get("result"), dict):
                    tools = [{"name": str(t.get("name", "")), "description": str(t.get("description") or "")}
                             for t in body["result"].get("tools") or [] if isinstance(t, dict)]
            ev["tools"] = tools
            ev["server_info"] = _server_info(init) or _server_info(noauth) or _server_info(foreign)
        return ev
