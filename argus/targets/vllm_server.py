"""Target adapter for a vLLM OpenAI-compatible server, for one passive check.

It sends a single `GET {url}/version` and records the version vLLM reports.
vLLM's `--api-key` does not cover `/version` (docs/usage/security.md), so a
bare server answers without credentials; the configured headers are sent
anyway for proxies that require them. A proxy that forwards only `/v1/*`
leaves the server unidentified, and the check fails closed.

Nothing else is sent. The vLLM advisories this feeds are denial-of-service
bugs; confirming them would mean taking the customer's server down.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import ClassVar

import httpx

from argus.targets._base import Target, Turn


@dataclass(frozen=True)
class VLLMServerSpec:
    kind: str = "vllm_server"
    # Server root, e.g. http://10.0.0.5:8000 (not the /v1 path).
    url: str = ""
    headers: tuple[tuple[str, str], ...] = ()
    timeout_s: float = 30.0

    def __post_init__(self) -> None:
        hdrs = self.headers
        if isinstance(hdrs, dict):
            object.__setattr__(self, "headers", tuple(hdrs.items()))
        elif isinstance(hdrs, list):
            object.__setattr__(self, "headers", tuple(tuple(h) for h in hdrs))
        if self.kind != "vllm_server":
            raise ValueError(f"kind must be 'vllm_server', got {self.kind!r}")
        if not self.url:
            raise ValueError("url is required")


class VLLMServerTarget(Target):
    compatible_classes: ClassVar[frozenset[str]] = frozenset({"vllm_server"})

    def __init__(self, spec: VLLMServerSpec) -> None:
        self.spec = spec
        self._transport: httpx.AsyncBaseTransport | None = None  # tests inject a MockTransport
        self._evidence: dict = {}

    async def begin_probe(self, probe) -> None:
        self._evidence = {}

    async def collect_evidence(self) -> dict:
        return dict(self._evidence)

    async def send_prompt(self, prompt: str, history: tuple[Turn, ...] = ()) -> tuple[str, float]:
        """Reads /version once per probe; `prompt` is not sent anywhere."""
        start = time.monotonic()
        if not self._evidence:
            self._evidence = await self._check()
        return str(self._evidence.get("server_version")), (time.monotonic() - start) * 1000.0

    async def _check(self) -> dict:
        ev: dict = {"interaction_count": 0, "server_version": None}
        url = self.spec.url.rstrip("/") + "/version"
        async with httpx.AsyncClient(timeout=self.spec.timeout_s, transport=self._transport) as c:
            try:
                r = await c.get(url, headers=dict(self.spec.headers))
            except httpx.HTTPError as e:
                ev["errors"] = [f"GET /version: {type(e).__name__}"]
                return ev
        ev["interaction_count"] = 1
        try:
            body = r.json() if r.is_success else None
        except ValueError:
            body = None
        if isinstance(body, dict) and isinstance(body.get("version"), str):
            ev["server_version"] = body["version"]
        else:
            ev["errors"] = [f"GET /version: HTTP {r.status_code}, no version field"]
        return ev
