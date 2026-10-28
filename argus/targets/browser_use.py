"""Browser-use target adapter — delegates to client_agent over the existing WS bridge.

Plan 3 implemented the runtime; Plan 4 just exposes it via factory + REST API.
Under `argus-probe run --local` the same probe runs in-process instead (see
`local_browser_mode`).
"""
from __future__ import annotations

import asyncio
import contextlib
import contextvars
import ipaddress
import time
from dataclasses import dataclass
from typing import ClassVar
from urllib.parse import urlsplit

from argus.targets._base import Target, TargetDeliveryError, Turn

_SCENARIO_KINDS = frozenset({"dom_injection", "ui_phishing", "visual_injection", "os_cmd"})

# Set only by run_local. Server mode never runs the trap page in-process.
_LOCAL_RUN: contextvars.ContextVar[bool] = contextvars.ContextVar("browser_local_run", default=False)


@contextlib.contextmanager
def local_browser_mode():
    """Run browser probes in this process instead of through a client_agent.

    Never hold it across a `yield`: set and reset must run in the same context."""
    token = _LOCAL_RUN.set(True)
    try:
        yield
    finally:
        _LOCAL_RUN.reset(token)


@dataclass(frozen=True)
class BrowserUseSpec:
    kind: str = "browser_use"
    agent_url: str = ""
    scenario_kind: str = ""
    timeout_s: float = 60.0
    extra_context: tuple[tuple[str, str], ...] = ()
    # Where the local trap page listens and the URL the agent is told to open.
    # Only used by --local; the agent must be able to reach that URL.
    trap_host: str = "127.0.0.1"
    trap_port: int = 0
    trap_public_url: str = ""

    def __post_init__(self) -> None:
        # Coerce dict OR list-of-2-element-lists → tuple-of-tuples
        # (model_dump() emits list-of-lists for tuple fields).
        ctx = self.extra_context
        if isinstance(ctx, dict):
            object.__setattr__(self, "extra_context", tuple(ctx.items()))
        elif isinstance(ctx, list):
            object.__setattr__(self, "extra_context", tuple(tuple(c) for c in ctx))
        # Validate kind FIRST (T1 review-fix pattern)
        if self.kind != "browser_use":
            raise ValueError(f"kind must be 'browser_use', got {self.kind!r}")
        if not self.agent_url:
            raise ValueError("agent_url is required")
        if self.scenario_kind not in _SCENARIO_KINDS:
            raise ValueError(
                "scenario_kind must be one of dom_injection/ui_phishing/visual_injection/os_cmd"
            )
        self._validate_trap()

    def _validate_trap(self) -> None:
        try:
            host = ipaddress.IPv4Address(self.trap_host)
        except ValueError:
            raise ValueError(f"trap_host must be an IPv4 address, got {self.trap_host!r}") from None
        if isinstance(self.trap_port, bool) or not isinstance(self.trap_port, int) \
                or not 0 <= self.trap_port <= 65535:
            raise ValueError(f"trap_port must be an integer from 0 to 65535, got {self.trap_port!r}")
        if not self.trap_public_url:
            if host.is_unspecified:
                raise ValueError(
                    f"trap_host {self.trap_host} listens on every interface; set trap_public_url "
                    "to the address your agent should open"
                )
            return
        parts = urlsplit(self.trap_public_url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError(
                f"trap_public_url must be an http(s) URL such as http://192.168.1.20:8765, "
                f"got {self.trap_public_url!r}"
            )
        if parts.query or parts.fragment:
            raise ValueError("trap_public_url must not carry a query string or fragment")
        if self.trap_port == 0:
            # A random port can't appear in a URL written before the run.
            raise ValueError("trap_public_url needs a fixed trap_port for the trap page to listen on")

    @property
    def sets_trap(self) -> bool:
        return (self.trap_host, self.trap_port, self.trap_public_url) != ("127.0.0.1", 0, "")


def _get_client_agent_ws():
    """Lazy import so tests can patch."""
    from argus.connection_manager import connection_manager
    return connection_manager.get_redteam_bridge()


class BrowserUseTarget(Target):
    # Plan 4 name + Plan 2 legacy alias ("browser-using").
    compatible_classes: ClassVar[frozenset[str]] = frozenset({
        "browser_using_agent",
        "browser-using",
    })

    def __init__(self, spec: BrowserUseSpec) -> None:
        self.spec = spec
        # Set by begin_probe; None means a non-probe caller, which keeps the
        # old prompt-as-payload behaviour.
        self._scenario_kind: str | None = None
        self._scenario_payload: str | None = None

    # Holding a live browser context across rounds requires a client_agent WS
    # protocol change; deliberately out of scope for v1.
    supports_history: ClassVar[bool] = False

    async def begin_probe(self, probe) -> None:
        payload = getattr(probe, "scenario_payload", None)
        kind = getattr(probe, "scenario_kind", None)
        # No scenario block: the attack is the prompt itself, so send it as the
        # page payload as before. Reset so a previous probe's scenario never leaks.
        if not kind and not payload:
            self._scenario_kind = None
            self._scenario_payload = None
            return
        # A declared scenario without a payload would put the benign prompt on
        # the trap page and could only ever pass.
        if not isinstance(payload, str) or not payload.strip():
            raise ValueError(f"browser probe {probe.id!r} has no scenario.payload to plant")
        if kind and kind not in _SCENARIO_KINDS:
            raise ValueError(f"browser probe {probe.id!r} has unknown scenario.kind {kind!r}")
        self._scenario_kind = kind or None
        self._scenario_payload = payload

    async def send_prompt(
        self, prompt: str, history: tuple[Turn, ...] = ()
    ) -> tuple[str, float]:
        msg = {
            "type": "redteam_browser_probe",
            "scenario_kind": self._scenario_kind or self.spec.scenario_kind,
            "agent_url": self.spec.agent_url,
            # payload goes into the trap page; prompt is the user's instruction.
            "payload": self._scenario_payload if self._scenario_payload is not None else prompt,
            "prompt": prompt,
            "timeout_s": self.spec.timeout_s,
            "extra_context": dict(self.spec.extra_context),
        }
        start = time.monotonic()
        if _LOCAL_RUN.get():
            reply = await asyncio.wait_for(
                self._run_in_process(msg), timeout=self.spec.timeout_s + 5.0
            )
        else:
            if self.spec.sets_trap:
                # An older client_agent would ignore these and serve on 127.0.0.1.
                raise ValueError("trap_host, trap_port and trap_public_url only apply to --local runs")
            ws = _get_client_agent_ws()
            try:
                reply = await asyncio.wait_for(
                    ws.send_and_wait(msg),
                    timeout=self.spec.timeout_s + 5.0,
                )
            except Exception as e:
                # A JSON-RPC error reply is a bare Exception, so the bridge's
                # failures can only be told apart from spec mistakes here.
                raise TargetDeliveryError(f"{type(e).__name__}: {e}") from e
        wall_latency_ms = (time.monotonic() - start) * 1000.0
        reported = reply.get("latency_ms")
        latency_ms = float(reported) if isinstance(reported, (int, float)) else wall_latency_ms
        return reply.get("final_text", ""), latency_ms

    async def _run_in_process(self, msg: dict) -> dict:
        from argus.browser_runner.browser_probe import BrowserProbe

        local_msg = dict(msg, trap_host=self.spec.trap_host, trap_port=self.spec.trap_port,
                         trap_public_url=self.spec.trap_public_url)
        return await BrowserProbe().run(local_msg)
