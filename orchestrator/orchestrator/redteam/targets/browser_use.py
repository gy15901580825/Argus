"""Browser-use target adapter — delegates to client_agent over the existing WS bridge.

Plan 3 implemented the runtime; Plan 4 just exposes it via factory + REST API.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import ClassVar

from orchestrator.redteam.targets._base import Target


@dataclass(frozen=True)
class BrowserUseSpec:
    kind: str = "browser_use"
    agent_url: str = ""
    scenario_kind: str = ""
    timeout_s: float = 60.0
    extra_context: tuple[tuple[str, str], ...] = ()

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
        if self.scenario_kind not in {"dom_injection", "ui_phishing", "visual_injection", "os_cmd"}:
            raise ValueError(
                "scenario_kind must be one of dom_injection/ui_phishing/visual_injection/os_cmd"
            )


def _get_client_agent_ws():
    """Lazy import so tests can patch."""
    from connection_manager import connection_manager
    return connection_manager.get_redteam_bridge()


class BrowserUseTarget(Target):
    # Plan 4 name + Plan 2 legacy alias ("browser-using").
    compatible_classes: ClassVar[frozenset[str]] = frozenset({
        "browser_using_agent",
        "browser-using",
    })

    def __init__(self, spec: BrowserUseSpec) -> None:
        self.spec = spec

    async def send_prompt(self, prompt: str) -> tuple[str, float]:
        ws = _get_client_agent_ws()
        msg = {
            "type": "redteam_browser_probe",
            "scenario_kind": self.spec.scenario_kind,
            "agent_url": self.spec.agent_url,
            "payload": prompt,
            "timeout_s": self.spec.timeout_s,
            "extra_context": dict(self.spec.extra_context),
        }
        start = time.monotonic()
        reply = await asyncio.wait_for(
            ws.send_and_wait(msg),
            timeout=self.spec.timeout_s + 5.0,
        )
        wall_latency_ms = (time.monotonic() - start) * 1000.0
        reported = reply.get("latency_ms")
        latency_ms = float(reported) if isinstance(reported, (int, float)) else wall_latency_ms
        return reply.get("final_text", ""), latency_ms
