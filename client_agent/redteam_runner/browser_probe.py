"""BrowserProbe — handles redteam_browser_probe WS messages from the orchestrator."""

from __future__ import annotations

import asyncio
import time

from argus_transport import (
    ExecutionPolicy,
    TransportSpec,
    TransportResult,
    TransportOutcome,
    SafeReasonCode,
)

from .scenarios import dom_injection, os_cmd, ui_phishing, visual_injection
from .server import ScenarioServer

_SCENARIOS = {
    "dom_injection": dom_injection,
    "ui_phishing": ui_phishing,
    "visual_injection": visual_injection,
    "os_cmd": os_cmd,
}


def _make_scenario_server(scenario_kind: str, payload: str, **bind) -> ScenarioServer:
    if scenario_kind not in _SCENARIOS:
        raise ValueError(f"unknown scenario_kind: {scenario_kind!r}")
    mod = _SCENARIOS[scenario_kind]

    # Looked up at render time: the sink URL (and its port) exist only after start().
    def render() -> tuple[bytes | str, str]:
        return mod.render(payload.replace("{sink_url}", server.sink_url))

    server = ScenarioServer(render_fn=render, **bind)
    return server


def _make_target_agent_driver(agent_url, scenario_url, prompt, timeout_s, **transport):
    from .target_agent_driver import TargetAgentDriver

    return TargetAgentDriver(
        agent_url=agent_url,
        scenario_url=scenario_url,
        prompt=prompt,
        timeout_s=timeout_s,
        **transport,
    )


class BrowserProbe:
    async def run(self, msg: dict, *, policy: ExecutionPolicy | None = None) -> dict:
        prompt = msg.get("prompt", msg["payload"])
        transport = msg.get("transport")
        spec = TransportSpec.from_dict(transport) if transport is not None else None
        timeout_s = float(msg.get("timeout_s", 60.0))
        cleanup = spec.timeout.cleanup_grace_s if spec else 2.0
        bind = {
            k: msg[f"trap_{k}"]
            for k in ("host", "port", "public_url")
            if msg.get(f"trap_{k}")
        }
        server = _make_scenario_server(msg["scenario_kind"], msg["payload"], **bind)
        scenario_url = await server.start()
        try:
            kwargs = {}
            if spec:
                kwargs = {
                    "transport": spec.to_dict(),
                    "policy": policy or ExecutionPolicy(),
                    "history": tuple(msg.get("history", ())),
                    "conversation_id": msg.get("conversation_id", ""),
                    "session_id": msg.get("session_id"),
                }
            agent = _make_target_agent_driver(
                msg.get("agent_url"), scenario_url, prompt, timeout_s, **kwargs
            )
            started = time.monotonic()
            result = await agent.run()
            if isinstance(result, dict):
                result = TransportResult(
                    TransportOutcome.SUCCEEDED,
                    result.get("final_text", ""),
                    (time.monotonic() - started) * 1000,
                    200,
                    None,
                    SafeReasonCode.OK,
                )
            try:
                await asyncio.wait_for(server.settle(), timeout=cleanup)
            except TimeoutError:
                pass
            evidence = server.evidence()
            if spec:
                evidence = agent.redactor.clean(evidence)
            reply = {
                "transport_result": result.as_dict(),
                "trap_url": scenario_url,
                "trap_evidence": evidence,
            }
            if spec is None:
                reply.update(
                    final_text=result.response_text or "",
                    screenshots=[],
                    latency_ms=result.latency_ms,
                )
            return reply
        finally:
            await server.stop()
