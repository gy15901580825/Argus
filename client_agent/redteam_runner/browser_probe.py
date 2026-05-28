"""BrowserProbe — handles redteam_browser_probe WS messages from the orchestrator."""

from __future__ import annotations

import time

from redteam_runner.scenarios import dom_injection, os_cmd, ui_phishing, visual_injection
from redteam_runner.server import ScenarioServer


_SCENARIOS = {
    "dom_injection": dom_injection,
    "ui_phishing": ui_phishing,
    "visual_injection": visual_injection,
    "os_cmd": os_cmd,
}


def _make_scenario_server(scenario_kind: str, payload: str) -> ScenarioServer:
    if scenario_kind not in _SCENARIOS:
        raise ValueError(f"unknown scenario_kind: {scenario_kind!r}")
    mod = _SCENARIOS[scenario_kind]
    return ScenarioServer(render_fn=lambda: mod.render(payload))


def _make_target_agent_driver(agent_url: str, scenario_url: str, prompt: str, timeout_s: float):
    """Returns a driver object with .run() coroutine that drives the customer's
    browser-using agent against the scenario URL.

    For v0 we assume the customer agent has a generic 'navigate to URL + follow
    instruction' interface accessible at agent_url. (CLI will validate this in
    `validate-target` subcommand.)
    """
    from redteam_runner.target_agent_driver import TargetAgentDriver  # see Task 7
    return TargetAgentDriver(agent_url=agent_url, scenario_url=scenario_url, prompt=prompt, timeout_s=timeout_s)


class BrowserProbe:
    async def run(self, msg: dict) -> dict:
        scenario_kind = msg["scenario_kind"]
        payload = msg["payload"]
        agent_url = msg["agent_url"]
        timeout_s = float(msg.get("timeout_s", 60.0))

        server = _make_scenario_server(scenario_kind, payload)
        scenario_url = await server.start()
        try:
            agent = _make_target_agent_driver(agent_url, scenario_url, payload, timeout_s)
            start = time.monotonic()
            result = await agent.run()
            latency_ms = (time.monotonic() - start) * 1000.0
            return {
                "final_text": result.get("final_text", ""),
                "screenshots": result.get("screenshots", []),
                "latency_ms": latency_ms,
            }
        finally:
            await server.stop()
