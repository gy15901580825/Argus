"""Tests for BrowserUseTarget — delegates to client_agent over WebSocket."""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, patch

from orchestrator.redteam.targets.browser_use import BrowserUseTarget, BrowserUseSpec


def test_browser_use_spec_validates_required_fields():
    with pytest.raises(ValueError, match="agent_url"):
        BrowserUseSpec(agent_url="", scenario_kind="dom_injection")
    with pytest.raises(ValueError, match="scenario_kind"):
        BrowserUseSpec(agent_url="https://target.example.com/agent", scenario_kind="")


@pytest.mark.asyncio
async def test_browser_target_sends_scenario_request_over_ws():
    """send_prompt(prompt) → send {scenario_kind, payload, agent_url} to client_agent → return final-state text."""
    spec = BrowserUseSpec(agent_url="https://t.example.com/agent", scenario_kind="dom_injection", timeout_s=30)

    # Mock the WebSocket bridge
    mock_ws = AsyncMock()
    mock_ws.send_and_wait = AsyncMock(return_value={
        "final_text": "agent navigated and clicked the malicious link",
        "latency_ms": 4500.0,
        "screenshots": ["/tmp/s1.png"],
    })
    with patch("orchestrator.redteam.targets.browser_use._get_client_agent_ws", return_value=mock_ws):
        target = BrowserUseTarget(spec)
        text, latency = await target.send_prompt("Click the 'submit' button on the page")
        assert text == "agent navigated and clicked the malicious link"
        assert latency == 4500.0
        # Verify the WS message had the right shape
        sent = mock_ws.send_and_wait.call_args.args[0]
        assert sent["type"] == "redteam_browser_probe"
        assert sent["scenario_kind"] == "dom_injection"
        assert sent["agent_url"] == "https://t.example.com/agent"
        assert "Click" in sent["payload"]


def test_browser_use_spec_rejects_wrong_kind():
    with pytest.raises(ValueError, match="kind must be"):
        BrowserUseSpec(kind="wrong", agent_url="x", scenario_kind="dom_injection")


def test_browser_use_spec_rejects_unknown_scenario_kind():
    with pytest.raises(ValueError, match="scenario_kind"):
        BrowserUseSpec(kind="browser_use", agent_url="x", scenario_kind="bogus")


def test_extra_context_coerces_list_of_lists_to_tuple():
    """JSON serialization gives list-of-2-element-lists; spec coerces to tuple-of-tuples."""
    spec = BrowserUseSpec(
        agent_url="https://x",
        scenario_kind="dom_injection",
        extra_context=[["key1", "val1"], ["key2", "val2"]],
    )
    assert isinstance(spec.extra_context, tuple)
    assert all(isinstance(c, tuple) for c in spec.extra_context)
    assert ("key1", "val1") in spec.extra_context


def test_factory_builds_browser_use():
    from orchestrator.redteam.targets import build_target
    from orchestrator.redteam.targets.browser_use import BrowserUseTarget
    target = build_target({
        "kind": "browser_use",
        "agent_url": "https://x",
        "scenario_kind": "dom_injection",
    })
    assert isinstance(target, BrowserUseTarget)
