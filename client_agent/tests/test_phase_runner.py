"""Tests for the run_all_phases orchestrator (Task 6)."""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

from web_ui_phases.runner import run_all_phases
from web_ui_phases.state import PhaseState


class _FakeHistory:
    def __init__(self, final_text: str, n_steps: int):
        self._final = final_text
        self.history = [MagicMock() for _ in range(n_steps)]

    def final_result(self) -> str:
        return self._final


def _mk_agent_factory(fake_outputs: list[str]):
    """Return a factory that produces a new MagicMock Agent per call."""
    calls = {"n": 0}

    def factory(task: str, **kwargs):
        idx = calls["n"]
        calls["n"] += 1
        out = fake_outputs[idx] if idx < len(fake_outputs) else ""
        agent = MagicMock()
        agent.run = AsyncMock(return_value=_FakeHistory(out, n_steps=2))
        agent._task_text = task
        return agent

    return factory, calls


def test_run_all_phases_no_credentials_skips_auth():
    state = PhaseState(url="https://x.com", domain="x.com")
    outputs = [
        '```json\n{"features": [{"name": "search", "url": "/s"}]}\n```',
        '```json\n{"features_tested": [{"name": "search", "status": "pass"}]}\n```',
        '```json\n{"bugs": [{"severity": "high", "description": "x"}]}\n```',
    ]
    factory, calls = _mk_agent_factory(outputs)
    asyncio.run(run_all_phases(
        state=state,
        max_steps=20,
        agent_factory=factory,
        on_phase_start=None,
        on_step_end=None,
    ))
    assert calls["n"] == 3  # auth skipped
    assert state.auth is None
    assert state.discovery is not None
    assert state.discovery.parsed["features"][0]["name"] == "search"
    assert len(state.feature_results) == 1
    assert len(state.bugs) == 1


def test_run_all_phases_with_credentials_runs_auth():
    state = PhaseState(
        url="https://x.com", domain="x.com",
        credentials={"username": "u", "password": "p"},
    )
    outputs = [
        '```json\n{"auth_status": "success"}\n```',
        '```json\n{"features": []}\n```',
        '```json\n{"features_tested": []}\n```',
        '```json\n{"bugs": []}\n```',
    ]
    factory, calls = _mk_agent_factory(outputs)
    asyncio.run(run_all_phases(
        state=state, max_steps=20, agent_factory=factory,
        on_phase_start=None, on_step_end=None,
    ))
    assert calls["n"] == 4
    assert state.auth is not None
    assert state.auth.parsed["auth_status"] == "success"


def test_run_all_phases_continues_on_malformed_phase_output():
    """A phase returning un-parseable JSON must NOT abort the whole pipeline."""
    state = PhaseState(url="https://x.com", domain="x.com")
    outputs = [
        "I forgot the JSON block, sorry.",       # phase 1 malformed
        '```json\n{"features_tested": []}\n```',
        '```json\n{"bugs": [{"severity": "low", "description": "y"}]}\n```',
    ]
    factory, calls = _mk_agent_factory(outputs)
    asyncio.run(run_all_phases(
        state=state, max_steps=20, agent_factory=factory,
        on_phase_start=None, on_step_end=None,
    ))
    assert calls["n"] == 3
    assert state.discovery is not None
    assert state.discovery.parsed == {}
    assert len(state.bugs) == 1


def test_run_all_phases_fires_on_phase_start_per_phase():
    state = PhaseState(url="https://x.com", domain="x.com")
    outputs = ['```json\n{}\n```'] * 3
    factory, _ = _mk_agent_factory(outputs)
    seen: list[str] = []

    async def on_start(name: str, budget: int):
        seen.append(name)

    asyncio.run(run_all_phases(
        state=state, max_steps=20, agent_factory=factory,
        on_phase_start=on_start, on_step_end=None,
    ))
    assert seen == ["discovery", "features", "bug_hunt"]
