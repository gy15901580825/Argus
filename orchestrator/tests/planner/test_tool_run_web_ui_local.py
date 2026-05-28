import json
from types import SimpleNamespace

import pytest

from orchestrator.planner.tools.run_web_ui_local import run_web_ui_local


def _ctx(state: dict):
    return SimpleNamespace(session=SimpleNamespace(state=state))


@pytest.mark.asyncio
async def test_happy_path_accumulates_bugs_and_script(monkeypatch):
    """Artifact + web_ui_bug events drive the terminal summary."""

    async def fake_runner(**_kwargs):
        yield {"event_type": "log",
               "payload": {"type": "log", "message": "starting"}}
        yield {"event_type": "web_ui_artifact",
               "payload": {"type": "web_ui_artifact",
                           "content": "def test(): pass"}}
        yield {"event_type": "web_ui_bug",
               "payload": {"type": "web_ui_bug",
                           "task_id": "t-42", "status": "completed",
                           "bug_counts": {"critical": 1, "high": 2,
                                          "medium": 0, "low": 3}}}

    monkeypatch.setattr(
        "orchestrator.agents.common.client_web_ui_runner.run_client_web_ui",
        fake_runner,
    )

    events = [e async for e in run_web_ui_local(
        url="https://example.com",
        ctx=_ctx({"user_id": "u-1", "auth_token": "tok"}),
    )]

    assert events[0]["event_type"] == "log"
    assert events[1]["event_type"] == "web_ui_artifact"
    assert events[2]["event_type"] == "web_ui_bug"
    terminal = events[-1]
    assert terminal["is_terminal"] is True
    summary = json.loads(terminal["result"])
    assert summary["task_id"] == "t-42"
    assert summary["status"] == "completed"
    assert summary["script_generated"] is True
    assert summary["bugs_found"] == 6


@pytest.mark.asyncio
async def test_error_event_yields_terminal_with_error(monkeypatch):
    async def fake_runner(**_kwargs):
        yield {"event_type": "error",
               "payload": {"type": "error", "message": "no client agent"}}

    monkeypatch.setattr(
        "orchestrator.agents.common.client_web_ui_runner.run_client_web_ui",
        fake_runner,
    )

    events = [e async for e in run_web_ui_local(
        url="https://example.com",
        ctx=_ctx({"user_id": "u-1"}),
    )]

    terminal = events[-1]
    assert terminal["is_terminal"] is True
    summary = json.loads(terminal["result"])
    assert summary["error"] == "no client agent"
    assert summary["script_generated"] is False
    assert summary["bugs_found"] == 0


@pytest.mark.asyncio
async def test_runner_receives_ctx_derived_kwargs(monkeypatch):
    captured: dict = {}

    async def fake_runner(**kwargs):
        captured.update(kwargs)
        if False:  # pragma: no cover — satisfies async generator contract
            yield

    monkeypatch.setattr(
        "orchestrator.agents.common.client_web_ui_runner.run_client_web_ui",
        fake_runner,
    )

    async for _ in run_web_ui_local(
        url="https://x.com",
        persona="buyer",
        max_steps=7,
        ctx=_ctx({
            "user_id": "u-9",
            "auth_token": "bearer",
            "cdp_url": "http://localhost:9222",
            "browser_model": "gpt-5.4-mini",
            "script_model": "gpt-5.3-codex",
            "business_context": "ecommerce",
        }),
    ):
        pass

    assert captured["user_id"] == "u-9"
    assert captured["auth_token"] == "bearer"
    assert captured["cdp_url"] == "http://localhost:9222"
    assert captured["max_steps"] == 7
    assert captured["user_persona"] == "buyer"
    assert captured["browser_model"] == "gpt-5.4-mini"
    assert captured["script_model"] == "gpt-5.3-codex"
    assert captured["business_context"] == "ecommerce"
