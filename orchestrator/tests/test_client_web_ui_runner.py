"""Smoke test for orchestrator.agents.common.client_web_ui_runner.

Patches the late imports (`connection_manager`, `server`) and the async-sleep
to walk the start → poll-until-completed → fetch-result path in one tick.
"""

from __future__ import annotations

import sys
import types

import pytest

from orchestrator.agents.common import client_web_ui_runner as runner_mod
from orchestrator.agents.common.client_web_ui_runner import run_client_web_ui


class _FakeConnMgr:
    def __init__(self, connected_agents, responses):
        self.active_connections = {aid: object() for aid in connected_agents}
        self._responses = responses
        self.sent: list[dict] = []

    async def send_command(self, agent_id, method, params):
        self.sent.append({"agent_id": agent_id, "method": method, "params": params})
        name = params.get("name")
        resp = self._responses[name]
        # responses may be a list (popped in order) or a single dict
        if isinstance(resp, list):
            return resp.pop(0)
        return resp


def _install_fake_modules(monkeypatch, *, conn_mgr, agent_id, api_base="http://api.local"):
    cm_mod = types.ModuleType("connection_manager")
    cm_mod.connection_manager = conn_mgr
    server_mod = types.ModuleType("server")
    server_mod.API_SERVICE_URL = api_base

    async def _get_user_agent_id(_user_id, _auth_token):
        return agent_id

    server_mod.get_user_agent_id = _get_user_agent_id

    monkeypatch.setitem(sys.modules, "connection_manager", cm_mod)
    monkeypatch.setitem(sys.modules, "server", server_mod)


@pytest.mark.asyncio
async def test_happy_path_start_poll_complete(monkeypatch):
    # Make polling instant and skip the real HTTP persistence.
    async def _instant_sleep(_secs):
        return None

    async def _noop_patch(**_):
        return None

    async def _noop_post(**_):
        return None

    monkeypatch.setattr(runner_mod.asyncio, "sleep", _instant_sleep)
    monkeypatch.setattr(runner_mod, "_patch_task", _noop_patch)
    monkeypatch.setattr(runner_mod, "_post_task", _noop_post)
    # Clear shared state between runs.
    runner_mod._active_tasks.clear()

    conn = _FakeConnMgr(
        connected_agents=["agent-A"],
        responses={
            "start_web_ui_test": {"task_id": "task-xyz"},
            "get_web_ui_test_status": [
                {"status": "running", "steps_done": 1, "max_steps": 30},
                {"status": "completed", "steps_done": 2, "max_steps": 30},
            ],
            "get_web_ui_test_result": {
                "status": "completed", "steps_done": 2,
                "bug_counts": {"critical": 0, "high": 1, "medium": 0, "low": 2},
                "test_script": "def test_demo(): pass",
                "screenshot_count": 3,
                "final_output": "all good",
            },
        },
    )
    _install_fake_modules(monkeypatch, conn_mgr=conn, agent_id="agent-A")

    events = [e async for e in run_client_web_ui(
        url="https://target.example", user_id="u-1", auth_token="tok",
        cdp_url="http://localhost:9222", max_steps=30,
    )]

    kinds = [e["event_type"] for e in events]
    assert "log" in kinds
    assert "web_ui_artifact" in kinds
    assert kinds[-1] == "web_ui_bug"

    artifact = next(e for e in events if e["event_type"] == "web_ui_artifact")
    assert artifact["payload"]["content"] == "def test_demo(): pass"
    assert artifact["payload"]["task_id"] == "task-xyz"

    result = events[-1]["payload"]
    assert result["task_id"] == "task-xyz"
    assert result["has_tests"] is True
    assert result["bug_counts"]["high"] == 1
    assert len(result["screenshot_urls"]) == 3
    # _active_tasks cleaned up on success
    assert "u-1" not in runner_mod._active_tasks


@pytest.mark.asyncio
async def test_no_agent_connected_yields_error(monkeypatch):
    async def _instant_sleep(_secs):
        return None

    monkeypatch.setattr(runner_mod.asyncio, "sleep", _instant_sleep)
    _install_fake_modules(
        monkeypatch,
        conn_mgr=_FakeConnMgr([], {}),  # no connections
        agent_id=None,                   # get_user_agent_id returns None
    )

    events = [e async for e in run_client_web_ui(
        url="https://x.example", user_id="u-2", auth_token=None,
    )]

    assert len(events) == 1
    assert events[0]["event_type"] == "error"
    assert "No active client agent" in events[0]["payload"]["message"]


@pytest.mark.asyncio
async def test_patch_response_urls_flow_into_web_ui_bug(monkeypatch):
    """When the api_service PATCH responds with tests_url + bug_report_url
    (because R2 upload succeeded server-side), those URLs MUST appear on
    the final web_ui_bug payload — the BugReportArtifact card surfaces
    them as 'View test script' / 'View bug report' links and they were
    null in production until this wiring landed."""
    async def _instant_sleep(_secs):
        return None

    captured_patches: list[dict] = []

    async def _capturing_patch(**kwargs):
        captured_patches.append(kwargs)
        # api_service shape: returns the WebUITaskResponse row including
        # the R2 URLs the server just generated.
        return {
            "id": kwargs["task_id"],
            "status": "completed",
            "tests_url": "https://r2.example/web-ui/u-1/task-xyz/test_script.py",
            "bug_report_url": "https://r2.example/web-ui/u-1/task-xyz/bug_report.txt",
        }

    async def _noop_post(**_):
        return None

    monkeypatch.setattr(runner_mod.asyncio, "sleep", _instant_sleep)
    monkeypatch.setattr(runner_mod, "_patch_task", _capturing_patch)
    monkeypatch.setattr(runner_mod, "_post_task", _noop_post)
    runner_mod._active_tasks.clear()

    conn = _FakeConnMgr(
        connected_agents=["agent-A"],
        responses={
            "start_web_ui_test": {"task_id": "task-xyz"},
            "get_web_ui_test_status": [
                {"status": "completed", "steps_done": 4, "max_steps": 30},
            ],
            "get_web_ui_test_result": {
                "status": "completed", "steps_done": 4,
                "bug_counts": {"critical": 1, "high": 0, "medium": 0, "low": 0},
                "test_script": "def test_demo(): pass",
                "screenshot_count": 2,
                "final_output": "1 critical bug found",
            },
        },
    )
    _install_fake_modules(monkeypatch, conn_mgr=conn, agent_id="agent-A")

    events = [e async for e in run_client_web_ui(
        url="https://target.example", user_id="u-1", auth_token="tok",
    )]

    bug_events = [e for e in events if e["event_type"] == "web_ui_bug"]
    assert len(bug_events) == 1
    bug = bug_events[0]["payload"]
    assert bug["tests_url"] == "https://r2.example/web-ui/u-1/task-xyz/test_script.py"
    assert bug["bug_report_url"] == "https://r2.example/web-ui/u-1/task-xyz/bug_report.txt"

    # The PATCH that produced those URLs carried test_script + final_output —
    # those are the body fields api_service uploads to R2.
    final_patch = captured_patches[-1]
    assert final_patch["body"]["test_script"] == "def test_demo(): pass"
    assert final_patch["body"]["final_output"] == "1 critical bug found"


@pytest.mark.asyncio
async def test_patch_failure_leaves_urls_null_but_doesnt_crash(monkeypatch):
    """If the PATCH returns None (api_service down, 500, transport error),
    the runner must still emit web_ui_bug — just with null URL fields."""
    async def _instant_sleep(_secs):
        return None

    async def _failing_patch(**_):
        return None  # what patch_task returns on any failure

    async def _noop_post(**_):
        return None

    monkeypatch.setattr(runner_mod.asyncio, "sleep", _instant_sleep)
    monkeypatch.setattr(runner_mod, "_patch_task", _failing_patch)
    monkeypatch.setattr(runner_mod, "_post_task", _noop_post)
    runner_mod._active_tasks.clear()

    conn = _FakeConnMgr(
        connected_agents=["agent-A"],
        responses={
            "start_web_ui_test": {"task_id": "task-yyy"},
            "get_web_ui_test_status": [
                {"status": "completed", "steps_done": 1, "max_steps": 30},
            ],
            "get_web_ui_test_result": {
                "status": "completed", "steps_done": 1,
                "bug_counts": {}, "test_script": "x = 1",
                "screenshot_count": 0, "final_output": "",
            },
        },
    )
    _install_fake_modules(monkeypatch, conn_mgr=conn, agent_id="agent-A")

    events = [e async for e in run_client_web_ui(
        url="https://x.example", user_id="u-2", auth_token=None,
    )]

    bug = next(e["payload"] for e in events if e["event_type"] == "web_ui_bug")
    assert bug["tests_url"] is None
    assert bug["bug_report_url"] is None


@pytest.mark.asyncio
async def test_agent_registered_but_not_connected(monkeypatch):
    async def _instant_sleep(_secs):
        return None

    monkeypatch.setattr(runner_mod.asyncio, "sleep", _instant_sleep)
    _install_fake_modules(
        monkeypatch,
        conn_mgr=_FakeConnMgr([], {}),   # empty active_connections
        agent_id="agent-B",              # resolved, but not in active set
    )

    events = [e async for e in run_client_web_ui(
        url="https://x.example", user_id="u-3", auth_token=None,
    )]

    assert events[0]["event_type"] == "error"
    assert "registered but not connected" in events[0]["payload"]["message"]
