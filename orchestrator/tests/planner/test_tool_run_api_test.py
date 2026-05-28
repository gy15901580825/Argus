import json
import pytest
from unittest.mock import patch

from orchestrator.planner.tools.run_api_test import run_api_test


@pytest.mark.asyncio
async def test_run_api_test_in_cluster_path(monkeypatch):
    monkeypatch.setenv("API_TESTING_SERVICE_URL", "http://api-test:8000")

    async def fake_http_runner(apis, auth):
        yield {"event_type": "progress", "payload": {"stage": "gen_script"}}
        yield {"event_type": "ssh_result", "payload": {
            "success": True, "stdout": "2 passed", "stderr": "", "exit_code": 0}}

    with patch("orchestrator.planner.tools.run_api_test._run_via_test_runner",
               new=fake_http_runner):
        events = [e async for e in run_api_test(apis=[{"url": "https://a.com/x"}], ctx=None)]

    assert events[-1]["is_terminal"] is True
    summary = json.loads(events[-1]["result"])
    assert summary["success"] is True
    types = [e.get("event_type") for e in events if not e.get("is_terminal")]
    assert "progress" in types
    assert "ssh_result" in types


@pytest.mark.asyncio
async def test_run_api_test_ssh_path_when_remote_given():
    async def fake_ssh_runner(apis, auth, remote):
        yield {"event_type": "ssh_result", "payload": {
            "success": True, "stdout": "ok", "stderr": "", "exit_code": 0}}

    with patch("orchestrator.planner.tools.run_api_test._run_via_ssh",
               new=fake_ssh_runner):
        events = [e async for e in run_api_test(
            apis=[{"url": "https://a.com/x"}],
            remote={"host": "1.2.3.4", "username": "u", "pem_key_base64": "k"},
            ctx=None,
        )]
    assert events[-1]["is_terminal"] is True
