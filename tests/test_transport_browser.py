from __future__ import annotations

import asyncio
import copy
import json
import pathlib
import sys
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from aiohttp import web

from argus_transport import TransportSpec
from tests.test_transport_engine import spec_dict

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "client_agent"))


def runners():
    from argus.browser_runner.browser_probe import BrowserProbe
    from redteam_runner.browser_probe import BrowserProbe as ClientProbe

    return (BrowserProbe, ClientProbe)


@asynccontextmanager
async def hosted_agent(mode="success", touch=True, delay=0):
    calls = []

    async def handle(request):
        body = await request.json()
        calls.append(body)
        if touch:
            async with httpx.AsyncClient(trust_env=False) as client:
                assert (await client.get(body["url"])).status_code == 200
                assert (
                    await client.post(
                        body["url"].replace("/scenario", "/sink"),
                        content=request.headers.get("X-Api-Key", "synthetic-canary"),
                    )
                ).status_code == 200
        if delay:
            await asyncio.sleep(delay)
        if mode == "blocked":
            response = {"status": "FAILED", "error": {"code": "POLICY_REFUSAL"}}
        elif mode == "failed":
            response = {"status": "FAILED", "result": "not scored"}
        else:
            response = {"status": "COMPLETED", "result": {"result": "done"}}
        return web.json_response(response)

    app = web.Application()
    app.router.add_post("/run", handle)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    url = f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}/run"
    try:
        yield url, calls
    finally:
        await runner.cleanup()


def browser_spec(url, deadline=3):
    data = spec_dict(url)
    data["request"]["body"]["json"]["url"] = {"context": "scenario_url"}
    data["timeout"].update(total_deadline_s=deadline, read_s=deadline)
    return data


@pytest.mark.parametrize("runner_index", [0, 1])
async def test_browser_transport_maps_goal_and_actual_url(runner_index):
    async with hosted_agent() as (url, calls):
        reply = await runners()[runner_index]().run(
            {
                "scenario_kind": "ui_phishing",
                "payload": "neutral page",
                "prompt": "read the page",
                "transport": browser_spec(url),
            },
            policy=__import__("argus_transport").ExecutionPolicy.local(
                TransportSpec.from_dict(browser_spec(url))
            ),
        )
    assert calls[0]["goal"] == "read the page" and "prompt" not in calls[0]
    assert calls[0]["url"] == reply["trap_url"]
    assert reply["transport_result"]["outcome"] == "succeeded"
    assert reply["transport_result"]["response_text"] == "done"
    assert reply["trap_evidence"]["page_loads"] == 1
    assert len(reply["trap_evidence"]["trap_requests"]) == 1
    async with httpx.AsyncClient(trust_env=False) as client:
        with pytest.raises(httpx.ConnectError):
            await client.get(reply["trap_url"])


@pytest.mark.parametrize(
    "mode,delay,expected",
    [
        ("blocked", 0, "blocked"),
        ("failed", 0, "target_error"),
        ("success", 0.2, "timed_out"),
    ],
)
@pytest.mark.parametrize("runner_index", [0, 1])
async def test_refusal_error_and_timeout_preserve_prior_trap_evidence(
    mode, delay, expected, runner_index
):
    async with hosted_agent(mode=mode, delay=delay) as (url, calls):
        reply = await runners()[runner_index]().run(
            {
                "scenario_kind": "ui_phishing",
                "payload": "neutral page",
                "prompt": "read",
                "transport": browser_spec(url, deadline=0.1 if delay else 3),
            },
            policy=__import__("argus_transport").ExecutionPolicy.local(
                TransportSpec.from_dict(browser_spec(url))
            ),
        )
    assert reply["transport_result"]["outcome"] == expected
    assert reply["transport_result"]["response_text"] is None
    assert reply["trap_evidence"]["page_loads"] == 1
    assert reply["trap_evidence"]["trap_requests"][0]["body"] == "synthetic-canary"
    assert len(calls) == 1


async def test_success_without_required_interaction_is_error(tmp_path):
    from argus.targets.browser_use import (
        BrowserUseSpec,
        BrowserUseTarget,
        local_browser_mode,
    )
    from argus.runner import Runner
    from argus.probe import Probe, ProbeMappings
    from argus_transport import local_transport_mode

    async with hosted_agent(touch=False) as (url, calls):
        target = BrowserUseTarget(
            BrowserUseSpec(transport=browser_spec(url), scenario_kind="ui_phishing")
        )
        probe = Probe(
            id="synthetic_browser",
            name="synthetic",
            target_class=["browser-using"],
            attack_class=["synthetic"],
            severity="high",
            prompts=["read"],
            assertions=[{"no_canary_in_trap_requests": "synthetic-canary"}],
            requires_interaction=True,
            mappings=ProbeMappings(),
            judge_model="m",
            judge_rubric_path="default.md",
        )
        judge = AsyncMock()
        with local_browser_mode(), local_transport_mode():
            findings = [
                f
                async for f in Runner(
                    target=target, judge=judge, rubrics_dir=tmp_path
                ).run_probe(probe)
            ]
    assert findings[0].verdict == "error"
    assert findings[0].evidence["interaction_count"] == 0
    assert judge.call_count == 0 and len(calls) == 1


async def test_configured_long_budget_reaches_driver_and_bridge(monkeypatch):
    from argus.targets.browser_use import BrowserUseSpec, BrowserUseTarget
    from argus_transport import TransportOutcome, TransportResult, SafeReasonCode

    target = BrowserUseTarget(
        BrowserUseSpec(
            transport=browser_spec("http://127.0.0.1:1/run", deadline=300),
            scenario_kind="ui_phishing",
        )
    )
    reply = {
        "transport_result": TransportResult(
            TransportOutcome.SUCCEEDED, "done", 1, 200, "completed", SafeReasonCode.OK
        ).as_dict(),
        "trap_evidence": {"page_loads": 1, "interaction_count": 1, "trap_requests": []},
        "trap_url": "http://127.0.0.1:1/x/scenario",
    }
    bridge = AsyncMock()
    bridge.send_and_wait.return_value = reply
    with patch("argus.targets.browser_use._get_client_agent_ws", return_value=bridge):
        text, _ = await target.send_prompt("read")
    assert text == "done"
    assert bridge.send_and_wait.call_args.kwargs["timeout_s"] >= 302
    assert (
        bridge.send_and_wait.call_args.args[0]["transport"]["timeout"][
            "total_deadline_s"
        ]
        == 300
    )


def test_transport_wire_result_rejects_ambiguous_outcomes():
    from argus_transport import TransportResult

    result = {
        "outcome": "succeeded",
        "response_text": "done",
        "latency_ms": 1,
        "http_status": 200,
        "matched_rule_id": "complete",
        "reason_code": "ok",
        "metadata": {},
        "diagnostics": {},
    }
    assert TransportResult.from_dict(result).response_text == "done"
    for mutation in (
        {"outcome": "accepted"},
        {"unknown": True},
        {"latency_ms": float("nan")},
        {"response_text": None},
    ):
        with pytest.raises(ValueError):
            TransportResult.from_dict({**result, **mutation})
    with pytest.raises(ValueError):
        TransportResult.from_dict({**result, "outcome": "blocked"})


async def test_old_client_rejects_transport_version_before_probe(monkeypatch):
    from argus.connection_manager import ConnectionManager

    manager = ConnectionManager()
    manager._post_status = AsyncMock()
    socket = AsyncMock()
    assert await manager.connect(socket, "old")
    socket.send_json.reset_mock()
    with pytest.raises(RuntimeError, match="transport version"):
        await manager.get_redteam_bridge().send_and_wait(
            {"transport": browser_spec("http://127.0.0.1:1/run")}, timeout_s=0.1
        )
    assert socket.send_json.call_count == 0
    assert manager.pending_commands == {}
    manager.set_transport_versions("old", socket, [1])
    replacement = AsyncMock()
    await manager.disconnect("old", connection=socket)
    assert await manager.connect(replacement, "old")
    with pytest.raises(RuntimeError, match="transport version"):
        await manager.get_redteam_bridge().send_and_wait(
            {"transport": browser_spec("http://127.0.0.1:1/run")}, timeout_s=0.1
        )
    assert replacement.send_json.call_count == 0


async def test_browser_validate_offline_and_execute_with_neutral_scenario(tmp_path):
    from click.testing import CliRunner
    from argus.cli.__main__ import main

    async with hosted_agent() as (url, calls):
        path = tmp_path / "browser.json"
        path.write_text(
            json.dumps(
                {
                    "kind": "browser_use",
                    "scenario_kind": "ui_phishing",
                    "transport": browser_spec(url),
                }
            )
        )
        offline = CliRunner().invoke(
            main, ["validate-target", "--target", str(path), "--offline"]
        )
        assert offline.exit_code == 0 and calls == []
        assert "requests.submit=0" in offline.output
        result = await asyncio.to_thread(
            CliRunner().invoke,
            main,
            ["validate-target", "--target", str(path), "--execute", "--with-scenario"],
        )
        assert result.exit_code == 0, result.output
        assert len(calls) == 1 and calls[0]["goal"] == "ping"
        assert "requests.submit=1" in result.output and "succeeded" in result.output
        assert "done" not in result.output


@pytest.mark.parametrize("runner_index", [0, 1])
async def test_secret_not_in_wire_result_logs_or_reports(
    tmp_path, caplog, runner_index
):
    from argus_transport import ExecutionPolicy

    synthetic = "fixture-auth-value/with+symbols"
    secret_file = tmp_path / "synthetic-auth.txt"
    secret_file.write_text(synthetic)
    async with hosted_agent() as (url, calls):
        data = browser_spec(url)
        data["auth"] = {
            "kind": "headers",
            "headers": [
                {
                    "name": "X-Api-Key",
                    "secret": {"source": "file", "path": str(secret_file)},
                }
            ],
        }
        spec = TransportSpec.from_dict(data)
        reply = await runners()[runner_index]().run(
            {
                "scenario_kind": "ui_phishing",
                "payload": "neutral",
                "prompt": "read",
                "transport": data,
            },
            policy=ExecutionPolicy.local(spec),
        )
    assert synthetic not in json.dumps(reply)
    assert synthetic not in caplog.text
    assert reply["trap_evidence"]["page_loads"] == 1
    assert reply["trap_evidence"]["trap_requests"][0]["body"] == "<redacted>"


async def test_server_session_wire_reply_requires_id():
    from argus.targets.browser_use import BrowserUseSpec, BrowserUseTarget
    from argus.targets._base import TargetTransportError
    from argus_transport import TransportResult, TransportOutcome, SafeReasonCode

    data = browser_spec("http://127.0.0.1:1/run")
    data["session"] = {"mode": "server_returned", "id_path": "$.session_id"}
    target = BrowserUseTarget(
        BrowserUseSpec(transport=data, scenario_kind="ui_phishing")
    )
    reply = {
        "transport_result": TransportResult(
            TransportOutcome.SUCCEEDED, "done", 1, 200, "completed", SafeReasonCode.OK
        ).as_dict(),
        "trap_url": "http://127.0.0.1:2/scenario",
        "trap_evidence": {"page_loads": 1, "interaction_count": 1, "trap_requests": []},
    }
    bridge = AsyncMock()
    bridge.send_and_wait.return_value = reply
    with patch("argus.targets.browser_use._get_client_agent_ws", return_value=bridge):
        with pytest.raises(TargetTransportError, match="session"):
            await target.send_prompt("read")
    assert target._session_id is None


def test_legacy_browser_warns_and_new_transport_is_silent():
    import warnings
    from argus.targets.browser_use import BrowserUseSpec

    with pytest.warns(DeprecationWarning, match="browser.*legacy"):
        BrowserUseSpec(agent_url="http://127.0.0.1:1/run", scenario_kind="ui_phishing")
    with warnings.catch_warnings(record=True) as seen:
        warnings.simplefilter("always")
        BrowserUseSpec(
            transport=browser_spec("http://127.0.0.1:1/run"),
            scenario_kind="ui_phishing",
        )
    assert not seen


@pytest.mark.parametrize("runner_index", [0, 1])
async def test_browser_start_failure_still_stops_scenario(runner_index):
    server = AsyncMock()
    server.start.side_effect = OSError("fixture bind failure")
    module = (
        "argus.browser_runner.browser_probe"
        if runner_index == 0
        else "redteam_runner.browser_probe"
    )
    with patch(module + "._make_scenario_server", return_value=server):
        with pytest.raises(OSError, match="fixture bind failure"):
            await runners()[runner_index]().run(
                {
                    "scenario_kind": "ui_phishing",
                    "payload": "neutral",
                    "agent_url": "http://127.0.0.1:1/run",
                }
            )
    server.stop.assert_awaited_once()
