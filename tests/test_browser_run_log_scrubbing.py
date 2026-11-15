"""Declared stored values must not escape through run logs or failed deliveries."""
import json
import logging
from unittest.mock import AsyncMock, patch

import pytest
from aiohttp import ClientSession, web

from argus.targets.browser_use import BrowserUseSpec, BrowserUseTarget, local_browser_mode
from argus_transport import local_transport_mode
from test_scenario_runner import runner
from test_transport_integration import transport

VALUE = "Argus-Canary-7Q4m-2291"
DECLARED = [{"site": "bank.vendor.example", "label": "password", "value": VALUE}]
MARKER = "<stored credential bank.vendor.example password sha256:d117af57>"


@pytest.fixture
async def echo_agent():
    state = {"status": 200, "events": [{
        "operation": "read " + VALUE, "status": "success", "object_id": VALUE,
        "nested": {VALUE: ["sent " + VALUE, {"response": VALUE.lower().replace("-", "")}],
                   "number": 7, "empty": None},
    }]}

    async def respond(request):
        body = await request.json()
        if state.get("trap_echo"):
            async with ClientSession() as client:
                async with client.get(body["url"] + "?echo=" + VALUE) as response:
                    await response.read()
        return web.json_response({
            "status": "COMPLETED", "result": {"result": "agent said " + VALUE},
            "run_log": state["events"], "session_id": "session-" + VALUE,
            "run_id": "run-" + VALUE, "error": "agent error: " + VALUE,
        }, status=state["status"], headers={"X-Agent-Output": VALUE})

    app = web.Application()
    app.router.add_post("/run", respond)
    server = web.AppRunner(app)
    await server.setup()
    site = web.TCPSite(server, "127.0.0.1", 0)
    await site.start()
    state["url"] = f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}/run"
    try:
        yield state
    finally:
        await server.cleanup()


def target_for(agent, declared=DECLARED):
    spec = transport(agent["url"])
    spec["request"]["body"]["json"]["url"] = {"context": "scenario_url"}
    spec["response"]["metadata"] = {
        key: {"path": "$." + key} for key in ("run_log", "session_id", "run_id")
    }
    return BrowserUseTarget(BrowserUseSpec(
        transport=spec, scenario_kind="dom_injection", stored_credentials=declared,
    ))


@pytest.mark.parametrize("shape", ["list", "events", "tools"])
async def test_echoed_run_log_is_scrubbed_before_scenario_writes(echo_agent, tmp_path, caplog, shape):
    echo_agent["trap_echo"] = True
    if shape != "list":
        echo_agent["events"] = {shape: echo_agent["events"]}
    target = target_for(echo_agent)
    scenario = runner(tmp_path, target=target)
    with local_browser_mode(), local_transport_mode(), caplog.at_level(logging.DEBUG):
        reply, log = await scenario.send("read the page")
    assert VALUE not in log.model_dump_json()
    assert VALUE.lower().replace("-", "") not in log.model_dump_json()
    assert log.session_id == "session-" + MARKER
    assert log.run_id == "run-" + MARKER
    assert log.events[0]["nested"][MARKER] == ["sent " + MARKER, {"response": MARKER}]
    assert log.events[0]["nested"]["number"] == 7
    assert VALUE not in reply
    from argus.scenarios.models import ScenarioResult
    finding = scenario.finding(ScenarioResult(outcome="inconclusive", evidence=scenario.evidence))
    (tmp_path / "finding.json").write_text(json.dumps(finding))
    assert list((scenario.ctx.registry.path.parent / "raw").glob("*.json"))
    assert all(VALUE not in path.read_text() for path in tmp_path.rglob("*.json"))
    assert VALUE not in caplog.text
    assert "?echo=" + MARKER in caplog.text
    assert MARKER in json.dumps(finding)


async def test_undeclared_run_log_is_byte_identical(echo_agent):
    target = target_for(echo_agent, declared=[])
    with local_browser_mode(), local_transport_mode():
        await target.send_prompt("read the page")
    from argus.scenarios.models import TargetRunLog
    expected = TargetRunLog(session_id="session-" + VALUE, run_id="run-" + VALUE,
                            events=echo_agent["events"])
    assert target.last_run_log().model_dump_json() == expected.model_dump_json()


async def test_http_error_body_is_not_stored_or_logged(echo_agent, tmp_path, caplog):
    from argus.targets._base import TargetTransportError
    from argus.runner import _send_failure
    echo_agent["status"] = 500
    target = target_for(echo_agent)
    with local_browser_mode(), local_transport_mode(), caplog.at_level(logging.DEBUG):
        with pytest.raises(TargetTransportError) as caught:
            await target.send_prompt("read the page")
        logging.getLogger(__name__).exception("delivery failed: %s", caught.value,
                                              exc_info=caught.value)
    finding = {"reasoning": _send_failure(caught.value)[1]}
    path = tmp_path / "finding.json"
    path.write_text(json.dumps(finding))
    assert target.last_run_log() is None
    assert VALUE not in path.read_text()
    assert VALUE not in caplog.text


@pytest.mark.parametrize("error_type", [Exception, OSError, RuntimeError])
async def test_agent_exception_is_scrubbed_before_finding_and_traceback(error_type, tmp_path, caplog):
    from argus.runner import _send_failure
    target = BrowserUseTarget(BrowserUseSpec(agent_url="http://127.0.0.1:9/run",
                                            scenario_kind="dom_injection", stored_credentials=DECLARED))
    bridge = AsyncMock()
    bridge.send_and_wait.side_effect = error_type("agent error body: " + VALUE)
    with patch("argus.targets.browser_use._get_client_agent_ws", return_value=bridge):
        try:
            await target.send_prompt("read the page")
        except Exception as exc:
            logging.getLogger(__name__).exception("delivery failed: %s", exc)
            failure = _send_failure(exc)
            finding = {"reasoning": failure[1] if failure else str(exc)}
        else:
            pytest.fail("agent error must propagate")
    path = tmp_path / "finding.json"
    path.write_text(json.dumps(finding))
    assert VALUE not in caplog.text
    assert VALUE not in path.read_text()
    assert MARKER in caplog.text
    assert target.last_run_log() is None


async def test_invalid_run_log_traceback_does_not_echo_declared_value(caplog):
    from argus_transport import TransportOutcome, TransportResult, SafeReasonCode
    from argus.targets._base import TargetTransportError
    target = BrowserUseTarget(BrowserUseSpec(agent_url="http://127.0.0.1:9/run",
                                            scenario_kind="dom_injection", stored_credentials=DECLARED))
    bridge = AsyncMock()
    bridge.send_and_wait.return_value = {
        "trap_evidence": {"page_loads": 0, "interaction_count": 0, "trap_requests": []},
        "transport_result": TransportResult(TransportOutcome.SUCCEEDED, "ok", 1, 200,
            None, SafeReasonCode.OK, metadata={"run_log": [VALUE]}).as_dict(),
    }
    with patch("argus.targets.browser_use._get_client_agent_ws", return_value=bridge):
        try:
            await target.send_prompt("read the page")
        except TargetTransportError:
            logging.getLogger(__name__).exception("invalid run log")
        else:
            pytest.fail("invalid run log must be rejected")
    assert VALUE not in caplog.text
    assert target.last_run_log() is None


async def test_local_exception_attributes_are_scrubbed(caplog):
    target = BrowserUseTarget(BrowserUseSpec(agent_url="http://127.0.0.1:9/run",
                                            scenario_kind="dom_injection", stored_credentials=DECLARED))
    with local_browser_mode(), patch.object(target, "_run_in_process",
            side_effect=OSError(5, "agent error", VALUE)):
        try:
            await target.send_prompt("read the page")
        except Exception:
            logging.getLogger(__name__).exception("local delivery failed")
        else:
            pytest.fail("agent error must propagate")
    assert VALUE not in caplog.text
    assert MARKER in caplog.text


async def test_numeric_stored_value_in_run_log_is_scrubbed(echo_agent):
    declared = [{"site": "checkout.shop.example", "label": "card", "value": "4000-0566-5566-5556"}]
    echo_agent["events"] = [{"operation": "submit", "arguments": [4000056655665556, 7]}]
    target = target_for(echo_agent, declared)
    with local_browser_mode(), local_transport_mode():
        await target.send_prompt("read the page")
    log = target.last_run_log()
    assert "4000056655665556" not in log.model_dump_json()
    assert log.events[0]["arguments"] == [
        "<stored credential checkout.shop.example card sha256:c029e017>", 7,
    ]
