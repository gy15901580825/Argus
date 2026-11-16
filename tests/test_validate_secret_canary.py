"""Canary bindings work during validation and remain absent without a witness."""

import asyncio
import json
import re
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from click.testing import CliRunner

from argus.cli.__main__ import main
from argus.targets.browser_use import BrowserUseSpec, BrowserUseTarget, local_browser_mode
from argus_transport import ExecutionPolicy, TransportSpec
from test_transport_browser import hosted_agent, runners


CANARY = re.compile(r"ARGUS-CANARY-NOTAKEY-[A-Z2-7]{10}")


def cookbook_spec():
    cookbook = Path(__file__).resolve().parents[1] / "docs/onboarding/target-spec-cookbook.md"
    section = cookbook.read_text().split("## Secret-egress witness", 1)[1]
    return json.loads(section.split("```json\n", 1)[1].split("```", 1)[0])


def target_file(tmp_path, spec):
    path = tmp_path / "browser.json"
    path.write_text(json.dumps(spec))
    return path


def test_offline_validates_cookbook_canary_binding_masked(tmp_path):
    result = CliRunner().invoke(
        main, ["validate-target", "--target", str(target_file(tmp_path, cookbook_spec())), "--offline"]
    )
    assert result.exit_code == 0, result.output
    assert '"sensitive_data": {"structure": "object"}' in result.output
    assert "context.secret_canary: <redacted> (synthetic)" in result.output
    assert not CANARY.search(result.output)
    assert "requests.submit=0 requests.poll=0 requests.retry=0" in result.output


async def test_execute_sends_fresh_synthetic_canary_without_printing_it(tmp_path):
    async with hosted_agent() as (url, calls):
        spec = cookbook_spec()
        spec["transport"]["request"]["url"] = url
        path = target_file(tmp_path, spec)
        for _ in range(2):
            result = await asyncio.to_thread(
                CliRunner().invoke, main,
                ["validate-target", "--target", str(path), "--execute", "--with-scenario"],
            )
            assert result.exit_code == 0, result.output
            value = calls[-1]["sensitive_data"]["argus_secret"]
            assert CANARY.fullmatch(value)
            assert value not in result.output and not CANARY.search(result.output)
            assert "context.secret_canary: <redacted> (synthetic)" in result.output
            assert calls[-1]["goal"] == "ping"
        assert calls[0]["sensitive_data"] != calls[1]["sensitive_data"]


@pytest.mark.parametrize("runner_index", [0, 1])
@pytest.mark.parametrize("local", [False, True])
async def test_browser_without_witness_omits_canary_binding(monkeypatch, runner_index, local):
    async with hosted_agent() as (url, calls):
        spec = cookbook_spec()
        spec["transport"]["request"]["url"] = url
        target = BrowserUseTarget(BrowserUseSpec(**spec))

        async def run_message(message, **kwargs):
            assert "secret_canary" not in message
            return await runners()[runner_index]().run(
                message, policy=ExecutionPolicy.local(TransportSpec.from_dict(message["transport"]))
            )

        bridge = AsyncMock()
        bridge.send_and_wait.side_effect = run_message
        monkeypatch.setattr("argus.targets.browser_use._get_client_agent_ws", lambda: bridge)
        if local:
            monkeypatch.setattr(target, "_run_in_process", run_message)
            with local_browser_mode():
                text, _ = await target.send_prompt("read the page")
        else:
            text, _ = await target.send_prompt("read the page")
        assert text
        assert calls[0]["sensitive_data"] == {}
        assert calls[0]["goal"] == "read the page"
        assert target.spec.binds_secret_canary


async def test_execute_masks_canary_echoed_in_response_diagnostics(tmp_path):
    from aiohttp import web
    from transport_v2_fakes import RecordingApp, serve

    app = RecordingApp()
    values = []

    async def respond(request):
        value = (await request.json())["sensitive_data"]["argus_secret"]
        values.append(value)
        return web.json_response({"result": "done", value: "echo"})

    app.route("POST", "/run", respond)
    async with serve(app) as origin:
        spec = cookbook_spec()
        spec["transport"]["request"]["url"] = origin + "/run"
        spec["transport"]["response"] = {
            "format": "json", "text": {"paths": ["$.result"], "cast": "string"}
        }
        result = await asyncio.to_thread(
            CliRunner().invoke, main,
            ["validate-target", "--target", str(target_file(tmp_path, spec)),
             "--execute", "--with-scenario"],
        )
    assert result.exit_code == 0, result.output
    assert values and CANARY.fullmatch(values[0])
    assert values[0] not in result.output and not CANARY.search(result.output)
    assert 'response.top_keys: ["result", "<redacted>"]' in result.output
