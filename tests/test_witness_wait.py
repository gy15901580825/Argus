"""Exercise witness wiring through the CLI with piped stdin and loopback servers."""

import asyncio
import json
import os
import signal
import sys
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from aiohttp import ClientConnectorError, ClientSession

from test_transport_integration import hosted_agent, transport
from test_witness import upstream

PROBE = "browser_secret_field_model_egress"


@asynccontextmanager
async def running_cli(tmp_path, agent, upstream, *, wait=True, probe=PROBE, witness=True, hosted=False, ports=None):
    connection = transport(agent["url"])
    connection["request"]["body"]["json"].update(
        url={"context": "scenario_url"},
        sensitive_data={"object": {"argus_secret": {"context": "secret_canary"}}},
    )
    target = {"kind": "browser_use", "scenario_kind": "dom_injection", "transport": connection}
    if witness:
        target["witness"] = {"model_relay": {"upstream": upstream["url"] + "/v1"}, "otlp": {}}
    if ports:
        for channel, port in ports.items():
            target["witness"][channel]["port"] = port
    if hosted:
        target.update(trap_mode="hosted", hosted={"service_url": "http://127.0.0.1:1"})
    target_file = tmp_path / "target.json"
    target_file.write_text(json.dumps(target))
    report = tmp_path / "run.json"
    args = [sys.executable, "-m", "argus.cli", "run", "--local", "--target", str(target_file),
            "--probes", probe, "--format", "json", "--out", str(report)]
    if wait:
        args.append("--witness-wait")
    env = dict(os.environ)
    for name in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "AZURE_OPENAI_API_KEY", "AZURE_API_KEY"):
        env.pop(name, None)
    process = await asyncio.create_subprocess_exec(
        *args, cwd=Path(__file__).resolve().parents[1], env=env,
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
    )
    try:
        yield process, report
    finally:
        if process.returncode is None:
            process.kill()
        await process.wait()
        process.stdin.close()


async def addresses_and_prompt(process):
    urls, output = {}, []
    async with asyncio.timeout(30):
        while True:
            line = (await process.stdout.readline()).decode()
            output.append(line)
            assert line, "CLI stopped before its wiring prompt: " + "".join(output)
            if line.startswith("Witness ") and ": http" in line:
                channel, url = line.strip().removeprefix("Witness ").split(": ", 1)
                urls[channel] = url
            if "press Enter to start the probes" in line:
                assert "model_relay" in urls
                assert any("Witness canary sha256:" in item for item in output)
                return urls


async def finish(process):
    output = (await asyncio.wait_for(process.stdout.read(), 30)).decode()
    await asyncio.wait_for(process.wait(), 5)
    return output


async def assert_closed(urls):
    async with ClientSession() as client:
        for url in urls.values():
            with pytest.raises(ClientConnectorError):
                await client.post(url, timeout=2)


async def test_wait_prevents_dispatch_until_stdin_line(tmp_path, hosted_agent, upstream):
    async with running_cli(tmp_path, hosted_agent, upstream) as (process, report):
        urls = await addresses_and_prompt(process)
        await asyncio.sleep(0.15)
        assert hosted_agent["requests"] == []
        assert process.returncode is None
        process.stdin.write(b"\n")
        await process.stdin.drain()
        output = await finish(process)
        assert process.returncode == 0, output
        assert len(hosted_agent["requests"]) == 1
        assert json.loads(report.read_text())["findings"][0]["verdict"] == "skipped"
        await assert_closed(urls)


async def test_relay_and_receiver_serve_during_wait(tmp_path, hosted_agent, upstream):
    async with running_cli(tmp_path, hosted_agent, upstream, probe=PROBE + ",browser_secret_trace_export") as (process, report):
        urls = await addresses_and_prompt(process)
        async with ClientSession() as client:
            async with client.post(urls["model_relay"] + "chat", json={"prompt": "wiring check"}, timeout=2) as response:
                assert response.status == 200
                assert await response.json() == {"answer": "ok"}
            async with client.post(urls["otlp"] + "v1/traces", json={}, timeout=2) as response:
                assert response.status == 200
        assert len(upstream["requests"]) == 1
        assert hosted_agent["requests"] == []
        process.stdin.write(b"\n")
        output = await finish(process)
        assert process.returncode == 0, output


async def test_pause_relay_traffic_is_outside_probe_window(tmp_path, hosted_agent, upstream):
    async with running_cli(tmp_path, hosted_agent, upstream) as (process, report):
        urls = await addresses_and_prompt(process)
        async with ClientSession() as client:
            async with client.post(urls["model_relay"] + "chat", json={"prompt": "wiring check"}, timeout=2) as response:
                assert await response.json() == {"answer": "ok"}
        assert hosted_agent["requests"] == []
        process.stdin.write(b"\n")
        output = await finish(process)
        assert process.returncode == 0, output
        finding = json.loads(report.read_text())["findings"][0]
        assert len(hosted_agent["requests"]) == 1
        assert finding["verdict"] == "skipped"
        assert "the model relay saw no traffic" in finding["reasoning"]
        assert finding["evidence"]["witness"]["model_relay"] == []


async def test_eof_stops_without_dispatch_and_closes_listeners(tmp_path, hosted_agent, upstream):
    async with running_cli(tmp_path, hosted_agent, upstream) as (process, report):
        urls = await addresses_and_prompt(process)
        process.stdin.close()
        output = await finish(process)
        assert process.returncode == 1, output
        assert "stdin reached EOF before witness wiring was confirmed; no probes started" in output
        assert hosted_agent["requests"] == []
        assert not report.exists()
        await assert_closed(urls)


@pytest.mark.skipif(sys.platform == "win32", reason="SIGINT subprocess delivery needs POSIX")
async def test_interrupt_during_wait_closes_listeners(tmp_path, hosted_agent, upstream):
    async with running_cli(tmp_path, hosted_agent, upstream) as (process, report):
        urls = await addresses_and_prompt(process)
        process.send_signal(signal.SIGINT)
        output = await finish(process)
        assert process.returncode == 130, output
        assert "run was stopped" in output
        assert hosted_agent["requests"] == []
        assert not report.exists()
        await assert_closed(urls)


@pytest.mark.parametrize("mode", ["non_witness_probe", "missing_witness", "hosted"])
async def test_no_listeners_never_waits_on_open_stdin(tmp_path, hosted_agent, upstream, mode):
    async with running_cli(
        tmp_path, hosted_agent, upstream,
        probe="browser_extraction_tamper" if mode == "non_witness_probe" else PROBE,
        witness=mode != "missing_witness", hosted=mode == "hosted",
    ) as (process, report):
        output = await finish(process)
        assert process.returncode == {"non_witness_probe": 1, "missing_witness": 0, "hosted": 2}[mode], output
        assert "press Enter" not in output
        assert "Witness model_relay:" not in output
        assert report.exists() == (mode != "hosted")
        if mode == "hosted":
            assert "witness channels are unsupported with hosted traps" in output
            assert "Running" not in output
            assert hosted_agent["requests"] == []


async def test_without_flag_prints_hint_and_does_not_wait(tmp_path, hosted_agent, upstream):
    async with running_cli(tmp_path, hosted_agent, upstream, wait=False) as (process, report):
        output = await finish(process)
        assert process.returncode == 0, output
        assert "Witness addresses change on every run unless fixed ports and ARGUS_WITNESS_TOKEN are configured; --witness-wait pauses for wiring." in output
        assert output.index("Witness canary sha256:") < output.index("Witness addresses change")
        assert "press Enter" not in output
        assert len(hosted_agent["requests"]) == 1


FAKE_TOKEN = "fake-witness-token-0123456789abcdef"


async def test_fixed_addresses_match_documented_format(tmp_path, hosted_agent, upstream, monkeypatch):
    import socket
    with socket.socket() as relay, socket.socket() as otlp:
        relay.bind(("127.0.0.1", 0))
        otlp.bind(("127.0.0.1", 0))
        ports = {"model_relay": relay.getsockname()[1], "otlp": otlp.getsockname()[1]}
    monkeypatch.setenv("ARGUS_WITNESS_TOKEN", FAKE_TOKEN)
    async with running_cli(tmp_path, hosted_agent, upstream, ports=ports,
                           probe=PROBE + ",browser_secret_trace_export") as (process, report):
        urls = await addresses_and_prompt(process)
        assert urls == {channel: f"http://127.0.0.1:{port}/r/{FAKE_TOKEN}/" for channel, port in ports.items()}
        async with ClientSession() as client:
            async with client.post(urls["model_relay"] + "chat", data=b"fixed address check", timeout=2) as response:
                assert await response.json() == {"answer": "ok"}
            async with client.post(urls["otlp"] + "v1/traces", json={}, timeout=2) as response:
                assert response.status == 200
        assert len(upstream["requests"]) == 1
        assert hosted_agent["requests"] == []
        process.stdin.write(b"\n")
        output = await finish(process)
        assert process.returncode == 0, output
        assert FAKE_TOKEN not in report.read_text()
        await assert_closed(urls)


@pytest.mark.parametrize("channel", ["model_relay", "otlp"])
async def test_occupied_port_fails_without_dispatch_or_fallback(tmp_path, hosted_agent, upstream, channel):
    import socket
    with socket.socket() as occupied, socket.socket() as available:
        occupied.bind(("127.0.0.1", 0))
        occupied.listen()
        available.bind(("127.0.0.1", 0))
        free_port = available.getsockname()[1]
        available.close()
        port = occupied.getsockname()[1]
        ports = {"model_relay": free_port, "otlp": free_port}
        ports[channel] = port
        async with running_cli(tmp_path, hosted_agent, upstream, ports=ports,
                               probe=PROBE + ",browser_secret_trace_export") as (process, report):
            output = await finish(process)
            assert process.returncode == 1, output
            assert f"witness {channel} could not bind port {port}" in output
            assert "Witness model_relay:" not in output
            assert hosted_agent["requests"] == []
            assert not report.exists()
            await assert_closed({"started_channel": f"http://127.0.0.1:{free_port}/"})


@pytest.mark.parametrize("token", ["short-fake", "fake invalid token with spaces 0123456789", ""])
async def test_invalid_token_fails_before_listeners(tmp_path, hosted_agent, upstream, monkeypatch, token):
    monkeypatch.setenv("ARGUS_WITNESS_TOKEN", token)
    async with running_cli(tmp_path, hosted_agent, upstream) as (process, report):
        output = await finish(process)
        assert process.returncode == 1, output
        assert "ARGUS_WITNESS_TOKEN must contain at least 32" in output
        if token:
            assert token not in output
        assert "Witness model_relay:" not in output
        assert hosted_agent["requests"] == []
        assert not report.exists()


def test_same_port_is_rejected():
    from argus.witness import WitnessSpec
    with pytest.raises(ValueError, match="must differ"):
        WitnessSpec(model_relay={"upstream": "http://127.0.0.1:1", "port": 19601}, otlp={"port": 19601})


@pytest.mark.parametrize("channel", ["model_relay", "otlp"])
@pytest.mark.parametrize("port", [0, 65536, True, "19601", 1.5, None])
def test_fixed_port_validation(channel, port):
    from argus.witness import WitnessSpec
    options = {"model_relay": {"upstream": "http://127.0.0.1:1"}, "otlp": {}}
    options[channel]["port"] = port
    with pytest.raises(ValueError, match=rf"witness.{channel}.port must be an integer"):
        WitnessSpec(**options)


def test_unset_token_remains_random_and_fixed_token_keeps_canary_random(monkeypatch):
    from argus.witness import WitnessRun, WitnessSpec
    monkeypatch.delenv("ARGUS_WITNESS_TOKEN", raising=False)
    first, second = WitnessRun(WitnessSpec()), WitnessRun(WitnessSpec())
    assert first.token != second.token
    monkeypatch.setenv("ARGUS_WITNESS_TOKEN", FAKE_TOKEN)
    first, second = WitnessRun(WitnessSpec()), WitnessRun(WitnessSpec())
    assert first.token == second.token == FAKE_TOKEN
    assert first.canary != second.canary


def test_server_mode_does_not_read_stdin(tmp_path, monkeypatch):
    from click.testing import CliRunner
    from argus.cli import api_client, local_run
    from argus.cli.cmd_run import cmd_run
    async def unexpected_read():
        pytest.fail("server mode read stdin")
    monkeypatch.setattr(local_run, "_read_witness_confirmation", unexpected_read)
    monkeypatch.setattr(api_client, "post_run", lambda *a, **k: {"run_id": "fake-run"})
    monkeypatch.setattr(api_client, "poll_until_complete", lambda *a, **k: {"status": "completed", "findings": []})
    monkeypatch.setattr(api_client, "get_report", lambda *a, **k: "<html>fake report</html>")
    target = tmp_path / "target.json"
    target.write_text(json.dumps({"kind": "browser_use", "scenario_kind": "dom_injection",
                                       "transport": transport("http://127.0.0.1:1/run")}))
    result = CliRunner().invoke(cmd_run, ["--witness-wait", "--target", str(target), "--probes", "fake",
                                        "--api-url", "http://127.0.0.1:1", "--token", "fake",
                                        "--out", str(tmp_path / "report.html")])
    assert result.exit_code == 0, result.output
    assert "press Enter" not in result.output
