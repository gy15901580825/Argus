import asyncio
import errno
import importlib.metadata
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time

import httpx
import pytest
from click.testing import CliRunner

import argus.targets
from argus.cli.__main__ import main
from argus.mcp_trap import driver, wiring
from argus.mcp_trap.driver import SCOPE_NOTE, RoundOutcome, TrapRun, Warmup
from argus.mcp_trap.wiring import TrapAddress, TrapPortInUse

# Copied verbatim from tests/test_contract_freeze.py.
RUN_JSON_KEYS = ["schema_version", "id", "status", "started_at", "finished_at",
                 "argus_version", "target_spec", "coverage", "findings"]

SPEC = {"kind": "openai_compat", "endpoint_url": "http://127.0.0.1:9/v1/chat/completions", "model": "m"}
SPEC_ARG = json.dumps(SPEC)
SECRET = "s3cr3t-value-123"
OUT_FILE = {"html": "argus-mcp-trap-report.html", "sarif": "argus-mcp-trap-report.sarif",
            "junit": "argus-mcp-trap-report.xml", "json": "argus-mcp-trap-report.json"}


@pytest.fixture(autouse=True)
def _isolated(monkeypatch, tmp_path):
    import argus.judge

    async def _forbidden(*args, **kwargs):
        raise AssertionError("mcp-trap must never call the LLM judge")

    monkeypatch.setattr(argus.judge.Judge, "judge", _forbidden)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    monkeypatch.setenv("no_proxy", "127.0.0.1,localhost")
    bound: list[int] = []

    # Other test runs may hold the default port; the trap itself listens on a free one.
    def _bind_free(address):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        sock.listen()
        bound.append(sock.getsockname()[1])
        return sock

    monkeypatch.setattr(wiring, "bind_trap_socket", _bind_free)
    return bound


def _invoke(*args):
    return CliRunner().invoke(main, ["mcp-trap", *args])


def _warm(status, detail=""):
    async def fake(trap, chat, mask=None):
        return Warmup(status, detail)
    return fake


def _fake_run(outcomes=None, evidence=None, calls=None, reply="agent reply", reason=None):
    """run_scenarios stand-in: `outcomes` maps scenario -> round outcomes (default: all passed)."""
    outcomes = outcomes or {}

    async def fake(trap, chat, probes, rounds, echo=lambda s: None, mask=lambda s: s):
        if calls is not None:
            calls.append([p.scenario_kind for p in probes])
        conversations = 1 + len(probes) * rounds
        findings, inconclusive = [], []
        for probe in probes:
            kinds = outcomes.get(probe.scenario_kind, ["passed"] * rounds)
            rounds_out = [
                RoundOutcome(i + 1, kind, reason or f"{kind} reason", probe.prompts[0], reply,
                             evidence or {"interaction_count": 1})
                for i, kind in enumerate(kinds)
            ]
            for r in rounds_out:
                echo(f"  {probe.scenario_kind:<16} round {r.round}/{rounds}: {r.outcome} ({r.reason})")
            finding = driver.scenario_finding(probe, rounds_out, conversations, mask=mask)
            findings.append(finding)
            if finding["verdict"] == "error":
                inconclusive.append(probe.scenario_kind)
        notes = [SCOPE_NOTE, f"{conversations} conversations sent to the agent."]
        return TrapRun(findings, notes, conversations, inconclusive)
    return fake


def _wired(monkeypatch, **kwargs):
    monkeypatch.setattr(driver, "warm_up", _warm("wired"))
    monkeypatch.setattr(driver, "run_scenarios", _fake_run(**kwargs))


@pytest.mark.parametrize("fmt", ["html", "sarif", "junit", "json"])
def test_agentic_tags_survive_mcp_trap_exports(monkeypatch, tmp_path, fmt):
    _wired(monkeypatch)
    real = driver.scenario_finding

    def tagged(*args, **kwargs):
        return {**real(*args, **kwargs), "owasp_agentic": ["ASI01", "ASI02"]}

    monkeypatch.setattr(driver, "scenario_finding", tagged)
    result = _invoke("--target", SPEC_ARG, "--scenarios", "tool_poisoning", "--format", fmt)
    assert result.exit_code == 0, result.output
    text = (tmp_path / OUT_FILE[fmt]).read_text()
    assert "ASI01" in text and "ASI02" in text
    assert "owasp-agentic-top10" in text if fmt != "junit" else "owasp_agentic" in text


def _no_sdk(monkeypatch):
    for name in [m for m in sys.modules if m == "mcp" or m.startswith("mcp.")]:
        monkeypatch.delitem(sys.modules, name)
    monkeypatch.setitem(sys.modules, "mcp", None)


def _no_build(monkeypatch):
    def _boom(spec):
        raise AssertionError("build_target must not be called")
    monkeypatch.setattr(argus.targets, "build_target", _boom)


# --- before the run ---

def test_print_config_sends_nothing_and_needs_no_sdk(monkeypatch, _isolated):
    _no_sdk(monkeypatch)
    _no_build(monkeypatch)
    result = _invoke("--target", SPEC_ARG, "--print-config")
    assert result.exit_code == 0, result.output
    assert '"mcpServers"' in result.output
    assert "http://127.0.0.1:8765/mcp" in result.output
    assert _isolated == []


def test_print_config_uses_public_url():
    result = _invoke("--target", SPEC_ARG, "--print-config",
                     "--trap-host", "0.0.0.0", "--trap-public-url", "http://192.168.1.20:8765")
    assert result.exit_code == 0, result.output
    assert "http://192.168.1.20:8765/mcp" in result.output


@pytest.mark.parametrize("flags, match", [
    (["--trap-host", "localhost"], "IPv4"),
    (["--trap-host", "0.0.0.0"], "--trap-public-url"),
    (["--trap-port", "0"], "--trap-port"),
    (["--trap-port", "65536"], "--trap-port"),
    (["--trap-public-url", "ftp://x"], "http"),
    (["--trap-public-url", "http://h:1/other"], "/mcp"),
    (["--trap-public-url", "http://h:1/?a=1"], "query"),
    (["--trap-public-url", "http://user:pw@h:1"], "user name or password"),
])
def test_bad_trap_flags_are_usage_errors(flags, match):
    result = _invoke("--target", SPEC_ARG, "--print-config", *flags)
    assert result.exit_code == 2, result.output
    assert match in result.output
    assert "Traceback" not in result.output


@pytest.mark.parametrize("flags, match", [
    (["--rounds", "0"], "--rounds"),
    (["--rounds", "21"], "--rounds"),
    (["--scenarios", ""], "--scenarios"),
    (["--scenarios", ","], "--scenarios"),
    (["--scenarios", "all,rug_pull"], "'all'"),
    (["--scenarios", "rug_pull,nope"], "nope"),
])
def test_bad_rounds_or_scenarios_are_usage_errors(monkeypatch, flags, match):
    _wired(monkeypatch)
    result = _invoke("--target", SPEC_ARG, *flags)
    assert result.exit_code == 2, result.output
    assert match in result.output


def test_unreadable_target_exits_1():
    result = _invoke("--target", "{not json")
    assert result.exit_code == 1
    assert "Error:" in result.output


def test_world_acting_spec_is_refused():
    spec = {"kind": "mcp_agent", "testbed_url": "http://t", "inner": {}, "sandbox": True}
    result = _invoke("--target", json.dumps(spec), "--print-config")
    assert result.exit_code == 2, result.output
    assert "openai_compat, custom_http or grpc" in result.output


def test_missing_sdk_says_how_to_install(monkeypatch, _isolated):
    _no_sdk(monkeypatch)
    _no_build(monkeypatch)
    result = _invoke("--target", SPEC_ARG)
    assert result.exit_code == 2, result.output
    assert "pip install 'argus-probe[mcp-trap]'" in result.output
    assert "Traceback" not in result.output
    assert _isolated == []


@pytest.mark.parametrize("found", ["1.27.0", "2.2.9", "3.0.0", "unparseable"])
def test_unsupported_sdk_version_names_the_found_version(monkeypatch, found):
    real = importlib.metadata.version
    monkeypatch.setattr(importlib.metadata, "version", lambda dist: found if dist == "mcp" else real(dist))
    _no_build(monkeypatch)
    result = _invoke("--target", SPEC_ARG)
    assert result.exit_code == 2, result.output
    assert "pip install 'argus-probe[mcp-trap]'" in result.output
    assert f"found mcp {found}" in result.output


def test_bad_spec_fields_exit_1(monkeypatch):
    spec = {**SPEC, "no_such_field": 1}
    result = _invoke("--target", json.dumps(spec))
    assert result.exit_code == 1, result.output
    assert result.output.startswith("Error:")
    assert "Traceback" not in result.output


def test_port_in_use_is_reported_cleanly(monkeypatch):
    def _busy(address):
        raise TrapPortInUse("127.0.0.1:8765 is already in use; pick another with --trap-port")
    monkeypatch.setattr(wiring, "bind_trap_socket", _busy)
    result = _invoke("--target", SPEC_ARG)
    assert result.exit_code == 2, result.output
    assert "127.0.0.1:8765 is already in use" in result.output
    assert "Traceback" not in result.output


def test_unbindable_address_is_reported_cleanly(monkeypatch):
    def _no_such_ip(address):
        raise OSError(errno.EADDRNOTAVAIL, "Cannot assign requested address")
    monkeypatch.setattr(wiring, "bind_trap_socket", _no_such_ip)
    result = _invoke("--target", SPEC_ARG)
    assert result.exit_code == 2, result.output
    assert "Error: cannot listen on 127.0.0.1:8765: Cannot assign requested address" in result.output
    assert "Traceback" not in result.output


def test_terminal_masks_what_the_reports_mask(monkeypatch):
    # A literal secret-named value and a ${VAR} value, both echoed back in a chat error.
    monkeypatch.setenv("MY_KEY", SECRET)
    literal = "lit-key-Q9Z8Y7X6"
    monkeypatch.setattr(driver, "warm_up", _warm("chat_error", f"401 for {literal} and {SECRET}"))
    spec = {**SPEC, "api_key": literal, "model": "${MY_KEY}"}
    result = _invoke("--target", json.dumps(spec))
    assert result.exit_code == 1, result.output
    assert "401 for *** and ***" in result.output
    assert literal not in result.output and SECRET not in result.output


# --- warm-up ---

def test_not_wired_warm_up_prints_config_and_exits_2(monkeypatch, tmp_path):
    monkeypatch.setattr(driver, "warm_up", _warm("not_wired"))
    monkeypatch.setattr(driver, "run_scenarios", _fake_run())
    result = _invoke("--target", SPEC_ARG)
    assert result.exit_code == 2, result.output
    assert "The trap at http://127.0.0.1:8765/mcp got no MCP request" in result.output
    assert "This is expected on a first run" in result.output
    assert '"mcpServers"' in result.output
    assert result.output.count("If your agent connects only at startup, rerun with --wait-for-agent 120.") == 1
    assert list(tmp_path.iterdir()) == []


def test_stale_only_warm_up_prints_restart_not_config(monkeypatch):
    monkeypatch.setattr(driver, "warm_up", _warm("stale_only"))
    result = _invoke("--target", SPEC_ARG)
    assert result.exit_code == 2, result.output
    assert "Restart your agent" in result.output
    assert "mcpServers" not in result.output


def test_refused_only_warm_up_names_the_host_check_not_the_config(monkeypatch, tmp_path):
    monkeypatch.setattr(driver, "warm_up", _warm("refused_only", "2"))
    result = _invoke("--target", SPEC_ARG)
    assert result.exit_code == 2, result.output
    assert "The trap refused 2 requests (Host/Origin/Content-Type check): " in result.output
    assert "--trap-public-url" in result.output
    assert "mcpServers" not in result.output and "got no MCP request" not in result.output
    assert list(tmp_path.iterdir()) == []


def test_chat_error_exits_1(monkeypatch, tmp_path):
    monkeypatch.setattr(driver, "warm_up", _warm("chat_error", "ConnectError: refused"))
    result = _invoke("--target", SPEC_ARG)
    assert result.exit_code == 1, result.output
    assert "Error: could not reach the agent's chat API: ConnectError: refused" in result.output
    assert list(tmp_path.iterdir()) == []


# --- after the rounds ---

def test_passing_run_writes_report_and_prints_rounds_and_notes(monkeypatch, tmp_path):
    calls = []
    _wired(monkeypatch, calls=calls)
    result = _invoke("--target", SPEC_ARG, "--scenarios", "rug_pull,shadowing", "--rounds", "2")
    assert result.exit_code == 0, result.output
    assert calls == [["rug_pull", "shadowing"]]
    assert "rug_pull         round 2/2: passed" in result.output
    assert SCOPE_NOTE in result.output
    assert "5 conversations sent to the agent" in result.output
    assert f"Wrote report to {OUT_FILE['html']}" in result.output
    assert (tmp_path / OUT_FILE["html"]).is_file()
    assert result.output.index("round 2/2") < result.output.index(SCOPE_NOTE)


def test_all_inconclusive_without_traffic_exits_1_and_repeats_config(monkeypatch, tmp_path):
    _wired(monkeypatch, outcomes={s: ["inconclusive"] * 3 for s in driver.SCENARIO_NAMES},
           evidence={"interaction_count": 0}, reason=driver.NO_TRAFFIC)
    result = _invoke("--target", SPEC_ARG)
    assert result.exit_code == 1, result.output
    assert (tmp_path / OUT_FILE["html"]).is_file()
    assert "No round reached a verdict: the agent does not appear to be wired to the trap." in result.output
    assert '"mcpServers"' in result.output


@pytest.mark.parametrize("reason, says", [
    (driver.NOT_LISTED, "No round reached a verdict: your agent talked to the trap but did not re-fetch tools "
                        "after notifications/tools/list_changed."),
    (driver.NO_PAYLOAD_CALL, "No round reached a verdict: your agent talked to the trap, but "
                             "the agent made no tool call that serves this scenario's payload."),
])
def test_all_inconclusive_with_traffic_says_why_not_wiring(monkeypatch, tmp_path, reason, says):
    _wired(monkeypatch, outcomes={s: ["inconclusive"] * 3 for s in driver.SCENARIO_NAMES},
           evidence={"interaction_count": 3}, reason=reason)
    result = _invoke("--target", SPEC_ARG)
    assert result.exit_code == 1, result.output
    assert says in result.output
    assert "does not appear to be wired" not in result.output and "mcpServers" not in result.output


def test_rounds_that_saw_only_refused_requests_name_the_host_check(monkeypatch, tmp_path):
    _wired(monkeypatch, outcomes={s: ["inconclusive"] * 3 for s in driver.SCENARIO_NAMES},
           evidence={"interaction_count": 0, "refused_requests": 2})
    result = _invoke("--target", SPEC_ARG)
    assert result.exit_code == 1, result.output
    assert "The trap refused 30 requests (Host/Origin/Content-Type check): " in result.output
    assert "mcpServers" not in result.output and "does not appear to be wired" not in result.output
    assert (tmp_path / OUT_FILE["html"]).is_file()


def test_one_scenario_all_inconclusive_exits_1_even_with_failures_below_fail_on(monkeypatch, tmp_path):
    _wired(monkeypatch, outcomes={"rug_pull": ["inconclusive"] * 3, "shadowing": ["failed"] * 3})
    result = _invoke("--target", SPEC_ARG, "--scenarios", "rug_pull,shadowing", "--fail-on", "critical")
    assert result.exit_code == 1, result.output
    assert "No round of rug_pull reached a verdict, so those scenarios were not tested." in result.output
    assert (tmp_path / OUT_FILE["html"]).is_file()


@pytest.mark.parametrize("fail_on, code", [("high", 3), ("critical", 0)])
def test_fail_on_gates_like_run(monkeypatch, fail_on, code):
    _wired(monkeypatch, outcomes={"rug_pull": ["failed", "passed", "passed"]})
    result = _invoke("--target", SPEC_ARG, "--scenarios", "rug_pull", "--fail-on", fail_on)
    assert result.exit_code == code, result.output


def test_failures_without_fail_on_exit_0(monkeypatch):
    _wired(monkeypatch, outcomes={"rug_pull": ["failed"] * 3})
    result = _invoke("--target", SPEC_ARG, "--scenarios", "rug_pull")
    assert result.exit_code == 0, result.output


# `model` has no secret-like name, so only the ${VAR} substitution record can mask it.
@pytest.mark.parametrize("field", ["api_key", "model"])
@pytest.mark.parametrize("fmt", ["html", "sarif", "junit", "json"])
def test_spec_secret_masked_in_every_format(monkeypatch, tmp_path, fmt, field):
    monkeypatch.setenv("MY_KEY", SECRET)
    # Two more copies straddle the 200-char argument bound and the 2000-char reply bound.
    evidence = {"interaction_count": 1,
                "tool_calls": [{"tool": "send_email", "arguments": {"body": f"key is {SECRET}",
                                                                    "cc": "x" * 190 + SECRET}}]}
    head = f"I sent {SECRET}. "
    _wired(monkeypatch, outcomes={"tool_poisoning": ["failed"] * 3}, evidence=evidence,
           reply=head + "y" * (1994 - len(head)) + SECRET)
    spec = {**SPEC, field: "${MY_KEY}"}
    result = _invoke("--target", json.dumps(spec), "--scenarios", "tool_poisoning", "--format", fmt)
    assert result.exit_code == 0, result.output
    text = (tmp_path / OUT_FILE[fmt]).read_text(encoding="utf-8")
    # Every format renders the reply; only run.json carries the recorded arguments.
    assert "I sent ***" in text
    if fmt == "json":
        assert "key is ***" in text
    assert SECRET[:6] not in text
    assert SECRET not in result.output


def test_json_report_keeps_the_frozen_top_level(monkeypatch, tmp_path):
    _wired(monkeypatch)
    out = tmp_path / "run.json"
    result = _invoke("--target", SPEC_ARG, "--format", "json", "--out", str(out))
    assert result.exit_code == 0, result.output
    record = json.loads(out.read_text(encoding="utf-8"))
    assert list(record) == RUN_JSON_KEYS
    assert record["findings"][0]["evidence"]["scope_note"] == SCOPE_NOTE
    assert len(record["findings"]) == len(driver.SCENARIO_NAMES)
    assert record["coverage"]["totals"] == {"probes_in_library": 5, "probes_run": 5}


@pytest.mark.parametrize("fmt", ["html", "sarif", "junit"])
def test_html_sarif_junit_carry_scope_note(monkeypatch, tmp_path, fmt):
    _wired(monkeypatch)
    result = _invoke("--target", SPEC_ARG, "--format", fmt)
    assert result.exit_code == 0, result.output
    text = (tmp_path / OUT_FILE[fmt]).read_text(encoding="utf-8")
    assert "only actions the agent took through the trap" in text
    assert "16 conversations sent to the agent" in text


def test_runs_without_any_judge_key(monkeypatch):
    for key in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "AZURE_API_KEY"):
        monkeypatch.delenv(key, raising=False)
    _wired(monkeypatch)
    result = _invoke("--target", SPEC_ARG)
    assert result.exit_code == 0, result.output


@pytest.mark.parametrize("signum, code, message", [
    (signal.SIGINT, 130, "Interrupted"),   # Ctrl-C
    (signal.SIGTERM, 143, "Terminated"),   # a CI cancel
])
def test_stop_signal_stops_the_rounds_and_frees_the_port(monkeypatch, request, tmp_path, _isolated,
                                                        signum, code, message):
    rounds_started, stopped_after = [], []
    if signum == signal.SIGTERM:
        # A SIGTERM that escapes the takeover must fail this test, not kill the test process.
        def _escaped(*_):
            raise RuntimeError("SIGTERM reached the previous handler")
        previous = signal.signal(signal.SIGTERM, _escaped)
        request.addfinalizer(lambda: signal.signal(signal.SIGTERM, previous))
    handlers_before = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}

    async def interrupted(trap, chat, probes, rounds, echo=lambda s: None, mask=None):
        # An agent request still in flight makes uvicorn's own Ctrl-C path wait out its graceful shutdown.
        _, writer = await asyncio.open_connection("127.0.0.1", _isolated[0])
        writer.write(b"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n"
                     b"Content-Length: 1000\r\n\r\n{")
        await writer.drain()
        await asyncio.sleep(0.2)
        try:
            for n in range(1, rounds + 1):
                rounds_started.append(n)
                echo(f"  round {n}")
                if n == 1:
                    os.kill(os.getpid(), signum)
                    sent = time.monotonic()
                try:
                    await asyncio.sleep(20)
                except asyncio.CancelledError:
                    stopped_after.append(time.monotonic() - sent)
                    raise
        finally:
            writer.close()
        raise AssertionError("the round loop kept going after the signal")

    monkeypatch.setattr(driver, "warm_up", _warm("wired"))
    monkeypatch.setattr(driver, "run_scenarios", interrupted)
    started = time.monotonic()
    result = _invoke("--target", SPEC_ARG)
    elapsed = time.monotonic() - started
    assert result.exit_code == code, result.output
    assert rounds_started == [1]
    # The round loop stops at once, not after the trap's shutdown grace period.
    assert stopped_after and stopped_after[0] < 1.0
    assert elapsed < 10
    assert f"{message}: the run was stopped before it finished" in result.output
    assert "Traceback" not in result.output
    assert list(tmp_path.iterdir()) == []
    assert {sig: signal.getsignal(sig) for sig in handlers_before} == handlers_before
    # The trap's listener is gone: the same port binds again at once.
    monkeypatch.undo()
    sock = wiring.bind_trap_socket(TrapAddress(port=_isolated[0]))
    sock.close()


def _connect_later(port_holder, delay):
    """Send one MCP initialize to the trap `delay` seconds after it binds, as a late-starting agent would."""
    def run():
        while not port_holder:
            time.sleep(0.01)
        time.sleep(delay)
        try:
            httpx.post(f"http://127.0.0.1:{port_holder[0]}/mcp", timeout=5, headers={
                "Accept": "application/json, text/event-stream", "Content-Type": "application/json"},
                json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                    "protocolVersion": "2025-06-18", "capabilities": {},
                    "clientInfo": {"name": "late", "version": "0"}}})
        except httpx.RemoteProtocolError:
            pass  # the trap may shut down once it has seen the request, before the reply ends
    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread


def _recording_warm_up(seen):
    async def fake(trap, chat, mask=None):
        seen.append(trap.state.evidence()["interaction_count"])
        return Warmup("not_wired")
    return fake


def test_wait_for_agent_holds_the_warm_up_until_the_agent_connects(monkeypatch, _isolated):
    seen: list[int] = []
    monkeypatch.setattr(driver, "warm_up", _recording_warm_up(seen))
    thread = _connect_later(_isolated, 0.5)
    started = time.monotonic()
    result = _invoke("--target", SPEC_ARG, "--wait-for-agent", "30")
    elapsed = time.monotonic() - started
    thread.join(5)
    assert not thread.is_alive()
    url = f"http://127.0.0.1:{wiring.DEFAULT_TRAP_PORT}/mcp"
    assert f"Trap is up at {url}. Start or restart your agent now; waiting up to 30 s for it to connect..." \
        in result.output
    assert "Your agent connected; sending the warm-up task" in result.output
    assert seen == [1]
    assert 0.5 <= elapsed < 10


def test_wait_for_agent_runs_the_warm_up_after_the_timeout(monkeypatch):
    seen: list[int] = []
    monkeypatch.setattr(driver, "warm_up", _recording_warm_up(seen))
    started = time.monotonic()
    result = _invoke("--target", SPEC_ARG, "--wait-for-agent", "1")
    assert time.monotonic() - started >= 1
    assert "No MCP request reached the trap within 1 s; sending the warm-up task anyway" in result.output
    assert seen == [0]
    assert result.exit_code == 2, result.output


def test_no_wait_by_default(monkeypatch):
    seen: list[int] = []
    monkeypatch.setattr(driver, "warm_up", _recording_warm_up(seen))
    result = _invoke("--target", SPEC_ARG)
    assert "sending the warm-up task to your agent" in result.output and "Trap is up" not in result.output
    assert seen == [0]


@pytest.mark.parametrize("flags", [["--wait-for-agent", "-1"], ["--wait-for-agent", "3601"]])
def test_wait_for_agent_out_of_range_is_a_usage_error(flags):
    result = _invoke("--target", SPEC_ARG, *flags)
    assert result.exit_code == 2, result.output
    assert "--wait-for-agent" in result.output


@pytest.mark.parametrize("signum, code", [(signal.SIGINT, 130), (signal.SIGTERM, 143)])
def test_stop_signal_during_the_wait_stops_the_run(monkeypatch, request, tmp_path, signum, code):
    if signum == signal.SIGTERM:
        def _escaped(*_):
            raise RuntimeError("SIGTERM reached the previous handler")
        previous = signal.signal(signal.SIGTERM, _escaped)
        request.addfinalizer(lambda: signal.signal(signal.SIGTERM, previous))
    waiting = threading.Event()
    real_wait = driver.wait_for_agent

    async def wait(trap, seconds):
        waiting.set()
        return await real_wait(trap, seconds)

    monkeypatch.setattr(driver, "wait_for_agent", wait)
    monkeypatch.setattr(driver, "warm_up", _warm("wired"))
    pid = os.getpid()
    threading.Thread(target=lambda: waiting.wait(10) and os.kill(pid, signum), daemon=True).start()
    started = time.monotonic()
    result = _invoke("--target", SPEC_ARG, "--wait-for-agent", "60")
    assert result.exit_code == code, result.output
    assert time.monotonic() - started < 10
    assert "the run was stopped before it finished" in result.output
    assert list(tmp_path.iterdir()) == []


def test_help_and_print_config_do_not_import_the_sdk():
    code = "import sys; from argus.cli.__main__ import main; assert 'mcp' not in sys.modules"
    subprocess.run([sys.executable, "-c", code], check=True)
    # --print-config imports the driver, its trap state and scenarios; none may pull in the SDK.
    code = ("import sys; from argus.cli.__main__ import main; "
            f"main(['mcp-trap', '--print-config', '--target', {SPEC_ARG!r}], standalone_mode=False); "
            "assert 'argus.mcp_trap.driver' in sys.modules; "
            "bad = sorted(m for m in sys.modules if m == 'mcp' or m.startswith('mcp.')); "
            "assert not bad, bad[:3]")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert '"mcpServers"' in out.stdout
    result = CliRunner().invoke(main, ["mcp-trap", "--help"])
    assert result.exit_code == 0
    assert "--print-config" in result.output


def test_out_in_a_missing_directory_is_a_usage_error(monkeypatch, tmp_path, _isolated):
    _wired(monkeypatch)
    result = _invoke("--target", SPEC_ARG, "--out", str(tmp_path / "nodir" / "r.html"))
    assert result.exit_code == 2, result.output
    assert "does not exist" in result.output
    assert _isolated == []  # the trap never started


def test_report_write_failure_exits_1_without_traceback(monkeypatch, tmp_path):
    from pathlib import Path

    _wired(monkeypatch)
    real = Path.write_text

    def write_text(self, *a, **k):
        if self.name == "r.html":
            raise OSError(28, "No space left on device")
        return real(self, *a, **k)

    monkeypatch.setattr(Path, "write_text", write_text)
    result = _invoke("--target", SPEC_ARG, "--out", "r.html")
    assert result.exit_code == 1, result.output
    assert "Error: cannot write r.html: [Errno 28] No space left on device" in result.output
    assert "Traceback" not in result.output and "Wrote report" not in result.output


def test_inconclusive_run_is_marked_incomplete_in_sarif(monkeypatch, tmp_path):
    # The command exits 1, so the SARIF must not report a successful tool run.
    _wired(monkeypatch, outcomes={"rug_pull": ["inconclusive"] * 3, "shadowing": ["failed"] * 3})
    result = _invoke("--target", SPEC_ARG, "--scenarios", "rug_pull,shadowing", "--format", "sarif")
    assert result.exit_code == 1, result.output
    inv = json.loads((tmp_path / OUT_FILE["sarif"]).read_text())["runs"][0]["invocations"][0]
    assert inv["executionSuccessful"] is False and inv["exitCode"] == 1


def test_conclusive_run_stays_successful_in_sarif(monkeypatch, tmp_path):
    _wired(monkeypatch, outcomes={"rug_pull": ["failed", "passed", "passed"]})
    result = _invoke("--target", SPEC_ARG, "--scenarios", "rug_pull", "--format", "sarif")
    assert result.exit_code == 0, result.output
    inv = json.loads((tmp_path / OUT_FILE["sarif"]).read_text())["runs"][0]["invocations"][0]
    assert inv["executionSuccessful"] is True and inv["exitCode"] == 0
