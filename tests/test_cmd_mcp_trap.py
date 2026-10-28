import asyncio
import errno
import importlib.metadata
import json
import os
import signal
import socket
import subprocess
import sys
import time

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
    async def fake(trap, chat):
        return Warmup(status, detail)
    return fake


def _fake_run(outcomes=None, evidence=None, calls=None, reply="agent reply"):
    """run_scenarios stand-in: `outcomes` maps scenario -> round outcomes (default: all passed)."""
    outcomes = outcomes or {}

    async def fake(trap, chat, probes, rounds, echo=lambda s: None):
        if calls is not None:
            calls.append([p.scenario_kind for p in probes])
        conversations = 1 + len(probes) * rounds
        findings, inconclusive = [], []
        for probe in probes:
            kinds = outcomes.get(probe.scenario_kind, ["passed"] * rounds)
            rounds_out = [
                RoundOutcome(i + 1, kind, f"{kind} reason", probe.prompts[0], reply,
                             evidence or {"interaction_count": 1})
                for i, kind in enumerate(kinds)
            ]
            for r in rounds_out:
                echo(f"  {probe.scenario_kind:<16} round {r.round}/{rounds}: {r.outcome} ({r.reason})")
            finding = driver.scenario_finding(probe, rounds_out, conversations)
            findings.append(finding)
            if finding["verdict"] == "error":
                inconclusive.append(probe.scenario_kind)
        notes = [SCOPE_NOTE, f"{conversations} conversations sent to the agent."]
        return TrapRun(findings, notes, conversations, inconclusive)
    return fake


def _wired(monkeypatch, **kwargs):
    monkeypatch.setattr(driver, "warm_up", _warm("wired"))
    monkeypatch.setattr(driver, "run_scenarios", _fake_run(**kwargs))


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
    assert list(tmp_path.iterdir()) == []


def test_stale_only_warm_up_prints_restart_not_config(monkeypatch):
    monkeypatch.setattr(driver, "warm_up", _warm("stale_only"))
    result = _invoke("--target", SPEC_ARG)
    assert result.exit_code == 2, result.output
    assert "Restart your agent" in result.output
    assert "mcpServers" not in result.output


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


def test_all_inconclusive_exits_1_and_repeats_config(monkeypatch, tmp_path):
    _wired(monkeypatch, outcomes={s: ["inconclusive"] * 3 for s in driver.SCENARIO_NAMES})
    result = _invoke("--target", SPEC_ARG)
    assert result.exit_code == 1, result.output
    assert (tmp_path / OUT_FILE["html"]).is_file()
    assert "No round reached a verdict: the agent does not appear to be wired to the trap." in result.output
    assert '"mcpServers"' in result.output


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
    evidence = {"interaction_count": 1,
                "tool_calls": [{"tool": "send_email", "arguments": {"body": f"key is {SECRET}"}}]}
    _wired(monkeypatch, outcomes={"tool_poisoning": ["failed"] * 3}, evidence=evidence,
           reply=f"I sent {SECRET}")
    spec = {**SPEC, field: "${MY_KEY}"}
    result = _invoke("--target", json.dumps(spec), "--scenarios", "tool_poisoning", "--format", fmt)
    assert result.exit_code == 0, result.output
    text = (tmp_path / OUT_FILE[fmt]).read_text(encoding="utf-8")
    # Every format renders the reply; only run.json carries the recorded arguments.
    assert "I sent ***" in text
    if fmt == "json":
        assert "key is ***" in text
    assert SECRET not in text
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

    async def interrupted(trap, chat, probes, rounds, echo=lambda s: None):
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
