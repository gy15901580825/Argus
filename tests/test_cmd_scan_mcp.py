import json
import logging
import os
import signal
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
from click.testing import CliRunner

from argus.cli import cmd_scan_mcp, mcp_sdk
from argus.cli.__main__ import main
from argus.mcp_scan import checks, scan
from argus.mcp_scan.client import ConnectError, HttpServer, StdioServer
from argus.mcp_scan.findings import SNYK_LINE, finding
from argus.mcp_scan.judging import CAP_REASON, ERROR_REASON
from argus.mcp_scan.scan import ScanResult, UnknownTools
from argus.mcp_scan.server_checks import server_probes
from argus.probe import load_all_probes

URL = "http://127.0.0.1:9/mcp"
STDIO = ["--on-host", "--", "python", "server.py"]
OUT_FILE = {"html": "argus-mcp-scan-report.html", "sarif": "argus-mcp-scan-report.sarif",
            "junit": "argus-mcp-scan-report.xml", "json": "argus-mcp-scan-report.json"}
PROBES = {p.id: p for p in [*load_all_probes(scan.SCAN_PROBES_DIR), *server_probes()]}
ON_HOST_MESSAGE = ("stdio servers need --on-host for now: it runs the server's code on this machine with your "
                   "privileges. Use it only for code you trust, or start the server yourself and scan its URL.")


@pytest.fixture(autouse=True)
def _isolated(monkeypatch, tmp_path):
    import argus.judge

    async def _forbidden(*args, **kwargs):
        raise AssertionError("the CLI tests must never call the LLM judge")

    monkeypatch.setattr(argus.judge.Judge, "judge", _forbidden)
    monkeypatch.chdir(tmp_path)
    for name in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "REDTEAM_MODEL_PROVIDER"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    monkeypatch.setenv("no_proxy", "127.0.0.1,localhost")
    # The engine is faked, so these tests run without the SDK too; the SDK tests put the real check back.
    monkeypatch.setattr(cmd_scan_mcp, "sdk_problem", lambda extra: None)


def _real_sdk_check(monkeypatch):
    monkeypatch.setattr(cmd_scan_mcp, "sdk_problem", mcp_sdk.sdk_problem)


def _invoke(*args):
    return CliRunner().invoke(main, ["scan-mcp", *args])


def _f(probe_id, verdict="fail", severity="high", **evidence):
    reasoning = evidence.pop("reasoning", f"{probe_id} reasoning")
    response = evidence.pop("target_response", "")
    return finding(PROBES[probe_id], verdict=verdict, severity=severity, reasoning=reasoning,
                   evidence={"transport": "http", **evidence}, target_response=response)


def _result(findings=(), notes=None, unexercised=False, unjudged=0, no_tool_called=False, out_of_time=False):
    return ScanResult(findings=list(findings), notes=list(notes or [SNYK_LINE]), server_info=None,
                      all_selected_unexercised=unexercised, unjudged=unjudged, no_tool_called=no_tool_called,
                      out_of_time=out_of_time)


def _fake(monkeypatch, result=None, *, raises=None, during=None):
    """Replace the engine; returns the list of ScanConfigs it was called with."""
    seen = []

    async def fake(cfg, *, mask, echo):
        seen.append(cfg)
        if during is not None:
            await during(cfg, mask, echo)
        if raises is not None:
            raise raises
        return result if result is not None else _result()

    monkeypatch.setattr(scan, "scan_mcp", fake)
    return seen


def _no_sdk(monkeypatch):
    for name in [m for m in sys.modules if m == "mcp" or m.startswith("mcp.")]:
        monkeypatch.delitem(sys.modules, name)
    monkeypatch.setitem(sys.modules, "mcp", None)


# --- the SDK ---

def test_help_works_without_the_sdk(monkeypatch):
    _no_sdk(monkeypatch)
    result = _invoke("--help")
    assert result.exit_code == 0, result.output
    assert "--on-host" in result.output and "--call-tools" in result.output
    code = ("import sys; from argus.cli.__main__ import main\n"
            "try:\n    main(['scan-mcp', '--help'])\nexcept SystemExit as e:\n    assert e.code == 0, e.code\n"
            "bad = sorted(m for m in sys.modules if m == 'mcp' or m.startswith('mcp.'))\n"
            "assert not bad, bad[:3]")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert "--per-run-cap" in out.stdout


def test_missing_sdk_says_scan_mcp_extra(monkeypatch, tmp_path):
    _real_sdk_check(monkeypatch)
    _no_sdk(monkeypatch)
    seen = _fake(monkeypatch)
    result = _invoke(URL)
    assert result.exit_code == 2, result.output
    assert "scan-mcp needs the MCP SDK 2.3 or newer: pip install 'argus-probe[scan-mcp]'" in result.stderr
    assert "Traceback" not in result.output
    assert seen == [] and list(tmp_path.iterdir()) == []


def test_unsupported_sdk_version_names_the_found_version(monkeypatch):
    import importlib.metadata

    _real_sdk_check(monkeypatch)
    monkeypatch.setitem(sys.modules, "mcp", sys.modules.get("mcp") or type(sys)("mcp"))
    real = importlib.metadata.version
    monkeypatch.setattr(importlib.metadata, "version", lambda dist: "1.27.0" if dist == "mcp" else real(dist))
    seen = _fake(monkeypatch)
    result = _invoke(URL)
    assert result.exit_code == 2, result.output
    assert "pip install 'argus-probe[scan-mcp]' (found mcp 1.27.0)" in result.stderr
    assert seen == []


def test_mcp_trap_sdk_messages_unchanged(monkeypatch):
    from argus.cli import cmd_mcp_trap, mcp_sdk

    _no_sdk(monkeypatch)
    old = "mcp-trap needs the MCP SDK 2.3 or newer: pip install 'argus-probe[mcp-trap]'"
    assert mcp_sdk.sdk_problem("mcp-trap") == old
    assert cmd_mcp_trap._sdk_problem() == old
    assert cmd_mcp_trap._STOP_MESSAGES is mcp_sdk.STOP_MESSAGES
    assert cmd_mcp_trap._CONTROL_RE is mcp_sdk.CONTROL_RE
    assert cmd_mcp_trap._cancel_on_stop_signals is mcp_sdk.cancel_on_stop_signals


# --- usage and setup: exit 2, the engine never runs ---

def test_stdio_without_on_host_exits_2_naming_the_flag(monkeypatch, tmp_path):
    seen = _fake(monkeypatch)
    result = _invoke("--", "python", "server.py")
    assert result.exit_code == 2, result.output
    assert ON_HOST_MESSAGE in result.stderr
    assert seen == [] and list(tmp_path.iterdir()) == []


def _args_file(tmp_path, content):
    path = tmp_path / "args.json"
    path.write_text(content, encoding="utf-8")
    return str(path)


@pytest.mark.parametrize("case, args, expect", [
    ("no target", [], "scan-mcp <url>"),
    ("url plus args", [URL, "extra"], "-- <command>"),
    ("header with stdio", ["--header", "X-Key: v", *STDIO], "--header"),
    ("env with url", ["--env", "HOME", URL], "--env"),
    ("on-host with url", ["--on-host", URL], "--on-host"),
    ("all mixed with names", ["--call-tools", "all,x", URL], "'all'"),
    ("empty call-tools", ["--call-tools", " , ", URL], "--call-tools"),
    ("args not an object", ["--args", "@[1, 2]", URL], "--args"),
    ("args value not an object", ["--args", '@{"t": 1}', URL], "--args"),
    ("args not json", ["--args", "@{nope", URL], "--args"),
    ("header without colon", ["--header", "Authorization", URL], "Name: value"),
    ("unset env name", ["--env", "ARGUS_T8_UNSET_VAR", *STDIO], "ARGUS_T8_UNSET_VAR"),
    ("cap nan", ["--per-run-cap", "nan", URL], "--per-run-cap"),
    ("cap inf", ["--per-run-cap", "inf", URL], "--per-run-cap"),
    ("cap negative", ["--per-run-cap", "-1", URL], "--per-run-cap"),
    ("timeout nan", ["--timeout", "nan", URL], "--timeout"),
    ("timeout below 1", ["--timeout", "0.5", URL], "--timeout"),
    ("max-runtime zero", ["--max-runtime", "0", URL], "--max-runtime"),
    ("max-runtime negative", ["--max-runtime", "-5", URL], "--max-runtime"),
    ("max-runtime inf", ["--max-runtime", "inf", URL], "--max-runtime"),
    ("max-runtime nan", ["--max-runtime", "nan", URL], "--max-runtime"),
])
def test_usage_errors(monkeypatch, tmp_path, case, args, expect):
    monkeypatch.delenv("ARGUS_T8_UNSET_VAR", raising=False)
    args = [_args_file(tmp_path, a[1:]) if a.startswith("@") else a for a in args]
    seen = _fake(monkeypatch)
    result = _invoke(*args)
    assert result.exit_code == 2, (case, result.output)
    assert expect in result.output, (case, result.output)
    assert "Traceback" not in result.output
    assert seen == []
    assert not any(p.name.startswith("argus-mcp-scan-report") for p in tmp_path.iterdir())


def test_no_target_names_both_forms(monkeypatch):
    _fake(monkeypatch)
    for args in ([], [URL, "extra"]):
        result = _invoke(*args)
        assert result.exit_code == 2
        assert "scan-mcp <url>" in result.output and "scan-mcp [options] -- <command>" in result.output


def test_auth_failure_exits_2_and_never_echoes_token(monkeypatch, tmp_path):
    token = "tok-" + "9f8e7d6c5b4a"
    message = (f"The server answered HTTP 401 for Bearer {token}; pass the credentials its clients send with "
               "--header 'Name: value'.")
    _fake(monkeypatch, raises=ConnectError("auth", message))
    result = _invoke(URL, "--header", f"Authorization: Bearer {token}")
    assert result.exit_code == 2, result.output
    assert token not in result.output
    assert "HTTP 401 for ***;" in result.stderr and "--header" in result.stderr
    assert "could not connect" not in result.output
    assert list(tmp_path.iterdir()) == []


def test_unknown_call_tools_exit_2_lists_names(monkeypatch, tmp_path):
    _fake(monkeypatch, raises=UnknownTools(["nope"], ["alpha", "beta\x1b[2J"]))
    result = _invoke(URL, "--call-tools", "nope")
    assert result.exit_code == 2, result.output
    assert "--call-tools names tools the server does not list: nope" in result.stderr
    assert "alpha, beta[2J" in result.stderr
    assert "\x1b" not in result.output
    assert list(tmp_path.iterdir()) == []


# --- exit 1 ---

@pytest.mark.parametrize("args, error", [
    ([URL], ConnectError("refused", "Could not connect to the server (connection refused).")),
    (["--on-host", "--", "python", "server.py", "--token=cmd-secret-4k2j"],
     ConnectError("died", "The server process exited before the MCP handshake finished.",
                  stderr_tail="Traceback: bad cmd-secret-4k2j\x1b[31m\nValueError: boom")),
])
def test_connect_failure_exits_1_without_report(monkeypatch, tmp_path, args, error):
    _fake(monkeypatch, raises=error)
    result = _invoke(*args)
    assert result.exit_code == 1, result.output
    assert f"Error: could not connect: {error}" in result.stderr
    if error.stderr_tail:
        assert "ValueError: boom" in result.stderr
        assert "cmd-secret-4k2j" not in result.output and "\x1b" not in result.output
    assert list(tmp_path.iterdir()) == []


def test_engine_crash_exits_1_and_says_why(monkeypatch, tmp_path):
    _fake(monkeypatch, raises=RuntimeError("unexpected engine state"))
    result = _invoke(URL)
    assert result.exit_code == 1, result.output
    assert "Error: unexpected engine state" in result.stderr
    assert "Traceback" not in result.output
    assert list(tmp_path.iterdir()) == []


def test_all_unexercised_exits_1_with_report(monkeypatch, tmp_path):
    errs = [_f(checks.COMMAND, "error", "info", reasoning="not exercised: echo")]
    _fake(monkeypatch, _result(errs, unexercised=True))
    result = _invoke(URL, "--call-tools", "all")
    assert result.exit_code == 1, result.output
    assert (tmp_path / OUT_FILE["html"]).is_file()
    assert "No tool selected for calling could be exercised" in result.stderr


def test_cap_unjudged_exits_1_after_counting_fail_on(monkeypatch, tmp_path):
    found = [_f(checks.SECRET, "fail", "high", tool="t", excerpt="x"),
             _f(checks.INJECTION, "error", "info", reasoning=CAP_REASON, tool="t")]
    _fake(monkeypatch, _result(found, unjudged=1))
    result = _invoke(URL, "--fail-on", "high")
    assert result.exit_code == 1, result.output
    assert f"1 finding(s) at or above high: {checks.SECRET}" in result.stderr
    assert "left unjudged" in result.stderr
    assert result.stderr.index("at or above high") < result.stderr.index("left unjudged")
    assert (tmp_path / OUT_FILE["html"]).is_file()


def test_unexercised_wins_over_fail_on(monkeypatch, tmp_path):
    _fake(monkeypatch, _result([_f(checks.DESCRIPTION, "fail", "high", tool="t", excerpt="x")], unexercised=True))
    result = _invoke(URL, "--fail-on", "low")
    assert result.exit_code == 1, result.output
    assert "1 finding(s) at or above low" in result.stderr


# --- exit 3 and 0 ---

def test_fail_on_exits_3(monkeypatch, tmp_path):
    _fake(monkeypatch, _result([_f(checks.COMMAND, "fail", "critical", tool="run", excerpt="ran 4321")]))
    result = _invoke(URL, "--fail-on", "high", "--format", "sarif")
    assert result.exit_code == 3, result.output
    assert f"1 finding(s) at or above high: {checks.COMMAND}" in result.stderr
    assert (tmp_path / OUT_FILE["sarif"]).is_file()


def test_fail_below_threshold_exits_0(monkeypatch, tmp_path):
    _fake(monkeypatch, _result([_f(checks.REFLECTION, "fail", "low", tool="echo", excerpt="x")]))
    result = _invoke(URL, "--fail-on", "high")
    assert result.exit_code == 0, result.output


def test_clean_exits_0(monkeypatch, tmp_path):
    clean = [_f(checks.COMMAND, "pass", "info", tools=["echo"]),
             _f(checks.SECRET, "skipped", "info", reasoning="no tool was called")]
    _fake(monkeypatch, _result(clean, no_tool_called=True))
    result = _invoke(URL, "--fail-on", "info", "--format", "json", "--out", "r.json")
    assert result.exit_code == 0, result.output
    doc = json.loads((tmp_path / "r.json").read_text())
    assert [f["probe_id"] for f in doc["findings"]] == [checks.COMMAND, checks.SECRET]
    assert doc["status"] == "completed"
    assert result.stderr == ""


# --- the config handed to the engine ---

def test_http_config(monkeypatch, tmp_path):
    seen = _fake(monkeypatch)
    args = _args_file(tmp_path, '{"echo": {"text": "hi"}}')
    result = _invoke(URL, "--header", "X-Api-Key: key-value-1234", "--header", "X-Trace:  t1 ",
                     "--call-tools", "echo, read", "--args", args, "--timeout", "5", "--per-run-cap", "0.25")
    assert result.exit_code == 0, result.output
    (cfg,) = seen
    assert cfg.target == HttpServer(url=URL, headers=(("X-Api-Key", "key-value-1234"), ("X-Trace", "t1")))
    assert cfg.call_tools == frozenset({"echo", "read"})
    assert dict(cfg.args) == {"echo": {"text": "hi"}}
    assert (cfg.timeout_s, cfg.per_run_cap_usd, cfg.transport) == (5.0, 0.25, "http")
    assert cfg.max_runtime_s == 1800.0
    seen.clear()
    assert _invoke(URL, "--max-runtime", "90").exit_code == 0
    assert seen[0].max_runtime_s == 90.0


def test_stdio_config_passes_only_named_env(monkeypatch):
    monkeypatch.setenv("ARGUS_T8_PASSED", "passed-value-1234")
    monkeypatch.setenv("ARGUS_T8_WITHHELD", "withheld-value-1234")
    seen = _fake(monkeypatch)
    result = _invoke("--env", "ARGUS_T8_PASSED", "--call-tools", "all", "--on-host", "--", "node", "s.js", "-v")
    assert result.exit_code == 0, result.output
    (cfg,) = seen
    assert isinstance(cfg.target, StdioServer)
    assert cfg.target.argv == ("node", "s.js", "-v")
    assert cfg.target.env["ARGUS_T8_PASSED"] == "passed-value-1234"
    assert "ARGUS_T8_WITHHELD" not in cfg.target.env
    assert set(cfg.target.env) <= {"PATH", "HOME", "LANG", "TMPDIR", "ARGUS_T8_PASSED"}
    assert (cfg.call_tools, cfg.transport) == ("all", "stdio-host")


def test_on_host_note_says_child_processes_may_outlive(monkeypatch):
    _fake(monkeypatch)
    result = _invoke(*STDIO)
    assert result.exit_code == 0, result.output
    assert "may outlive the scan" in result.stdout
    http = _invoke(URL)
    assert "outlive" not in http.output


# --- the judge ---

@pytest.mark.parametrize("env, args, reason", [
    ({}, [], "ANTHROPIC_API_KEY is not set"),
    ({"ANTHROPIC_API_KEY": "anthropic-key-1234"}, ["--per-run-cap", "0"], "--per-run-cap 0 turns the judge off"),
    ({"REDTEAM_MODEL_PROVIDER": "nosuch"}, [], "REDTEAM_MODEL_PROVIDER='nosuch' is not supported"),
])
def test_no_judge_credentials_is_a_note_not_an_exit(monkeypatch, env, args, reason):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    seen = []

    async def fake(cfg, *, mask, echo):
        seen.append(cfg)
        return _result(notes=[f"Judge skipped: {cfg.judge_off_reason}; 1 text(s) were not judged:", SNYK_LINE])

    monkeypatch.setattr(scan, "scan_mcp", fake)
    result = _invoke(URL, *args)
    assert result.exit_code == 0, result.output
    (cfg,) = seen
    assert cfg.judge_config is None
    assert reason in cfg.judge_off_reason
    assert "Judge skipped" in result.stdout and reason in result.stdout


def test_judge_credentials_reach_the_engine(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "anthropic-key-1234")
    seen = _fake(monkeypatch)
    result = _invoke(URL)
    assert result.exit_code == 0, result.output
    (cfg,) = seen
    assert cfg.judge_config is not None and cfg.judge_off_reason == ""


# --- console ---

def test_console_ends_with_snyk_line(monkeypatch):
    found = [
        _f(checks.COMMAND, "fail", "critical", tool="run_cmd", decided_by="rule",
           excerpt="uid=0(root)\n   gid=0 " + "z" * 200),
        _f(checks.INJECTION, "fail", "high", tool="fetch", decided_by="judge", excerpt="Ignore the user"),
        _f(checks.LIST_CHANGED, "fail", "medium", tool=None, excerpt="the listing changed"),
        _f("mcp_server_no_auth", "fail", "high", reasoning="the server answered without credentials"),
        _f(checks.SECRET, "pass", "info", tools=["fetch"]),
    ]
    _fake(monkeypatch, _result(found, notes=["read_env [no annotations]: not called by policy", SNYK_LINE]))
    result = _invoke(URL)
    assert result.exit_code == 0, result.output
    lines = result.stdout.splitlines()
    assert lines[-1] == SNYK_LINE
    assert lines[-2] == "read_env [no annotations]: not called by policy"
    assert lines[-3] == f"Wrote report to {OUT_FILE['html']}"
    fails = [ln for ln in lines if ln.startswith("  ")]
    assert fails[0] == f"  {'critical':<9} {checks.COMMAND:<36} run_cmd  " + ("uid=0(root) gid=0 " + "z" * 200)[:97] + "..."
    assert fails[1] == f"  {'high':<9} {checks.INJECTION:<36} fetch  judged  Ignore the user"
    assert fails[2] == f"  {'medium':<9} {checks.LIST_CHANGED:<36} -  the listing changed"
    assert fails[3] == f"  {'high':<9} {'mcp_server_no_auth':<36} -  the server answered without credentials"
    assert len(fails) == 4


# --- secrets ---

HEADER_VALUE = "hdr-" + "secret-81af"
ENV_VALUE = "env-" + "secret-62bd"
URL_PASSWORD = "url-" + "pass-37ce"
QUERY_TOKEN = "query-" + "tok-49df"
CMD_TOKEN = "cmd-" + "tok-15ea"
SECRETS = (HEADER_VALUE, ENV_VALUE, URL_PASSWORD, QUERY_TOKEN, CMD_TOKEN)


def _leaky(*values):
    text = " ".join(values) + " \x1b[31m"
    return [_f(checks.SECRET, "fail", "high", tool=f"t {values[0]}", excerpt=text, url=text, target_response=text,
               reasoning=f"leaked {text}", items=[{"excerpt": text, values[-1]: text}])]


@pytest.mark.parametrize("transport", ["http", "stdio"])
@pytest.mark.parametrize("fmt", ["html", "sarif", "junit", "json"])
def test_known_secrets_absent_from_every_format(monkeypatch, tmp_path, fmt, transport):
    monkeypatch.setenv("ARGUS_T8_TOKEN", ENV_VALUE)
    if transport == "http":
        url = f"https://argus:{URL_PASSWORD}@example.invalid/mcp?access_token={QUERY_TOKEN}"
        args = [url, "--header", f"Authorization: Bearer {HEADER_VALUE}"]
        values = (HEADER_VALUE, URL_PASSWORD, QUERY_TOKEN)
    else:
        args = ["--env", "ARGUS_T8_TOKEN", "--on-host", "--", "python", "s.py", f"--token={CMD_TOKEN}",
                f"https://argus:{URL_PASSWORD}@example.invalid/?access_token={QUERY_TOKEN}"]
        values = (ENV_VALUE, CMD_TOKEN, URL_PASSWORD, QUERY_TOKEN)

    async def during(cfg, mask, echo):
        echo(f"calling with {' '.join(values)}")
        for v in values:
            assert mask(f"<{v}>") == "<***>"

    _fake(monkeypatch, _result(_leaky(*values), notes=[f"note {' '.join(values)}", SNYK_LINE]), during=during)
    result = _invoke("--format", fmt, *args)
    assert result.exit_code == 0, result.output
    report = (tmp_path / OUT_FILE[fmt]).read_text(encoding="utf-8")
    for v in SECRETS:
        assert v not in report, (v, fmt)
        assert v not in result.output, v
    assert "\x1b" not in result.output
    if fmt == "json":
        spec = json.loads(report)["target_spec"]
        if transport == "http":
            assert spec == {"kind": "mcp_server", "url": "https://example.invalid/mcp?access_token=***",
                            "headers": {"Authorization": "***"}}
        else:
            assert spec["kind"] == "mcp_stdio" and spec["sandbox"] is False
            assert spec["command"][:3] == ["python", "s.py", "--token=***"]


def test_control_stripped_secret_is_masked_on_the_console(monkeypatch):
    # A secret holding a control byte is printed with the byte stripped; that form must be masked too.
    raw = "ctl-sec\x07ret-5521"
    _fake(monkeypatch, _result(_leaky("ctl-secret-5521")))
    result = _invoke(URL, "--header", f"X-Api-Key: {raw}")
    assert result.exit_code == 0, result.output
    assert "ctl-secret-5521" not in result.output
    assert f"{checks.SECRET:<36} t ***  " in result.stdout


# --- signals ---

@pytest.mark.parametrize("signum, code, message", [
    (signal.SIGINT, 130, "Interrupted"),
    (signal.SIGTERM, 143, "Terminated"),
])
def test_sigint_writes_no_report_and_exits_130(monkeypatch, request, tmp_path, signum, code, message):
    import asyncio

    if signum == signal.SIGTERM:
        # A SIGTERM that escapes the takeover must fail this test, not kill the test process.
        def _escaped(*_):
            raise RuntimeError("SIGTERM reached the previous handler")
        previous = signal.signal(signal.SIGTERM, _escaped)
        request.addfinalizer(lambda: signal.signal(signal.SIGTERM, previous))
    handlers_before = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
    cancelled = []

    async def during(cfg, mask, echo):
        os.kill(os.getpid(), signum)
        try:
            await asyncio.sleep(20)
        except asyncio.CancelledError:
            cancelled.append(True)
            raise
        raise AssertionError("the scan kept going after the signal")

    _fake(monkeypatch, during=during)
    result = _invoke(URL)
    assert result.exit_code == code, result.output
    assert cancelled == [True]
    assert f"{message}: the scan was stopped before it finished; no report was written." in result.stderr
    assert "Traceback" not in result.output
    assert list(tmp_path.iterdir()) == []
    assert {sig: signal.getsignal(sig) for sig in handlers_before} == handlers_before


# --- SDK logging ---

def test_sdk_warnings_never_reach_stderr(monkeypatch):
    # As in a real run, no root handler: logging's last resort would print to the (captured) stderr.
    monkeypatch.setattr(logging.getLogger(), "handlers", [])
    loggers = [logging.getLogger(name) for name in ("mcp", "client")]
    before = [(list(log.handlers), log.propagate, log.level) for log in loggers]

    async def during(cfg, mask, echo):
        try:
            raise ValueError("server-supplied SERVERTEXT-1 \x1b[31m")
        except ValueError:
            # The SDK's client session logs under the bare name "client".
            logging.getLogger("client").warning("Failed to validate notification: %s", "x", exc_info=True)
            logging.getLogger("mcp.client.streamable_http").exception("Error parsing SSE message %s",
                                                                      "SERVERTEXT-2 \x1b[2J")

    _fake(monkeypatch, during=during)
    result = _invoke(URL, "--header", "X-Api-Key: SERVERTEXT-2")
    assert result.exit_code == 0, result.output
    assert "Failed to validate" not in result.output and "SERVERTEXT-1" not in result.output
    assert "Traceback" not in result.output
    # An SDK error stays visible, as one masked line without the traceback.
    assert "MCP SDK error: Error parsing SSE message ***" in result.stderr
    assert "\x1b" not in result.output
    assert [(list(log.handlers), log.propagate, log.level) for log in loggers] == before


_RAW_SERVER = textwrap.dedent('''
    import json, sys
    def send(m):
        sys.stdout.write(json.dumps(m) + "\\n"); sys.stdout.flush()
    for line in sys.stdin:
        msg = json.loads(line)
        method, mid = msg.get("method"), msg.get("id")
        if method == "initialize":
            send({"jsonrpc": "2.0", "id": mid, "result": {"protocolVersion": msg["params"]["protocolVersion"],
                  "capabilities": {"tools": {}}, "serverInfo": {"name": "raw", "version": "1.0.0"}}})
        elif method == "tools/list":
            # notifications/message with a level no MCP version defines: the SDK fails to validate it.
            send({"jsonrpc": "2.0", "method": "notifications/message",
                  "params": {"level": "SERVERTEXT-bogus", "data": "x"}})
            send({"jsonrpc": "2.0", "id": mid, "result": {"tools": []}})
        elif mid is not None:
            send({"jsonrpc": "2.0", "id": mid, "result": {}})
''')


def test_invalid_server_notification_is_not_printed_end_to_end(tmp_path):
    pytest.importorskip("mcp")
    server = tmp_path / "raw_server.py"
    server.write_text(_RAW_SERVER, encoding="utf-8")
    env = {k: v for k, v in os.environ.items()
           if k not in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "REDTEAM_MODEL_PROVIDER")}
    out = subprocess.run([sys.executable, "-c", "from argus.cli.__main__ import main; main()", "scan-mcp",
                          "--on-host", "--timeout", "10", "--", sys.executable, str(server)],
                         capture_output=True, text=True, cwd=tmp_path, env=env, timeout=120)
    assert out.returncode == 0, out.stdout + out.stderr
    assert "Listed 0 tool(s)" in out.stdout
    assert "--call-tools" in out.stdout  # static-only scans exit 0 with the hint
    assert "SERVERTEXT" not in out.stderr + out.stdout
    assert "Failed to validate" not in out.stderr
    assert out.stdout.splitlines()[-1] == SNYK_LINE
    assert (Path(tmp_path) / OUT_FILE["html"]).is_file()


def test_console_cut_never_leaves_part_of_a_secret(monkeypatch):
    # The secret straddles the 100-character cut; cutting before masking would print its first part.
    value = "cut-" + "secret-value-7731"
    excerpt = "x" * 90 + value + " tail"
    _fake(monkeypatch, _result([_f(checks.SECRET, "fail", "high", tool="t", excerpt=excerpt)]))
    result = _invoke(URL, "--header", f"X-Api-Key: {value}")
    assert result.exit_code == 0, result.output
    assert "cut-secr" not in result.output
    assert f"{'x' * 90}*** tail" in result.stdout


def test_usage_and_on_host_are_checked_before_the_sdk(monkeypatch):
    _real_sdk_check(monkeypatch)
    _no_sdk(monkeypatch)
    usage = _invoke(URL, "--on-host")
    assert usage.exit_code == 2 and "--on-host applies to stdio servers only" in usage.output
    on_host = _invoke("--", "python", "server.py")
    assert on_host.exit_code == 2 and ON_HOST_MESSAGE in on_host.stderr
    assert "MCP SDK" not in usage.output + on_host.output


# --- fix round 1 ---

def test_env_values_below_the_known_secrets_floor_are_not_masked(monkeypatch, tmp_path):
    monkeypatch.setenv("ARGUS_T8_SHORT", "k3x")
    monkeypatch.setenv("ARGUS_T8_LONG", "m8vp")
    _fake(monkeypatch, _result(_leaky("k3x m8vp")))
    result = _invoke("--format", "json", "--env", "ARGUS_T8_SHORT", "--env", "ARGUS_T8_LONG", *STDIO)
    assert result.exit_code == 0, result.output
    report = (tmp_path / OUT_FILE["json"]).read_text(encoding="utf-8")
    assert "k3x ***" in report and "m8vp" not in report
    assert "k3x ***" in result.stdout and "m8vp" not in result.output


def test_out_in_a_missing_directory_is_a_usage_error(monkeypatch, tmp_path):
    seen = _fake(monkeypatch)
    result = _invoke("--out", str(tmp_path / "nodir" / "r.html"), URL)
    assert result.exit_code == 2, result.output
    assert "does not exist" in result.output and "nodir" in result.output
    assert seen == []


def _unwritable(monkeypatch, name):
    real = Path.write_text

    def write_text(self, *a, **k):
        if self.name == name:
            raise OSError(28, "No space left on device")
        return real(self, *a, **k)

    monkeypatch.setattr(Path, "write_text", write_text)


def test_report_write_failure_exits_1_without_traceback(monkeypatch, tmp_path):
    _fake(monkeypatch)
    _unwritable(monkeypatch, "r.html")
    result = _invoke("--out", "r.html", URL)
    assert result.exit_code == 1, result.output
    assert "Error: cannot write r.html: [Errno 28] No space left on device" in result.stderr
    assert "Traceback" not in result.output and "Wrote report" not in result.output


def test_unknown_call_tools_shows_ten_names_and_a_count(monkeypatch):
    names = [f"tool_{i:02d}" for i in range(25)]
    _fake(monkeypatch, raises=UnknownTools(["nope"], names))
    result = _invoke(URL, "--call-tools", "nope")
    assert result.exit_code == 2, result.output
    assert f"The server lists: {', '.join(names[:10])} and 15 more." in result.stderr
    assert "tool_10" not in result.output
    _fake(monkeypatch, raises=UnknownTools(["nope"], names[:10]))
    exact = _invoke(URL, "--call-tools", "nope")
    assert f"The server lists: {', '.join(names[:10])}." in exact.stderr and "more" not in exact.stderr


def _stderr_secrets() -> list[str]:
    # Built from parts so repo secret scanners do not flag the shapes.
    return ["gh" + "p_" + "Zq9W" * 9, "AKIA" + "Q" * 16, "hunter2" + "hunter2"]


def test_server_stderr_tail_is_redacted_end_to_end(tmp_path):
    pytest.importorskip("mcp")
    token, aws, password = _stderr_secrets()
    server = tmp_path / "stderr_server.py"
    server.write_text(textwrap.dedent(f'''
        import sys
        sys.stderr.write("config loaded GITHUB_TOKEN={token} aws={aws}\\n")
        sys.stderr.write("password={password}\\n")
        sys.exit(1)
    '''), encoding="utf-8")
    env = {k: v for k, v in os.environ.items()
           if k not in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "REDTEAM_MODEL_PROVIDER")}
    out = subprocess.run([sys.executable, "-c", "from argus.cli.__main__ import main; main()", "scan-mcp",
                          "--on-host", "--timeout", "10", "--", sys.executable, str(server)],
                         capture_output=True, text=True, cwd=tmp_path, env=env, timeout=120)
    assert out.returncode == 1, out.stdout + out.stderr
    assert "The server's stderr ended with:" in out.stderr
    assert "config loaded" in out.stderr and "[REDACTED:" in out.stderr
    assert [s for s in (token, aws, password) if s in out.stdout + out.stderr] == []


def test_sdk_error_lines_are_redacted(monkeypatch):
    token, aws, _ = _stderr_secrets()

    async def during(cfg, mask, echo):
        logging.getLogger("mcp.client.streamable_http").error("Error parsing SSE message %s %s", token, aws)

    _fake(monkeypatch, during=during)
    result = _invoke(URL)
    assert result.exit_code == 0, result.output
    assert "MCP SDK error: Error parsing SSE message [REDACTED:" in result.stderr
    assert token not in result.output and aws not in result.output


def test_run_time_limit_exits_1_with_report_after_counting_fail_on(monkeypatch, tmp_path):
    fails = [_f(checks.COMMAND, "fail", "high", tool="run")]
    _fake(monkeypatch, _result(fails, out_of_time=True))
    result = _invoke(URL, "--fail-on", "high", "--max-runtime", "60")
    assert result.exit_code == 1, result.output
    assert (tmp_path / OUT_FILE["html"]).is_file()
    message = ("The run time limit (--max-runtime 60 s) was reached before every tool was called, so the scan is "
               "incomplete; raise --max-runtime to finish it.")
    assert f"1 finding(s) at or above high: {checks.COMMAND}" in result.stderr and message in result.stderr
    assert result.stderr.index("at or above high") < result.stderr.index(message)


@pytest.mark.parametrize("reasons, says, never", [
    ([CAP_REASON], ["1 probe result(s) were left unjudged by the cost cap", "raise --per-run-cap"], ["provider"]),
    ([ERROR_REASON], ["1 probe result(s) were left unjudged because the judge's reply could not be used",
                      "check the judge provider and its key"], ["--per-run-cap"]),
    ([CAP_REASON, ERROR_REASON], ["raise --per-run-cap", "check the judge provider"], []),
])
def test_unjudged_hint_names_the_cause(monkeypatch, reasons, says, never):
    found = [_f(checks.INJECTION, "error", "info", reasoning=r, tool=f"t{i}") for i, r in enumerate(reasons)]
    _fake(monkeypatch, _result(found, unjudged=len(found)))
    result = _invoke(URL)
    assert result.exit_code == 1, result.output
    assert all(s in result.stderr for s in says), result.stderr
    assert not any(s in result.stderr for s in never), result.stderr
