"""Tests for `argus-probe quickstart`. The engine modules it calls are faked in sys.modules."""

import contextlib
import os
from pathlib import Path
import re
import shlex
import sys
import types

from click.testing import CliRunner

from argus.cli.__main__ import main

FAKE_SPEC = {"kind": "mcp_agent", "endpoint_url": "http://127.0.0.1:1/mcp"}
FAKE_PROBE_IDS = ("mcp_probe_a", "mcp_probe_b")


def _finding(probe_id, verdict):
    return {
        "id": "00000000-0000-0000-0000-000000000001", "probe_id": probe_id, "verdict": verdict,
        "severity": "high", "confidence": 1.0, "reasoning": "r", "attack_prompt": "p",
        "target_response": "t", "target_latency_ms": 1.0, "judge_model": "assertion",
        "escalated_model": None, "atlas_id": [], "owasp_id": [], "nist_id": [], "eu_ai_act_id": [],
    }


async def _ok_run(target, probe_ids, *, mode="static", per_run_cap_usd=None, env=None, skip_judged=False):
    yield _finding("mcp_probe_a", "fail")
    yield _finding("mcp_probe_b", "pass")
    yield {"type": "coverage", "coverage": {"thin_threshold": 2, "standards": {}}}


def _clean_proxy_env(monkeypatch, no_proxy=None):
    # setenv first so monkeypatch restores (removes) vars the quickstart creates
    for name in ("NO_PROXY", "no_proxy"):
        monkeypatch.setenv(name, "")
        monkeypatch.delenv(name)
    if no_proxy:
        monkeypatch.setenv("NO_PROXY", no_proxy)


def _install(monkeypatch, run_local):
    mods = {
        "argus.local": types.ModuleType("argus.local"),
        "argus.demo.servers": types.ModuleType("argus.demo.servers"),
    }
    mods["argus.local"].run_local = run_local
    mods["argus.local"].LocalRunError = type("LocalRunError", (Exception,), {})
    servers = mods["argus.demo.servers"]
    servers.PROBE_IDS = FAKE_PROBE_IDS

    @contextlib.contextmanager
    def start_mcp_demo():
        yield FAKE_SPEC

    servers.start_mcp_demo = start_mcp_demo
    for name, mod in mods.items():
        monkeypatch.setitem(sys.modules, name, mod)


def _invoke(tmp_path):
    out = tmp_path / "qs.html"
    try:
        runner = CliRunner(mix_stderr=False)
    except TypeError:  # click >= 8.2 always separates stderr and dropped the kwarg
        runner = CliRunner()
    return runner.invoke(main, ["quickstart", "--out", str(out)]), out


def test_quickstart_writes_report_and_exits_zero_with_failures(tmp_path, monkeypatch):
    _install(monkeypatch, _ok_run)
    result, out = _invoke(tmp_path)
    assert result.exit_code == 0, result.output
    assert "<html" in out.read_text()
    assert "1 of 2 probes caught" in result.output
    assert "argus-probe init" in result.output


def test_quickstart_runs_exactly_the_demo_probes_against_the_demo_spec(tmp_path, monkeypatch):
    calls = []

    async def _spy(target, probe_ids, *, mode="static", per_run_cap_usd=None, env=None, skip_judged=False):
        calls.append((target, probe_ids))
        yield _finding("mcp_probe_a", "pass")

    _install(monkeypatch, _spy)
    result, _ = _invoke(tmp_path)
    assert result.exit_code == 0, result.output
    assert calls == [(FAKE_SPEC, list(FAKE_PROBE_IDS))]


def test_quickstart_mid_run_error_exits_1(tmp_path, monkeypatch):
    async def _boom(target, probe_ids, *, mode="static", per_run_cap_usd=None, env=None, skip_judged=False):
        yield _finding("mcp_probe_a", "fail")
        raise RuntimeError("boom")

    _install(monkeypatch, _boom)
    result, _ = _invoke(tmp_path)
    assert result.exit_code == 1
    assert "Error: boom" in result.stderr


def test_quickstart_appends_localhost_to_existing_no_proxy(tmp_path, monkeypatch):
    _install(monkeypatch, _ok_run)
    _clean_proxy_env(monkeypatch, "corp.example")
    result, _ = _invoke(tmp_path)
    assert result.exit_code == 0, result.output
    assert os.environ["NO_PROXY"] == "corp.example,127.0.0.1"
    assert "127.0.0.1" in os.environ["no_proxy"]


def test_quickstart_sets_no_proxy_when_unset(tmp_path, monkeypatch):
    _install(monkeypatch, _ok_run)
    _clean_proxy_env(monkeypatch)
    result, _ = _invoke(tmp_path)
    assert result.exit_code == 0, result.output
    assert os.environ["NO_PROXY"] == "127.0.0.1"
    assert os.environ["no_proxy"] == "127.0.0.1"


def _printed_commands(output):
    return [shlex.split(line) for line in output.splitlines() if line.startswith("  argus-probe ")]


def test_quickstart_hands_off_to_init_for_the_selected_kind(tmp_path, monkeypatch):
    from argus.cli.target_loader import load_target_spec

    _install(monkeypatch, _ok_run)
    result, _ = _invoke(tmp_path)
    assert result.exit_code == 0, result.output
    commands = _printed_commands(result.output)
    assert commands == [["argus-probe", "init"]]
    assert "prints the run command for the kind you pick" in result.output
    assert "owasp_07_system_prompt_leakage" not in result.output

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("argus.cli.cmd_init._stdin_is_tty", lambda: True)
    init = CliRunner().invoke(main, commands[0][1:], input="mcp_server\nhttp://127.0.0.1:3001/mcp\nn\n")
    assert init.exit_code == 0, init.output
    run_line = next(line for line in init.output.splitlines() if line.startswith("Next: "))
    argv = shlex.split(run_line.removeprefix("Next: "))
    assert argv[:2] == ["argus-probe", "run"]
    with main.commands["run"].make_context("run", argv[2:]) as ctx:
        assert ctx.params["probe_ids"] == "all"
        spec = load_target_spec(str(tmp_path / ctx.params["target"]))
        assert spec["kind"] == "mcp_server"
        assert spec["url"] == "http://127.0.0.1:3001/mcp"


def test_quickstart_documented_kinds_match_the_registry():
    from argus.cli.target_loader import _KNOWN_KINDS

    text = (Path(__file__).resolve().parents[1] / "docs/onboarding/quickstart.md").read_text()
    step_two = text.split("## 2. Generate a target spec\n", 1)[1].split("\n## ", 1)[0]
    match = re.search(r"^The (\d+) supported `kind` values: (.+?)\.", step_two, re.MULTILINE)
    assert match is not None
    kinds = re.findall(r"`([^`]+)`", match.group(2))
    assert int(match.group(1)) == len(kinds) == len(_KNOWN_KINDS)
    assert len(kinds) == len(set(kinds))
    assert set(kinds) == _KNOWN_KINDS
