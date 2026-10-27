"""Tests for `argus-probe run --local`. `argus.local` is replaced by a fake module
in sys.modules, so these tests run no probes."""

import json
import sys
import types

from click.testing import CliRunner

from argus.cli.cmd_run import cmd_run

FAIL_FINDING = {
    "id": "00000000-0000-0000-0000-000000000001",
    "probe_id": "owasp_01_prompt_injection_basic",
    "verdict": "fail",
    "severity": "critical",
    "confidence": 0.9,
    "reasoning": "leaked",
    "attack_prompt": "p",
    "target_response": "r",
    "target_latency_ms": 10.0,
    "judge_model": "fake",
    "escalated_model": None,
    "atlas_id": [],
    "owasp_id": [],
    "nist_id": [],
    "eu_ai_act_id": [],
}

FAKE_COVERAGE = {"thin_threshold": 2, "standards": {}}


class _LocalRunError(Exception):
    def __init__(self, message, code):
        super().__init__(message)
        self.code = code


def _install_fake_engine(monkeypatch, run_local):
    local = types.ModuleType("argus.local")
    local.run_local = run_local
    local.LocalRunError = _LocalRunError
    monkeypatch.setitem(sys.modules, "argus.local", local)


async def _ok_run(target, probe_ids, *, mode="static", per_run_cap_usd=None, env=None):
    yield FAIL_FINDING
    yield {"type": "coverage", "coverage": FAKE_COVERAGE}


def _target(tmp_path):
    p = tmp_path / "t.json"
    p.write_text('{"kind":"openai_compat","endpoint_url":"https://x","model":"m"}')
    return str(p)


def test_local_writes_sarif_without_api_url(tmp_path, monkeypatch):
    _install_fake_engine(monkeypatch, _ok_run)
    monkeypatch.delenv("ARGUS_API_URL", raising=False)
    monkeypatch.delenv("ARGUS_API_TOKEN", raising=False)
    out = tmp_path / "r.sarif"
    result = CliRunner().invoke(
        cmd_run, ["--local", "--target", _target(tmp_path), "--probes", "owasp_01_prompt_injection_basic",
                  "--format", "sarif", "--out", str(out)],
    )
    assert result.exit_code == 0, result.output
    sarif = json.loads(out.read_text())
    assert len(sarif["runs"][0]["results"]) == 1
    assert sarif["runs"][0]["properties"]["coverage"] == FAKE_COVERAGE
    assert "fail" in result.output and "owasp_01_prompt_injection_basic" in result.output


def test_local_fail_on_exits_3(tmp_path, monkeypatch):
    _install_fake_engine(monkeypatch, _ok_run)
    out = tmp_path / "r.html"
    result = CliRunner().invoke(
        cmd_run, ["--local", "--target", _target(tmp_path), "--probes", "owasp_01_prompt_injection_basic",
                  "--out", str(out), "--fail-on", "high"],
    )
    assert result.exit_code == 3, result.output
    assert out.exists()


def test_local_passes_probes_and_cap_through(tmp_path, monkeypatch):
    seen = {}

    async def _spy(target, probe_ids, *, mode="static", per_run_cap_usd=None, env=None):
        seen.update(target=target, probe_ids=probe_ids, cap=per_run_cap_usd)
        yield {"type": "coverage", "coverage": {}}

    _install_fake_engine(monkeypatch, _spy)
    result = CliRunner().invoke(
        cmd_run, ["--local", "--target", _target(tmp_path), "--probes", "all",
                  "--out", str(tmp_path / "r.html"), "--per-run-cap", "6"],
    )
    assert result.exit_code == 0, result.output
    assert seen["probe_ids"] == []          # "all" is the empty list by convention
    assert seen["cap"] == 6.0
    assert seen["target"]["kind"] == "openai_compat"


def test_local_cost_cap_exits_4(tmp_path, monkeypatch):
    async def _cost(target, probe_ids, **kw):
        raise _LocalRunError("estimated $9.00 exceeds per-run cap $0.50", "cost")
        yield  # pragma: no cover

    _install_fake_engine(monkeypatch, _cost)
    result = CliRunner().invoke(
        cmd_run, ["--local", "--target", _target(tmp_path), "--probes", "all", "--out", str(tmp_path / "r.html")],
    )
    assert result.exit_code == 4, result.output
    assert "per-run cap" in result.output
    assert "Run rejected for cost" in result.output


def test_local_config_error_exits_1(tmp_path, monkeypatch):
    async def _cfg(target, probe_ids, **kw):
        raise _LocalRunError("ANTHROPIC_API_KEY is not set", "config")
        yield  # pragma: no cover

    _install_fake_engine(monkeypatch, _cfg)
    result = CliRunner().invoke(
        cmd_run, ["--local", "--target", _target(tmp_path), "--probes", "p", "--out", str(tmp_path / "r.html")],
    )
    assert result.exit_code == 1, result.output
    assert "ANTHROPIC_API_KEY" in result.output


def test_local_midrun_error_exits_1(tmp_path, monkeypatch):
    async def _mid(target, probe_ids, **kw):
        yield FAIL_FINDING
        raise RuntimeError("judge call failed: 401 from provider")

    _install_fake_engine(monkeypatch, _mid)
    out = tmp_path / "r.html"
    result = CliRunner().invoke(
        cmd_run, ["--local", "--target", _target(tmp_path), "--probes", "p", "--out", str(out)],
    )
    assert result.exit_code == 1, result.output
    assert "judge call failed" in result.output
    assert "Traceback" not in result.output
    assert not out.exists()


def test_local_rejects_api_url(tmp_path, monkeypatch):
    _install_fake_engine(monkeypatch, _ok_run)
    result = CliRunner().invoke(
        cmd_run, ["--local", "--api-url", "https://argus.example", "--target", _target(tmp_path),
                  "--probes", "p", "--out", str(tmp_path / "r.html")],
    )
    assert result.exit_code == 2, result.output
    assert "--local" in result.output and "--api-url" in result.output


def test_remote_still_requires_api_url(tmp_path, monkeypatch):
    monkeypatch.delenv("ARGUS_API_URL", raising=False)
    result = CliRunner().invoke(
        cmd_run, ["--target", _target(tmp_path), "--probes", "p", "--out", str(tmp_path / "r.html"), "--token", "t"],
    )
    assert result.exit_code == 2, result.output
    assert "Missing option '--api-url'" in result.output


def test_local_runs_browser_use_target(tmp_path, monkeypatch):
    seen = {}

    async def run(target, probe_ids, **kw):
        seen["target"] = target
        yield {**FAIL_FINDING, "probe_id": "browser_dom_inject_basic"}
        yield {"type": "coverage", "coverage": FAKE_COVERAGE}

    _install_fake_engine(monkeypatch, run)
    spec = {"kind": "browser_use", "agent_url": "http://127.0.0.1:9/agent",
            "scenario_kind": "dom_injection", "trap_host": "0.0.0.0", "trap_port": 8765,
            "trap_public_url": "http://192.168.1.20:8765"}
    p = tmp_path / "b.json"
    p.write_text(json.dumps(spec))
    out = tmp_path / "r.html"
    result = CliRunner().invoke(
        cmd_run, ["--local", "--target", str(p), "--probes", "browser_dom_inject_basic", "--out", str(out)],
    )
    assert result.exit_code == 0, result.output
    assert seen["target"] == spec
    assert "browser_dom_inject_basic" in result.output
    assert out.exists()


def test_local_ignores_env_api_url_and_token(tmp_path, monkeypatch):
    _install_fake_engine(monkeypatch, _ok_run)
    monkeypatch.setenv("ARGUS_API_URL", "https://argus.example")
    monkeypatch.setenv("ARGUS_API_TOKEN", "t")
    out = tmp_path / "r.sarif"
    result = CliRunner().invoke(
        cmd_run, ["--local", "--target", _target(tmp_path), "--probes", "p", "--format", "sarif", "--out", str(out)],
    )
    assert result.exit_code == 0, result.output
    assert out.exists()


def test_local_missing_transitive_dependency_is_not_the_install_hint(tmp_path, monkeypatch):
    async def _dep(target, probe_ids, **kw):
        raise ModuleNotFoundError("No module named 'litellm'", name="litellm")
        yield  # pragma: no cover

    _install_fake_engine(monkeypatch, _dep)
    result = CliRunner().invoke(
        cmd_run, ["--local", "--target", _target(tmp_path), "--probes", "p", "--out", str(tmp_path / "r.html")],
    )
    assert result.exit_code == 1, result.output
    assert "litellm" in result.output


def test_warning_event_goes_to_stderr_not_report(tmp_path, monkeypatch):
    async def _warn(target, probe_ids, *, mode="static", per_run_cap_usd=None, env=None):
        yield {"type": "warning", "message": "Judge model x is small."}
        yield FAIL_FINDING
        yield {"type": "coverage", "coverage": FAKE_COVERAGE}

    _install_fake_engine(monkeypatch, _warn)
    out = tmp_path / "r.sarif"
    try:
        runner = CliRunner(mix_stderr=False)
    except TypeError:  # click >= 8.2 always separates stderr and dropped the kwarg
        runner = CliRunner()
    result = runner.invoke(
        cmd_run,
        ["--local", "--target", _target(tmp_path), "--probes", "owasp_01_prompt_injection_basic",
         "--format", "sarif", "--out", str(out)],
    )
    assert result.exit_code == 0, result.output
    assert "Warning: Judge model x is small." in result.stderr
    assert "Judge model x" not in result.stdout
    assert len(json.loads(out.read_text())["runs"][0]["results"]) == 1
