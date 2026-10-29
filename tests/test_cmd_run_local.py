"""Tests for `argus-probe run --local`. `argus.local` is replaced by a fake module
in sys.modules, so these tests run no probes."""

import json
import sys
import types

import pytest

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
    assert not (tmp_path / "r.html").exists()  # a run that never started has nothing to report


def test_local_midrun_error_writes_partial_report_and_exits_1(tmp_path, monkeypatch):
    # The findings gathered before the failure are the user's evidence; they must reach disk.
    async def _mid(target, probe_ids, **kw):
        yield FAIL_FINDING
        raise RuntimeError("judge call failed: 401 from provider")

    _install_fake_engine(monkeypatch, _mid)
    out = tmp_path / "run.json"
    result = CliRunner().invoke(
        cmd_run, ["--local", "--target", _target(tmp_path), "--probes", "p", "--format", "json",
                  "--out", str(out), "--fail-on", "high"],
    )
    assert result.exit_code == 1, result.output
    assert "Run stopped early: RuntimeError: judge call failed: 401 from provider" in result.output
    assert "Traceback" not in result.output
    record = json.loads(out.read_text())
    assert record["status"] == "incomplete"
    assert [f["probe_id"] for f in record["findings"]] == ["owasp_01_prompt_injection_basic"]


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


def _finding(probe_id, verdict, severity="info", reasoning="r"):
    return {**FAIL_FINDING, "id": f"id-{probe_id}-{verdict}", "probe_id": probe_id,
            "verdict": verdict, "severity": severity, "reasoning": reasoning,
            "judge_model": "fake" if verdict in ("pass", "fail") else ""}


def _engine(*events, then=None):
    async def run(target, probe_ids, **kw):
        for e in events:
            yield e
        if then is not None:
            raise then
        yield {"type": "coverage", "coverage": FAKE_COVERAGE}
    return run


def _invoke(tmp_path, *extra, target=None):
    return CliRunner().invoke(
        cmd_run, ["--local", "--target", target or _target(tmp_path), "--probes", "p", *extra],
    )


def test_error_finding_exits_1_and_wins_over_fail_on(tmp_path, monkeypatch):
    _install_fake_engine(monkeypatch, _engine(
        FAIL_FINDING,
        _finding("p2", "error", reasoning="target returned HTTP 401 (unauthorized; check credentials)"),
        _finding("p2", "error", reasoning="target returned HTTP 401 (unauthorized; check credentials)"),
        _finding("p3", "error", reasoning="target request failed: ReadTimeout"),
        _finding("p4", "pass"),
    ))
    out = tmp_path / "r.html"
    result = _invoke(tmp_path, "--out", str(out), "--fail-on", "high")
    assert result.exit_code == 1, result.output
    assert out.exists()
    assert "2 of 4 probes errored; run incomplete" in result.output
    assert "target returned HTTP 401 (unauthorized; check credentials)" in result.output
    assert "target request failed: ReadTimeout" in result.output
    # The --fail-on summary still prints, so the user sees both problems.
    assert "1 finding(s) at or above high: owasp_01_prompt_injection_basic" in result.output


def test_reasons_list_at_most_three_distinct_causes(tmp_path, monkeypatch):
    _install_fake_engine(monkeypatch, _engine(
        *[_finding(f"p{i}", "error", reasoning=f"cause {i}") for i in range(5)],
    ))
    result = _invoke(tmp_path, "--out", str(tmp_path / "r.html"))
    assert result.exit_code == 1
    assert "cause 2" in result.output and "cause 3" not in result.output


def test_error_finding_marks_every_report_format_incomplete(tmp_path, monkeypatch):
    events = (_finding("p1", "pass"), _finding("p2", "error", reasoning="target returned HTTP 502 (server error)"))
    for fmt, name in (("json", "r.json"), ("html", "r.html"), ("sarif", "r.sarif"), ("junit", "r.xml")):
        _install_fake_engine(monkeypatch, _engine(*events))
        out = tmp_path / name
        result = _invoke(tmp_path, "--format", fmt, "--out", str(out))
        assert result.exit_code == 1, (fmt, result.output)
        text = out.read_text()
        if fmt == "json":
            assert json.loads(text)["status"] == "incomplete"
        else:
            assert "1 of 2 probes errored; run incomplete" in text, fmt
    html = (tmp_path / "r.html").read_text()
    assert "Status: <strong>incomplete</strong>" in html
    assert "This run is incomplete." in html


def test_clean_run_stays_completed_and_exits_0(tmp_path, monkeypatch):
    # blocked_by_target and skipped are verdicts, not failures to run: they do not make a run incomplete.
    _install_fake_engine(monkeypatch, _engine(
        _finding("p1", "pass"), _finding("p2", "blocked_by_target"), _finding("p3", "skipped"),
    ))
    out = tmp_path / "r.json"
    result = _invoke(tmp_path, "--format", "json", "--out", str(out), "--fail-on", "low")
    assert result.exit_code == 0, result.output
    assert json.loads(out.read_text())["status"] == "completed"
    assert "incomplete" not in result.output
    assert "This run is incomplete." not in out.read_text()


def test_midrun_cost_cap_writes_partial_report_and_exits_4(tmp_path, monkeypatch):
    _install_fake_engine(monkeypatch, _engine(
        _finding("p1", "pass"), then=_LocalRunError("daily cap reached", "cost"),
    ))
    out = tmp_path / "r.json"
    result = _invoke(tmp_path, "--format", "json", "--out", str(out))
    assert result.exit_code == 4, result.output
    assert "Run stopped early: daily cap reached" in result.output
    assert json.loads(out.read_text())["status"] == "incomplete"


def test_ctrl_c_exits_130_without_a_report(tmp_path, monkeypatch):
    _install_fake_engine(monkeypatch, _engine(_finding("p1", "pass"), then=KeyboardInterrupt()))
    out = tmp_path / "r.html"
    result = _invoke(tmp_path, "--out", str(out))
    assert result.exit_code == 130, result.output
    assert "Interrupted: the run was stopped before it finished; no report was written." in result.output
    assert not out.exists()


def test_console_reasons_are_masked(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_TEST_TARGET_TOKEN", "tok-9f8e7d6c")
    spec = tmp_path / "t.json"
    spec.write_text('{"kind":"openai_compat","endpoint_url":"https://x/${ARGUS_TEST_TARGET_TOKEN}","model":"m"}')
    _install_fake_engine(monkeypatch, _engine(
        _finding("p1", "error", reasoning="target request failed: ConnectError: https://x/tok-9f8e7d6c"),
    ))
    result = _invoke(tmp_path, "--out", str(tmp_path / "r.html"), target=str(spec))
    assert result.exit_code == 1, result.output
    assert "target request failed: ConnectError: https://x/***" in result.output
    assert "tok-9f8e7d6c" not in result.output


# --- fix round 1 -------------------------------------------------------------------------------

def test_unknown_probe_ids_exit_2_with_no_report(tmp_path, monkeypatch):
    _install_fake_engine(monkeypatch, _engine(then=_LocalRunError(
        "unknown probe id(s): typo; run `argus-probe list-probes` to see the valid ids", "usage")))
    out = tmp_path / "r.html"
    result = _invoke(tmp_path, "--out", str(out))
    assert result.exit_code == 2, result.output
    assert "unknown probe id(s): typo" in result.output and "list-probes" in result.output
    assert not out.exists()


def test_unreachable_target_stop_writes_partial_report_and_exits_1(tmp_path, monkeypatch):
    reason = "target unreachable: 5 probes in a row failed (target request failed: ReadTimeout)"
    _install_fake_engine(monkeypatch, _engine(
        *[_finding(f"p{i}", "error", reasoning="target request failed: ReadTimeout") for i in range(5)],
        then=_LocalRunError(reason, "unreachable"),
    ))
    out = tmp_path / "r.json"
    result = _invoke(tmp_path, "--format", "json", "--out", str(out))
    assert result.exit_code == 1, result.output
    assert f"Run stopped early: {reason}." in result.output
    record = json.loads(out.read_text())
    assert record["status"] == "incomplete"
    assert reason in record["incomplete_reason"]


def test_any_aborted_cost_finding_marks_incomplete_and_exits_4(tmp_path, monkeypatch):
    _install_fake_engine(monkeypatch, _engine(
        _finding("p1", "aborted_cost", reasoning="cost cap hit at round 2: cap"), _finding("p2", "pass"),
        FAIL_FINDING,
    ))
    out = tmp_path / "r.json"
    result = _invoke(tmp_path, "--format", "json", "--out", str(out), "--fail-on", "high")
    assert result.exit_code == 4, result.output
    assert "1 probe(s) stopped at the cost cap; run incomplete" in result.output
    record = json.loads(out.read_text())
    assert record["status"] == "incomplete"
    assert "stopped at the cost cap" in record["incomplete_reason"]


def test_run_json_carries_incomplete_reason_only_when_incomplete(tmp_path, monkeypatch):
    _install_fake_engine(monkeypatch, _engine(_finding("p1", "error", reasoning="target returned HTTP 502 (server error)")))
    out = tmp_path / "r.json"
    _invoke(tmp_path, "--format", "json", "--out", str(out))
    record = json.loads(out.read_text())
    assert record["incomplete_reason"] == "1 of 1 probes errored; run incomplete; target returned HTTP 502 (server error)"
    assert list(record)[:4] == ["schema_version", "id", "status", "incomplete_reason"]

    _install_fake_engine(monkeypatch, _engine(_finding("p1", "pass")))
    _invoke(tmp_path, "--format", "json", "--out", str(out))
    assert "incomplete_reason" not in json.loads(out.read_text())


def _blocked(pid, code=400):
    return _finding(pid, "blocked_by_target",
                    reasoning=f"target returned HTTP {code} to the attack prompt; counted as blocked")


def test_a_run_blocked_with_one_status_code_warns_but_keeps_exit_0(tmp_path, monkeypatch):
    _install_fake_engine(monkeypatch, _engine(*[_blocked(f"p{i}") for i in range(9)], _finding("p9", "pass")))
    out = tmp_path / "r.json"
    result = _invoke(tmp_path, "--format", "json", "--out", str(out))
    assert result.exit_code == 0, result.output
    warning = "almost every probe was blocked with HTTP 400; check the request format"
    assert f"Warning: {warning}" in result.output
    record = json.loads(out.read_text())
    assert record["status"] == "completed"
    assert record["notes"] == [warning]


@pytest.mark.parametrize("events", [
    [_blocked(f"p{i}") for i in range(4)],                                     # fewer than 5
    [*[_blocked(f"p{i}") for i in range(8)], *[_finding(f"q{i}", "pass") for i in range(2)]],  # 80%
    [*[_blocked(f"p{i}") for i in range(5)], *[_blocked(f"q{i}", 403) for i in range(5)]],     # mixed codes
])
def test_blocked_warning_needs_five_and_ninety_percent_on_one_code(tmp_path, monkeypatch, events):
    _install_fake_engine(monkeypatch, _engine(*events))
    result = _invoke(tmp_path, "--out", str(tmp_path / "r.html"))
    assert result.exit_code == 0
    assert "check the request format" not in result.output


def test_all_blocked_says_every(tmp_path, monkeypatch):
    _install_fake_engine(monkeypatch, _engine(*[_blocked(f"p{i}", 422) for i in range(5)]))
    result = _invoke(tmp_path, "--out", str(tmp_path / "r.html"))
    assert "Warning: every probe was blocked with HTTP 422; check the request format" in result.output


def test_sarif_marks_an_incomplete_run_as_unsuccessful(tmp_path, monkeypatch):
    _install_fake_engine(monkeypatch, _engine(_finding("p1", "pass"), _finding("p2", "error", reasoning="x")))
    out = tmp_path / "r.sarif"
    _invoke(tmp_path, "--format", "sarif", "--out", str(out))
    inv = json.loads(out.read_text())["runs"][0]["invocations"][0]
    assert inv["executionSuccessful"] is False and inv["exitCode"] == 1
    assert {n["level"] for n in inv["toolExecutionNotifications"]} == {"warning"}


def test_html_summary_counts_errors_and_does_not_call_them_deterministic(tmp_path, monkeypatch):
    _install_fake_engine(monkeypatch, _engine(_finding("p1", "error", reasoning="x"), _finding("p2", "pass")))
    out = tmp_path / "r.html"
    _invoke(tmp_path, "--out", str(out))
    html = out.read_text()
    assert "1 error</div>" in html
    assert "no model consulted" not in html and "from captured evidence" not in html
    assert "not judged:" in html.lower()


def test_blocked_warning_ignores_skipped_probes(tmp_path, monkeypatch):
    # `--probes all` skips probes for other target classes; they were never sent and must not dilute the share.
    _install_fake_engine(monkeypatch, _engine(
        *[_blocked(f"p{i}") for i in range(6)], *[_finding(f"s{i}", "skipped") for i in range(4)],
    ))
    result = _invoke(tmp_path, "--out", str(tmp_path / "r.html"))
    assert result.exit_code == 0, result.output
    assert "Warning: every probe was blocked with HTTP 400; check the request format" in result.output


# --- fix round 2: SARIF exitCode is the process exit code --------------------------------------

@pytest.mark.parametrize("events, then, code", [
    ([_finding("p1", "aborted_cost", reasoning="cost cap hit at round 1: cap"), FAIL_FINDING], None, 4),
    ([FAIL_FINDING], _LocalRunError("daily cap reached", "cost"), 4),
    ([FAIL_FINDING, _finding("p2", "pass")], None, 3),
    ([FAIL_FINDING, _finding("p2", "error", reasoning="x")], None, 1),
    ([_finding("p1", "pass")], None, 0),
])
def test_sarif_exit_code_equals_the_process_exit_code(tmp_path, monkeypatch, events, then, code):
    _install_fake_engine(monkeypatch, _engine(*events, then=then))
    out = tmp_path / "r.sarif"
    result = _invoke(tmp_path, "--format", "sarif", "--out", str(out), "--fail-on", "high")
    assert result.exit_code == code, result.output
    assert json.loads(out.read_text())["runs"][0]["invocations"][0]["exitCode"] == code


def test_exit_code_is_not_written_to_run_json(tmp_path, monkeypatch):
    _install_fake_engine(monkeypatch, _engine(FAIL_FINDING))
    out = tmp_path / "r.json"
    _invoke(tmp_path, "--format", "json", "--out", str(out), "--fail-on", "high")
    assert "exit_code" not in json.loads(out.read_text())


def test_run_exit_code_precedence():
    from argus.cli.severity import run_exit_code

    class Stop(Exception):
        def __init__(self, code):
            self.code = code

    fail = {"probe_id": "a", "verdict": "fail", "severity": "critical"}
    err = {"probe_id": "b", "verdict": "error", "severity": "info"}
    aborted = {"probe_id": "c", "verdict": "aborted_cost", "severity": "info"}
    assert run_exit_code([fail], None, None) == 0
    assert run_exit_code([fail], None, "high") == 3
    assert run_exit_code([fail, err], None, "high") == 1
    assert run_exit_code([fail], RuntimeError("judge down"), "high") == 1
    assert run_exit_code([fail, err, aborted], None, "high") == 4
    assert run_exit_code([fail], Stop("cost"), None) == 4
    assert run_exit_code([fail], Stop("unreachable"), None) == 1


# --- no judge key: skipped, not incomplete -------------------------------------------------------

_NO_KEY = "no judge key: ANTHROPIC_API_KEY is not set; this probe needs an LLM judge"
_SKIP_LINE = ("2 of 3 probes skipped: no judge key. To run them, set ANTHROPIC_API_KEY or OPENAI_API_KEY, "
              "or set REDTEAM_MODEL_PROVIDER to azure or litellm.")


def _no_key_engine(*extra):
    return _engine(_finding("j1", "skipped", reasoning=_NO_KEY), _finding("j2", "skipped", reasoning=_NO_KEY),
                   _finding("a1", "pass"), *extra)


def test_no_judge_key_skips_are_noted_and_keep_exit_0(tmp_path, monkeypatch):
    _install_fake_engine(monkeypatch, _no_key_engine())
    out = tmp_path / "r.json"
    result = _invoke(tmp_path, "--format", "json", "--out", str(out), "--fail-on", "low")
    assert result.exit_code == 0, result.output
    assert _SKIP_LINE in result.output
    assert "incomplete" not in result.output
    record = json.loads(out.read_text())
    assert record["status"] == "completed"
    assert record["notes"] == [_SKIP_LINE]


def test_no_judge_key_skips_do_not_hide_a_fail_on_hit(tmp_path, monkeypatch):
    _install_fake_engine(monkeypatch, _no_key_engine(FAIL_FINDING))
    out = tmp_path / "r.sarif"
    result = _invoke(tmp_path, "--format", "sarif", "--out", str(out), "--fail-on", "high")
    assert result.exit_code == 3, result.output
    sarif = json.loads(out.read_text())
    assert sarif["runs"][0]["invocations"][0]["exitCode"] == 3
    assert "2 of 4 probes skipped: no judge key" in result.output


def test_other_skips_print_no_judge_key_line(tmp_path, monkeypatch):
    _install_fake_engine(monkeypatch, _engine(
        _finding("p1", "skipped", reasoning="probe.target_class ['x'] disjoint from target.compatible_classes ['y']"),
        _finding("p2", "pass"),
    ))
    out = tmp_path / "r.json"
    result = _invoke(tmp_path, "--format", "json", "--out", str(out))
    assert result.exit_code == 0
    assert "no judge key" not in result.output
    assert "notes" not in json.loads(out.read_text())


def test_local_help_no_longer_says_a_key_is_required():
    result = CliRunner().invoke(cmd_run, ["--help"])
    assert "Needs a judge API key" not in result.output
    assert "skipped" in result.output
