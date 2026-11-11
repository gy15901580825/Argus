"""Local comparisons through the real CLI, engine, and a loopback HTTP target."""

import json
import threading
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from click.testing import CliRunner

from argus import api, local
from argus.cli.__main__ import main
from argus.cli.run_json import render_json
from argus.probe import load_probe_library


@pytest.fixture
def target(monkeypatch):
    base = load_probe_library(api.PROBES_DIR)[0]
    probes = [replace(
        base, id=pid, severity=severity, target_class=("llm_chat",),
        prompts=(pid,), assertions=({"no_secret_in_response": "LEAK"},),
        judge_when_assertions_pass=False, conversation=False,
        requires_interaction=False, trials=1,
    ) for pid, severity in (("probe_a", "high"), ("probe_b", "critical"))]
    monkeypatch.setattr(api, "load_probe_library", lambda *_: probes)
    monkeypatch.setattr(local, "load_probe_library", lambda *_: probes)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    state = {"requests": [], "replies": ["LEAK"], "status": 200}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            state["requests"].append(body)
            replies = state["replies"]
            reply = replies.pop(0) if len(replies) > 1 else replies[0]
            self.send_response(state["status"])
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"choices": [{"message": {"content": reply}}]}).encode())

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    state["spec"] = {"kind": "openai_compat", "model": "test-model",
                     "endpoint_url": f"http://127.0.0.1:{server.server_port}/chat"}
    try:
        yield state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def baseline(tmp_path, target, findings=(), **overrides):
    path = tmp_path / "baseline.json"
    record = {
        "schema_version": "argus.run/1", "id": "previous-run",
        "status": "completed", "started_at": "2026-11-01T00:00:00+00:00",
        "finished_at": "2026-11-01T00:01:00+00:00", "argus_version": "1.9.0",
        "target_spec": target["spec"], "coverage": None, "summary": {},
        "findings": [{"probe_id": pid, "verdict": verdict, "severity": severity}
                     for pid, verdict, severity in findings],
        **overrides,
    }
    path.write_text(json.dumps(record))
    return path


def run(tmp_path, target, base=None, *, probes="probe_a", extra=(), local_mode=True,
        report_format="json"):
    out = tmp_path / f"head.{report_format}"
    args = ["run", "--target", json.dumps(target["spec"]), "--probes", probes,
            "--format", report_format, "--out", str(out), "--fail-on", "high"]
    if local_mode:
        args.append("--local")
    if base is not None:
        args.extend(["--baseline", str(base)])
    result = CliRunner().invoke(main, [*args, *extra])
    return result, out


@pytest.mark.parametrize("previous,category,code", [
    ([], "new", 3),
    ([("probe_a", "pass", "high")], "new", 3),
    ([("probe_a", "error", "high")], "new", 3),
    ([("probe_a", "fail", "high")], "still_failing", 0),
])
def test_gate_counts_only_new_failures(tmp_path, target, previous, category, code):
    base = baseline(tmp_path, target, previous)
    result, out = run(tmp_path, target, base)
    assert result.exit_code == code, result.output
    label = "still failing" if category == "still_failing" else category
    assert f"{label}: 1" in result.output
    if category == "new":
        assert "  new  high      probe_a" in result.output
    else:
        assert "  new  " not in result.output
    record = json.loads(out.read_text())
    assert record["schema_version"] == "argus.run/1"
    assert record["baseline"] == {
        "id": "previous-run", "finished_at": "2026-11-01T00:01:00+00:00",
        "new": [{"probe_id": "probe_a", "severity": "high"}] if category == "new" else [],
        "fixed": [], "still_failing": [{"probe_id": "probe_a", "severity": "high"}]
        if category == "still_failing" else [], "not_run": [],
    }
    assert len(target["requests"]) == 1


def test_fixed_and_missing_probe_are_distinct(tmp_path, target):
    target["replies"] = ["safe"]
    base = baseline(tmp_path, target, [("probe_a", "fail", "high"), ("probe_b", "fail", "critical")])
    result, out = run(tmp_path, target, base)
    assert result.exit_code == 0, result.output
    assert f"Compared with {base}: new: 0, fixed: 1, still failing: 0, not run: 1" in result.output
    comparison = json.loads(out.read_text())["baseline"]
    assert comparison["fixed"] == [{"probe_id": "probe_a", "severity": "high"}]
    assert comparison["not_run"] == [{"probe_id": "probe_b", "severity": "critical"}]


def test_error_in_head_is_not_fixed_and_keeps_incomplete_exit(tmp_path, target):
    target["status"] = 500
    base = baseline(tmp_path, target, [("probe_a", "fail", "high")])
    result, out = run(tmp_path, target, base)
    assert result.exit_code == 1, result.output
    assert "fixed: 0, still failing: 0, not run: 1" in result.output
    assert json.loads(out.read_text())["baseline"]["not_run"] == [{"probe_id": "probe_a", "severity": "high"}]


@pytest.mark.parametrize("previous,category,code", [
    ([], "new", 3),
    ([("probe_a", "pass", "critical"), ("probe_a", "fail", "low"),
      ("probe_a", "fail", "high")], "still_failing", 0),
])
def test_trials_any_failure_counts_once(tmp_path, target, previous, category, code):
    target["replies"] = ["LEAK", "safe"]
    base = baseline(tmp_path, target, previous)
    result, out = run(tmp_path, target, base, extra=["--trials", "2"])
    assert result.exit_code == code, result.output
    record = json.loads(out.read_text())
    assert [f["verdict"] for f in record["findings"]] == ["fail"]
    assert record["findings"][0]["evidence"]["trial_summary"]["fail"] == 1
    assert record["findings"][0]["evidence"]["trial_summary"]["pass"] == 1
    assert record["baseline"][category] == [{"probe_id": "probe_a", "severity": "high"}]
    assert len(target["requests"]) == 2


@pytest.mark.parametrize("invalid", [
    "missing", "bad_json", "wrong_schema", "target", "mode", "remote",
    "directory", "shape", "findings", "no_target", "bad_key",
])
def test_invalid_baseline_sends_no_probes(tmp_path, target, invalid):
    base = baseline(tmp_path, target)
    if invalid == "missing":
        base.unlink()
    elif invalid == "bad_json":
        base.write_text("{")
    elif invalid == "directory":
        base = tmp_path
    elif invalid == "shape":
        base.write_text("[]")
    elif invalid == "findings":
        base.write_text(json.dumps({
            "schema_version": "argus.run/1", "target_spec": target["spec"], "findings": [None],
        }))
    elif invalid == "no_target":
        base.write_text('{"schema_version":"argus.run/1","findings":[]}')
    elif invalid == "bad_key":
        baseline(tmp_path, target, baseline_key=[])
    elif invalid == "wrong_schema":
        baseline(tmp_path, target, schema_version="argus.run/2")
    elif invalid == "target":
        baseline(tmp_path, target, target_spec={**target["spec"], "model": "other-model"})
    elif invalid == "mode":
        baseline(tmp_path, target, deep={"seed": "old"})
    result, out = run(tmp_path, target, base, local_mode=invalid != "remote")
    assert result.exit_code == 2, result.output
    assert "baseline" in result.output
    if invalid != "remote":
        assert str(base) in result.output
    assert target["requests"] == []
    assert not out.exists()


def test_static_baseline_rejected_before_deep_run(tmp_path, target):
    base = baseline(tmp_path, target)
    result, _ = run(tmp_path, target, base, extra=["--mode", "deep"])
    assert result.exit_code == 2, result.output
    assert str(base) in result.output and "mode" in result.output
    assert target["requests"] == []


def test_legacy_redacted_run_without_key_matches(tmp_path, target, monkeypatch):
    monkeypatch.setenv("BASELINE_PRIVATE", "test-model")
    spec = {**target["spec"], "model": "${BASELINE_PRIVATE}", "api_key": "secret-value"}
    # The 1.9.0 renderer's target redaction also masks secrets in non-secret fields.
    legacy = json.loads(render_json({
        "id": "previous-run", "status": "completed", "finished_at": "2026-11-01T00:01:00+00:00",
        "target_spec": {**target["spec"], "api_key": "secret-value"}, "findings": [],
    }, secret_values=["test-model"]))
    legacy.pop("baseline_key", None)
    legacy["argus_version"] = "1.9.0"
    assert legacy["target_spec"]["model"] == "***"
    base = tmp_path / "legacy.json"
    base.write_text(json.dumps(legacy))
    target["spec"] = spec
    result, out = run(tmp_path, target, base)
    assert result.exit_code == 3, result.output
    assert json.loads(out.read_text())["baseline"]["id"] == "previous-run"


def test_saved_key_survives_redaction_and_reuses_baseline(tmp_path, target, monkeypatch):
    monkeypatch.setenv("BASELINE_SHORT_SECRET", "a")
    target["spec"]["api_key"] = "${BASELINE_SHORT_SECRET}"
    first, out = run(tmp_path, target)
    assert first.exit_code == 3, first.output
    record = json.loads(out.read_text())
    assert len(record["baseline_key"]) == 32
    assert all(c in "0123456789abcdef" for c in record["baseline_key"])
    base = tmp_path / "saved.json"
    record["id"] = "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa"
    base.write_text(json.dumps(record))
    second, out = run(tmp_path, target, base)
    assert second.exit_code == 0, second.output
    assert "still failing: 1" in second.output
    comparison = json.loads(out.read_text())["baseline"]
    assert comparison["id"] == "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa"
    assert comparison["finished_at"] == record["finished_at"]
    assert comparison["still_failing"] == [{"probe_id": "probe_a", "severity": "high"}]


def test_html_summary_includes_comparison(tmp_path, target):
    base = baseline(tmp_path, target)
    result, out = run(tmp_path, target, base, report_format="html")
    assert result.exit_code == 3, result.output
    html = out.read_text()
    assert "Baseline comparison" in html
    assert "new: 1, fixed: 0, still failing: 0, not run: 0" in html
    assert "probe_a" in html


@pytest.mark.parametrize("verdicts,category,code,severity", [
    ([("pass", "critical"), ("fail", "low"), ("fail", "high")], "still_failing", 0, "high"),
    ([("pass", "high"), ("error", "info")], "not_run", 1, "critical"),
    ([("fail", "high"), ("error", "info")], "still_failing", 1, "high"),
    ([("fail", "high"), ("error", "info"), ("aborted_cost", "info")], "still_failing", 4, "high"),
])
def test_multiple_findings_and_exit_precedence(tmp_path, target, monkeypatch,
                                             verdicts, category, code, severity):
    from test_cmd_run_local import FAIL_FINDING, _install_fake_engine

    async def events(*_, **__):
        for verdict, severity in verdicts:
            yield {**FAIL_FINDING, "probe_id": "probe_a", "verdict": verdict, "severity": severity}

    _install_fake_engine(monkeypatch, events)
    base = baseline(tmp_path, target, [("probe_a", "fail", "critical")])
    result, out = run(tmp_path, target, base)
    assert result.exit_code == code, result.output
    record = json.loads(out.read_text())
    assert record["baseline"][category] == [{"probe_id": "probe_a", "severity": severity}]
    assert record["baseline"]["fixed"] == []


def test_sarif_exit_code_agrees_with_baseline_gate(tmp_path, target):
    base = baseline(tmp_path, target, [("probe_a", "fail", "high")])
    result, out = run(tmp_path, target, base, report_format="sarif")
    assert result.exit_code == 0, result.output
    sarif = json.loads(out.read_text())
    assert sarif["runs"][0]["invocations"][0]["exitCode"] == 0
    assert sarif["runs"][0]["results"][0]["kind"] == "fail"


@pytest.mark.parametrize("extra_verdict,code", [("error", 1), ("aborted_cost", 4)])
def test_new_failure_gate_does_not_override_cost_or_incomplete(tmp_path, target, monkeypatch,
                                                            extra_verdict, code):
    from test_cmd_run_local import FAIL_FINDING, _install_fake_engine

    async def events(*_, **__):
        yield {**FAIL_FINDING, "probe_id": "probe_a", "severity": "high"}
        yield {**FAIL_FINDING, "probe_id": "probe_b", "verdict": extra_verdict}

    _install_fake_engine(monkeypatch, events)
    base = baseline(tmp_path, target)
    result, out = run(tmp_path, target, base)
    assert result.exit_code == code, result.output
    assert "  new  high      probe_a" in result.output
    assert "1 finding(s) at or above high" in result.output
    assert json.loads(out.read_text())["baseline"]["new"] == [{"probe_id": "probe_a", "severity": "high"}]
