"""Tests for `argus-probe run`."""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import httpx
import pytest
from click.testing import CliRunner

from argus.cli import api_client
from argus.cli.__main__ import main
from argus.cli.cmd_run import cmd_run


def test_run_calls_api_and_writes_report(tmp_path):
    runner = CliRunner()
    target_spec = {
        "kind": "openai_compat",
        "endpoint_url": "https://api.example.com/v1/chat/completions",
        "model": "gpt-4",
        "api_key": "sk-test",
    }
    target_file = tmp_path / "target.json"
    target_file.write_text(json.dumps(target_spec))

    fake_api = {
        "post_run": {"run_id": "abc-123"},
        "poll": [{"status": "running", "findings": []},
                 {"status": "completed", "findings": [{"id":"f1","probe_id":"p1","verdict":"pass","severity":"info"}]}],
        "report": "<html><body>Test report</body></html>",
    }

    with patch("argus.cli.api_client.post_run", return_value=fake_api["post_run"]) as mock_post, \
         patch("argus.cli.api_client.get_run") as mock_get, \
         patch("argus.cli.api_client.get_report", return_value=fake_api["report"]):
        mock_get.side_effect = fake_api["poll"]

        out_file = tmp_path / "report.html"
        result = runner.invoke(main, [
            "run",
            "--target", str(target_file),
            "--probes", "p1",
            "--format", "html",
            "--out", str(out_file),
            "--token", "test-token",
            "--api-url", "https://dev.example.com",
        ])
        assert result.exit_code == 0, result.output
        assert "abc-123" in result.output
        assert out_file.exists()
        assert "Test report" in out_file.read_text()
        # Verify the post call shape
        body = mock_post.call_args.kwargs["body"]
        assert body["target"]["model"] == "gpt-4"
        assert body["probe_ids"] == ["p1"]


def test_run_passes_per_run_cap_in_body(tmp_path):
    """--per-run-cap value flows into the POST body as per_run_cap_usd."""
    runner = CliRunner()
    target_spec = {
        "kind": "openai_compat",
        "endpoint_url": "https://api.example.com/v1/chat/completions",
        "model": "gpt-4",
        "api_key": "sk-test",
    }
    target_file = tmp_path / "target.json"
    target_file.write_text(json.dumps(target_spec))

    with patch("argus.cli.api_client.post_run", return_value={"run_id": "cap-run"}) as mock_post, \
         patch("argus.cli.api_client.poll_until_complete", return_value={"status": "completed", "findings": []}), \
         patch("argus.cli.api_client.get_report", return_value="<html/>"):
        out_file = tmp_path / "report.html"
        result = runner.invoke(main, [
            "run",
            "--target", str(target_file),
            "--probes", "p1",
            "--out", str(out_file),
            "--token", "test-token",
            "--api-url", "https://dev.example.com",
            "--per-run-cap", "0.25",
        ])
        assert result.exit_code == 0, result.output
        body = mock_post.call_args.kwargs["body"]
        assert body["per_run_cap_usd"] == 0.25


def test_run_exits_4_on_cost_rejection(tmp_path):
    """When server returns HTTP 402, CLI exits with code 4 and prints detail to stderr."""
    runner = CliRunner()
    target_spec = {
        "kind": "openai_compat",
        "endpoint_url": "https://api.example.com/v1/chat/completions",
        "model": "gpt-4",
        "api_key": "sk-test",
    }
    target_file = tmp_path / "target.json"
    target_file.write_text(json.dumps(target_spec))

    fake_response = MagicMock()
    fake_response.status_code = 402
    fake_response.json = lambda: {"detail": "estimated $1.50 > per_run_cap $0.50"}

    def fake_post_run_402(*args, **kwargs):
        raise httpx.HTTPStatusError("402", request=MagicMock(), response=fake_response)

    with patch("argus.cli.api_client.post_run", side_effect=fake_post_run_402):
        result = runner.invoke(main, [
            "run",
            "--target", str(target_file),
            "--probes", "p1",
            "--out", str(tmp_path / "report.html"),
            "--token", "test-token",
            "--api-url", "https://dev.example.com",
            "--per-run-cap", "0.10",
        ])
        assert result.exit_code == 4
        assert "cost" in result.output.lower() or "cost cap" in (result.output + "").lower()


def _target_file(tmp_path):
    spec = {
        "kind": "openai_compat",
        "endpoint_url": "https://api.example.com/v1/chat/completions",
        "model": "gpt-4",
        "api_key": "sk-test",
    }
    path = tmp_path / "target.json"
    path.write_text(json.dumps(spec))
    return path


def test_run_requires_api_url(tmp_path):
    """No --api-url and no ARGUS_API_URL: fail loudly instead of POSTing to a placeholder."""
    runner = CliRunner()
    result = runner.invoke(main, [
        "run",
        "--target", str(_target_file(tmp_path)),
        "--probes", "p1",
        "--out", str(tmp_path / "report.html"),
        "--token", "test-token",
    ], env={"ARGUS_API_URL": ""})
    assert result.exit_code == 2, result.output
    assert "api-url" in result.output.lower()


def test_run_reads_api_url_from_env(tmp_path):
    """ARGUS_API_URL satisfies --api-url, mirroring ARGUS_API_TOKEN/--token."""
    runner = CliRunner()
    out_file = tmp_path / "report.html"
    with patch("argus.cli.api_client.post_run", return_value={"run_id": "env-run"}) as mock_post, \
         patch("argus.cli.api_client.poll_until_complete", return_value={"status": "completed", "findings": []}), \
         patch("argus.cli.api_client.get_report", return_value="<html/>"):
        result = runner.invoke(main, [
            "run",
            "--target", str(_target_file(tmp_path)),
            "--probes", "p1",
            "--out", str(out_file),
            "--token", "test-token",
        ], env={"ARGUS_API_URL": "https://argus.internal"})
    assert result.exit_code == 0, result.output
    assert mock_post.call_args.args[0] == "https://argus.internal"


def test_run_all_alone_sends_empty_probe_ids(tmp_path):
    """--probes all is the 'whole library' convention: an empty probe_ids list."""
    runner = CliRunner()
    with patch("argus.cli.api_client.post_run", return_value={"run_id": "all-run"}) as mock_post, \
         patch("argus.cli.api_client.poll_until_complete", return_value={"status": "completed", "findings": []}), \
         patch("argus.cli.api_client.get_report", return_value="<html/>"):
        result = runner.invoke(main, [
            "run",
            "--target", str(_target_file(tmp_path)),
            "--probes", " all ",
            "--out", str(tmp_path / "report.html"),
            "--token", "test-token",
            "--api-url", "https://dev.example.com",
        ])
    assert result.exit_code == 0, result.output
    assert mock_post.call_args.kwargs["body"]["probe_ids"] == []


def test_run_rejects_all_mixed_with_probe_ids(tmp_path):
    """`all` mixed with explicit ids used to be silently dropped, shrinking the scan."""
    runner = CliRunner()
    with patch("argus.cli.api_client.post_run") as mock_post:
        result = runner.invoke(main, [
            "run",
            "--target", str(_target_file(tmp_path)),
            "--probes", "owasp_01,all",
            "--out", str(tmp_path / "report.html"),
            "--token", "test-token",
            "--api-url", "https://dev.example.com",
        ])
    assert result.exit_code == 2, result.output
    assert "all" in result.output.lower()
    mock_post.assert_not_called()


def test_run_rejects_empty_probes(tmp_path):
    """An empty list is the wire convention for 'everything', so `--probes ""`
    must not silently launch a full sweep."""
    runner = CliRunner()
    with patch("argus.cli.api_client.post_run") as mock_post:
        result = runner.invoke(main, [
            "run",
            "--target", str(_target_file(tmp_path)),
            "--probes", " , ",
            "--out", str(tmp_path / "report.html"),
            "--token", "test-token",
            "--api-url", "https://dev.example.com",
        ])
    assert result.exit_code == 2, result.output
    mock_post.assert_not_called()


def _stub_remote(monkeypatch, findings):
    monkeypatch.setattr(api_client, "post_run", lambda *a, **k: {"run_id": "r1"})
    monkeypatch.setattr(
        api_client, "poll_until_complete", lambda *a, **k: {"status": "completed", "findings": findings}
    )
    monkeypatch.setattr(api_client, "get_report", lambda *a, **k: "<html></html>")


def test_run_fail_on_exits_3_when_threshold_hit(tmp_path, monkeypatch):
    _stub_remote(monkeypatch, [{"probe_id": "p", "verdict": "fail", "severity": "critical"}])
    target = tmp_path / "t.json"
    target.write_text('{"kind":"openai_compat","endpoint_url":"https://x","model":"m"}')
    out = tmp_path / "r.html"
    result = CliRunner().invoke(
        cmd_run,
        ["--target", str(target), "--probes", "p", "--out", str(out), "--token", "t",
         "--api-url", "https://argus.example", "--fail-on", "high"],
    )
    assert result.exit_code == 3, result.output
    assert "1 finding" in result.output
    assert out.read_text() == "<html></html>"


def test_run_without_fail_on_exits_0_on_findings(tmp_path, monkeypatch):
    _stub_remote(monkeypatch, [{"probe_id": "p", "verdict": "fail", "severity": "critical"}])
    target = tmp_path / "t.json"
    target.write_text('{"kind":"openai_compat","endpoint_url":"https://x","model":"m"}')
    out = tmp_path / "r.html"
    result = CliRunner().invoke(
        cmd_run,
        ["--target", str(target), "--probes", "p", "--out", str(out), "--token", "t",
         "--api-url", "https://argus.example"],
    )
    assert result.exit_code == 0, result.output


def test_run_exits_1_when_run_failed_but_still_writes_report(tmp_path, monkeypatch):
    _stub_remote(monkeypatch, [])
    monkeypatch.setattr(
        api_client, "poll_until_complete", lambda *a, **k: {"status": "failed", "findings": []}
    )
    target = tmp_path / "t.json"
    target.write_text('{"kind":"openai_compat","endpoint_url":"https://x","model":"m"}')
    out = tmp_path / "r.html"
    result = CliRunner().invoke(
        cmd_run,
        ["--target", str(target), "--probes", "p", "--out", str(out), "--token", "t",
         "--api-url", "https://argus.example", "--fail-on", "critical"],
    )
    assert result.exit_code == 1, result.output
    assert "ended with status failed" in result.output
    assert out.read_text() == "<html></html>"


def test_run_fail_on_exits_0_below_threshold(tmp_path, monkeypatch):
    _stub_remote(monkeypatch, [{"probe_id": "p", "verdict": "fail", "severity": "low"}])
    target = tmp_path / "t.json"
    target.write_text('{"kind":"openai_compat","endpoint_url":"https://x","model":"m"}')
    out = tmp_path / "r.html"
    result = CliRunner().invoke(
        cmd_run,
        ["--target", str(target), "--probes", "p", "--out", str(out), "--token", "t",
         "--api-url", "https://argus.example", "--fail-on", "high"],
    )
    assert result.exit_code == 0, result.output


def _compare_args(tmp_path, *extra):
    target = tmp_path / "t.json"
    target.write_text('{"kind":"openai_compat","endpoint_url":"https://x","model":"m"}')
    return ["--target", str(target), "--probes", "p", "--out", str(tmp_path / "r.html"), "--token", "t",
            "--api-url", "https://argus.example", *extra]


def test_run_sends_git_context(tmp_path, monkeypatch):
    _stub_remote(monkeypatch, [])
    bodies = []
    monkeypatch.setattr(api_client, "post_run", lambda *a, **k: bodies.append(k["body"]) or {"run_id": "r1"})
    monkeypatch.setattr(
        "argus.cli.cmd_run.git_context.detect",
        lambda: {"repo": "o/r", "branch": "feat", "commit": "abc"},
    )
    result = CliRunner().invoke(cmd_run, _compare_args(tmp_path))
    assert result.exit_code == 0, result.output
    assert (bodies[0]["repo"], bodies[0]["branch"], bodies[0]["commit"]) == ("o/r", "feat", "abc")


def _with_repo(monkeypatch):
    monkeypatch.setattr("argus.cli.cmd_run.git_context.detect", lambda: {"repo": "o/r", "branch": "feat", "commit": "abc"})


def _diff(new):
    return {"base_run_id": "b1", "new": new, "fixed": [],
            "still_failing": [{"probe_id": "p", "severity": "critical"}], "not_run": []}


def test_compare_to_gates_only_new_failures(tmp_path, monkeypatch):
    _with_repo(monkeypatch)
    _stub_remote(monkeypatch, [{"probe_id": "p", "verdict": "fail", "severity": "critical"}])
    monkeypatch.setattr(api_client, "get_diff", lambda *a, **k: _diff([]))
    result = CliRunner().invoke(cmd_run, _compare_args(tmp_path, "--fail-on", "high", "--compare-to", "main"))
    assert result.exit_code == 0, result.output
    assert "still failing: 1" in result.output


def test_compare_to_fails_on_new_failure(tmp_path, monkeypatch):
    _with_repo(monkeypatch)
    _stub_remote(monkeypatch, [{"probe_id": "p", "verdict": "fail", "severity": "critical"}])
    monkeypatch.setattr(api_client, "get_diff", lambda *a, **k: _diff([{"probe_id": "p", "severity": "critical"}]))
    result = CliRunner().invoke(cmd_run, _compare_args(tmp_path, "--fail-on", "high", "--compare-to", "main"))
    assert result.exit_code == 3, result.output
    assert "p" in result.output
    assert (tmp_path / "r.html").read_text() == "<html></html>"


def test_compare_to_with_local_is_usage_error(tmp_path):
    result = CliRunner().invoke(cmd_run, _compare_args(tmp_path, "--local", "--compare-to", "main")[:-5] + ["--local", "--compare-to", "main"])
    assert result.exit_code == 2, result.output


def test_run_sends_baseline_key(tmp_path, monkeypatch):
    from argus.cli.baseline_key import baseline_key
    _stub_remote(monkeypatch, [])
    bodies = []
    monkeypatch.setattr(api_client, "post_run", lambda *a, **k: bodies.append(k["body"]) or {"run_id": "r1"})
    result = CliRunner().invoke(cmd_run, _compare_args(tmp_path))
    assert result.exit_code == 0, result.output
    spec = json.loads((tmp_path / "t.json").read_text())
    assert bodies[0]["baseline_key"] == baseline_key(spec)


def test_compare_to_without_repo_exits_2_before_posting(tmp_path, monkeypatch):
    monkeypatch.setattr("argus.cli.cmd_run.git_context.detect", lambda: {})
    posted = []
    monkeypatch.setattr(api_client, "post_run", lambda *a, **k: posted.append(1))
    result = CliRunner().invoke(cmd_run, _compare_args(tmp_path, "--compare-to", "main"))
    assert result.exit_code == 2, result.output
    assert "--compare-to needs the repository name" in result.output
    assert posted == []


def test_compare_to_diff_http_error_exits_1_with_message(tmp_path, monkeypatch):
    _with_repo(monkeypatch)
    _stub_remote(monkeypatch, [])
    req = httpx.Request("GET", "https://argus.example/diff")

    def boom(*a, **k):
        raise httpx.HTTPStatusError("409", request=req, response=httpx.Response(409, json={"detail": "run has no repo recorded"}, request=req))

    monkeypatch.setattr(api_client, "get_diff", boom)
    result = CliRunner().invoke(cmd_run, _compare_args(tmp_path, "--compare-to", "main"))
    assert result.exit_code == 1, result.output
    assert "Error: could not compare with main: run has no repo recorded" in result.output
    assert "Traceback" not in result.output
    assert (tmp_path / "r.html").read_text() == "<html></html>"


def test_baseline_key_same_for_different_probe_selection(tmp_path, monkeypatch):
    _stub_remote(monkeypatch, [])
    bodies = []
    monkeypatch.setattr(api_client, "post_run", lambda *a, **k: bodies.append(k["body"]) or {"run_id": "r1"})
    args = _compare_args(tmp_path)
    CliRunner().invoke(cmd_run, args)
    args[args.index("--probes") + 1] = "p,q"
    CliRunner().invoke(cmd_run, args)
    assert bodies[0]["probe_ids"] != bodies[1]["probe_ids"]
    assert bodies[0]["baseline_key"] == bodies[1]["baseline_key"]


def test_run_submits_trap_options_without_local(tmp_path, monkeypatch):
    _stub_remote(monkeypatch, [])
    bodies = []
    monkeypatch.setattr(api_client, "post_run", lambda *a, **k: bodies.append(k["body"]) or {"run_id": "r1"})
    spec = {"kind": "browser_use", "agent_url": "http://a", "scenario_kind": "dom_injection",
            "trap_host": "0.0.0.0", "trap_port": 8765, "trap_public_url": "http://10.0.0.5:8765"}
    p = tmp_path / "b.json"
    p.write_text(json.dumps(spec))
    result = CliRunner().invoke(cmd_run, [
        "--target", str(p), "--probes", "p", "--out", str(tmp_path / "r.html"),
        "--api-url", "https://argus.example", "--token", "t",
    ])
    assert result.exit_code == 0, result.output
    assert len(bodies) == 1
    assert bodies[0]["target"] == spec


@pytest.mark.parametrize("trap, match", [
    ({"trap_host": "0.0.0.0", "trap_port": 8765}, "set trap_public_url"),
    ({"trap_public_url": "http://10.0.0.5:8765"}, "fixed trap_port"),
    ({"trap_host": "localhost"}, "IPv4"),
])
def test_run_validates_browser_spec_before_submitting(tmp_path, trap, match):
    p = tmp_path / "b.json"
    p.write_text(json.dumps({"kind": "browser_use", "agent_url": "http://a", "scenario_kind": "dom_injection", **trap}))
    with patch("argus.cli.api_client.post_run") as post_run:
        result = CliRunner().invoke(cmd_run, [
            "--target", str(p), "--probes", "p", "--out", str(tmp_path / "r.html"),
            "--api-url", "https://argus.example", "--token", "t",
        ])
    assert result.exit_code == 2, result.output
    assert match in result.output
    post_run.assert_not_called()


def test_run_rejects_malformed_browser_spec_without_traceback(tmp_path):
    p = tmp_path / "b.json"
    p.write_text(json.dumps({"kind": "browser_use", "agent_url": "http://a", "scenario_kind": "dom_injection",
                             "extra_context": [1]}))
    with patch("argus.cli.api_client.post_run") as post_run:
        result = CliRunner().invoke(cmd_run, [
            "--target", str(p), "--probes", "p", "--out", str(tmp_path / "r.html"),
            "--api-url", "https://argus.example", "--token", "t",
        ])
    assert result.exit_code == 2, result.output
    assert isinstance(result.exception, SystemExit)
    assert "invalid browser_use target: 'int' object is not iterable" in result.output
    post_run.assert_not_called()


@pytest.mark.parametrize("detail, shown", [
    ("trap_port must be an integer from 0 to 65535, got 70000", "trap_port must be an integer from 0 to 65535, got 70000"),
    ([{"loc": ["body", "target"], "msg": "field required"}], "field required"),
])
def test_run_exits_2_on_server_422_without_traceback(tmp_path, detail, shown):
    fake_response = MagicMock()
    fake_response.status_code = 422
    fake_response.json = lambda: {"detail": detail}

    def fake_post_run_422(*args, **kwargs):
        raise httpx.HTTPStatusError("422", request=MagicMock(), response=fake_response)

    with patch("argus.cli.api_client.post_run", side_effect=fake_post_run_422):
        result = CliRunner().invoke(cmd_run, [
            "--target", str(_target_file(tmp_path)), "--probes", "p", "--out", str(tmp_path / "r.html"),
            "--api-url", "https://argus.example", "--token", "t",
        ])
    assert result.exit_code == 2, result.output
    assert isinstance(result.exception, SystemExit)
    assert f"Error: server rejected the run: {shown}" in result.output


def _local_args(tmp_path, out):
    target = tmp_path / "t.json"
    target.write_text(json.dumps({"kind": "openai_compat", "endpoint_url": "http://127.0.0.1:9/v1", "model": "m"}))
    return ["run", "--target", str(target), "--probes", "p", "--out", str(out), "--local"]


@pytest.mark.parametrize("local", [True, False])
def test_out_in_a_missing_directory_is_a_usage_error_before_any_work(tmp_path, monkeypatch, local):
    calls = []
    monkeypatch.setattr("argus.cli.cmd_run.run_local_and_render", lambda *a, **k: calls.append(1))
    monkeypatch.setattr(api_client, "post_run", lambda *a, **k: calls.append(1))
    args = _local_args(tmp_path, tmp_path / "nodir" / "r.html")
    if not local:
        args = args[:-1] + ["--token", "t", "--api-url", "http://127.0.0.1:9"]
    result = CliRunner().invoke(main, args)
    assert result.exit_code == 2, result.output
    assert "does not exist" in result.output
    assert calls == []


@pytest.mark.parametrize("local", [True, False])
def test_report_write_failure_exits_1_without_traceback(tmp_path, monkeypatch, local):
    from pathlib import Path

    from argus.cli.local_run import LocalRunResult

    monkeypatch.setattr("argus.cli.cmd_run.run_local_and_render", lambda *a, **k: LocalRunResult("<html></html>", []))
    monkeypatch.setattr(api_client, "post_run", lambda *a, **k: {"run_id": "r1"})
    monkeypatch.setattr(api_client, "poll_until_complete", lambda *a, **k: {"status": "completed", "findings": []})
    monkeypatch.setattr(api_client, "get_report", lambda *a, **k: "<html></html>")
    real = Path.write_text

    def write_text(self, *a, **k):
        if self.name == "r.html":
            raise OSError(28, "No space left on device")
        return real(self, *a, **k)

    monkeypatch.setattr(Path, "write_text", write_text)
    args = _local_args(tmp_path, tmp_path / "r.html")
    if not local:
        args = args[:-1] + ["--token", "t", "--api-url", "http://127.0.0.1:9"]
    result = CliRunner().invoke(main, args)
    assert result.exit_code == 1, result.output
    assert f"Error: cannot write {tmp_path / 'r.html'}: [Errno 28] No space left on device" in result.output
    assert "Traceback" not in result.output and "Wrote report" not in result.output


def _server(monkeypatch, run):
    monkeypatch.setattr(api_client, "post_run", lambda *a, **k: {"run_id": "r1"})
    monkeypatch.setattr(api_client, "poll_until_complete", lambda *a, **k: run)
    monkeypatch.setattr(api_client, "get_report", lambda *a, **k: "<html>server report</html>")


def _server_args(tmp_path, out, *extra):
    return _local_args(tmp_path, out)[:-1] + ["--token", "t", "--api-url", "http://127.0.0.1:9", *extra]


def test_server_mode_error_finding_exits_1_after_writing_report(tmp_path, monkeypatch):
    _server(monkeypatch, {"status": "completed", "findings": [
        {"probe_id": "a", "verdict": "fail", "severity": "critical"},
        {"probe_id": "b", "verdict": "error", "severity": "info", "reasoning": "target returned HTTP 429 (rate limited; slow down or retry later)"},
    ]})
    out = tmp_path / "r.html"
    result = CliRunner().invoke(main, _server_args(tmp_path, out, "--fail-on", "high"))
    assert result.exit_code == 1, result.output
    assert out.read_text() == "<html>server report</html>"
    assert "1 of 2 probes errored; run incomplete" in result.output
    assert "rate limited" in result.output


def test_server_mode_without_errors_keeps_fail_on_exit_3(tmp_path, monkeypatch):
    _server(monkeypatch, {"status": "completed", "findings": [
        {"probe_id": "a", "verdict": "fail", "severity": "critical"},
        {"probe_id": "b", "verdict": "blocked_by_target", "severity": "info"},
    ]})
    result = CliRunner().invoke(main, _server_args(tmp_path, tmp_path / "r.html", "--fail-on", "high"))
    assert result.exit_code == 3, result.output
    assert "incomplete" not in result.output


def test_server_mode_aborted_cost_exits_4(tmp_path, monkeypatch):
    _server(monkeypatch, {"status": "completed", "findings": [
        {"probe_id": "a", "verdict": "aborted_cost", "severity": "info", "reasoning": "cost cap hit at round 1: cap"},
        {"probe_id": "b", "verdict": "error", "severity": "info", "reasoning": "x"},
    ]})
    out = tmp_path / "r.html"
    result = CliRunner().invoke(main, _server_args(tmp_path, out))
    assert result.exit_code == 4, result.output
    assert out.exists()
    assert "1 probe(s) stopped at the cost cap; run incomplete" in result.output
