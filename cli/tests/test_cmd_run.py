"""Tests for `argus-probe run`."""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import httpx
import pytest
from click.testing import CliRunner

from argus_probe.__main__ import main


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

    with patch("argus_probe.api_client.post_run", return_value=fake_api["post_run"]) as mock_post, \
         patch("argus_probe.api_client.get_run") as mock_get, \
         patch("argus_probe.api_client.get_report", return_value=fake_api["report"]):
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

    with patch("argus_probe.api_client.post_run", return_value={"run_id": "cap-run"}) as mock_post, \
         patch("argus_probe.api_client.poll_until_complete", return_value={"status": "completed", "findings": []}), \
         patch("argus_probe.api_client.get_report", return_value="<html/>"):
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


def test_run_returns_402_on_cost_rejection(tmp_path):
    """When server returns 402, CLI exits with code 402 and prints detail to stderr."""
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

    with patch("argus_probe.api_client.post_run", side_effect=fake_post_run_402):
        result = runner.invoke(main, [
            "run",
            "--target", str(target_file),
            "--probes", "p1",
            "--out", str(tmp_path / "report.html"),
            "--token", "test-token",
            "--api-url", "https://dev.example.com",
            "--per-run-cap", "0.10",
        ])
        assert result.exit_code == 402
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
    with patch("argus_probe.api_client.post_run", return_value={"run_id": "env-run"}) as mock_post, \
         patch("argus_probe.api_client.poll_until_complete", return_value={"status": "completed", "findings": []}), \
         patch("argus_probe.api_client.get_report", return_value="<html/>"):
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
    with patch("argus_probe.api_client.post_run", return_value={"run_id": "all-run"}) as mock_post, \
         patch("argus_probe.api_client.poll_until_complete", return_value={"status": "completed", "findings": []}), \
         patch("argus_probe.api_client.get_report", return_value="<html/>"):
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
    with patch("argus_probe.api_client.post_run") as mock_post:
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
