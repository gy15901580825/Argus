"""Tests for argus-probe init subcommand."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from argus_probe.cmd_init import init_command


def test_init_openai_compat_writes_target_json(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    result = runner.invoke(
        init_command,
        ["--kind", "openai_compat", "--no-workflow"],
        input="https://api.openai.com/v1/chat/completions\ngpt-4o-mini\nOPENAI_API_KEY\n",
    )
    assert result.exit_code == 0, result.output
    spec = json.loads((tmp_path / "argus-target.json").read_text())
    assert spec["kind"] == "openai_compat"
    assert spec["model"] == "gpt-4o-mini"
    assert spec["endpoint_url"] == "https://api.openai.com/v1/chat/completions"
    assert spec["api_key"] == "${OPENAI_API_KEY}"


def test_init_anthropic_native_writes_target_json(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    result = runner.invoke(
        init_command,
        ["--kind", "anthropic_native", "--no-workflow"],
        input="claude-haiku-4-5-20251001\nANTHROPIC_API_KEY\n",
    )
    assert result.exit_code == 0, result.output
    spec = json.loads((tmp_path / "argus-target.json").read_text())
    assert spec["kind"] == "anthropic_native"
    assert spec["model"] == "claude-haiku-4-5-20251001"
    assert spec["api_key"] == "${ANTHROPIC_API_KEY}"


def test_init_custom_http_writes_target_json(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    result = runner.invoke(
        init_command,
        ["--kind", "custom_http", "--no-workflow"],
        input='https://agent.example/chat\n{"input": {{prompt|tojson}}}\n$.output\n',
    )
    assert result.exit_code == 0, result.output
    spec = json.loads((tmp_path / "argus-target.json").read_text())
    assert spec["kind"] == "custom_http"
    assert spec["request_url"] == "https://agent.example/chat"
    assert "prompt|tojson" in spec["request_body_template"]
    assert spec["response_jsonpath"] == "$.output"


def test_init_grpc_writes_target_json(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    result = runner.invoke(
        init_command,
        ["--kind", "grpc", "--no-workflow"],
        input="agent.example:50051\nagent.AgentService/Chat\nuser_input\nresponse\n",
    )
    assert result.exit_code == 0, result.output
    spec = json.loads((tmp_path / "argus-target.json").read_text())
    assert spec["kind"] == "grpc"
    assert spec["endpoint"] == "agent.example:50051"
    assert spec["service_method"] == "agent.AgentService/Chat"


def test_init_browser_use_writes_target_json(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    result = runner.invoke(
        init_command,
        ["--kind", "browser_use", "--no-workflow"],
        input="https://my-agent.example/run\ndom_injection\n",
    )
    assert result.exit_code == 0, result.output
    spec = json.loads((tmp_path / "argus-target.json").read_text())
    assert spec["kind"] == "browser_use"
    assert spec["agent_url"] == "https://my-agent.example/run"
    assert spec["scenario_kind"] == "dom_injection"


def test_init_with_workflow_writes_workflow_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    result = runner.invoke(
        init_command,
        ["--kind", "openai_compat", "--workflow"],
        input="https://x\ny\nOPENAI_API_KEY\n",
    )
    assert result.exit_code == 0, result.output
    wf_path = tmp_path / ".github" / "workflows" / "argus-probe.yml"
    assert wf_path.exists()
    content = wf_path.read_text()
    assert "<your-gh-user>/argus-probe-action" in content
    assert "argus-target.json" in content


def test_init_refuses_overwrite_without_confirmation(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "argus-target.json").write_text('{"kind":"existing"}')
    runner = CliRunner()
    # Send 'n' for confirm-overwrite prompt
    result = runner.invoke(
        init_command,
        ["--kind", "openai_compat", "--no-workflow"],
        input="https://x\ny\nOPENAI_API_KEY\nn\n",
    )
    assert result.exit_code != 0  # Click.Abort
    # Original file unchanged
    assert json.loads((tmp_path / "argus-target.json").read_text())["kind"] == "existing"
