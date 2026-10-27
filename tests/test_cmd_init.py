"""Tests for argus-probe init subcommand."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from argus.cli.cmd_init import init_command
from argus.cli.target_loader import load_target_spec


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


def test_init_payment_agent_writes_target_json(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    inner = (
        '{"kind": "openai_compat", '
        '"endpoint_url": "http://127.0.0.1:8091/v1/chat/completions", '
        '"model": "argus-demo-payment-agent"}'
    )
    result = runner.invoke(
        init_command,
        ["--kind", "payment_agent", "--no-workflow"],
        input=f"http://127.0.0.1:8090\n{inner}\n",
    )
    assert result.exit_code == 0, result.output
    spec = json.loads((tmp_path / "argus-target.json").read_text())
    assert spec["kind"] == "payment_agent"
    assert spec["testbed_url"] == "http://127.0.0.1:8090"
    assert spec["inner"] == json.loads(inner)
    assert spec["sandbox"] is True
    # The scaffold must pass the loader without hand-editing.
    load_target_spec(str(tmp_path / "argus-target.json"))


def test_init_mcp_agent_writes_target_json(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    inner = (
        '{"kind": "openai_compat", '
        '"endpoint_url": "http://127.0.0.1:8093/v1/chat/completions", '
        '"model": "argus-demo-mcp-agent"}'
    )
    result = runner.invoke(
        init_command,
        ["--kind", "mcp_agent", "--no-workflow"],
        input=f"http://127.0.0.1:8092\n{inner}\n",
    )
    assert result.exit_code == 0, result.output
    spec = json.loads((tmp_path / "argus-target.json").read_text())
    assert spec["kind"] == "mcp_agent"
    assert spec["testbed_url"] == "http://127.0.0.1:8092"
    assert spec["inner"] == json.loads(inner)
    assert spec["sandbox"] is True
    load_target_spec(str(tmp_path / "argus-target.json"))


def test_init_testbed_agent_writes_target_json(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    inner = (
        '{"kind": "openai_compat", '
        '"endpoint_url": "http://127.0.0.1:8093/v1/chat/completions", '
        '"model": "argus-demo-mcp-agent"}'
    )
    result = runner.invoke(
        init_command,
        ["--kind", "testbed_agent", "--no-workflow"],
        input=f"mcp\nhttp://127.0.0.1:8092\n{inner}\n",
    )
    assert result.exit_code == 0, result.output
    spec = json.loads((tmp_path / "argus-target.json").read_text())
    assert spec["kind"] == "testbed_agent"
    assert spec["environment"] == "mcp"
    assert spec["testbed_url"] == "http://127.0.0.1:8092"
    assert spec["inner"] == json.loads(inner)
    assert spec["sandbox"] is True
    load_target_spec(str(tmp_path / "argus-target.json"))


def test_init_http_upload_writes_target_json(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    result = runner.invoke(
        init_command,
        ["--kind", "http_upload", "--no-workflow"],
        input="https://my-agent.example/api/upload\nfile\npayload.svg\nimage/svg+xml\n$.url\n",
    )
    assert result.exit_code == 0, result.output
    spec = json.loads((tmp_path / "argus-target.json").read_text())
    assert spec["kind"] == "http_upload"
    assert spec["upload_url"] == "https://my-agent.example/api/upload"
    assert spec["render_url_jsonpath"] == "$.url"
    load_target_spec(str(tmp_path / "argus-target.json"))


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
    wf = yaml.safe_load(content)
    steps = wf["jobs"]["redteam"]["steps"]
    action = next(s for s in steps if "argus-probe-action" in s.get("uses", ""))
    assert action["uses"] == "gy15901580825/argus-probe-action@v1"
    assert action["with"]["target"] == "argus-target.json"
    assert action["with"]["fail-on"] == "critical"
    assert action["env"] == {
        "ANTHROPIC_API_KEY": "${{ secrets.ANTHROPIC_API_KEY }}",
        "OPENAI_API_KEY": "${{ secrets.OPENAI_API_KEY }}",
    }
    assert wf["jobs"]["redteam"]["permissions"]["security-events"] == "write"
    assert "git+https" not in content
    # PyYAML parses the key `on` as boolean True.
    triggers = wf[True]
    assert triggers["pull_request"] == {"branches": ["main"]}
    assert triggers["push"] == {"branches": ["main"]}
    assert "schedule" in triggers
    assert "workflow_dispatch" in triggers
    assert "ANTHROPIC_API_KEY as a repository secret" in result.output


def test_init_workflow_does_not_repeat_anthropic_key(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(
        init_command,
        ["--kind", "anthropic_native", "--workflow"],
        input="\n\n",
    )
    assert result.exit_code == 0, result.output
    content = (tmp_path / ".github" / "workflows" / "argus-probe.yml").read_text()
    assert content.count("ANTHROPIC_API_KEY:") == 1
    steps = yaml.safe_load(content)["jobs"]["redteam"]["steps"]
    action = next(s for s in steps if "argus-probe-action" in s.get("uses", ""))
    assert action["env"] == {"ANTHROPIC_API_KEY": "${{ secrets.ANTHROPIC_API_KEY }}"}


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
