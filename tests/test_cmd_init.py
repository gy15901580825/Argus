"""Tests for argus-probe init subcommand."""
from __future__ import annotations

import json
import shlex
import subprocess
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from argus.cli.cmd_init import init_command
from argus.cli.target_loader import load_target_spec


@pytest.fixture(autouse=True)
def interactive_stdin(monkeypatch, tmp_path):
    # Existing prompt tests supply answers as though stdin were a terminal.
    monkeypatch.setattr("argus.cli.cmd_init._stdin_is_tty", lambda: True)
    # Test scratch directories live inside a checkout; do not discover that parent repo.
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path.parent))


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


@pytest.mark.parametrize("send_answer,send_selector", [
    ("button#send", "button#send"),
    ("", ""),  # empty means press Enter
])
def test_init_web_chat_writes_target_json(tmp_path, monkeypatch, send_answer, send_selector):
    from argus.targets.web_chat import WebChatSpec

    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(
        init_command,
        ["--kind", "web_chat", "--no-workflow"],
        input=f"https://chat.example/\n\n.msg.assistant\n{send_answer}\n",
    )
    assert result.exit_code == 0, result.output
    spec = json.loads((tmp_path / "argus-target.json").read_text())
    assert spec == {
        "kind": "web_chat",
        "url": "https://chat.example/",
        "input_selector": "textarea",
        "response_selector": ".msg.assistant",
        "send_selector": send_selector,
    }
    load_target_spec(str(tmp_path / "argus-target.json"))
    WebChatSpec(**spec)  # the engine accepts the scaffold too


def test_init_web_chat_gets_the_chat_probes(tmp_path, monkeypatch):
    # Checked against the class, not build_target: the main CI job has no Playwright.
    from argus.api import PROBES_DIR
    from argus.probe import load_probe_library
    from argus.targets.web_chat import WebChatTarget

    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(init_command, ["--kind", "web_chat", "--workflow"],
                                input="https://chat.example/\n\n.reply\n\n")
    assert result.exit_code == 0, result.output
    workflow = yaml.safe_load((tmp_path / ".github/workflows/argus-probe.yml").read_text())
    step = next(s for s in workflow["jobs"]["redteam"]["steps"] if "with" in s)
    probes = "owasp_01_prompt_injection_basic,syscard_crescendo"
    assert step["with"]["probes"] == probes
    assert f"--probes {probes} " in result.output
    library = {p.id: p for p in load_probe_library(PROBES_DIR)}
    assert all(set(library[i].target_class) & WebChatTarget.compatible_classes for i in probes.split(","))


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
    assert action["uses"] == "gy15901580825/argus-probe-action@v2"
    assert action["with"]["target"] == "argus-target.json"
    assert action["with"]["fail-on"] == "critical"
    assert action["env"] == {
        "ANTHROPIC_API_KEY": "${{ secrets.ANTHROPIC_API_KEY }}",
        "OPENAI_API_KEY": "${{ secrets.OPENAI_API_KEY }}",
    }
    assert wf["jobs"]["redteam"]["permissions"]["security-events"] == "write"
    assert "git+https" not in content
    triggers = wf.get("on", wf.get(True))
    assert triggers["pull_request"] == {}
    assert "push" not in triggers
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


@pytest.mark.parametrize("kind,answers", [("mcp_agent", "\n\n"), ("payment_agent", "\n\n"),
                                          ("testbed_agent", "payment\n\n\n")])
def test_init_testbed_kinds_default_to_the_bundled_testbed(tmp_path, monkeypatch, kind, answers):
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(init_command, ["--kind", kind, "--no-workflow"], input=answers)
    assert result.exit_code == 0, result.output
    spec = json.loads((tmp_path / "argus-target.json").read_text())
    assert spec["testbed_url"] == "local"
    assert "127.0.0.1" in result.output  # says where the bundled testbed listens
    load_target_spec(str(tmp_path / "argus-target.json"))


@pytest.mark.parametrize("kind,answers,probes", [
    ("mcp_agent", "\n\n", "all"),
    ("payment_agent", "\n\n", "all"),
    ("testbed_agent", "mcp\n\n\n", "all"),
    ("openai_compat", "\nm\n\n", "owasp_01_prompt_injection_basic,syscard_crescendo"),
])
def test_init_picks_probes_that_fit_the_kind(tmp_path, monkeypatch, kind, answers, probes):
    # A chat probe against an MCP or payment target is skipped, so a job using it tests nothing.
    from argus.api import PROBES_DIR
    from argus.probe import load_probe_library
    from argus.targets import build_target

    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(init_command, ["--kind", kind, "--workflow"], input=answers)
    assert result.exit_code == 0, result.output
    workflow = yaml.safe_load((tmp_path / ".github/workflows/argus-probe.yml").read_text())
    step = next(s for s in workflow["jobs"]["redteam"]["steps"] if "with" in s)
    assert step["with"]["probes"] == probes
    assert f"--probes {probes} " in result.output  # the printed next command runs as shown
    if probes != "all":
        spec = json.loads((tmp_path / "argus-target.json").read_text())
        classes = build_target({**spec, "api_key": "x"}).compatible_classes
        library = {p.id: p for p in load_probe_library(PROBES_DIR)}
        assert all(set(library[i].target_class) & classes for i in probes.split(","))


@pytest.mark.parametrize("kind,answers", [("mcp_agent", "\n\n"), ("openai_compat", "\nm\n\n")])
def test_workflow_installs_the_argus_version_that_wrote_it(tmp_path, monkeypatch, kind, answers):
    # Pin the workflow to the generating version instead of the Action's default.
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("argus.cli.cmd_init._installed_version", lambda: "9.8.7")
    result = CliRunner().invoke(init_command, ["--kind", kind, "--workflow"], input=answers)
    assert result.exit_code == 0, result.output
    workflow = yaml.safe_load((tmp_path / ".github/workflows/argus-probe.yml").read_text())
    step = next(s for s in workflow["jobs"]["redteam"]["steps"] if "with" in s)
    assert step["with"]["argus-version"] == "9.8.7"


def test_workflow_leaves_the_version_to_the_action_from_an_uninstalled_tree(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("argus.cli.cmd_init._installed_version", lambda: None)
    result = CliRunner().invoke(init_command, ["--kind", "mcp_agent", "--workflow"], input="\n\n")
    assert result.exit_code == 0, result.output
    workflow = yaml.safe_load((tmp_path / ".github/workflows/argus-probe.yml").read_text())
    step = next(s for s in workflow["jobs"]["redteam"]["steps"] if "with" in s)
    assert "argus-version" not in step["with"]


@pytest.mark.parametrize("installed_version,expected_pin", [
    ("1.22.0", "1.22.0"),
    ("1.22.1.dev0", None),
])
def test_workflow_pins_releases_and_leaves_main_builds_to_the_action(
    tmp_path, monkeypatch, installed_version, expected_pin,
):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("argus.cli.cmd_init._installed_version", lambda: installed_version)
    result = CliRunner().invoke(init_command, ["--kind", "mcp_agent", "--workflow"], input="\n\n")
    assert result.exit_code == 0, result.output
    workflow = yaml.safe_load((tmp_path / ".github/workflows/argus-probe.yml").read_text())
    step = next(s for s in workflow["jobs"]["redteam"]["steps"] if "with" in s)
    if expected_pin is not None:
        assert step["with"]["argus-version"] == expected_pin
    else:
        assert "argus-version" not in step["with"]


def test_every_known_kind_has_init_questions():
    # --kind offers every known kind, so a kind without questions crashes init.
    from argus.targets import _BUILDERS, _BUILTIN_KINDS

    assert all(_BUILTIN_KINDS[kind].init_questions for kind in _BUILDERS)


@pytest.mark.parametrize("kind,url", [
    ("mcp_server", "http://127.0.0.1:3001/mcp"),
    ("a2a_server", "http://127.0.0.1:8765"),
    ("vllm_server", "http://10.0.0.5:8000"),
])
def test_init_server_kinds_write_a_loadable_spec(tmp_path, monkeypatch, kind, url):
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(init_command, ["--kind", kind, "--no-workflow"], input=f"{url}\n")
    assert result.exit_code == 0, result.output
    spec = json.loads((tmp_path / "argus-target.json").read_text())
    assert spec == {"kind": kind, "url": url}
    assert load_target_spec(str(tmp_path / "argus-target.json")) == spec


def test_init_a2a_agent_writes_loadable_spec_with_sandbox(tmp_path, monkeypatch):
    from argus.targets import build_target
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(init_command, ["--kind", "a2a_agent", "--no-workflow"], input="\n\n\n")
    assert result.exit_code == 0, result.output
    spec = json.loads((tmp_path / "argus-target.json").read_text())
    assert spec["sandbox"] is True
    assert spec["capabilities"] == ["peer_http_json_1_0"]
    assert build_target(spec).compatible_classes == {"a2a_agent"}


def test_init_python_kind_writes_a_local_run(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(
        init_command,
        ["--kind", "python", "--workflow"],
        input="agent.py:answer\n",
    )
    assert result.exit_code == 0, result.output
    assert json.loads((tmp_path / "argus-target.json").read_text()) == {
        "kind": "python",
        "entry": "agent.py:answer",
    }
    workflow = (tmp_path / ".github/workflows/argus-probe.yml").read_text()
    assert "uses: gy15901580825/argus-probe-action@v2" in workflow
    scan = yaml.safe_load(workflow)["jobs"]["redteam"]["steps"][1]
    assert scan["with"]["target"] == "argus-target.json"
    assert "probes: owasp_01_prompt_injection_basic,syscard_crescendo" in workflow
    assert "--api-url" not in workflow
    assert (
        "With a judge key: argus-probe run --local --target argus-target.json "
        "--probes owasp_01_prompt_injection_basic,syscard_crescendo "
        "--out argus-report.html"
    ) in result.output


def _on_a_terminal(monkeypatch):
    # CliRunner replaces stdin with a pipe, so a terminal has to be simulated.
    monkeypatch.setattr("argus.cli.cmd_init._stdin_is_tty", lambda: True)


def test_bare_init_on_a_terminal_asks_for_the_kind_and_defaults_to_openai_compat(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _on_a_terminal(monkeypatch)
    result = CliRunner().invoke(init_command, [], input="\n\nmy-model\n\nn\n")
    assert result.exit_code == 0, result.output
    spec = json.loads((tmp_path / "argus-target.json").read_text())
    assert spec["kind"] == "openai_compat"
    assert spec["model"] == "my-model"


def test_bare_init_on_a_terminal_lists_every_kind_with_a_description(tmp_path, monkeypatch):
    from argus.targets import kinds
    registered = kinds()

    monkeypatch.chdir(tmp_path)
    _on_a_terminal(monkeypatch)
    result = CliRunner().invoke(init_command, ["--no-workflow"], input="mcp_agent\n\n\n")
    assert result.exit_code == 0, result.output
    for kind, info in registered.items():
        assert f"{kind}  " in result.output and info.description in result.output
    assert json.loads((tmp_path / "argus-target.json").read_text())["kind"] == "mcp_agent"


def test_bare_init_without_a_terminal_exits_2_and_lists_the_kinds(tmp_path, monkeypatch):
    from argus.targets import kinds
    registered = kinds()

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("argus.cli.cmd_init._stdin_is_tty", lambda: False)
    result = CliRunner().invoke(init_command, ["--no-workflow"], input="\n\nm\n\n")
    assert result.exit_code == 2, result.output
    for kind in registered:
        assert kind in result.output
    assert "argus-probe init --kind openai_compat" in result.output
    assert not (tmp_path / "argus-target.json").exists()


def test_kind_flag_does_not_ask_for_the_kind(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _on_a_terminal(monkeypatch)
    result = CliRunner().invoke(
        init_command, ["--kind", "custom_http", "--no-workflow"], input="https://agent.example/chat\n\n\n"
    )
    assert result.exit_code == 0, result.output
    assert "Target kind [" not in result.output
    assert json.loads((tmp_path / "argus-target.json").read_text())["kind"] == "custom_http"


def test_every_known_kind_has_a_description():
    # The kind prompt shows every known kind, so a kind without a description shows a blank line.
    from argus.targets import _BUILTIN_KINDS

    assert all(info.description for info in _BUILTIN_KINDS.values())


def _init_repo(path):
    subprocess.run(["git", "init", "--quiet", str(path)], check=True)
    subprocess.run(
        ["git", "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/develop"],
        cwd=path, check=True,
    )


@pytest.mark.parametrize("absolute,subdirectory", [(False, False), (True, False), (False, True)])
def test_workflow_preserves_repository_relative_target_path(tmp_path, monkeypatch, absolute, subdirectory):
    _init_repo(tmp_path)
    working_dir = tmp_path / "tools" if subdirectory else tmp_path
    working_dir.mkdir(exist_ok=True)
    monkeypatch.chdir(working_dir)
    target = tmp_path / ".argus/target.json"
    target.parent.mkdir()
    output = str(target) if absolute else "../.argus/target.json" if subdirectory else ".argus/target.json"
    result = CliRunner().invoke(init_command, ["--kind", "anthropic_native", "--workflow", "--output", output], input="\n\n")
    assert result.exit_code == 0, result.output
    workflow = yaml.safe_load((tmp_path / ".github/workflows/argus-probe.yml").read_text())
    scan = next(s for s in workflow["jobs"]["redteam"]["steps"] if "argus-probe-action" in s.get("uses", ""))
    assert scan["with"]["target"] == ".argus/target.json"
    triggers = workflow.get("on", workflow.get(True))
    assert triggers["pull_request"] == {"branches": ["develop"]}
    assert triggers["push"] == {"branches": ["develop"]}


def test_workflow_has_secret_guard_timeout_and_always_upload(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(init_command, ["--kind", "anthropic_native", "--workflow"], input="\n\n")
    assert result.exit_code == 0, result.output
    workflow = yaml.safe_load((tmp_path / ".github/workflows/argus-probe.yml").read_text())
    job = workflow["jobs"]["redteam"]
    assert job["if"] == "${{ github.actor != 'dependabot[bot]' && (github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository) }}"
    assert 0 < job["timeout-minutes"] <= 30
    scan = next(s for s in job["steps"] if "argus-probe-action" in s.get("uses", ""))
    upload = next(s for s in job["steps"] if "actions/upload-artifact" in s.get("uses", ""))
    assert job["steps"].index(upload) > job["steps"].index(scan)
    assert upload["if"] == "always()"
    assert upload["with"]["path"] == scan["with"]["output"] == "argus.sarif"
    assert "default branch" in result.output
    assert "without a branch filter" in result.output


def test_next_command_runs_keyless_probes_before_keyed_command(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(init_command, ["--kind", "python", "--no-workflow"], input="agent.py:answer\n")
    assert result.exit_code == 0, result.output
    next_line = next(line for line in result.output.splitlines() if line.startswith("Next:"))
    args = shlex.split(next_line.removeprefix("Next: "))
    assert "--skip-judged" in args
    assert args[args.index("--probes") + 1] == "all"
    assert result.output.index("Next:") < result.output.index("With a judge key:")


def test_noninteractive_init_lists_missing_model_option(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("argus.cli.cmd_init._stdin_is_tty", lambda: False)
    result = CliRunner().invoke(init_command, ["--kind", "openai_compat"])
    assert result.exit_code == 2, result.output
    assert "--model" in result.output
    assert "Aborted!" not in result.output
    assert not (tmp_path / "argus-target.json").exists()


def test_noninteractive_init_uses_flags_and_defaults(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("argus.cli.cmd_init._stdin_is_tty", lambda: False)
    result = CliRunner().invoke(init_command, ["--kind", "openai_compat", "--model", "my-model", "--output", ".argus/target.json"])
    assert result.exit_code == 0, result.output
    assert json.loads((tmp_path / ".argus/target.json").read_text()) == {
        "kind": "openai_compat", "model": "my-model",
        "endpoint_url": "https://api.openai.com/v1/chat/completions", "api_key": "${OPENAI_API_KEY}",
    }
    assert not (tmp_path / ".github").exists()


def test_noninteractive_init_with_all_defaults_never_prompts(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("argus.cli.cmd_init._stdin_is_tty", lambda: False)
    result = CliRunner().invoke(init_command, ["--kind", "anthropic_native"])
    assert result.exit_code == 0, result.output
    assert json.loads((tmp_path / "argus-target.json").read_text())["model"] == "claude-haiku-4-5-20251001"


def test_noninteractive_init_refuses_overwrite_with_guidance(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("argus.cli.cmd_init._stdin_is_tty", lambda: False)
    target = tmp_path / "argus-target.json"
    target.write_text("existing")
    result = CliRunner().invoke(init_command, ["--kind", "anthropic_native"])
    assert result.exit_code == 2, result.output
    assert "--output" in result.output
    assert "Aborted!" not in result.output
    assert target.read_text() == "existing"


def test_noninteractive_other_kinds_list_and_accept_missing_fields(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("argus.cli.cmd_init._stdin_is_tty", lambda: False)
    result = CliRunner().invoke(init_command, ["--kind", "web_chat"])
    assert result.exit_code == 2, result.output
    assert "--set url=VALUE" in result.output
    assert "--set response_selector=VALUE" in result.output
    result = CliRunner().invoke(init_command, ["--kind", "web_chat", "--set", "url=https://chat.example", "--set", "response_selector=.reply"])
    assert result.exit_code == 0, result.output
    spec = load_target_spec(str(tmp_path / "argus-target.json"))
    assert spec["url"] == "https://chat.example"
    assert spec["response_selector"] == ".reply"


def test_noninteractive_endpoint_and_key_flags_override_defaults(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("argus.cli.cmd_init._stdin_is_tty", lambda: False)
    result = CliRunner().invoke(init_command, [
        "--kind", "openai_compat", "--model", "my-model",
        "--endpoint-url", "https://agent.example/v1/chat/completions", "--api-key-env", "AGENT_API_KEY",
    ])
    assert result.exit_code == 0, result.output
    spec = json.loads((tmp_path / "argus-target.json").read_text())
    assert spec["endpoint_url"] == "https://agent.example/v1/chat/completions"
    assert spec["api_key"] == "${AGENT_API_KEY}"


@pytest.mark.parametrize("args,fix", [
    (["--set", "typo=value"], "--set"),
    (["--set", "model"], "FIELD=VALUE"),
    (["--api-key-env", "invalid-key"], "--api-key-env"),
])
def test_invalid_initializer_options_are_actionable(tmp_path, monkeypatch, args, fix):
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(init_command, ["--kind", "anthropic_native", *args], input="\n\n")
    assert result.exit_code == 2, result.output
    assert fix in result.output
    assert not (tmp_path / "argus-target.json").exists()


def test_workflow_rejects_output_outside_repository(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    _init_repo(repo)
    monkeypatch.chdir(repo)
    result = CliRunner().invoke(init_command, ["--kind", "anthropic_native", "--workflow", "--output", "../target.json"], input="\n\n")
    assert result.exit_code == 2, result.output
    assert "--output must be inside the repository" in result.output
    assert not (tmp_path / "target.json").exists()
    assert not (repo / ".github").exists()


def test_workflow_and_next_command_quote_target_path(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(init_command, ["--kind", "anthropic_native", "--workflow", "--output", "targets/agent #1.json"], input="\n\n")
    assert result.exit_code == 0, result.output
    workflow = yaml.safe_load((tmp_path / ".github/workflows/argus-probe.yml").read_text())
    assert workflow["jobs"]["redteam"]["steps"][1]["with"]["target"] == "targets/agent #1.json"
    next_line = next(line for line in result.output.splitlines() if line.startswith("Next:"))
    args = shlex.split(next_line.removeprefix("Next: "))
    assert args[args.index("--target") + 1] == "targets/agent #1.json"
