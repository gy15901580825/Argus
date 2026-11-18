"""First-use guidance through the CLI, with no judge calls."""
import json
import re

import pytest
from click.testing import CliRunner

from argus.cli.__main__ import main
from test_local_baseline import target  # Real loopback target and deterministic probes.


SPEC = json.dumps({"kind": "openai_compat", "endpoint_url": "http://127.0.0.1:1/chat", "model": "test"})


def invoke(tmp_path, probes, *extra, spec=SPEC, suffix="html"):
    return CliRunner().invoke(main, ["run", "--target", spec, "--probes", probes,
                                    "--out", str(tmp_path / f"report.{suffix}"), *extra])


def test_missing_server_explains_local_command(tmp_path):
    result = invoke(tmp_path, "all")
    assert result.exit_code == 2
    assert "--local runs the scan on this machine" in result.output
    assert "argus-probe run --local --target" in result.output
    assert "--probes all" in result.output and "--out" in result.output


@pytest.mark.parametrize("probes,count", [("owasp_01_prompt_injection_basic", 0),
    ("owasp_01_prompt_injection_basic,garak_leakreplay_nytcloze", 1)])
def test_no_judge_explains_keyless_selection(tmp_path, probes, count):
    result = invoke(tmp_path, probes, "--local")
    assert result.exit_code == 1
    assert "--skip-judged" in result.output
    assert f"{count} selected probe" in result.output
    assert "export ANTHROPIC_API_KEY=" in result.output
    if count == 0:
        assert "--probes all --skip-judged" in result.output
    assert "Running" not in result.output


def test_unknown_probe_suggests_before_running(tmp_path):
    result = invoke(tmp_path, "owasp_01_prompt_injection", "--local")
    assert result.exit_code == 2
    assert "unknown probe" in result.output
    assert "did you mean owasp_01_prompt_injection_basic" in result.output
    assert "Running" not in result.output


def test_incompatible_selection_refuses_before_running(tmp_path):
    result = invoke(tmp_path, "mcp_poison_description_exfil", "--local")
    assert result.exit_code == 2
    assert "no selected probes can run" in result.output.lower()
    assert "mcp_poison_description_exfil" in result.output and "mcp_agent" in result.output
    assert "openai_compat" in result.output
    assert "--probes all" in result.output
    assert "Running" not in result.output


@pytest.mark.parametrize("suffix,marker", [("sarif", '"version": "2.1.0"'),
    ("xml", "<testsuite"), ("json", '"schema_version": "argus.run/1"'), ("html", "<!doctype html>")])
def test_run_infers_report_format(tmp_path, target, suffix, marker):
    result = invoke(tmp_path, "probe_a", "--local", spec=json.dumps(target["spec"]), suffix=suffix)
    assert result.exit_code == 0, result.output
    assert marker in (tmp_path / f"report.{suffix}").read_text()


@pytest.mark.parametrize("command", ["run", "report", "mcp-trap"])
def test_format_mismatch_is_usage_error(tmp_path, command):
    args = {"run": ["--local", "--target", SPEC, "--probes", "all"],
            "report": ["--run-id", "test", "--api-url", "http://127.0.0.1:1", "--token", "test"],
            "mcp-trap": ["--target", SPEC]}[command]
    result = CliRunner().invoke(main, [command, *args, "--format", "html", "--out", str(tmp_path / "r.sarif")])
    assert result.exit_code == 2, result.output
    assert "--format html" in result.output and "--out" in result.output and "sarif" in result.output
    assert "disagree" in result.output


@pytest.mark.parametrize("command", ["run", "report", "mcp-trap"])
def test_format_default_in_help(command):
    result = CliRunner().invoke(main, [command, "--help"])
    assert re.search(r"--format.*?\[default: html\]", result.output, re.S)


@pytest.mark.parametrize("fail_on,code", [(None, 0), ("high", 3), ("critical", 0)])
def test_run_summary_explains_gate(tmp_path, target, fail_on, code):
    extra = ["--fail-on", fail_on] if fail_on else []
    result = invoke(tmp_path, "probe_a", "--local", *extra, spec=json.dumps(target["spec"]))
    assert result.exit_code == code, result.output
    last = result.output.strip().splitlines()[-1]
    assert "1 fail" in last and f"Exit {code}" in last
    assert f"--fail-on {fail_on or 'info'}" in last
    if fail_on is None:
        assert "fail CI on findings" in last


def test_missing_baseline_runs_and_gates_all_current_failures(tmp_path, target):
    result = invoke(tmp_path, "probe_a", "--local", "--baseline", str(tmp_path / "missing.json"),
                    "--fail-on", "high", spec=json.dumps(target["spec"]), suffix="json")
    assert result.exit_code == 3, result.output
    assert "missing.json" in result.output and "empty baseline" in result.output
    record = json.loads((tmp_path / "report.json").read_text())
    assert record["baseline"]["new"] == [{"probe_id": "probe_a", "severity": "high"}]
    assert len(target["requests"]) == 1


def test_run_incomplete_summary_names_errors(tmp_path, target):
    target["status"] = 500
    result = invoke(tmp_path, "probe_a", "--local", spec=json.dumps(target["spec"]))
    assert result.exit_code == 1, result.output
    last = result.output.strip().splitlines()[-1]
    assert "1 error" in last and "Exit 1" in last and "incomplete" in last


def test_unknown_extension_keeps_html_default(tmp_path, target):
    result = invoke(tmp_path, "probe_a", "--local", spec=json.dumps(target["spec"]), suffix="txt")
    assert result.exit_code == 0, result.output
    assert "<!doctype html>" in (tmp_path / "report.txt").read_text()


def test_incompatible_history_selection_names_reason(tmp_path):
    agent = tmp_path / "agent.py"
    agent.write_text("def reply(prompt, material, context):\n    return 'refused'\n")
    spec = json.dumps({"kind": "python", "entry": f"{agent}:reply", "history": False})
    result = invoke(tmp_path, "syscard_crescendo", "--local", spec=spec)
    assert result.exit_code == 2, result.output
    assert "history" in result.output and "--probes all" in result.output
    assert "Running" not in result.output


def test_no_judge_names_configured_provider_key(tmp_path):
    result = invoke(tmp_path, "owasp_01_prompt_injection_basic", "--local", "--judge-provider", "openai")
    assert result.exit_code == 1, result.output
    assert "export OPENAI_API_KEY=" in result.output
    assert "--skip-judged would run 0 selected probes" in result.output


def test_all_without_compatible_library_explains_target(tmp_path, monkeypatch):
    from dataclasses import replace
    from argus import api, local
    from argus.probe import load_probe_library

    incompatible = replace(load_probe_library(api.PROBES_DIR)[0], target_class=("mcp_agent",))
    monkeypatch.setattr(api, "load_probe_library", lambda *_: [incompatible])
    monkeypatch.setattr(local, "load_probe_library", lambda *_: [incompatible])
    result = invoke(tmp_path, "all", "--local")
    assert result.exit_code == 2, result.output
    assert "no probe in the library fits target kind openai_compat" in result.output
    assert "argus-probe list-probes --target" in result.output
    assert "Running" not in result.output


def test_missing_server_guides_local_json_scan(tmp_path):
    result = invoke(tmp_path, "all", suffix="json")
    assert result.exit_code == 2
    assert "--local runs the scan on this machine" in result.output
    assert "argus-probe run --local --target" in result.output


@pytest.mark.parametrize("probe", ["browser_secret_field_model_egress", "browser_secret_field_model_egress_control",
                                   "browser_secret_trace_export", "browser_secret_trace_export_control"])
def test_hosted_only_selection_explains_witness_restriction_before_running(tmp_path, probe):
    from tests.test_transport_engine import spec_dict

    spec = json.dumps({"kind": "browser_use", "transport": spec_dict(), "scenario_kind": "field_egress",
                       "trap_mode": "hosted", "hosted": {"service_url": "http://127.0.0.1:1"}})
    result = invoke(tmp_path, probe, "--local", spec=spec)
    assert result.exit_code == 2, result.output
    assert "witness channels are unsupported with hosted traps" in result.output
    assert "--probes all" in result.output
    assert "Running" not in result.output
