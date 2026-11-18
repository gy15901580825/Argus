"""Target mistakes must stop both CLI paths before execution."""

import json
from unittest.mock import AsyncMock, Mock

import pytest
from click.testing import CliRunner

from argus.cli.__main__ import main
from argus.cli.local_run import LocalRunResult
from argus.cli.target_loader import load_target_spec_with_secrets
from argus.targets import _BUILDERS, build_target


@pytest.fixture
def execution(monkeypatch):
    ping = AsyncMock(return_value="pong")
    run = Mock(return_value=LocalRunResult("", []))
    monkeypatch.setattr("argus.cli.cmd_validate_target._ping", ping)
    monkeypatch.setattr("argus.cli.cmd_run.run_local_and_render", run)
    return ping, run


def invoke(path, command):
    args = [command, "--target", str(path)]
    if command == "run":
        args += ["--local", "--probes", "garak_leakreplay_nytcloze", "--out", str(path.parent / "report.html")]
    return CliRunner().invoke(main, args)


@pytest.mark.parametrize("reference", ["${ARGUS_T1_UNSET}", "$ARGUS_T1_UNSET"])
@pytest.mark.parametrize("command", ["validate-target", "run"])
def test_unset_variable_names_field_and_fix(tmp_path, monkeypatch, execution, reference, command):
    monkeypatch.delenv("ARGUS_T1_UNSET", raising=False)
    path = tmp_path / "target.json"
    path.write_text(json.dumps({"kind": "openai_compat", "endpoint_url": "https://example.com/chat", "model": "m", "api_key": reference}))
    result = invoke(path, command)
    assert result.exit_code == 1, result.output
    assert "ARGUS_T1_UNSET" in result.output
    assert "target.api_key" in result.output
    assert "export ARGUS_T1_UNSET" in result.output
    assert "$$" in result.output
    for call in execution:
        call.assert_not_called()


@pytest.mark.parametrize("command", ["validate-target", "run"])
def test_json_syntax_error_has_location_without_yaml_fallback(tmp_path, execution, command):
    path = tmp_path / "target.json"
    path.write_text('{"kind":"openai_compat","endpoint_url":"https://example.com/chat","model":"m",}')
    result = invoke(path, command)
    assert result.exit_code == 1, result.output
    assert "target JSON malformed" in result.output
    assert "line 1 column 79" in result.output
    assert "Expecting property name enclosed in double quotes" in result.output
    for call in execution:
        call.assert_not_called()


@pytest.mark.parametrize("command", ["validate-target", "run"])
@pytest.mark.parametrize("field,suggestion", [("apikey", "Did you mean 'api_key'?"), ("unrelated_field", None)])
def test_unknown_field_names_kind_valid_fields_and_suggestion(tmp_path, execution, command, field, suggestion):
    path = tmp_path / "target.json"
    path.write_text(json.dumps({"kind": "openai_compat", "endpoint_url": "https://example.com/chat", "model": "m", field: "synthetic-value"}))
    result = invoke(path, command)
    assert result.exit_code == 1, result.output
    assert f"unknown field '{field}'" in result.output
    assert "openai_compat" in result.output
    assert "Valid fields:" in result.output
    assert "api_key" in result.output
    assert "endpoint_url" in result.output
    assert "input_limits" in result.output
    if suggestion:
        assert suggestion in result.output
    assert "TypeError" not in result.output
    assert "Running" not in result.output
    for call in execution:
        call.assert_not_called()


@pytest.mark.parametrize("extension", ["yaml", "yml"])
@pytest.mark.parametrize("command", ["validate-target", "run"])
def test_yaml_targets_are_accepted_by_both_commands(tmp_path, execution, extension, command):
    path = tmp_path / f"target.{extension}"
    path.write_text("kind: openai_compat\nendpoint_url: https://example.com/chat\nmodel: m\n")
    result = invoke(path, command)
    assert result.exit_code == 0, result.output


def test_nested_unset_variable_and_dollar_escape(tmp_path, monkeypatch):
    monkeypatch.delenv("ARGUS_T1_UNSET", raising=False)
    monkeypatch.setenv("ARGUS_T1_SET", "synthetic-${NOT_REEXPANDED}")
    path = tmp_path / "target.json"
    spec = {"kind": "openai_compat", "endpoint_url": "https://example.com/chat", "model": "m", "extra_headers": {"X-Test": ["$$ARGUS_T1_UNSET $${ARGUS_T1_UNSET} $ARGUS_T1_SET"]}}
    path.write_text(json.dumps(spec))
    loaded, secrets = load_target_spec_with_secrets(str(path))
    assert loaded["extra_headers"]["X-Test"] == ["$ARGUS_T1_UNSET ${ARGUS_T1_UNSET} synthetic-${NOT_REEXPANDED}"]
    assert secrets == ["synthetic-${NOT_REEXPANDED}"]
    spec["extra_headers"]["X-Test"] = ["${ARGUS_T1_UNSET}"]
    path.write_text(json.dumps(spec))
    with pytest.raises(ValueError, match=r"target.extra_headers.X-Test\[0\].*ARGUS_T1_UNSET"):
        load_target_spec_with_secrets(str(path))


def test_validate_target_help_explains_requests():
    result = CliRunner().invoke(main, ["validate-target", "--help"])
    assert "Legacy chat targets send one prompt by default" in result.output
    assert "Transport targets send requests only with --execute" in " ".join(result.output.split())
    assert "--offline sends no requests" in result.output


@pytest.mark.parametrize("kind", sorted(_BUILDERS))
def test_factory_unknown_fields_name_each_builtin_kind(kind):
    with pytest.raises(ValueError) as exc:
        build_target({"kind": kind, "unknown_option": "synthetic-value"}, trusted_code=True)
    assert "unknown field 'unknown_option'" in str(exc.value)
    assert f"target kind '{kind}'" in str(exc.value)
    assert "Valid fields:" in str(exc.value)
    assert "input_limits" in str(exc.value)


@pytest.mark.parametrize("extension,content,expected", [
    ("json", "kind: openai_compat\nmodel: m\n", "target JSON malformed"),
    ("yaml", "kind: [unclosed\n", "target YAML malformed"),
    ("json", '{"endpoint_url":"https://example.com/chat","model":"m"}', "add the 'kind' field"),
    ("yaml", "endpoint_url: https://example.com/chat\nmodel: m\n", "add the 'kind' field"),
    ("json", "[]", "target must be a JSON object"),
])
def test_file_errors_match_between_commands(tmp_path, execution, extension, content, expected):
    path = tmp_path / f"target.{extension}"
    path.write_text(content)
    validation = invoke(path, "validate-target")
    run = invoke(path, "run")
    assert validation.exit_code == run.exit_code == 1
    assert validation.output == run.output
    assert expected in validation.output
    for call in execution:
        call.assert_not_called()


def test_offline_unset_variable_also_fails_before_execution(tmp_path, monkeypatch, execution):
    monkeypatch.delenv("ARGUS_T1_UNSET", raising=False)
    path = tmp_path / "target.json"
    path.write_text(json.dumps({"kind": "openai_compat", "endpoint_url": "https://example.com/chat", "model": "m", "api_key": "${ARGUS_T1_UNSET}"}))
    result = CliRunner().invoke(main, ["validate-target", "--target", str(path), "--offline"])
    assert result.exit_code == 1
    assert "target.api_key" in result.output
    assert "export ARGUS_T1_UNSET" in result.output
    for call in execution:
        call.assert_not_called()


def test_inner_unknown_field_names_inner_kind(tmp_path):
    path = tmp_path / "target.json"
    path.write_text(json.dumps({"kind": "mcp_agent", "sandbox": True, "testbed_url": "local", "inner": {"kind": "openai_compat", "apikey": "synthetic-value"}}))
    with pytest.raises(ValueError, match="unknown field 'apikey' for target kind 'openai_compat'.*Did you mean 'api_key'"):
        load_target_spec_with_secrets(str(path))
