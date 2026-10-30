import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from click.testing import CliRunner

from argus.cli.__main__ import main

URL = "https://api.example.com/v1/chat/completions"
CUSTOM_HTTP = {
    "kind": "custom_http",
    "request_url": "https://agent.example/chat",
    "request_body_template": '{"input": {{prompt|tojson}}}',
    "response_jsonpath": "$.output",
}


def _ok_json():
    return {"choices": [{"message": {"content": "ok"}}]}


def _invoke(target_file):
    return CliRunner().invoke(main, ["validate-target", "--target", str(target_file)])


def test_validate_target_returns_ok_for_valid_endpoint(tmp_path, httpx_mock):
    # A YAML spec without `kind` predates the field and still means openai_compat.
    target_file = tmp_path / "t.yaml"
    target_file.write_text(f"endpoint_url: {URL}\nmodel: gpt-4o-mini\napi_key: sk-test\n")
    httpx_mock.add_response(url=URL, method="POST", json=_ok_json())
    result = _invoke(target_file)
    assert result.exit_code == 0, result.output
    assert f"OK — target {URL} replied with 2 chars" in result.output
    request = httpx_mock.get_request()
    assert request.headers["Authorization"] == "Bearer sk-test"
    assert json.loads(request.content)["model"] == "gpt-4o-mini"


def test_validate_target_waits_as_long_as_run_does(tmp_path, httpx_mock):
    # validate-target must not fail an agent that `run` would wait for.
    target_file = tmp_path / "t.yaml"
    for extra, expected in (("", 120.0), ("timeout_s: 45\n", 45.0)):
        target_file.write_text(f"endpoint_url: {URL}\nmodel: m\n{extra}")
        httpx_mock.add_response(url=URL, method="POST", json=_ok_json())
        assert _invoke(target_file).exit_code == 0
        assert httpx_mock.get_requests()[-1].extensions["timeout"]["read"] == expected


def test_validate_target_expands_env_vars_like_run(tmp_path, httpx_mock, monkeypatch):
    # `init` writes api_key as "${VAR}"; sending it unexpanded gets a 401 that `run` never sees.
    monkeypatch.setenv("ARGUS_TEST_TARGET_KEY", "expanded-value")
    target_file = tmp_path / "t.json"
    target_file.write_text(json.dumps(
        {"kind": "openai_compat", "endpoint_url": URL, "model": "m", "api_key": "${ARGUS_TEST_TARGET_KEY}"}))
    httpx_mock.add_response(url=URL, method="POST", json=_ok_json())
    assert _invoke(target_file).exit_code == 0
    assert httpx_mock.get_request().headers["Authorization"] == "Bearer expanded-value"


def test_validate_target_custom_http(tmp_path, httpx_mock):
    target_file = tmp_path / "t.json"
    target_file.write_text(json.dumps(CUSTOM_HTTP))
    httpx_mock.add_response(url="https://agent.example/chat", method="POST", json={"output": "pong!"})
    result = _invoke(target_file)
    assert result.exit_code == 0, result.output
    assert "OK — target https://agent.example/chat replied with 5 chars" in result.output
    assert json.loads(httpx_mock.get_request().content) == {"input": "ping"}


def test_validate_target_anthropic_native(tmp_path):
    target_file = tmp_path / "t.json"
    target_file.write_text(json.dumps({"kind": "anthropic_native", "model": "claude-x", "api_key": "k"}))
    send = AsyncMock(return_value=("hello", 1.0))
    with patch("argus.targets.anthropic_native.AnthropicNativeTarget.send_prompt", send):
        result = _invoke(target_file)
    assert result.exit_code == 0, result.output
    assert "OK — target anthropic claude-x replied with 5 chars" in result.output
    send.assert_awaited_once_with("ping")


def test_validate_target_empty_reply_is_an_error(tmp_path, httpx_mock):
    # A response path that matches nothing is an error in `run`, so it must not pass here.
    target_file = tmp_path / "t.json"
    target_file.write_text(json.dumps(CUSTOM_HTTP))
    httpx_mock.add_response(url="https://agent.example/chat", method="POST", json={"answer": "pong"})
    result = _invoke(target_file)
    assert result.exit_code == 1
    assert "reply text is empty" in result.output


@pytest.mark.parametrize("spec", [
    {"kind": "mcp_server", "url": "http://127.0.0.1:3001/mcp"},
    {"kind": "vllm_server", "url": "http://10.0.0.5:8000"},
])
def test_validate_target_refuses_kinds_a_ping_cannot_check(tmp_path, spec, httpx_mock):
    target_file = tmp_path / "t.json"
    target_file.write_text(json.dumps(spec))
    result = _invoke(target_file)
    assert result.exit_code == 2
    assert f"not {spec['kind']}" in result.output
    assert "argus-probe run --local" in result.output
    assert httpx_mock.get_requests() == []


def test_validate_target_reports_spec_errors_without_a_traceback(tmp_path):
    target_file = tmp_path / "t.json"
    target_file.write_text(json.dumps({"kind": "custom_http", "request_url": "https://agent.example/chat"}))
    result = _invoke(target_file)
    assert result.exit_code == 1
    assert "missing required fields" in result.output
    assert isinstance(result.exception, SystemExit)


def test_validate_target_reports_http_status(tmp_path, httpx_mock):
    target_file = tmp_path / "t.yaml"
    target_file.write_text(f"endpoint_url: {URL}\nmodel: m\n")
    httpx_mock.add_response(url=URL, method="POST", status_code=401, text="bad key")
    result = _invoke(target_file)
    assert result.exit_code == 1
    assert "target returned 401: bad key" in result.output


def test_validate_target_reports_network_error(tmp_path, httpx_mock):
    target_file = tmp_path / "t.yaml"
    target_file.write_text(f"endpoint_url: {URL}\nmodel: m\n")
    httpx_mock.add_exception(httpx.ConnectError("refused"), url=URL)
    result = _invoke(target_file)
    assert result.exit_code == 1
    assert "network error: refused" in result.output
