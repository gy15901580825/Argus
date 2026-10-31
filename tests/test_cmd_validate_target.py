import importlib.util
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
    {"kind": "a2a_server", "url": "http://127.0.0.1:8765"},
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
    assert "network error: ConnectError: refused" in result.output


def test_validate_target_names_a_timeout_with_no_message(tmp_path, httpx_mock):
    target_file = tmp_path / "t.yaml"
    target_file.write_text(f"endpoint_url: {URL}\nmodel: m\n")
    httpx_mock.add_exception(httpx.ReadTimeout(""), url=URL)
    result = _invoke(target_file)
    assert result.exit_code == 1
    assert "network error: ReadTimeout" in result.output


@pytest.mark.parametrize("exc,expected", [
    (RuntimeError("boom"), "target request failed: RuntimeError: boom"),
    (type("APIStatusError", (Exception,), {"status_code": 403})("forbidden"), "target returned 403: forbidden"),
])
def test_validate_target_reports_adapter_failures(tmp_path, exc, expected):
    from argus.targets._base import TargetBlockedError

    target_file = tmp_path / "t.json"
    target_file.write_text(json.dumps({"kind": "anthropic_native", "model": "claude-x", "api_key": "k"}))
    for raised, text in ((exc, expected), (TargetBlockedError("refusal"), "target withheld its reply: refusal")):
        with patch("argus.targets.anthropic_native.AnthropicNativeTarget.send_prompt",
                   AsyncMock(side_effect=raised)):
            result = _invoke(target_file)
        assert result.exit_code == 1
        assert text in result.output


@pytest.mark.parametrize("content,expected", [
    ("endpoint_url: [unclosed\n", "cannot read the target file"),
    ("", "must be a JSON object"),
    ("- a\n- b\n", "must be a JSON object"),
    ('{"kind": "nope"}', "unknown target.kind"),
    ('{"kind": ["openai_compat"]}', "unknown target.kind"),
    (json.dumps({**CUSTOM_HTTP, "response_jsonpath": "$[["}), "target spec invalid"),
    (f"endpoint_url: {URL}\nmodel: m\nmax_tokens: 10\n", "target spec invalid"),
])
def test_validate_target_reports_bad_specs_without_a_traceback(tmp_path, content, expected, httpx_mock):
    target_file = tmp_path / "t.json"
    target_file.write_text(content)
    result = _invoke(target_file)
    assert result.exit_code == 1, result.output
    assert expected in result.output
    assert isinstance(result.exception, SystemExit)
    assert httpx_mock.get_requests() == []


def test_validate_target_reports_unreadable_files(tmp_path):
    binary = tmp_path / "t.bin"
    binary.write_bytes(b"\xff\xfe\x00bad")
    result = _invoke(binary)
    assert result.exit_code == 1
    assert "cannot read the target file" in result.output
    # A directory is a usage error from click, not a traceback.
    assert _invoke(tmp_path).exit_code == 2


def test_validate_target_reads_tab_indented_json_like_run(tmp_path, httpx_mock):
    # YAML forbids tabs; run reads JSON, so validate-target must too.
    target_file = tmp_path / "t.json"
    target_file.write_text('{\n\t"kind": "openai_compat",\n\t"endpoint_url": "%s",\n\t"model": "m"\n}' % URL)
    httpx_mock.add_response(url=URL, method="POST", json=_ok_json())
    assert _invoke(target_file).exit_code == 0


def test_validate_target_masks_secrets_like_run(tmp_path, httpx_mock, monkeypatch):
    # The expanded URL and an error body that echoes the key must not reach CI logs.
    monkeypatch.setenv("ARGUS_TEST_URL_KEY", "url-secret-value")
    url = "https://agent.example/chat?key=url-secret-value"
    target_file = tmp_path / "t.json"
    target_file.write_text(json.dumps({**CUSTOM_HTTP, "request_url": "https://agent.example/chat?key=${ARGUS_TEST_URL_KEY}",
                                       "api_key": "literal-key-value"}))
    httpx_mock.add_response(url=url, method="POST", json={"output": "pong"})
    result = _invoke(target_file)
    assert result.exit_code == 0, result.output
    assert "url-secret-value" not in result.output
    assert "${ARGUS_TEST_URL_KEY}" in result.output
    httpx_mock.add_response(url=url, method="POST", status_code=401,
                            text="bad key literal-key-value for url-secret-value")
    result = _invoke(target_file)
    assert result.exit_code == 1
    assert "target returned 401" in result.output
    assert "literal-key-value" not in result.output and "url-secret-value" not in result.output


@pytest.mark.skipif(importlib.util.find_spec("playwright") is None, reason="Playwright is not installed")
@pytest.mark.parametrize("send,code", [
    (AsyncMock(return_value=("hi there", 1.0)), 0),
    (AsyncMock(side_effect=RuntimeError("page gone")), 1),
])
def test_validate_target_web_chat_closes_the_browser(tmp_path, send, code):
    target_file = tmp_path / "t.json"
    target_file.write_text(json.dumps({"kind": "web_chat", "url": "https://chat.example/",
                                       "input_selector": "#in", "response_selector": ".bot"}))
    aclose = AsyncMock()
    with patch("argus.targets.web_chat.WebChatTarget.send_prompt", send), \
         patch("argus.targets.web_chat.WebChatTarget.aclose", aclose):
        result = _invoke(target_file)
    assert result.exit_code == code, result.output
    if code == 0:
        assert "OK — target https://chat.example/ replied with 8 chars" in result.output
    aclose.assert_awaited_once()


def test_validate_target_rejects_invalid_a2a_server_fields(tmp_path):
    from click.testing import CliRunner
    from argus.cli.cmd_validate_target import cmd_validate_target
    target = tmp_path / 'target.json'
    target.write_text(json.dumps({'kind':'a2a_server', 'url':'http://127.0.0.1:8765', 'second_client':{'headers':[['Authorization','Bearer bob']], 'forbidden_on_primary_tasks':['delete']}}))
    result = CliRunner().invoke(cmd_validate_target, ['--target', str(target)])
    assert result.exit_code == 1
    assert 'target spec invalid' in result.output and 'Traceback' not in result.output
