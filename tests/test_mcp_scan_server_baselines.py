"""Passive server checks use capability evidence and a matching product identity."""
import pytest

from argus import assertions
from argus.mcp_scan.models import ServerInfo, ToolInfo
from argus.mcp_scan.server_checks import stdio_server_findings


def tool(name, description, schema=None):
    return ToolInfo(name=name, title="", description=description, input_schema=schema,
                    annotations={}, raw={})


def check(tools, info=None):
    return {f["probe_id"]: f for f in stdio_server_findings(tools, info)}


@pytest.mark.parametrize("name,description", [
    ("state", "Returns whether the job reached a terminal state."),
    ("context", "Reports the rendering environment and viewport size."),
])
def test_sensitive_tools_ordinary_words_are_not_capabilities(name, description):
    assert check([tool(name, description)])["mcp_server_sensitive_tools"]["verdict"] == "pass"


@pytest.mark.parametrize("name,description,schema", [
    ("page_evaluate", "Evaluates arbitrary JavaScript in the current page.", None),
    ("page", "Execute script in the active page.", None),
    ("action", "Run code in the page.", None),
    ("page", "Perform a page action.", {"type": "object", "properties": {"expression": {
        "anyOf": [{"type": "string"}, {"type": "null"}]}}}),
])
def test_sensitive_tools_code_execution_is_detected(name, description, schema):
    assert check([tool(name, description, schema)])["mcp_server_sensitive_tools"]["verdict"] == "fail"


def test_sensitive_tools_environment_dump_remains_detected():
    assert check([tool("dump", "Prints the environment")])["mcp_server_sensitive_tools"]["verdict"] == "fail"

@pytest.mark.parametrize("matches", [False, True])
def test_version_check_requires_matching_product_name(monkeypatch, matches):
    monkeypatch.setattr(assertions, "KNOWN_VULNERABLE_MCP_SERVERS", {
        "fixture-product": ((2, 0, 0), "fixture-advisory"),
    })
    info = ServerInfo("fixture-product" if matches else "fixture-framework", "1.0.0")
    result = check([], info)["mcp_server_known_vulnerable_version"]
    assert result["verdict"] == ("fail" if matches else "skipped")
    if not matches:
        assert "server reported a different name" in result["reasoning"]
    else:
        assert "below 2.0.0" in result["reasoning"]


@pytest.mark.parametrize("name,description", [
    ("get_environment_variable", "Look up a setting."),
    ("lookup", "Returns an environment variable."),
])
def test_sensitive_tools_singular_environment_variable_is_detected(name, description):
    assert check([tool(name, description)])["mcp_server_sensitive_tools"]["verdict"] == "fail"


def test_sensitive_tools_terminal_state_and_test_environment_are_benign():
    listed = tool("status", "Reports the terminal state in a test environment.")
    assert check([listed])["mcp_server_sensitive_tools"]["verdict"] == "pass"
