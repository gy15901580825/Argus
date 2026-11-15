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
