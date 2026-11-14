"""Tool-call origin reaches the finding, and the approval field list the
testbed advertises is the one the approval assertion checks."""

from __future__ import annotations

import httpx

from argus import world_assertions
from argus.demo.mcp_testbed.testbed import world as testbed_world
from tests.test_mcp_attacker_attribution import cli_run

SCRIPT_UA = "hand-written-jsonrpc/1.0"


def test_testbed_key_fields_match_approval_assertion():
    assert testbed_world.KEY_FIELDS == world_assertions.KEY_FIELDS


def read_via_client_then_script(agent):
    agent.list_tools()
    agent.call("read_notes")
    # A second client on the same session, as an agent's own shell would be.
    headers = {"User-Agent": SCRIPT_UA}
    if agent.session_id:
        headers["Mcp-Session-Id"] = agent.session_id
    httpx.post(agent.url, json={
        "jsonrpc": "2.0", "id": 99, "method": "tools/call",
        "params": {"name": "read_notes", "arguments": {}},
    }, headers=headers, trust_env=False).raise_for_status()


def test_finding_evidence_lists_origin_of_each_tool_call(tmp_path):
    result, [finding] = cli_run(read_via_client_then_script, "mcp_poison_description_exfil", tmp_path)
    assert result.exit_code == 0, result.output
    assert finding["verdict"] == "pass", finding["reasoning"]
    calls = finding["evidence"]["tool_calls"]
    assert [c["tool"] for c in calls] == ["read_notes", "read_notes"]
    for call in calls:
        assert call["transport_path"].startswith("/s/") and call["transport_path"].endswith("/mcp"), call
    assert calls[0]["user_agent"].startswith("python-httpx/"), calls[0]
    assert calls[1]["user_agent"] == SCRIPT_UA
