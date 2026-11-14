"""The testbed should not hand an agent artefacts the attack does not need:
empty notes, an opaque approval schema, or tool calls with no origin."""
import pytest
from fastapi.testclient import TestClient

from testbed import app as mod
from testbed import fixed
from testbed.scenarios import SCENARIOS
from testbed.world import KEY_FIELDS, WORLD_TOOLS

client = TestClient(mod.app, headers={"Authorization": "Bearer test-control-token"})


def _open(body):
    response = client.post("/sessions", json=body)
    assert response.status_code == 200, response.text
    return response.json()["session_id"]


def _rpc(sid, method, params=None, path="mcp", headers=None):
    response = client.post(
        f"/s/{sid}/{path}",
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}},
        headers=headers or {},
    )
    assert response.status_code == 200, response.text
    return response.json()


def _text(result):
    return "".join(p.get("text", "") for p in result["result"]["content"])


@pytest.mark.parametrize("scenario", ["tool_poisoning", "shadowing"])
def test_read_notes_returns_notes(scenario):
    sid = _open({"scenario": scenario})
    tools = [t["name"] for t in _rpc(sid, "tools/list")["result"]["tools"]]
    text = _text(_rpc(sid, "tools/call", {"name": "read_notes", "arguments": {}}))
    assert text != "read_notes executed."
    assert len(text.splitlines()) >= 3
    # Notes must not steer the agent: no tool name, no address, no secret.
    for name in tools + ["sync_notes"]:
        assert name not in text
    assert "@" not in text and ".example" not in text and "sk-" not in text


def test_shadow_tool_result_is_unchanged():
    sid = _open({"scenario": "shadowing"})
    out = _rpc(sid, "tools/call", {"name": "read_notes_v2", "arguments": {}})
    assert _text(out) == "read_notes_v2 executed."


def test_other_scenarios_keep_their_read_notes_result():
    for scenario in ("rug_pull", "credential_lure"):
        sid = _open({"scenario": scenario})
        out = _rpc(sid, "tools/call", {"name": "read_notes", "arguments": {}})
        assert _text(out) == "read_notes executed.", scenario
    assert SCENARIOS["confused_deputy"].call_result_fn.__name__ == "_confused_deputy_call"


def _approval_params_schema():
    [tool] = [t for t in WORLD_TOOLS if t["name"] == "request_approval"]
    return tool["inputSchema"]["properties"]


def test_approval_schema_names_every_key_field_per_action():
    props = _approval_params_schema()
    assert sorted(props["action"]["enum"]) == sorted(KEY_FIELDS)
    params = props["params"]
    assert params["type"] == "object"
    for action, fields in KEY_FIELDS.items():
        for field in fields:
            assert field in params["properties"], (action, field)
        line = next(l for l in params["description"].splitlines() if l.startswith(f"{action}:"))
        for field in fields:
            assert field in line, (action, field, line)
    # pay_invoice's own call takes `amount`; the approval accepts either form.
    assert "amount" in params["properties"]


def test_approval_schema_does_not_add_validation():
    params = _approval_params_schema()["params"]
    assert "required" not in params
    assert "additionalProperties" not in params


def test_served_approval_schema_matches_world_tools():
    sid = _open({"scenario": "agent_world", "world": "invoice_approval"})
    tools = {t["name"]: t for t in _rpc(sid, "tools/list")["result"]["tools"]}
    assert tools["request_approval"]["inputSchema"]["properties"] == _approval_params_schema()


def test_incomplete_payment_params_still_denied():
    sid = _open({"scenario": "agent_world", "world": "invoice_approval"})
    out = _rpc(sid, "tools/call", {"name": "request_approval",
                                   "arguments": {"action": "pay_invoice", "params": {}}})
    assert '"decision": "denied"' in _text(out)


def _calls(sid):
    return client.get(f"/sessions/{sid}/evidence").json()["tool_calls"]


def test_tool_call_records_user_agent_and_path():
    sid = _open({"scenario": "tool_poisoning"})
    _rpc(sid, "tools/call", {"name": "read_notes", "arguments": {}},
         headers={"User-Agent": "hand-written-script/1.0"})
    [call] = _calls(sid)
    assert call["user_agent"] == "hand-written-script/1.0"
    assert call["transport_path"] == f"/s/{sid}/mcp"


def test_user_agent_is_truncated():
    sid = _open({"scenario": "tool_poisoning"})
    _rpc(sid, "tools/call", {"name": "read_notes", "arguments": {}},
         headers={"User-Agent": "x" * 500})
    assert _calls(sid)[0]["user_agent"] == "x" * 120


def test_missing_user_agent_is_recorded_empty():
    sid = _open({"scenario": "tool_poisoning"})
    _rpc(sid, "tools/call", {"name": "read_notes", "arguments": {}},
         headers={"User-Agent": ""})
    assert _calls(sid)[0]["user_agent"] == ""


@pytest.mark.parametrize("path", ["mcp2", "mcp2/mcp"])
def test_second_server_call_records_origin(path):
    sid = _open({"scenario": "agent_world", "world": "cross_server_mail"})
    _rpc(sid, "tools/call", {"name": "timezone_lookup", "arguments": {"city": "London"}},
         path=path, headers={"User-Agent": "second-client/2"})
    [call] = _calls(sid)
    assert call["server"] == "second"
    assert call["user_agent"] == "second-client/2"
    assert call["transport_path"] == f"/s/{sid}/{path}"


def test_fixed_endpoint_call_records_origin(monkeypatch):
    monkeypatch.setattr(mod, "FIXED", fixed.FixedEndpoint())
    sid = _open({"scenario": "tool_poisoning"})
    lid = client.post("/lease").json()["lease_id"]
    assert client.post(f"/lease/{lid}/activate", json={"session_id": sid}).status_code == 200
    init = client.post("/mcp", json={"id": 1, "method": "initialize", "params": {}})
    header = init.headers["Mcp-Session-Id"]
    client.post("/mcp", json={"id": 2, "method": "tools/call",
                              "params": {"name": "read_notes", "arguments": {}}},
                headers={"Mcp-Session-Id": header, "User-Agent": "fixed-client/3"})
    [call] = _calls(sid)
    assert call["user_agent"] == "fixed-client/3"
    assert call["transport_path"] == "/mcp"
