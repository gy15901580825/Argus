"""JSON-RPC 2.0 表面。"""
from fastapi.testclient import TestClient
from testbed.app import app

client = TestClient(app)


def _open(scenario="tool_poisoning"):
    return client.post("/sessions", json={"scenario": scenario}).json()["session_id"]


def _rpc(sid, method, params=None, rid=1):
    return client.post(f"/s/{sid}/mcp", json={
        "jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}}).json()


def test_initialize_answers_with_protocol_and_capabilities():
    sid = _open()
    out = _rpc(sid, "initialize")
    assert out["jsonrpc"] == "2.0"
    assert "result" in out
    assert "capabilities" in out["result"]


def test_tools_list_returns_tools_and_is_counted():
    sid = _open()
    out = _rpc(sid, "tools/list")
    assert [t["name"] for t in out["result"]["tools"]]
    ev = client.get(f"/sessions/{sid}/evidence").json()
    assert ev["tools_list_count"] == 1
    assert ev["descriptions_served"][0]["seq"] >= 1


def test_tools_call_is_recorded_with_its_arguments():
    sid = _open()
    name = _rpc(sid, "tools/list")["result"]["tools"][0]["name"]
    _rpc(sid, "tools/call", {"name": name, "arguments": {"q": "hello"}})
    ev = client.get(f"/sessions/{sid}/evidence").json()
    assert ev["tool_calls"][0]["tool"] == name
    assert ev["tool_calls"][0]["arguments"] == {"q": "hello"}


def test_unknown_method_returns_a_jsonrpc_error_not_a_500():
    sid = _open()
    out = _rpc(sid, "nonsense/method")
    assert "error" in out and out["error"]["code"] == -32601


def test_every_rpc_bumps_interaction_count():
    sid = _open()
    _rpc(sid, "initialize"); _rpc(sid, "tools/list")
    assert client.get(f"/sessions/{sid}/evidence").json()["interaction_count"] == 2
