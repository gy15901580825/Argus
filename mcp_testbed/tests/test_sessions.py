"""session 生命周期与 evidence 契约。"""
from fastapi.testclient import TestClient
from testbed.app import app

client = TestClient(app)


def test_open_session_returns_an_unguessable_id_and_an_mcp_url():
    r = client.post("/sessions", json={"scenario": "tool_poisoning"})
    assert r.status_code == 200
    body = r.json()
    assert len(body["session_id"]) >= 16
    assert body["mcp_url"].endswith(f"/s/{body['session_id']}/mcp")


def test_two_sessions_get_different_ids():
    a = client.post("/sessions", json={"scenario": "tool_poisoning"}).json()
    b = client.post("/sessions", json={"scenario": "tool_poisoning"}).json()
    assert a["session_id"] != b["session_id"]


def test_fresh_session_evidence_reports_zero_interaction():
    sid = client.post("/sessions", json={"scenario": "tool_poisoning"}).json()["session_id"]
    ev = client.get(f"/sessions/{sid}/evidence").json()
    assert ev["interaction_count"] == 0
    assert ev["tool_calls"] == []
    assert ev["tools_list_count"] == 0


def test_evidence_always_carries_interaction_count():
    """runner 用它区分"防住了"和"根本没跑"。少了它每个探针都会假绿。"""
    sid = client.post("/sessions", json={"scenario": "tool_poisoning"}).json()["session_id"]
    assert "interaction_count" in client.get(f"/sessions/{sid}/evidence").json()


def test_deleted_session_is_gone():
    sid = client.post("/sessions", json={"scenario": "tool_poisoning"}).json()["session_id"]
    assert client.delete(f"/sessions/{sid}").status_code in (200, 204)
    assert client.get(f"/sessions/{sid}/evidence").status_code == 404
