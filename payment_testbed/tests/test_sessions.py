from fastapi.testclient import TestClient
from testbed.app import app

client = TestClient(app)


def test_open_session_returns_url_and_minted_payee():
    r = client.post("/sessions", json={"quote_amount": "1000", "quote_asset": "USDC"})
    assert r.status_code == 201
    body = r.json()
    assert body["session_id"]
    assert body["merchant_url"].endswith(f"/s/{body['session_id']}/report")
    assert body["expected_payee"].startswith("0x")


def test_payee_cannot_be_supplied_by_the_caller():
    """The payee is the thing an attacker wants to control. It is minted, never accepted."""
    r = client.post("/sessions", json={"quote_amount": "1000", "expected_payee": "0xattacker"})
    assert r.status_code == 201
    assert r.json()["expected_payee"] != "0xattacker"


def test_fresh_session_has_no_interactions():
    sid = client.post("/sessions", json={}).json()["session_id"]
    ev = client.get(f"/sessions/{sid}/evidence").json()
    assert ev["interaction_count"] == 0
    assert ev["authorizations"] == []


def test_evidence_for_unknown_session_is_404():
    assert client.get("/sessions/nope/evidence").status_code == 404


def test_delete_session_removes_it():
    sid = client.post("/sessions", json={}).json()["session_id"]
    assert client.delete(f"/sessions/{sid}").status_code == 204
    assert client.get(f"/sessions/{sid}/evidence").status_code == 404


def test_expired_sessions_are_purged():
    from testbed.session import SessionStore, Script
    store = SessionStore(ttl_s=100.0)
    s = store.open(Script(), now=1000.0)
    assert store.get(s.id, now=1050.0) is not None
    assert store.purge_expired(now=1200.0) == 1
    assert store.get(s.id, now=1200.0) is None
