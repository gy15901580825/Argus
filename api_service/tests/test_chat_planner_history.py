"""L3 tests for routers/chat.py — GET /chat/sessions/{id}/planner-history.

Service-to-service endpoint — no user JWT; auth is via
`x-service-secret` + `x-user-id` headers. Content is capped at 500 chars.
"""
from __future__ import annotations

from uuid import UUID


SESSION_ID = "33333333-3333-3333-3333-333333333333"
USER_ID = "11111111-1111-1111-1111-111111111111"
URL = f"/api/v1/chat/sessions/{SESSION_ID}/planner-history"


def test_planner_history_requires_service_secret(client):
    resp = client.get(URL, headers={"x-user-id": USER_ID})
    assert resp.status_code == 401
    assert "service secret" in resp.json()["detail"].lower()


def test_planner_history_rejects_wrong_secret(client):
    resp = client.get(
        URL,
        headers={"x-user-id": USER_ID, "x-service-secret": "wrong"},
    )
    assert resp.status_code == 401


def test_planner_history_requires_user_id(client):
    resp = client.get(URL, headers={"x-service-secret": "test-secret"})
    assert resp.status_code == 400
    assert "x-user-id" in resp.json()["detail"].lower()


def test_planner_history_session_not_found(client, mock_db):
    mock_db.fetch_one.return_value = None

    resp = client.get(
        URL,
        headers={"x-user-id": USER_ID, "x-service-secret": "test-secret"},
    )
    assert resp.status_code == 404


def test_planner_history_returns_filtered_pairs(client, mock_db):
    mock_db.fetch_one.return_value = {"id": UUID(SESSION_ID)}
    long_content = "x" * 800
    mock_db.fetch_all.return_value = [
        {"role": "user", "content": "hi"},
        {"role": "assistant", "content": long_content},
        {"role": "user", "content": "again"},
        {"role": "assistant", "content": "short reply"},
    ]

    resp = client.get(
        URL,
        headers={"x-user-id": USER_ID, "x-service-secret": "test-secret"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "messages" in body
    messages = body["messages"]
    assert len(messages) == 4
    assert messages[0] == {"role": "user", "content": "hi"}
    # Long assistant message truncated to 500 chars
    assert messages[1]["role"] == "assistant"
    assert len(messages[1]["content"]) == 500
    assert messages[3] == {"role": "assistant", "content": "short reply"}


def test_planner_history_limit_passed_to_query(client, mock_db):
    mock_db.fetch_one.return_value = {"id": UUID(SESSION_ID)}
    mock_db.fetch_all.return_value = []

    resp = client.get(
        URL,
        params={"limit": 3},
        headers={"x-user-id": USER_ID, "x-service-secret": "test-secret"},
    )
    assert resp.status_code == 200
    # limit * 2 = 6 rows requested
    call_kwargs = mock_db.fetch_all.call_args.kwargs
    assert call_kwargs["values"]["lim"] == 6


def test_planner_history_handles_none_content(client, mock_db):
    """DB may return None for content — endpoint must coerce to empty string."""
    mock_db.fetch_one.return_value = {"id": UUID(SESSION_ID)}
    mock_db.fetch_all.return_value = [
        {"role": "user", "content": None},
        {"role": "assistant", "content": "reply"},
    ]

    resp = client.get(
        URL,
        headers={"x-user-id": USER_ID, "x-service-secret": "test-secret"},
    )
    assert resp.status_code == 200
    messages = resp.json()["messages"]
    assert messages[0]["content"] == ""
