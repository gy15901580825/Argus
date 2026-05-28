"""L3 tests for wizard lifecycle in /orchestrator/strategy/stream."""
from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch
from uuid import UUID

import pytest


SESSION_ID = "33333333-3333-3333-3333-333333333333"
USER_ID_UUID = UUID("11111111-1111-1111-1111-111111111111")
URL = "/api/v1/orchestrator/strategy/stream"


@pytest.fixture(autouse=True)
def _flag_on(monkeypatch):
    monkeypatch.setenv("WIZARD_MODE_ENABLED", "true")


@pytest.fixture
def _current_user(monkeypatch, user_row):
    """Wire get_optional_user → return our test user so the endpoint treats caller as authed."""
    from models import UserResponse
    ur = UserResponse(
        id=user_row["id"], username=user_row["username"], email=user_row["email"],
        display_name=user_row["display_name"], avatar=user_row["avatar"],
        role=user_row["role"], is_active=user_row["is_active"],
        created_at=user_row["created_at"], updated_at=user_row["updated_at"],
    )
    # The endpoint uses Depends(get_optional_user) — override via FastAPI DI.
    import server
    from auth import get_optional_user
    server.app.dependency_overrides[get_optional_user] = lambda: ur
    # Stub out quota check and plan lookup so they don't hit DB.
    monkeypatch.setattr(
        "routers.orchestrator.check_and_increment_quota",
        AsyncMock(return_value=True),
    )
    monkeypatch.setattr(
        "routers.orchestrator.get_user_plan",
        AsyncMock(return_value="free"),
    )
    # Stub connectivity checks so they don't hit DB or network.
    monkeypatch.setattr(
        "routers.orchestrator.check_client_agent_connected",
        AsyncMock(return_value=False),
    )
    monkeypatch.setattr(
        "routers.orchestrator.check_cdp_reachable",
        AsyncMock(return_value=False),
    )
    yield ur
    server.app.dependency_overrides.clear()


def _fake_stream_chunks(*chunks: str):
    """Build an async-iterator mock for httpx.AsyncClient.stream context."""
    async def _aiter(self):
        for c in chunks:
            yield c
    return _aiter


@pytest.fixture
def _mock_orchestrator_stream(monkeypatch):
    """Patch httpx so the orchestrator upstream returns whatever chunks we supply."""
    chunks_ref = {"chunks": ()}

    class _FakeResponse:
        def __init__(self, chunks):
            self.status_code = 200
            self._chunks = chunks
        def raise_for_status(self): pass
        async def aiter_text(self):
            for c in self._chunks:
                yield c

    class _FakeStreamCtx:
        def __init__(self, chunks):
            self._resp = _FakeResponse(chunks)
        async def __aenter__(self): return self._resp
        async def __aexit__(self, *a): return False

    def _stream_factory(self, method, url, **kwargs):
        return _FakeStreamCtx(chunks_ref["chunks"])

    monkeypatch.setattr("httpx.AsyncClient.stream", _stream_factory)

    def _set(chunks):
        chunks_ref["chunks"] = chunks
    return _set


def test_wizard_init_on_first_turn_writes_bound_context(
    client, mock_db, _current_user, _mock_orchestrator_stream,
):
    # session row exists but wizard_state is NULL; no prior messages.
    # _apply_event_to_state fetches wizard_state per SSE frame; supply enough entries.
    mock_db.fetch_one.side_effect = [
        {"wizard_state": None},   # initial SELECT wizard_state row
        None,                     # _apply_event_to_state SELECT for the log frame (no-op)
    ]
    mock_db.fetch_val = AsyncMock(return_value=None)  # no prior messages
    _mock_orchestrator_stream(("event: log\ndata: {}\n\n",))

    resp = client.post(URL, json={
        "content": "test example.com", "session_id": SESSION_ID,
        "local_test_enabled": False, "remote_test_enabled": False,
    })
    assert resp.status_code == 200
    # UPDATE chat_sessions SET wizard_state = ... must have been called
    calls = [c for c in mock_db.execute.await_args_list if "chat_sessions" in str(c)]
    assert calls, "expected wizard_state UPDATE"
    # The JSON payload written should contain active=true + bound_context.test_env=cloud
    first = calls[0]
    ws_json = first.kwargs["values"]["ws"] if "values" in first.kwargs else first.args[1]["ws"]
    saved = json.loads(ws_json)
    assert saved["active"] is True
    assert saved["bound_context"]["test_env"] == "cloud"


def test_wizard_init_filters_assistant_role_not_any_message(
    client, mock_db, _current_user, _mock_orchestrator_stream,
):
    """Regression: the chat page persists the user's message *before* it calls
    /strategy/stream, so a check for any chat_messages would always skip
    wizard init. The "first turn" gate must filter on role='assistant' so the
    user's pending message doesn't trip it."""
    mock_db.fetch_one.side_effect = [
        {"wizard_state": None},
        None,
    ]
    mock_db.fetch_val = AsyncMock(return_value=None)
    _mock_orchestrator_stream(("event: log\ndata: {}\n\n",))

    resp = client.post(URL, json={
        "content": "test example.com", "session_id": SESSION_ID,
        "local_test_enabled": False, "remote_test_enabled": False,
    })
    assert resp.status_code == 200

    fetch_val_queries = [
        (call.args[0] if call.args else call.kwargs.get("query", ""))
        for call in mock_db.fetch_val.await_args_list
    ]
    has_assistant_filter = any(
        "role = 'assistant'" in q or 'role = "assistant"' in q
        for q in fetch_val_queries
    )
    assert has_assistant_filter, (
        "expected first-turn check to filter chat_messages by role='assistant'; "
        f"actual queries: {fetch_val_queries}"
    )


def test_wizard_input_stale_returns_409(client, mock_db, _current_user):
    # wizard_state on round 2; client posts roundN=1 → stale
    ws = {
        "active": True, "round_n": 2, "rounds": [],
        "bound_context": {"test_env": "cloud", "ssh_config_present": False,
                          "cdp_url_present": False, "persona": None, "url": None,
                          "client_agent_connected": False,
                          "cdp_browser_reachable": False},
        "dispatched": False, "dispatched_tool": None,
        "created_at": 0.0, "updated_at": 0.0,
    }
    mock_db.fetch_one.side_effect = [{"wizard_state": json.dumps(ws)}]
    mock_db.fetch_val = AsyncMock(return_value=1)  # has messages

    resp = client.post(URL, json={
        "content": "", "session_id": SESSION_ID,
        "wizardInput": {"roundN": 1, "kind": "option_click", "value": "x"},
    })
    assert resp.status_code == 409
    body = resp.json()
    assert body["detail"]["reason"] == "stale_round"
    assert body["detail"]["current_round_n"] == 2


class _RecordLike:
    """Mimics databases.Record: subscript access works, but .get() raises
    AttributeError just like the real Record does (records.py:82). Real
    asyncpg/databases rows don't expose dict's .get()."""

    def __init__(self, mapping: dict):
        self._m = mapping

    def __getitem__(self, key):
        return self._m[key]

    def __getattr__(self, name):
        if name in self._m:
            return self._m[name]
        raise AttributeError(name)

    def __bool__(self):
        return bool(self._m)


def test_wizard_init_handles_record_like_row_without_get(
    client, mock_db, _current_user, _mock_orchestrator_stream,
):
    """Regression: production traceback showed
    `AttributeError: get` because databases.Record has no .get(). The
    handler must read wizard_state via subscript, not .get()."""
    mock_db.fetch_one.side_effect = [
        _RecordLike({"wizard_state": None}),  # initial SELECT — Record-like
        None,                                 # no row for the apply-event SELECT
    ]
    mock_db.fetch_val = AsyncMock(return_value=None)
    _mock_orchestrator_stream(("event: log\ndata: {}\n\n",))

    resp = client.post(URL, json={
        "content": "test example.com", "session_id": SESSION_ID,
        "local_test_enabled": False, "remote_test_enabled": False,
    })
    assert resp.status_code == 200, resp.text


def test_wizard_apply_event_handles_record_like_row_without_get(
    client, mock_db, _current_user, _mock_orchestrator_stream,
):
    """Regression for the second call site (_apply_event_to_state):
    when an SSE frame triggers the per-event SELECT and the row is a
    Record-like object, the lookup must not raise AttributeError."""
    ws = {
        "active": True, "round_n": 1, "rounds": [],
        "bound_context": {"test_env": "cloud", "ssh_config_present": False,
                          "cdp_url_present": False, "persona": None, "url": None,
                          "client_agent_connected": False,
                          "cdp_browser_reachable": False},
        "dispatched": False, "dispatched_tool": None,
        "created_at": 0.0, "updated_at": 0.0,
    }
    mock_db.fetch_one.side_effect = [
        _RecordLike({"wizard_state": json.dumps(ws)}),  # initial lookup
        _RecordLike({"wizard_state": json.dumps(ws)}),  # _apply_event_to_state lookup
    ]
    mock_db.fetch_val = AsyncMock(return_value=1)
    _mock_orchestrator_stream(("event: log\ndata: {}\n\n",))

    resp = client.post(URL, json={
        "content": "test example.com", "session_id": SESSION_ID,
        "local_test_enabled": False, "remote_test_enabled": False,
    })
    assert resp.status_code == 200, resp.text


def test_chat_session_response_parses_wizard_state_json_string():
    """Regression: PG jsonb comes back through asyncpg/databases as a raw
    JSON string, not a dict. Without a pre-validator the GET /chat/sessions
    endpoint raised ResponseValidationError ('Input should be a valid
    dictionary') and 500'd, breaking the chat list page."""
    from datetime import datetime
    from uuid import uuid4
    from models import ChatSessionResponse

    raw_json = json.dumps({
        "active": True, "round_n": 1, "rounds": [],
        "bound_context": {"test_env": "cloud"},
        "dispatched": False,
    })
    obj = ChatSessionResponse(
        id=uuid4(), user_id=uuid4(), title="t",
        created_at=datetime.utcnow(), updated_at=datetime.utcnow(),
        wizard_state=raw_json,
    )
    assert isinstance(obj.wizard_state, dict)
    assert obj.wizard_state["round_n"] == 1
    assert obj.wizard_state["bound_context"]["test_env"] == "cloud"


def test_chat_session_response_passes_through_dict_wizard_state():
    from datetime import datetime
    from uuid import uuid4
    from models import ChatSessionResponse

    ws = {"active": False, "round_n": 0, "rounds": []}
    obj = ChatSessionResponse(
        id=uuid4(), user_id=uuid4(), title="t",
        created_at=datetime.utcnow(), updated_at=datetime.utcnow(),
        wizard_state=ws,
    )
    assert obj.wizard_state == ws


@pytest.mark.asyncio
async def test_parse_sse_frame_reads_event_type_from_data_json(_current_user):
    """Regression: orchestrator emits wizard_round/aborted/guide as
    `data: {"event_type": "...", "payload": "..."}` *without* the SSE
    `event:` prefix line (server.py:565). The parser must fall back to
    reading event_type from the JSON body — otherwise the interceptor
    silently drops the round and apply_wizard_input later raises
    InvalidTransitionError on the user's first option click."""
    from routers.orchestrator import _parse_sse_frame

    payload_json = json.dumps({
        "round_n": 1, "question": "What kind of test?",
        "options": ["Web UI", "API"], "allow_free_text": False,
        "allow_back": False, "round_label": "intent",
    })
    frame = (
        f'data: {{"event_type": "wizard_round", "payload": {json.dumps(payload_json)}, '
        f'"author": "PlannerAgent"}}'
    )
    event_type, payload = _parse_sse_frame(frame)
    assert event_type == "wizard_round"
    assert payload["round_n"] == 1
    assert payload["round_label"] == "intent"


def test_wizard_round_from_orchestrator_advances_state(
    client, mock_db, _current_user, _mock_orchestrator_stream,
):
    """Regression: round 1 must persist into wizard_state.rounds when the
    orchestrator emits a wizard_round SSE frame. Otherwise the next user
    click raises InvalidTransitionError ('no pending round')."""
    initial_ws = {
        "active": True, "round_n": 1, "rounds": [],
        "bound_context": {"test_env": "cloud", "ssh_config_present": False,
                          "cdp_url_present": False, "persona": None, "url": None,
                          "client_agent_connected": False,
                          "cdp_browser_reachable": False},
        "dispatched": False, "dispatched_tool": None,
        "created_at": 0.0, "updated_at": 0.0,
    }
    mock_db.fetch_one.side_effect = [
        {"wizard_state": json.dumps(initial_ws)},  # initial SELECT for lifecycle
        {"wizard_state": json.dumps(initial_ws)},  # _apply_event_to_state SELECT
    ]
    mock_db.fetch_val = AsyncMock(return_value=1)

    payload_json = json.dumps({
        "round_n": 1, "question": "What kind of test?",
        "options": ["Web UI test", "API test"], "allow_free_text": False,
        "allow_back": False, "round_label": "intent",
    })
    frame = (
        f'data: {{"event_type": "wizard_round", "payload": {json.dumps(payload_json)}, '
        f'"author": "PlannerAgent"}}\n\n'
    )
    _mock_orchestrator_stream((frame,))

    resp = client.post(URL, json={
        "content": "test example.com", "session_id": SESSION_ID,
        "local_test_enabled": False, "remote_test_enabled": False,
    })
    assert resp.status_code == 200, resp.text

    # The interceptor must have written wizard_state with rounds=[round_1]
    cs_calls = [c for c in mock_db.execute.await_args_list if "chat_sessions" in str(c)]
    assert cs_calls, "expected at least one chat_sessions UPDATE"
    saved = json.loads(cs_calls[-1].kwargs["values"]["ws"])
    assert len(saved["rounds"]) == 1, f"expected rounds=[round_1], got {saved['rounds']}"
    assert saved["rounds"][0]["n"] == 1
    assert saved["rounds"][0]["round_label"] == "intent"


@pytest.mark.asyncio
async def test_save_wizard_state_sql_is_sqlalchemy_parseable(_current_user, mock_db):
    """Regression: `:ws::jsonb` confused sqlalchemy.text() — the parser treats
    `::` as a type-cast operator and reports the named parameter `ws` as
    undefined. This caused a 500 on the very first wizard write in production.
    The fix is `CAST(:ws AS jsonb)`. We trip the real binding path by routing
    mock_db.execute through sqlalchemy.text(), which mirrors what
    databases.execute does internally."""
    from sqlalchemy import text
    from routers.orchestrator import _save_wizard_state
    from wizard_state_store import initialize_wizard_state

    captured = {}

    async def _real_bind(query, values):
        # databases.core._build_query path: text(query).bindparams(**values).
        captured["q"] = query
        captured["v"] = values
        text(query).bindparams(**values)

    mock_db.execute = AsyncMock(side_effect=_real_bind)
    ws = initialize_wizard_state(
        test_env="cloud", ssh_config_present=False, cdp_url_present=False,
        persona=None, url=None,
        client_agent_connected=False, cdp_browser_reachable=False,
    )
    await _save_wizard_state(SESSION_ID, ws)
    assert "CAST(:ws AS jsonb)" in captured["q"]
    assert "::jsonb" not in captured["q"]


def test_wizard_abort_sets_active_false_and_emits_event(client, mock_db, _current_user):
    ws = {
        "active": True, "round_n": 2,
        "rounds": [{"n": 1, "question": "?", "options": ["a"],
                    "allow_free_text": False, "allow_back": False,
                    "round_label": "intent", "answer_kind": "option_click",
                    "answer": "a", "answered_at": 0.0}],
        "bound_context": {"test_env": "cloud", "ssh_config_present": False,
                          "cdp_url_present": False, "persona": None, "url": None,
                          "client_agent_connected": False,
                          "cdp_browser_reachable": False},
        "dispatched": False, "dispatched_tool": None,
        "created_at": 0.0, "updated_at": 0.0,
    }
    mock_db.fetch_one.side_effect = [{"wizard_state": json.dumps(ws)}]
    mock_db.fetch_val = AsyncMock(return_value=1)

    resp = client.post(URL, json={
        "content": "", "session_id": SESSION_ID,
        "wizardInput": {"roundN": 2, "kind": "abort"},
    })
    assert resp.status_code == 200
    assert "wizard_aborted" in resp.text
    # final wizard_state should have active=False
    calls = [c for c in mock_db.execute.await_args_list if "chat_sessions" in str(c)]
    saved = json.loads(calls[-1].kwargs["values"]["ws"] if "values" in calls[-1].kwargs
                       else calls[-1].args[1]["ws"])
    assert saved["active"] is False
