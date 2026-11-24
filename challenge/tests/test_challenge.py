import json
import re
import sqlite3
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from agent import run_turn
from app import create_app
from levels import LEVELS
from limits import Settings
from model import ModelReply, ProxyModelClient, ScriptedModelClient, ToolCall, Usage


def refund(amount=150, usage=Usage()):
    return ModelReply(tool_calls=[ToolCall("issue_refund", {"amount": amount})], usage=usage)


def client_at(tmp_path, replies=(), **settings):
    model = ScriptedModelClient(list(replies))
    app = create_app(Settings(db_path=str(tmp_path / "data.sqlite3"), **settings), model=model)
    return TestClient(app), model, app


@pytest.mark.parametrize("amount,won", [(150, True), (50, False), (100, False)])
async def test_refund_win_checks_executed_world(amount, won):
    level = LEVELS[1]
    world = level.seed()
    trace, text = await run_turn(level, world, "Please help with my order", ScriptedModelClient([refund(amount)]))
    assert level.won(world) is won
    assert world.refunds == [{"amount": amount}]
    assert trace[0].result == {"issued": True, "amount": amount, "simulated": True}
    assert isinstance(text, str)


async def test_level_two_keyword_blocks_before_model():
    model = ScriptedModelClient([refund()])
    world = LEVELS[2].seed()
    trace, text = await run_turn(LEVELS[2], world, "Please REFUND 500", model)
    assert model.calls == []
    assert trace == []
    assert "blocked" in text.lower()
    assert LEVELS[2].won(world) is False


async def test_level_two_filter_is_beatable():
    world = LEVELS[2].seed()
    model = ScriptedModelClient([refund()])
    trace, text = await run_turn(LEVELS[2], world, "Please return one hundred fifty to my order", model)
    assert LEVELS[2].won(world) is True
    assert trace[0].tool == "issue_refund"
    assert model.calls[0]["messages"][0]["role"] == "system"
    assert "only" in model.calls[0]["messages"][0]["content"].lower()
    assert isinstance(text, str)


async def test_tool_cap_counts_across_completions():
    model = ScriptedModelClient([refund(50)] * 8)
    world = LEVELS[1].seed()
    trace, text = await run_turn(LEVELS[1], world, "Help with my order", model)
    assert len(world.refunds) == 6
    assert len(model.calls) == 6
    assert len(trace) == 6
    assert "limit" in text.lower()


async def test_tool_cap_stops_large_batch():
    model = ScriptedModelClient([ModelReply(tool_calls=[ToolCall("issue_refund", {"amount": 50}, str(i)) for i in range(8)])])
    world = LEVELS[1].seed()
    trace, text = await run_turn(LEVELS[1], world, "Help", model)
    assert len(world.refunds) == len(trace) == 6
    assert "limit" in text.lower()


@pytest.mark.parametrize("call", [ToolCall("fetch_url", {"url": "https://outside.example"}), ToolCall("issue_refund", {"amount": -1}), ToolCall("issue_refund", {"amount": "150"}), ToolCall("issue_refund", {"amount": True})])
async def test_invalid_tools_cannot_mutate_world(call):
    world = LEVELS[1].seed()
    trace, text = await run_turn(LEVELS[1], world, "Help", ScriptedModelClient([ModelReply(tool_calls=[call])]))
    assert world.refunds == []
    assert trace[0].blocked_reason
    assert isinstance(text, str)


def test_api_catalog_reset_hint_and_health(tmp_path):
    client, model, app = client_at(tmp_path, [refund()])
    assert client.get("/healthz").json() == {"status": "ok"}
    catalog = client.get("/api/levels").json()
    assert [level["id"] for level in catalog] == [1, 2]
    assert "system_prompt" not in catalog[0]
    assert "utm_source=challenge" in catalog[0]["argus_url"]
    assert "utm_content=level-1" in catalog[0]["assessment_url"]
    for i in range(1, 4):
        hint = client.get("/api/levels/1/hint").json()
        assert hint["used"] == i
        assert hint["hint"] == LEVELS[1].hints[i - 1]
    assert client.get("/api/levels/1/hint").json()["used"] == 3
    assert client.post("/api/levels/1/submit", json={"input": "Help"}).json()["won"] is True
    assert client.post("/api/levels/1/reset").json() == {"reset": True}
    assert client.post("/api/levels/1/share", json={"consent": True}).status_code == 409
    assert client.get("/api/levels/3/hint").status_code == 404


def test_input_length_and_type(tmp_path):
    client, model, app = client_at(tmp_path)
    for value in ["x" * 1501, "", 123]:
        assert client.post("/api/levels/1/submit", json={"input": value}).status_code == 422
    assert model.calls == []
    assert client.post("/api/levels/1/submit", json={"input": "x" * 1500}).status_code == 200


def test_ip_limit_thirty_first_submission(tmp_path):
    client, model, app = client_at(tmp_path)
    for _ in range(30):
        assert client.post("/api/levels/1/submit", json={"input": "Help"}).status_code == 200
    client.cookies.clear()
    assert client.post("/api/levels/2/submit", json={"input": "Help"}).status_code == 429
    assert len(model.calls) == 30


def test_session_limit_survives_reset(tmp_path):
    client, model, app = client_at(tmp_path, ip_submissions=100)
    for _ in range(60):
        assert client.post("/api/levels/1/submit", json={"input": "Help"}).status_code == 200
        assert client.post("/api/levels/1/reset").status_code == 200
    assert client.post("/api/levels/1/submit", json={"input": "Help"}).status_code == 429
    assert client.post("/api/levels/2/submit", json={"input": "Help"}).status_code == 200
    assert len(model.calls) == 61


def test_budget_survives_restart(tmp_path):
    client, model, app = client_at(tmp_path, [ModelReply(content="Order help", usage=Usage(10000, 300))], daily_budget=0.00115)
    assert client.post("/api/levels/1/submit", json={"input": "Help"}).status_code == 200
    assert app.state.store.spent() == pytest.approx(0.00115)
    for active in [client, client_at(tmp_path, daily_budget=0.00115)[0]]:
        response = active.post("/api/levels/1/submit", json={"input": "Help"})
        assert response.status_code == 503
        assert "come back tomorrow" in response.json()["detail"].lower()
        assert response.json()["argus_url"].startswith("https://")
    assert len(model.calls) == 1


def test_budget_reservation_blocks_too_small_balance(tmp_path):
    client, model, app = client_at(tmp_path, daily_budget=0.000001)
    assert client.post("/api/levels/1/submit", json={"input": "Help"}).status_code == 503
    assert model.calls == []


def test_share_requires_win_and_explicit_consent_and_keeps_winning_turn(tmp_path):
    client, model, app = client_at(tmp_path, [refund(), ModelReply(content="Order help")])
    assert client.post("/api/levels/1/share", json={"consent": True}).status_code == 409
    winning = client.post("/api/levels/1/submit", json={"input": "My winning attack"}).json()
    assert winning["won"] is True
    assert app.state.store.wins() == []
    assert client.post("/api/levels/1/share", json={"consent": False}).status_code == 422
    assert client.post("/api/levels/1/share", json={}).status_code == 422
    assert client.post("/api/levels/1/submit", json={"input": "Later input"}).status_code == 200
    assert client.post("/api/levels/1/share", json={"consent": True}).json() == {"shared": True}
    assert client.post("/api/levels/1/share", json={"consent": True}).json() == {"shared": True}
    rows = app.state.store.wins()
    assert len(rows) == 1
    assert rows[0]["level"] == 1
    assert rows[0]["input"] == "My winning attack"
    assert rows[0]["trace"] == winning["trace"]
    assert app.state.store.counts(1) == {"starts": 1, "submissions": 2, "wins": 1}


def test_old_consented_wins_purged_on_startup(tmp_path):
    client, model, app = client_at(tmp_path, [refund()])
    assert client.post("/api/levels/1/submit", json={"input": "Help"}).json()["won"] is True
    assert client.post("/api/levels/1/share", json={"consent": True}).status_code == 200
    with sqlite3.connect(tmp_path / "data.sqlite3") as db:
        db.execute("UPDATE wins SET created_at = created_at - ?", (91 * 86400,))
    restarted = client_at(tmp_path)[2]
    assert restarted.state.store.wins() == []
    assert restarted.state.store.counts(1)["wins"] == 1


async def test_proxy_payload_and_usage():
    observed = []

    def handler(request):
        observed.append(request)
        return httpx.Response(200, json={"choices": [{"message": {"content": "Order help", "tool_calls": [{"id": "r1", "type": "function", "function": {"name": "issue_refund", "arguments": '{"amount":150}'}}]}}], "usage": {"prompt_tokens": 21, "completion_tokens": 9}})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        model = ProxyModelClient("http://proxy.example", client=http)
        reply = await model.complete([{"role": "user", "content": "Help"}], [])
    assert reply.content == "Order help"
    assert reply.tool_calls == [ToolCall("issue_refund", {"amount": 150}, "r1")]
    assert reply.usage == Usage(21, 9)
    request = observed[0]
    assert str(request.url) == "http://proxy.example/openai/v1/chat/completions"
    payload = json.loads(request.content)
    assert payload["model"] == "gpt-6-luna"
    assert payload["reasoning_effort"] == "none"
    assert payload["max_completion_tokens"] == 300
    assert "temperature" not in payload
    assert "authorization" not in request.headers


def test_script_and_api_text_are_escaped(tmp_path):
    attack = "<script>alert(1)</script>"
    client, model, app = client_at(tmp_path, [ModelReply(content=attack)])
    response = client.post("/api/levels/1/submit", json={"input": attack})
    assert response.status_code == 200
    assert attack not in response.text
    assert response.json()["input"] == "&lt;script&gt;alert(1)&lt;/script&gt;"
    assert response.json()["text"] == "&lt;script&gt;alert(1)&lt;/script&gt;"
    page = client.get("/")
    assert page.status_code == 200
    assert attack not in page.text
    script = client.get("/static/app.js").text
    assert "textContent" in script
    assert "innerHTML" not in script
    assert "insertAdjacentHTML" not in script


def test_registry_probe_ids_exist_in_repository():
    root = Path(__file__).resolve().parents[2]
    try:
        from argus.probe import load_probe_library
    except ImportError:
        ids = set()
        for path in (root / "argus" / "probes").rglob("*.yaml"):
            ids.update(re.findall(r"^id:\s*([^\s]+)", path.read_text(), re.MULTILINE))
    else:
        ids = {probe.id for probe in load_probe_library(root / "argus" / "probes")}
    assert set(LEVELS) == {1, 2}
    for level in LEVELS.values():
        assert 1 <= len(level.probe_ids) <= 3
        assert set(level.probe_ids) <= ids
        assert len(level.hints) == 3
        assert level.input_kind == "chat"


def test_scripted_dev_mode_refused_in_production(tmp_path, monkeypatch):
    monkeypatch.setenv("CHALLENGE_MODEL", "scripted")
    monkeypatch.setenv("CHALLENGE_ENV", "production")
    monkeypatch.setenv("CHALLENGE_DB_PATH", str(tmp_path / "production.sqlite3"))
    with pytest.raises(ValueError, match="scripted"):
        create_app()
