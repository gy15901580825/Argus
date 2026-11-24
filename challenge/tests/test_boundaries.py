import asyncio
from dataclasses import replace

import httpx
import pytest

from agent import run_turn
from levels import Guard, LEVELS
from limits import BudgetedModelClient, BudgetExhausted, IpLimiter, Settings
from model import ModelError, ModelReply, ProxyModelClient, ScriptedModelClient, ToolCall
from store import Store
from test_challenge import client_at, refund


def test_ip_window_expires_and_forwarded_ip_cannot_bypass(tmp_path):
    limiter = IpLimiter(1)
    assert limiter.admit("peer", now=0) is True
    assert limiter.admit("peer", now=599) is False
    assert limiter.admit("peer", now=600) is True
    client, model, app = client_at(tmp_path, ip_submissions=1)
    assert client.post("/api/levels/1/submit", json={"input": "Help"}).status_code == 200
    response = client.post("/api/levels/1/submit", json={"input": "Help"}, headers={"X-Forwarded-For": "192.0.2.8"})
    assert response.status_code == 429
    assert len(model.calls) == 1


def test_sessions_are_isolated_and_expire(tmp_path, monkeypatch):
    now = [100.0]
    monkeypatch.setattr("app.time.monotonic", lambda: now[0])
    client, model, app = client_at(tmp_path, [refund(), ModelReply(content="Help")])
    assert client.post("/api/levels/1/submit", json={"input": "Help"}).json()["won"] is True
    original_cookie = client.cookies.get("challenge_session")
    client.cookies.clear()
    assert client.post("/api/levels/1/share", json={"consent": True}).status_code == 409
    assert len(app.state.sessions) == 2
    now[0] += 1801
    client.cookies.clear()
    client.cookies.set("challenge_session", original_cookie, domain="testserver.local")
    assert client.post("/api/levels/1/share", json={"consent": True}).status_code == 409
    assert len(app.state.sessions) == 1
    assert client.cookies.get("challenge_session") != original_cookie


def test_budget_rolls_over_by_utc_day(tmp_path, monkeypatch):
    store = Store(str(tmp_path / "ledger.sqlite3"))
    monkeypatch.setattr(store, "today", lambda: "2026-11-24")
    assert store.reserve(0.5, 0.5) == "2026-11-24"
    assert store.spent() == 0.5
    assert store.reserve(0.1, 0.5) is None
    monkeypatch.setattr(store, "today", lambda: "2026-11-25")
    assert store.spent() == 0
    assert store.reserve(0.1, 0.5) == "2026-11-25"
    assert store.spent() == 0.1


async def test_failed_model_keeps_persistent_reservation(tmp_path):
    store = Store(str(tmp_path / "ledger.sqlite3"))

    class FailingModel:
        async def complete(self, messages, tools):
            raise ModelError("Unavailable")

    meter = BudgetedModelClient(FailingModel(), store, Settings())
    with pytest.raises(ModelError):
        await meter.complete([{"role": "user", "content": "Help"}], [])
    reserved = store.spent()
    assert reserved > 0
    assert Store(store.path).spent() == reserved


async def test_parallel_completions_reserve_before_await(tmp_path):
    store = Store(str(tmp_path / "ledger.sqlite3"))
    gate = asyncio.Event()
    entered = asyncio.Event()

    class WaitingModel:
        async def complete(self, messages, tools):
            entered.set()
            await gate.wait()
            return ModelReply(content="Help")

    meter = BudgetedModelClient(WaitingModel(), store, Settings(daily_budget=0.0002))
    first = asyncio.create_task(meter.complete([], []))
    await asyncio.wait_for(entered.wait(), timeout=1)
    with pytest.raises(BudgetExhausted):
        await meter.complete([], [])
    gate.set()
    reply = await first
    assert reply.content == "Help"
    assert store.spent() == 0


async def test_tool_guard_blocks_a_call_without_mutation():
    level = replace(LEVELS[1], defenses=(Guard("tool_call", lambda world, tool, arguments: "Not permitted"),))
    world = level.seed()
    trace, text = await run_turn(level, world, "Help", ScriptedModelClient([refund()]))
    assert world.refunds == []
    assert trace[0].blocked_reason == "Not permitted"
    assert isinstance(text, str)


async def test_win_ends_turn_before_another_paid_completion():
    model = ScriptedModelClient([refund(), ModelReply(content="Unnecessary follow-up")])
    world = LEVELS[1].seed()
    trace, text = await run_turn(LEVELS[1], world, "Help", model)
    assert len(model.calls) == 1
    assert LEVELS[1].won(world) is True
    assert len(trace) == 1
    assert text


@pytest.mark.parametrize("data", [{"choices": [], "usage": {}}, {"choices": [{"message": {"content": "Help"}}]}, {"choices": [{"message": {"content": "Help"}}], "usage": {"prompt_tokens": -1, "completion_tokens": 0}}])
async def test_bad_proxy_response_fails_closed(data):
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(200, json=data))) as http:
        with pytest.raises(ModelError):
            await ProxyModelClient("http://proxy.example", client=http).complete([], [])


def test_trace_and_validation_errors_do_not_embed_player_html(tmp_path):
    attack = "<script>alert(1)</script>"
    client, model, app = client_at(tmp_path, [ModelReply(tool_calls=[ToolCall(attack, {"value": attack})])])
    response = client.post("/api/levels/1/submit", json={"input": attack})
    assert response.status_code == 200
    assert attack not in response.text
    assert response.json()["trace"][0]["arguments"]["value"] == "&lt;script&gt;alert(1)&lt;/script&gt;"
    assert response.headers["content-security-policy"].startswith("default-src 'self'")
    invalid = client.post("/api/levels/1/submit", json={"input": attack * 200})
    assert invalid.status_code == 422
    assert attack not in invalid.text
    huge = client.post("/api/levels/1/submit", json={"input": "x" * 13000})
    assert huge.status_code == 413


def test_configuration_has_spec_defaults(monkeypatch):
    settings = Settings()
    assert settings.daily_budget == 20
    assert settings.input_cost_per_million == 0.10
    assert settings.output_cost_per_million == 0.50
    monkeypatch.setenv("CHALLENGE_DAILY_BUDGET", "2.5")
    monkeypatch.setenv("CHALLENGE_ENV", "production")
    monkeypatch.setenv("CHALLENGE_ASSESSMENT_URL", "https://assessment.example/review?campaign=demo")
    settings = Settings.from_env()
    assert settings.daily_budget == 2.5
    assert settings.environment == "production"
    assert settings.assessment_url.endswith("campaign=demo")


def test_session_cookie_lifetime_is_refreshed_on_activity(tmp_path):
    client, model, app = client_at(tmp_path)
    first = client.get("/api/levels/1/hint")
    cookie = client.cookies.get("challenge_session")
    assert "Max-Age=1800" in first.headers["set-cookie"]
    second = client.get("/api/levels/1/hint")
    assert second.status_code == 200
    assert "Max-Age=1800" in second.headers.get("set-cookie", "")
    assert client.cookies.get("challenge_session") == cookie


@pytest.mark.parametrize("consent", [1, "true", None])
def test_share_requires_boolean_true(tmp_path, consent):
    client, model, app = client_at(tmp_path, [refund()])
    assert client.post("/api/levels/1/submit", json={"input": "Help"}).json()["won"] is True
    assert client.post("/api/levels/1/share", json={"consent": consent}).status_code == 422
    assert app.state.store.wins() == []
