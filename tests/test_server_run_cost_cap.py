import asyncio
import json
from collections import Counter

import httpx
import pytest
from fastapi import FastAPI

from argus import api, cost_meter, llm
from argus.cost_meter import CostMeter
from argus.probe import Probe, ProbeMappings


@pytest.fixture
def server_run(monkeypatch, tmp_path):
    probes = [
        Probe(
            id=f"probe_{i}", name=f"Probe {i}", target_class=(),
            attack_class=("prompt-injection",), severity="info", prompts=(f"attack_{i}",),
            mappings=ProbeMappings(), judge_model="test-model", judge_rubric_path="test.md",
        )
        for i in range(1, 4)
    ]
    (tmp_path / "test.md").write_text("Assess the target response.")
    monkeypatch.setattr(api, "RUBRICS_DIR", tmp_path)
    monkeypatch.setattr(api, "load_probe_library", lambda _: probes)
    config = llm.LLMConfig(
        provider="test", fast_model="test-model", strong_model="test-model",
        fallback_enabled=False, anthropic_api_key=None,
    )
    monkeypatch.setattr(llm, "resolve_config", lambda *args, **kwargs: config)
    monkeypatch.setattr(llm, "credential_error", lambda _: None)
    monkeypatch.setattr("argus.decider.from_env", lambda: None)
    monkeypatch.setitem(cost_meter._PRICES_PER_M_TOKENS, "test-model", {"input": 1.0, "output": 0.0})
    monkeypatch.setattr(api, "build_deep_probes", lambda base, *args, **kwargs: [base])
    started = []
    closed = []
    first_calls = set()
    both_started = asyncio.Event()

    class Target:
        compatible_classes = frozenset()
        supports_history = False

        def __init__(self, label, overlap):
            self.label = label
            self.overlap = overlap

        async def send_prompt(self, prompt, **kwargs):
            started.append((self.label, prompt))
            if self.overlap and self.label not in first_calls:
                first_calls.add(self.label)
                if len(first_calls) == 2:
                    both_started.set()
                await both_started.wait()
            return "The target answered.", 0.0

        async def aclose(self):
            closed.append(self.label)

    monkeypatch.setattr(api, "build_target", lambda spec: Target(spec["label"], spec.get("overlap", False)))

    async def complete(*args, **kwargs):
        return llm.Completion(
            text=json.dumps({"verdict": "pass", "severity": "info", "confidence": 1.0, "reasoning": "No violation."}),
            input_tokens=30_000, output_tokens=0, model="test-model",
        )

    monkeypatch.setattr(llm, "complete", complete)
    app = FastAPI()
    app.include_router(api.router)

    async def run(meter, *, label="run", mode="static", cap=None, overlap=False):
        monkeypatch.setattr(api, "_COST_METER", meter)
        body = {
            "target": {"kind": "test", "label": label, "overlap": overlap},
            "probe_ids": [p.id for p in probes], "mode": mode, "deep_pairs": 1,
        }
        if cap is not None:
            body["per_run_cap_usd"] = cap
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://127.0.0.1") as client:
            response = await client.post("/redteam/run", json=body)
        assert response.status_code == 200, response.text
        events = [json.loads(line[6:]) for line in response.text.splitlines() if line.startswith("data: ")]
        return response.text, events

    return run, started, closed


def findings(events):
    return [(event["probe_id"], event["verdict"]) for event in events if "verdict" in event]


@pytest.mark.parametrize("override", [False, True])
async def test_server_stops_judged_calls_at_the_per_run_cap(server_run, override):
    run, started, closed = server_run
    meter = CostMeter(daily_cap_usd=100, per_run_cap_usd=0.20 if override else 0.05)
    text, events = await run(meter, cap=0.05 if override else None)
    assert findings(events) == [
        ("probe_1", "pass"), ("probe_2", "aborted_cost"), ("probe_3", "aborted_cost"),
    ]
    assert started == [("run", "attack_1"), ("run", "attack_2")]
    assert meter.spent_today() == pytest.approx(0.06)
    assert meter.spent_today_deep() == 0
    assert "event: error" in text
    assert events[-1]["type"] == "CostExceededError"
    assert "per_run cap $0.05" in events[-1]["detail"]
    assert "not started" in events[2]["reasoning"]
    assert closed == ["run"]


@pytest.mark.parametrize("partition", [False, True])
async def test_server_deep_spend_obeys_deep_caps_and_partition(server_run, partition):
    run, started, closed = server_run
    meter = CostMeter(
        daily_cap_usd=0.10 if partition else 100, per_run_cap_usd=0.01,
        deep_per_run_cap_usd=10 if partition else 0.08, alert_threshold=2,
    )
    text, events = await run(meter, mode="deep")
    assert findings(events) == [
        ("probe_1", "pass"), ("probe_2", "pass"), ("probe_3", "aborted_cost"),
    ]
    assert meter.spent_today() == pytest.approx(0.09)
    assert meter.spent_today_deep() == pytest.approx(0.09)
    assert "event: error" in text
    assert events[-1]["type"] == "CostExceededError"
    assert ("deep daily budget" if partition else "deep per_run cap $0.08") in events[-1]["detail"]
    assert len(started) == 3
    assert closed == ["run"]


async def test_concurrent_server_runs_have_independent_caps_and_shared_daily_spend(server_run):
    run, started, closed = server_run
    meter = CostMeter(daily_cap_usd=100, per_run_cap_usd=0.20)
    (text_a, events_a), (text_b, events_b) = await asyncio.wait_for(asyncio.gather(
        run(meter, label="a", cap=0.05, overlap=True),
        run(meter, label="b", cap=0.20, overlap=True),
    ), timeout=5)
    assert findings(events_a) == [
        ("probe_1", "pass"), ("probe_2", "aborted_cost"), ("probe_3", "aborted_cost"),
    ]
    assert findings(events_b) == [("probe_1", "pass"), ("probe_2", "pass"), ("probe_3", "pass")]
    assert events_a[-1]["type"] == "CostExceededError"
    assert "event: end" in text_b
    assert "event: error" not in text_b
    assert "non-reentrant" not in text_a + text_b
    assert Counter(label for label, _ in started) == {"a": 2, "b": 3}
    assert meter.spent_today() == pytest.approx(0.15)
    assert meter.spent_today_deep() == 0
    assert sorted(closed) == ["a", "b"]


async def test_closing_the_server_stream_releases_target_and_scope(server_run, monkeypatch):
    _, started, closed = server_run
    meter = CostMeter(daily_cap_usd=100, per_run_cap_usd=0.20)
    monkeypatch.setattr(api, "_COST_METER", meter)
    response = await api.run(api.RunRequest(
        target={"kind": "test", "label": "cancel"}, probe_ids=["probe_1", "probe_2", "probe_3"],
    ))
    stream = response.body_iterator
    first = await stream.__anext__()
    assert b'"verdict": "pass"' in first
    with meter.run_scope("unrelated"):
        assert meter.spent_in_current_run() == 0
    await stream.aclose()
    assert started == [("cancel", "attack_1")]
    assert closed == ["cancel"]
    assert meter.spent_today() == pytest.approx(0.03)


async def test_child_task_and_thread_charge_the_parent_scope(monkeypatch):
    monkeypatch.setitem(cost_meter._PRICES_PER_M_TOKENS, "test-model", {"input": 1.0, "output": 0.0})
    meter = CostMeter(daily_cap_usd=100, per_run_cap_usd=0.20)

    async def charge():
        meter.record("test-model", 30_000, 0)

    with meter.run_scope("parent"):
        await asyncio.create_task(charge())
        await asyncio.to_thread(meter.record, "test-model", 30_000, 0)
        assert meter.spent_in_current_run() == pytest.approx(0.06)
    assert meter.spent_in_current_run() == 0
    assert meter.spent_today() == pytest.approx(0.06)


async def test_independent_tasks_can_overlap_meter_scopes(monkeypatch):
    monkeypatch.setitem(cost_meter._PRICES_PER_M_TOKENS, "test-model", {"input": 1.0, "output": 0.0})
    meter = CostMeter(daily_cap_usd=100, per_run_cap_usd=0.20)
    active = set()
    both_active = asyncio.Event()

    async def charge(label, tokens):
        with meter.run_scope(label):
            active.add(label)
            if len(active) == 2:
                both_active.set()
            await both_active.wait()
            meter.record("test-model", tokens, 0)
            return meter.spent_in_current_run()

    a, b = await asyncio.wait_for(asyncio.gather(charge("a", 30_000), charge("b", 60_000)), timeout=5)
    assert a == pytest.approx(0.03)
    assert b == pytest.approx(0.06)
    assert meter.spent_today() == pytest.approx(0.09)
    assert meter.spent_in_current_run() == 0
