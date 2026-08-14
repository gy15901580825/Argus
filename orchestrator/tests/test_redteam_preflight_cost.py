"""The pre-run cost gate must estimate the run that will actually happen.

`check_or_abort_pre_run` used to be called with `iterative_rounds=1` and one
"exchange" per probe, regardless of mode. A deep run turns each probe into
`deep_pairs` threads of up to 20 rounds, and a static probe sends every prompt
it declares — so the estimate was low by 1–2 orders of magnitude and the gate
waved through runs it exists to reject.
"""

from pathlib import Path

from fastapi.testclient import TestClient

from orchestrator.redteam.api import PROBES_DIR
from orchestrator.redteam.cost_meter import CostMeter
from orchestrator.redteam.persona_strategy import DEFAULT_MAX_ROUNDS
from orchestrator.redteam.probe import load_all_probes
from server import app


TARGET = {
    "kind": "openai_compat",
    "endpoint_url": "https://api.example.com/v1/chat/completions",
    "model": "gpt-4",
    "api_key": "sk-test",
}


def _capture(monkeypatch) -> dict:
    captured = {}

    def fake_pre_run(self, probe_ids, target_kind, **kwargs):
        captured["probe_ids"] = probe_ids
        captured.update(kwargs)
        return 0.0

    monkeypatch.setattr(CostMeter, "check_or_abort_pre_run", fake_pre_run)
    return captured


def _multi_prompt_probe_ids(n: int = 3) -> list[str]:
    probes = [p for p in load_all_probes(PROBES_DIR) if len(p.prompts) > 1]
    assert len(probes) >= n, "expected several multi-prompt probes in the library"
    return [p.id for p in probes[:n]]


def _prompt_total(probe_ids: list[str]) -> int:
    by_id = {p.id: p for p in load_all_probes(PROBES_DIR)}
    return sum(len(by_id[pid].prompts) for pid in probe_ids)


def test_static_preflight_counts_every_prompt(monkeypatch):
    captured = _capture(monkeypatch)
    probe_ids = _multi_prompt_probe_ids()
    expected = _prompt_total(probe_ids)
    assert expected > len(probe_ids), "fixture must contain multi-prompt probes"

    resp = TestClient(app).post(
        "/redteam/run/preflight", json={"target": TARGET, "probe_ids": probe_ids}
    )
    assert resp.status_code == 200
    assert captured["total_exchanges"] == expected


def test_deep_preflight_counts_pairs_times_rounds(monkeypatch):
    captured = _capture(monkeypatch)
    probe_ids = _multi_prompt_probe_ids(2)

    resp = TestClient(app).post(
        "/redteam/run/preflight",
        json={"target": TARGET, "probe_ids": probe_ids, "mode": "deep", "deep_pairs": 3},
    )
    assert resp.status_code == 200
    assert captured["total_exchanges"] == len(probe_ids) * 3 * DEFAULT_MAX_ROUNDS
    assert captured["deep"] is True


def test_streaming_run_uses_the_same_estimate_as_preflight(monkeypatch):
    """Pitfall #1: an estimate applied on only one of the two paths is no gate."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    captured = _capture(monkeypatch)
    probe_ids = _multi_prompt_probe_ids(2)

    TestClient(app).post(
        "/redteam/run",
        json={"target": TARGET, "probe_ids": probe_ids, "mode": "deep", "deep_pairs": 3},
    )
    assert captured["total_exchanges"] == len(probe_ids) * 3 * DEFAULT_MAX_ROUNDS
    assert captured["deep"] is True


def test_deep_run_over_the_caller_cap_is_rejected_where_static_passes():
    """The bug, end to end: the same 5 probes cost ~20x more in deep mode, but
    both preflighted as identical (and passing) before the fix."""
    client = TestClient(app)
    probe_ids = [p.id for p in load_all_probes(PROBES_DIR)][:5]
    static_body = {"target": TARGET, "probe_ids": probe_ids, "per_run_cap_usd": 0.50}
    deep_body = {**static_body, "mode": "deep", "deep_pairs": 3}

    assert client.post("/redteam/run/preflight", json=static_body).status_code == 200
    resp = client.post("/redteam/run/preflight", json=deep_body)
    assert resp.status_code == 402, resp.text
    assert "per_run_cap" in resp.json()["detail"]
