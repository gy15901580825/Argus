"""Tests for auto-derived scan suites (suites.py + GET /redteam/suites)."""

from pathlib import Path

from fastapi.testclient import TestClient

from orchestrator.redteam.probe import Probe, ProbeMappings, load_all_probes
from orchestrator.redteam.suites import SUITE_IDS, derive_suites
from server import app


PROBES_DIR = Path("orchestrator/redteam/probes")


def _probe(probe_id: str, **mappings) -> Probe:
    return Probe(
        id=probe_id,
        name=probe_id,
        target_class=("http-chat",),
        attack_class=("prompt-injection",),
        severity="medium",
        prompts=("hello",),
        mappings=ProbeMappings(**mappings),
        judge_model="claude-haiku-4-5-20251001",
        judge_rubric_path="rubrics/default.md",
    )


def test_probe_with_empty_mappings_joins_no_suite():
    assert derive_suites([_probe("unmapped")]) == {}


def test_probe_joins_every_suite_whose_mapping_is_populated():
    probe = _probe(
        "multi",
        atlas=("AML.T0051.000",),
        owasp_llm=("LLM01",),
        nist_ai_rmf=("MAP-2.3",),
        eu_ai_act=("Article 15(3)",),
    )
    suites = derive_suites([probe])
    assert suites == {
        "owasp-llm-top10": ["multi"],
        "mitre-atlas": ["multi"],
        "nist-ai-rmf": ["multi"],
        "eu-ai-act": ["multi"],
    }


def test_partially_mapped_probe_joins_only_matching_suites():
    probe = _probe("partial", owasp_llm=("LLM01",), eu_ai_act=("Article 15(3)",))
    assert set(derive_suites([probe])) == {"owasp-llm-top10", "eu-ai-act"}


def test_empty_suites_are_omitted_not_returned_empty():
    """Only atlas is populated → the other three keys must be absent, not []."""
    suites = derive_suites([_probe("atlas_only", atlas=("AML.T0051.000",))])
    assert suites == {"mitre-atlas": ["atlas_only"]}
    for suite_id in SUITE_IDS:
        if suite_id != "mitre-atlas":
            assert suite_id not in suites


def test_probe_ids_within_a_suite_are_sorted():
    probes = [_probe(pid, owasp_llm=("LLM01",)) for pid in ("zeta", "alpha", "mike")]
    assert derive_suites(probes)["owasp-llm-top10"] == ["alpha", "mike", "zeta"]


def test_derive_suites_is_stable_across_input_ordering():
    ids = ("zeta", "alpha", "mike")
    forward = derive_suites([_probe(pid, atlas=("AML.T0051.000",)) for pid in ids])
    reverse = derive_suites([_probe(pid, atlas=("AML.T0051.000",)) for pid in reversed(ids)])
    assert forward == reverse


def test_derive_suites_accepts_an_iterator():
    """load_all_probes yields a generator — derive_suites must not require a list."""
    probes = iter([_probe("gen", nist_ai_rmf=("MAP-2.3",))])
    assert derive_suites(probes) == {"nist-ai-rmf": ["gen"]}


def test_real_probe_library_yields_all_four_suites():
    probes = list(load_all_probes(PROBES_DIR))
    assert len(probes) >= 167, f"expected the shipped library, got {len(probes)} probes"

    suites = derive_suites(probes)
    assert set(suites) == set(SUITE_IDS)
    for suite_id, probe_ids in suites.items():
        assert probe_ids, f"{suite_id} is empty"
        assert probe_ids == sorted(probe_ids)
        assert len(probe_ids) == len(set(probe_ids)), f"{suite_id} has duplicate probe ids"


def test_suites_endpoint_returns_expected_shape():
    client = TestClient(app)
    resp = client.get("/redteam/suites")
    assert resp.status_code == 200

    data = resp.json()
    assert set(data) == {"suites"}
    suites = data["suites"]
    assert set(suites) == set(SUITE_IDS)
    for probe_ids in suites.values():
        assert isinstance(probe_ids, list)
        assert probe_ids
        assert all(isinstance(pid, str) for pid in probe_ids)
    assert "owasp_07_system_prompt_leakage" in suites["owasp-llm-top10"]


def test_run_rejects_both_suite_and_probe_ids(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    client = TestClient(app)
    body = {
        "target": {
            "kind": "openai_compat",
            "endpoint_url": "https://api.example.com/v1/chat/completions",
            "model": "gpt-4",
            "api_key": "sk-test",
        },
        "probe_ids": ["owasp_07_system_prompt_leakage"],
        "suite": "owasp-llm-top10",
    }
    resp = client.post("/redteam/run", json=body)
    assert resp.status_code == 422
    assert "mutually exclusive" in resp.json()["detail"]


def test_preflight_rejects_unknown_suite_and_lists_valid_ids():
    client = TestClient(app)
    body = {
        "target": {
            "kind": "openai_compat",
            "endpoint_url": "https://api.example.com/v1/chat/completions",
            "model": "gpt-4",
            "api_key": "sk-test",
        },
        "suite": "owasp-top-ten",
    }
    resp = client.post("/redteam/run/preflight", json=body)
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert "owasp-top-ten" in detail
    for suite_id in SUITE_IDS:
        assert suite_id in detail


def test_suite_resolves_to_that_suites_probe_ids(monkeypatch):
    """A suite-only request runs exactly the suite's probes."""
    from orchestrator.redteam.cost_meter import CostMeter

    captured = {}

    def fake_pre_run(self, probe_ids, target_kind, **kwargs):
        captured["probe_ids"] = probe_ids
        return 0.0

    monkeypatch.setattr(CostMeter, "check_or_abort_pre_run", fake_pre_run)

    client = TestClient(app)
    body = {
        "target": {
            "kind": "openai_compat",
            "endpoint_url": "https://x",
            "model": "y",
            "api_key": "k",
        },
        "suite": "eu-ai-act",
    }
    resp = client.post("/redteam/run/preflight", json=body)
    assert resp.status_code == 200

    expected = derive_suites(load_all_probes(PROBES_DIR))["eu-ai-act"]
    assert captured["probe_ids"] == expected
