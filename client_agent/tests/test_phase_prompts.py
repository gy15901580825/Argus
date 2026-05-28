from web_ui_phases.prompts import (
    build_auth_prompt,
    build_discovery_prompt,
    build_features_prompt,
    build_bug_hunt_prompt,
)
from web_ui_phases.state import PhaseState, PhaseResult


def _state():
    return PhaseState(
        url="https://example-target.com/",
        domain="example-target.com",
        credentials={"username": "u", "password": "p"},
        business_context=None,
        user_persona="new_user",
    )


def test_auth_prompt_contains_credentials_and_budget():
    p = build_auth_prompt(_state(), max_steps=2)
    assert "example-target.com" in p
    assert "username='u'" in p
    assert "password='p'" in p
    assert "2 steps" in p
    assert "JSON" in p


def test_auth_prompt_no_credentials_raises():
    s = _state()
    s.credentials = None
    import pytest
    with pytest.raises(ValueError):
        build_auth_prompt(s, max_steps=2)


def test_discovery_prompt_structure():
    p = build_discovery_prompt(_state(), max_steps=3)
    assert "Phase 1" in p or "DISCOVERY" in p
    assert "example-target.com" in p
    assert "features" in p.lower()
    assert "```json" in p


def test_discovery_prompt_forbids_final_report():
    p = build_discovery_prompt(_state(), max_steps=3)
    assert "FINAL REPORT" not in p
    assert "do NOT" in p.lower() or "do not" in p.lower()


def test_features_prompt_includes_discovery_context():
    s = _state()
    s.discovery = PhaseResult(
        phase="discovery", raw_output="",
        parsed={"features": [{"name": "resume upload", "url": "/upload"}]},
        steps_used=3,
    )
    p = build_features_prompt(s, max_steps=7)
    assert "resume upload" in p
    assert "/upload" in p


def test_bug_hunt_prompt_includes_prior_findings():
    s = _state()
    s.feature_results = [{"name": "search", "status": "pass"}]
    p = build_bug_hunt_prompt(s, max_steps=10)
    assert "search" in p
    assert "bug" in p.lower()
    assert "severity" in p.lower()


def test_all_prompts_forbid_premature_done_signal():
    s = _state()
    prompts = [
        build_auth_prompt(s, 2),
        build_discovery_prompt(s, 3),
        build_features_prompt(s, 7),
        build_bug_hunt_prompt(s, 10),
    ]
    for p in prompts:
        # Each phase must tell the LLM NOT to write a cross-task FINAL REPORT;
        # the whole-task report is assembled by Python after Phase 3.
        assert "only this phase" in p.lower() or "this phase only" in p.lower()
