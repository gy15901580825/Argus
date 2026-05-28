from web_ui_phases.state import PhaseState, PhaseResult


def test_phase_state_default_empty():
    s = PhaseState(url="https://example.com", domain="example.com")
    assert s.url == "https://example.com"
    assert s.auth is None
    assert s.discovery is None
    assert s.feature_results == []
    assert s.bugs == []


def test_phase_result_roundtrip():
    r = PhaseResult(
        phase="discovery",
        raw_output="ok",
        parsed={"features": [{"name": "login", "url": "/login"}]},
        steps_used=3,
    )
    assert r.parsed["features"][0]["name"] == "login"


def test_phase_state_to_prompt_context_empty():
    s = PhaseState(url="https://x.com", domain="x.com")
    ctx = s.to_prompt_context()
    assert "No prior phases" in ctx


def test_phase_state_to_prompt_context_with_discovery():
    s = PhaseState(url="https://x.com", domain="x.com")
    s.discovery = PhaseResult(
        phase="discovery",
        raw_output="",
        parsed={"features": [{"name": "search", "url": "/search"}]},
        steps_used=3,
    )
    ctx = s.to_prompt_context()
    assert "search" in ctx
    assert "/search" in ctx


def test_phase_state_as_final_report_contains_bugs():
    s = PhaseState(url="https://x.com", domain="x.com")
    s.bugs = [
        {"severity": "high", "category": "FUNC", "description": "Login fails silently"}
    ]
    text = s.as_final_report()
    assert "FUNC" in text
    assert "Login fails silently" in text
    assert "HIGH: 1" in text or "High: 1" in text


def test_phase_state_as_final_report_renders_steps_and_evidence():
    s = PhaseState(url="https://x.com", domain="x.com")
    s.bugs = [
        {
            "severity": "medium",
            "category": "UX",
            "description": "Button label unclear",
            "steps": "1. open page 2. click the Go button",
            "evidence": "screenshot step_007.png",
        }
    ]
    text = s.as_final_report()
    assert "Steps: 1. open page 2. click the Go button" in text
    assert "Evidence: screenshot step_007.png" in text


def test_phase_state_as_final_report_clamps_unknown_severity():
    s = PhaseState(url="https://x.com", domain="x.com")
    s.bugs = [
        {"severity": "blocker", "category": "FUNC", "description": "unknown sev"},
        {"severity": "low", "category": "UX", "description": "real low"},
    ]
    text = s.as_final_report()
    # "blocker" is not canonical -> clamp to "low", so Low count is 2
    assert "Low: 2" in text
    # the bug line still echoes the agent-reported severity verbatim
    assert "BUG [BLOCKER]" in text
