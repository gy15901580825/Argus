"""Browser probes are decided by what the agent sent to the trap, not by its reply."""
from pathlib import Path

from argus.probe import load_all_probes

DIR = Path(__file__).resolve().parents[1] / "argus" / "probes" / "browser"
ASSERTION_NAMES = {"no_trap_request", "no_canary_in_trap_requests"}


def _probes():
    return list(load_all_probes(DIR))


def _merged(p):
    return {k: v for e in p.assertions for k, v in e.items()}


def _phishing():
    return [p for p in _probes() if p.scenario_kind == "ui_phishing"]


def test_library_has_all_31_browser_probes():
    assert len(_probes()) == 31
    assert len(_phishing()) == 9


def test_every_probe_has_known_assertions_and_requires_interaction():
    for p in _probes():
        assert p.assertions, p.id
        assert set(_merged(p)) <= ASSERTION_NAMES, p.id
        assert p.requires_interaction is True, p.id


def test_ui_phishing_canary_is_in_the_prompt_and_never_in_the_payload():
    canaries = {}
    for p in _phishing():
        merged = _merged(p)
        if "no_canary_in_trap_requests" not in merged:
            continue
        canary = merged["no_canary_in_trap_requests"]
        canaries[p.id] = canary
        assert isinstance(canary, str) and len(canary) >= 8, p.id
        assert "123456" not in canary, p.id
        assert canary in p.prompts[0], p.id
        assert canary not in p.scenario_payload, p.id
    assert len(canaries) == 8
    assert len(set(canaries.values())) == 8


def test_oauth_consent_has_no_secret_and_fails_on_any_trap_request():
    (p,) = [p for p in _phishing() if p.id == "browser_ui_phishing_oauth_consent"]
    assert _merged(p) == {"no_trap_request": True}


def test_ui_phishing_is_fully_observable_and_states_the_legit_destination():
    for p in _phishing():
        assert p.judge_when_assertions_pass is False, p.id
        assert p.scenario_payload.startswith("{sink_url}/"), p.id
        assert "{sink_url}" not in p.prompts[0], p.id
        if p.id != "browser_ui_phishing_oauth_consent":
            assert " only " in p.prompts[0] or "never" in p.prompts[0].lower(), p.id


def test_other_probes_fail_on_any_trap_request_and_still_get_the_judge():
    others = [p for p in _probes() if p.scenario_kind != "ui_phishing"]
    assert len(others) == 22
    for p in others:
        assert _merged(p) == {"no_trap_request": True}, p.id
        assert p.judge_when_assertions_pass is True, p.id


def test_no_payload_names_an_attacker_host_and_every_url_uses_the_sink():
    for p in _probes():
        payload = p.scenario_payload
        # Email addresses stay as exfil text for the judge; only URLs must move to the sink.
        assert "://attacker.example" not in payload, p.id
        assert "attacker-credential-collector" not in payload, p.id
        assert "{sink_url}" not in "".join(p.prompts), p.id
        if "://" in payload or "http" in payload.lower():
            assert "{sink_url}" in payload, p.id
        assert "://" not in payload.replace("{sink_url}", ""), p.id
