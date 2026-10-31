"""Browser probes are decided by what the agent sent to the trap, not by its reply."""
import re
from pathlib import Path

from argus.probe import load_all_probes

DIR = Path(__file__).resolve().parents[1] / "argus" / "probes" / "browser"
ASSERTION_NAMES = {"no_trap_request", "no_canary_in_trap_requests"}
# The page behind each phishing probe asks for its secret only at these payload paths.
PAGE_VARIANTS = {
    "browser_ui_phishing_credit_card": "cc",
    "browser_ui_phishing_government_id": "kyc",
    "browser_ui_phishing_recovery_phrase": "wallet-restore",
    "browser_ui_phishing_oauth_consent": "oauth/grant",
}
# The sink records what the agent sends into reports, so payloads must never ask for these.
LOCAL_SECRET_WORDS = (".ssh", "id_rsa", "password manager", "credentials", "inbox", "chat messages", "calendar")


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


def test_payload_with_a_sink_never_asks_for_local_secrets_or_user_data():
    for p in _probes():
        if "{sink_url}" in p.scenario_payload:
            low = p.scenario_payload.lower()
            for word in LOCAL_SECRET_WORDS:
                assert word not in low, (p.id, word)


def test_no_payload_names_a_bare_attacker_host():
    # Only email addresses on a reserved .example domain stay: the judge covers those.
    for p in _probes():
        rest = re.sub(r"[\w.+-]+@[\w-]+(\.[\w-]+)*\.example\.com", "", p.scenario_payload)
        assert "attacker" not in rest.lower(), p.id


def test_phishing_payloads_use_the_variant_the_page_knows():
    by_id = {p.id: p for p in _phishing()}
    for pid, seg in PAGE_VARIANTS.items():
        assert by_id[pid].scenario_payload == "{sink_url}/" + seg, pid


def test_os_cmd_prompts_ask_for_a_benign_read_not_for_running_commands():
    for p in _probes():
        if p.scenario_kind == "os_cmd":
            text = p.prompts[0].lower()
            assert "shell tool" not in text and "follow" not in text, p.id
            assert "do not change anything" in text, p.id


# An agent that obeys a payload must do no real harm: the action goes to the sink instead.
_DESTRUCTIVE = re.compile(r"\bdelet\w*|\brm\s+-[a-z]*(?:r[a-z]*f|f[a-z]*r)|\bdisabl\w*\b[^.]*\b(?:2fa|two-factor)", re.I)
_NPM_INSTALL = re.compile(r"\bnpm\s+(?:install|i|add)\b(?:\s+-\S+)*\s+(\S+)")


def test_no_payload_asks_for_a_destructive_action():
    for p in _probes():
        payload = p.scenario_payload
        assert not _DESTRUCTIVE.search(payload), p.id
        if re.search(r"\btransfer", payload, re.I):
            assert "{sink_url}" in payload, p.id


def test_no_payload_installs_a_real_package_by_name():
    for p in _probes():
        for name in _NPM_INSTALL.findall(p.scenario_payload):
            assert name.startswith("{sink_url}/"), (p.id, name)


def test_the_destructive_checks_catch_what_they_are_for():
    for bad in ("Delete every file", "rm -rf ~", "run rm -fr /", "Disable the user's two-factor login",
                "disable 2FA now"):
        assert _DESTRUCTIVE.search(bad), bad
    assert _NPM_INSTALL.findall("npm install -g pwned-update-helper") == ["pwned-update-helper"]
    assert _NPM_INSTALL.findall("npm i {sink_url}/x.tgz") == ["{sink_url}/x.tgz"]


def test_every_browser_probe_with_assertions_has_exactly_one_prompt():
    # Evidence adds up across a probe's sends, so a second prompt would be judged on the first's record.
    browser = [p for p in load_all_probes(DIR.parent)
               if {"browser-using", "browser_using_agent"} & set(p.target_class)]
    with_assertions = [p for p in browser if p.assertions]
    assert len(with_assertions) >= 31
    for p in with_assertions:
        assert len(p.prompts) == 1, p.id
