"""The shipped payment probe family."""

from pathlib import Path

from orchestrator.redteam.api import PROBES_DIR, RunRequest, _estimate_exchanges, _judged_exchanges
from orchestrator.redteam.probe import load_all_probes

TARGET = {"kind": "openai_compat", "endpoint_url": "https://x", "model": "m"}


def _payment_probes():
    return [p for p in load_all_probes(PROBES_DIR) if p.id.startswith("pay_")]


def test_the_payment_family_ships():
    assert len(_payment_probes()) == 26


def test_every_payment_probe_is_mapped_and_scoped_to_the_testbed():
    for p in _payment_probes():
        assert p.target_class == ("payment_agent",), p.id
        assert p.mappings.owasp_llm and p.mappings.atlas and p.mappings.nist_ai_rmf, p.id


def test_only_credential_probes_fall_back_to_the_judge():
    """Anything provable from the payment record is asserted, not judged. A
    disclosure in prose is not provable that way, so those three keep a rubric."""
    judged = {p.id for p in _payment_probes() if not p.assertions}
    assert judged == {
        "pay_wallet_key_exfil_compliance",
        "pay_wallet_key_exfil_encoded",
        "pay_wallet_key_exfil_partial",
    }


def test_multi_turn_payment_probes_declare_conversation():
    for p in _payment_probes():
        if "multi-turn" in p.attack_class:
            assert p.conversation, p.id


def test_every_payment_probe_carries_a_testbed_script():
    for p in _payment_probes():
        assert p.scenario_kind, p.id
        assert p.scenario_payload.startswith("{"), p.id


def test_probes_that_need_the_merchant_url_say_so():
    for p in _payment_probes():
        assert any("{merchant_url}" in prompt for prompt in p.prompts), p.id


def test_assertion_probes_are_not_billed_for_judge_calls():
    req = RunRequest(target=TARGET, probe_ids=["pay_x402_quote_tampering"])
    assert _estimate_exchanges(req, ["pay_x402_quote_tampering"]) == 1
    assert _judged_exchanges(req, ["pay_x402_quote_tampering"]) == 0


def test_ordinary_probes_are_still_billed_for_judge_calls():
    req = RunRequest(target=TARGET, probe_ids=["encoded_payload_base64_link"])
    assert _judged_exchanges(req, ["encoded_payload_base64_link"]) == 1


def test_a_payment_only_run_costs_us_nothing_at_the_gate(monkeypatch):
    """Payment probes spend the customer's tokens, not ours: no judge, no
    attacker LLM. The pre-run gate must not reject a run that is free."""
    from fastapi.testclient import TestClient
    from server import app

    captured = {}

    from orchestrator.redteam.cost_meter import CostMeter

    def fake_pre_run(self, probe_ids, target_kind, **kwargs):
        captured.update(kwargs)
        return 0.0

    monkeypatch.setattr(CostMeter, "check_or_abort_pre_run", fake_pre_run)
    resp = TestClient(app).post(
        "/redteam/run/preflight",
        json={"target": TARGET, "probe_ids": [p.id for p in _payment_probes()]},
    )
    assert resp.status_code == 200
    # Only the three judged credential probes cost anything; the rest are
    # decided from evidence and never reach a model.
    assert captured["total_exchanges"] == 3
