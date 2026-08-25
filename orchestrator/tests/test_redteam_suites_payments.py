"""A suite the customer can actually name.

Standards suites answer "show me OWASP coverage". A prospect running a trial
asks a different question — "run the payment tests" — and there was no id for
that, so the six payment probes were reachable only by listing their ids.
"""

from orchestrator.redteam.api import PROBES_DIR
from orchestrator.redteam.probe import load_all_probes
from orchestrator.redteam.suites import derive_suites


def _suites():
    return derive_suites(load_all_probes(PROBES_DIR))


def test_payments_suite_exists():
    assert "payments" in _suites()


def test_payments_suite_holds_exactly_the_payment_probes():
    suites = _suites()
    all_payment = {p.id for p in load_all_probes(PROBES_DIR) if p.id.startswith("pay_")}
    assert set(suites["payments"]) == all_payment


def test_standards_suites_are_unchanged_by_the_new_dimension():
    suites = _suites()
    for sid in ("owasp-llm-top10", "mitre-atlas", "nist-ai-rmf", "eu-ai-act"):
        assert sid in suites
        assert len(suites[sid]) > 100


def test_a_payment_probe_still_joins_its_standards_suites():
    """Tagging by attack_class must add a suite, not replace the mappings."""
    suites = _suites()
    assert "pay_x402_quote_tampering" in suites["owasp-llm-top10"]
    assert "pay_x402_quote_tampering" in suites["payments"]
