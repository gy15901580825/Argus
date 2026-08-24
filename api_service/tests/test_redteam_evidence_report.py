"""Evidence in the report: a payments finding must show the captured facts."""

from redteam.reports import render_html


def _run(findings):
    return {"id": "r1", "status": "completed", "findings": findings}


def _finding(**kw):
    base = {
        "probe_id": "pay_x402_quote_tampering", "verdict": "fail", "severity": "critical",
        "reasoning": "authorization of 500000000 exceeds the 1000 limit",
        "attack_prompt": "buy the report", "target_response": "paid",
        "atlas_id": [], "owasp_id": ["LLM06"], "nist_id": [], "eu_ai_act_id": [],
        "confidence": 1.0, "judge_model": "", "escalated_model": None,
        "target_latency_ms": 12.0, "probed_at": "2026-08-15T00:00:00Z",
        "evidence": None,
    }
    base.update(kw)
    return base


def test_report_shows_captured_authorizations():
    f = _finding(evidence={
        "authorizations": [
            {"amount": "500000000", "asset": "USDC", "payee": "0xattacker", "settled": False}
        ],
        "interaction_count": 3,
        "expected_payee": "0xhonest",
    })
    html = render_html(_run([f]))
    assert "0xattacker" in html
    assert "500000000" in html


def test_report_states_that_payments_were_simulated():
    """A payments customer must never mistake a finding for a real transfer."""
    f = _finding(evidence={"authorizations": [], "interaction_count": 1})
    assert "simulated" in render_html(_run([f])).lower()


def test_report_without_evidence_is_unchanged():
    html = render_html(_run([_finding(verdict="pass", severity="info")]))
    assert "Evidence" not in html


def test_evidence_values_are_escaped():
    f = _finding(evidence={
        "authorizations": [{"amount": "1", "asset": "USDC",
                            "payee": "<script>alert(1)</script>", "settled": True}],
        "interaction_count": 1,
    })
    html = render_html(_run([f]))
    assert "<script>alert(1)</script>" not in html


def test_jsonb_evidence_is_decoded_before_it_reaches_the_report():
    """The driver hands back JSONB as text; a string would be truthy in the
    template while every attribute on it resolved to undefined."""
    from redteam.runs import decode_finding_row

    row = {"probe_id": "p", "evidence": '{"authorizations": [], "interaction_count": 2}'}
    assert decode_finding_row(row)["evidence"] == {"authorizations": [], "interaction_count": 2}


def test_unparseable_evidence_becomes_none_rather_than_a_string():
    from redteam.runs import decode_finding_row

    assert decode_finding_row({"evidence": "{not json"})["evidence"] is None


def test_evidence_that_is_already_a_dict_is_left_alone():
    from redteam.runs import decode_finding_row

    ev = {"authorizations": []}
    assert decode_finding_row({"evidence": ev})["evidence"] is ev


def test_report_names_what_was_scanned():
    """A prospect reading a demo report must not think we scanned them."""
    run = _run([_finding()])
    run["target_spec"] = {"kind": "payment_agent", "label": "Argus demo payment agent"}
    html = render_html(run)
    assert "payment_agent" in html
    assert "Argus demo payment agent" in html


def test_deterministic_findings_say_so_instead_of_showing_an_empty_judge():
    html = render_html(_run([_finding(judge_model="")]))
    assert "judge: ·" not in html
    assert "deterministic" in html.lower()


def test_judged_findings_still_name_the_model():
    html = render_html(_run([_finding(judge_model="claude-haiku-4-5-20251001")]))
    assert "claude-haiku-4-5-20251001" in html
