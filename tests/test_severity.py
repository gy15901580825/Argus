from argus.cli.severity import SEVERITY_ORDER, findings_at_or_above


def _f(verdict, severity):
    return {"probe_id": "p", "verdict": verdict, "severity": severity}


def test_order_is_info_to_critical():
    assert SEVERITY_ORDER == ("info", "low", "medium", "high", "critical")


def test_findings_at_or_above_filters_by_rank_and_verdict():
    findings = [_f("fail", "low"), _f("fail", "high"), _f("fail", "critical"), _f("pass", "critical"), _f("warn", "high")]
    hits = findings_at_or_above(findings, "high")
    assert [h["severity"] for h in hits] == ["high", "critical"]


def test_findings_at_or_above_treats_unknown_severity_as_info():
    findings = [_f("fail", None), _f("fail", "weird"), {"probe_id": "p", "verdict": "fail"}]
    assert findings_at_or_above(findings, "info") == findings
    assert findings_at_or_above(findings, "low") == []
