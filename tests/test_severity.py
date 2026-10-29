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


def _aborted(pid, reasoning):
    return {"probe_id": pid, "verdict": "aborted_cost", "severity": "info", "reasoning": reasoning}


def test_cost_cap_line_separates_stopped_from_never_started():
    from argus.cli.severity import incomplete_lines

    stopped = _aborted("p1", "cost cap reached: per_run cap $0.50 exceeded: this run has spent $0.5100")
    never = [_aborted(f"q{i}", "not started: the run had stopped at the cost cap (x)") for i in range(3)]
    assert incomplete_lines([stopped, *never])[0] == (
        "1 probe(s) stopped at the cost cap and 3 not started; run incomplete")
    assert incomplete_lines([stopped])[0] == "1 probe(s) stopped at the cost cap; run incomplete"
    assert incomplete_lines(never)[0] == "3 probe(s) not started because of the cost cap; run incomplete"
