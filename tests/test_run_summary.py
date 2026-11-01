from argus.coverage import (
    SUMMARY_SEVERITIES,
    SUMMARY_VERDICTS,
    _TESTED_VERDICTS,
    build_summary,
)

ZERO_VERDICTS = {
    "fail": 0, "pass": 0, "warn": 0, "skipped": 0,
    "blocked_by_target": 0, "aborted_cost": 0, "error": 0,
}
ZERO_SEVERITIES = {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}


def _f(verdict, severity="info", probe_id="p"):
    return {"probe_id": probe_id, "verdict": verdict, "severity": severity}


def test_empty_list_is_all_zeros():
    assert build_summary([]) == {
        "total": 0,
        "evaluated": 0,
        "evaluated_verdicts": ["fail", "pass", "warn"],
        "by_verdict": ZERO_VERDICTS,
        "failed_by_severity": ZERO_SEVERITIES,
    }


def test_key_orders_are_fixed():
    summary = build_summary([])
    assert list(summary) == [
        "total", "evaluated", "evaluated_verdicts", "by_verdict", "failed_by_severity",
    ]
    assert list(summary["by_verdict"]) == [
        "fail", "pass", "warn", "skipped", "blocked_by_target", "aborted_cost", "error",
    ]
    assert list(summary["failed_by_severity"]) == ["info", "low", "medium", "high", "critical"]


def test_only_untested_verdicts_evaluate_nothing():
    findings = [_f("skipped"), _f("error"), _f("blocked_by_target"), _f("aborted_cost"), _f("error")]
    summary = build_summary(findings)
    assert summary["total"] == 5 and summary["evaluated"] == 0
    assert summary["by_verdict"] == {
        **ZERO_VERDICTS, "skipped": 1, "error": 2, "blocked_by_target": 1, "aborted_cost": 1,
    }
    assert summary["failed_by_severity"] == ZERO_SEVERITIES


def test_mixed_findings_exact_counts():
    findings = [
        _f("fail", "critical"), _f("fail", "high"), _f("fail", "info"),
        _f("warn", "high"), _f("pass"), _f("pass"), _f("skipped"), _f("error"),
    ]
    summary = build_summary(findings)
    assert summary["total"] == 8 and summary["evaluated"] == 6
    assert summary["by_verdict"] == {
        **ZERO_VERDICTS, "fail": 3, "warn": 1, "pass": 2, "skipped": 1, "error": 1,
    }
    assert summary["failed_by_severity"] == {
        **ZERO_SEVERITIES, "critical": 1, "high": 1, "info": 1,
    }


def test_counts_findings_not_probes():
    summary = build_summary([_f("fail", "high", "p1"), _f("pass", probe_id="p1")])
    assert summary["total"] == 2 and summary["evaluated"] == 2


def test_unknown_verdict_and_severity_get_their_own_key():
    summary = build_summary([_f("weird"), _f("fail", "n/a"), _f("pass")])
    assert summary["by_verdict"]["weird"] == 1
    assert summary["failed_by_severity"]["n/a"] == 1
    assert summary["total"] == sum(summary["by_verdict"].values()) == 3
    assert sum(summary["failed_by_severity"].values()) == summary["by_verdict"]["fail"] == 1
    assert summary["evaluated"] == 2


def test_evaluated_set_is_the_coverage_tested_set():
    assert build_summary([])["evaluated_verdicts"] == sorted(_TESTED_VERDICTS)
    assert set(SUMMARY_VERDICTS) >= _TESTED_VERDICTS


def test_input_is_not_mutated_and_generators_work():
    findings = [_f("fail", "low")]
    assert build_summary(iter(findings))["by_verdict"]["fail"] == 1
    assert findings == [_f("fail", "low")]
