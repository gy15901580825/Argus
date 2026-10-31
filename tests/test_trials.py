import datetime
import pytest
from argus.trials import aggregate_trials, pass_wording


def test_any_fail_is_fail():
    assert aggregate_trials(["pass", "fail", "error"]).verdict == "fail"


def test_warn_without_fail_is_warn():
    assert aggregate_trials(["pass", "warn", "skipped"]).verdict == "warn"


def test_all_pass_is_pass():
    assert aggregate_trials(["pass", "pass"]).verdict == "pass"


def test_all_skipped_is_skipped():
    assert aggregate_trials(["skipped", "skipped"]).verdict == "skipped"


def test_all_blocked_is_blocked_by_target():
    assert aggregate_trials(["blocked_by_target"] * 2).verdict == "blocked_by_target"


def test_pass_plus_error_is_error_incomplete_trials():
    result = aggregate_trials(["pass", "error"])
    assert (result.verdict, result.reason_code) == ("error", "incomplete_trials")


def test_pass_plus_skipped_is_error_incomplete_trials():
    result = aggregate_trials(["pass", "skipped"])
    assert (result.verdict, result.reason_code) == ("error", "incomplete_trials")


def test_all_error_is_error_incomplete_trials():
    result = aggregate_trials(["error", "error"])
    assert (result.verdict, result.reason_code) == ("error", "incomplete_trials")


def test_pass_plus_blocked_is_error_incomplete_trials():
    result = aggregate_trials(["pass", "blocked_by_target"])
    assert (result.verdict, result.reason_code) == ("error", "incomplete_trials")


def test_cost_cap_keeps_fail_or_warn_else_aborted_cost():
    for verdicts, want in [
        (["pass", "fail"], "fail"),
        (["warn", "error"], "warn"),
        (["pass"], "aborted_cost"),
        ([], "aborted_cost"),
    ]:
        assert aggregate_trials(verdicts, stopped_at_cost_cap=True).verdict == want
    assert aggregate_trials([]).verdict == "error"


def test_counts_line_has_seven_counts_and_valid():
    result = aggregate_trials(["pass", "fail", "error", "skipped"])
    assert (
        result.counts_line()
        == "attempted=4 pass=1 fail=1 warn=0 error=1 skipped=1 blocked_by_target=0 valid=2"
    )
    assert result.as_dict()["valid"] == 2


def test_sentence_wording():
    assert (
        aggregate_trials(["pass", "fail", "error", "skipped"]).sentence()
        == "1 of 2 valid trials failed (4 attempted; 1 error, 1 skipped)."
    )


def test_pass_wording_says_not_observed():
    text = pass_wording(3, datetime.date(2026, 11, 2))
    assert (
        text
        == "Not observed in this environment on 2026-11-02 in 3 of 3 trials; a pass is weak evidence, not proof of safety."
    )


def test_report_formats_show_all_counts():
    from argus.cli import reports

    run = {
        "id": "trial-report",
        "status": "completed",
        "findings": [
            {
                "probe_id": "p",
                "verdict": "fail",
                "severity": "high",
                "confidence": 1,
                "reasoning": aggregate_trials(
                    ["pass", "fail", "error", "skipped"]
                ).counts_line(),
                "attack_prompt": "",
                "target_response": "",
                "target_latency_ms": 0,
                "judge_model": "",
                "atlas_id": [],
                "owasp_id": [],
                "nist_id": [],
                "eu_ai_act_id": [],
            }
        ],
    }
    for render in [reports.render_html, reports.render_junit, reports.render_sarif]:
        rendered = render(run)
        for key in [
            "attempted",
            "pass",
            "fail",
            "warn",
            "error",
            "skipped",
            "blocked_by_target",
            "valid",
        ]:
            assert key + "=" in rendered
