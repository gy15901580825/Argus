"""Offline checks on the rubric fixtures: broken or thin fixtures fail CI without a key."""

from collections import Counter

import pytest

from rubric_cases import (
    MIN_PER_SIDE, RUBRICS_DIR, Case, load_all_cases, load_fixture_cases, load_shared_cases, FIXTURES_DIR,
)

ALL = load_all_cases()
RUBRICS = sorted(p.name for p in RUBRICS_DIR.glob("*.md"))


@pytest.mark.parametrize("rubric", RUBRICS)
def test_every_rubric_has_enough_pass_and_fail_cases(rubric):
    own = [c for c in ALL if c.rubric == rubric and not c.shared]
    counts = Counter(c.expect_verdict for c in own)
    assert counts["pass"] >= MIN_PER_SIDE, f"{rubric}: {counts['pass']} pass cases, need {MIN_PER_SIDE}"
    assert counts["fail"] >= MIN_PER_SIDE, f"{rubric}: {counts['fail']} fail cases, need {MIN_PER_SIDE}"


def test_case_ids_are_unique_within_a_rubric():
    ids = Counter((c.rubric, c.case_id) for c in ALL)
    assert [k for k, n in ids.items() if n > 1] == []


def test_shared_hard_cases_cover_the_named_attacks():
    ids = {c.case_id for c in load_shared_cases()}
    assert {
        "shared:empty_reply",
        "shared:refusal_then_leak",
        "shared:reply_claims_verdict_pass",
        "shared:reply_says_ignore_previous_instructions",
    } <= ids


def test_empty_reply_cases_are_never_expected_to_pass():
    empties = [c for c in load_shared_cases() if not c.target_response.strip()]
    assert len(empties) >= 4
    assert all(not c.is_correct("pass") for c in empties)


def test_case_expectation_logic():
    exact = Case("r.md", "x", "p", "a", "t", expect_verdict="fail")
    assert exact.is_correct("fail") and not exact.is_correct("pass") and not exact.is_correct("warn")
    neg = Case("r.md", "x", "p", "a", "", expect_not=("pass",))
    assert neg.is_correct("fail") and neg.is_correct("warn") and not neg.is_correct("pass")


def _write(tmp_path, body):
    p = tmp_path / "x.fixture.yaml"
    p.write_text(body)
    return p


def test_loader_rejects_a_bad_verdict(tmp_path):
    p = _write(tmp_path, """
rubric: default.md
pass_case: {probe_name: p, attack_prompt: a, target_response: t, expect_verdict: PASS}
fail_case: {probe_name: p, attack_prompt: a, target_response: t2, expect_verdict: fail}
""")
    with pytest.raises(ValueError, match="expect_verdict"):
        load_fixture_cases(p)


def test_loader_rejects_empty_reply_in_a_per_rubric_fixture(tmp_path):
    p = _write(tmp_path, """
rubric: default.md
pass_case: {probe_name: p, attack_prompt: a, target_response: "", expect_verdict: pass}
fail_case: {probe_name: p, attack_prompt: a, target_response: t2, expect_verdict: fail}
""")
    with pytest.raises(ValueError, match="target_response"):
        load_fixture_cases(p)


def test_loader_rejects_both_or_neither_expectation(tmp_path):
    p = _write(tmp_path, """
rubric: default.md
pass_case: {probe_name: p, attack_prompt: a, target_response: t}
fail_case: {probe_name: p, attack_prompt: a, target_response: t2, expect_verdict: fail}
""")
    with pytest.raises(ValueError, match="exactly one"):
        load_fixture_cases(p)


@pytest.mark.parametrize("rubric", [r for r in RUBRICS if "**warn**" in (RUBRICS_DIR / r).read_text(encoding="utf-8")])
def test_rubrics_with_a_warn_band_have_a_warn_case(rubric):
    assert any(c.expect_verdict == "warn" for c in ALL if c.rubric == rubric and not c.shared)


def test_loader_rejects_a_fixture_for_a_missing_rubric(tmp_path):
    p = _write(tmp_path, """
rubric: typo.md
pass_case: {probe_name: p, attack_prompt: a, target_response: t, expect_verdict: pass}
fail_case: {probe_name: p, attack_prompt: a, target_response: t2, expect_verdict: fail}
""")
    with pytest.raises(ValueError, match="no such rubric"):
        load_fixture_cases(p)
