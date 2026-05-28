import pytest

from web_ui_phases.budget import allocate_phase_budgets


def test_budget_no_credentials_max_20():
    b = allocate_phase_budgets(max_steps=20, has_credentials=False)
    assert b["auth"] == 0
    assert b["discovery"] == 3
    assert b["features"] == 7
    assert b["bug_hunt"] == 10
    assert sum(b.values()) == 20


def test_budget_with_credentials_max_20():
    b = allocate_phase_budgets(max_steps=20, has_credentials=True)
    assert b["auth"] == 2
    assert b["discovery"] + b["features"] + b["bug_hunt"] == 18
    assert sum(b.values()) == 20


def test_budget_enforces_min_bug_hunt():
    b = allocate_phase_budgets(max_steps=10, has_credentials=False)
    assert b["bug_hunt"] >= 5
    assert sum(b.values()) == 10


def test_budget_small_max_still_allocates_all_phases():
    b = allocate_phase_budgets(max_steps=6, has_credentials=False)
    assert b["discovery"] >= 1
    assert b["features"] >= 1
    assert b["bug_hunt"] >= 1
    assert sum(b.values()) == 6


def test_budget_min_boundary_with_credentials_sum_invariant():
    """Regression: max_steps=4 with credentials violated sum invariant (sum was 5, not 4).

    When has_credentials=True, auth consumes 2, leaving 2 for discovery+features+bug_hunt.
    Each phase has a min of 1, so we need at least 3 non-auth steps -> min max_steps=5.
    """
    with pytest.raises(ValueError, match="max_steps must be >= 5"):
        allocate_phase_budgets(max_steps=4, has_credentials=True)

    b = allocate_phase_budgets(max_steps=5, has_credentials=True)
    assert b == {"auth": 2, "discovery": 1, "features": 1, "bug_hunt": 1}
    assert sum(b.values()) == 5


def test_budget_no_credentials_min_boundary_still_accepts_4():
    """When has_credentials=False, max_steps=4 is still valid (no auth budget needed)."""
    b = allocate_phase_budgets(max_steps=4, has_credentials=False)
    assert b["auth"] == 0
    assert sum(b.values()) == 4
