from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from argus.scenarios.models import Evidence, IntegrationScenario, ScenarioResult


def test_defended_requires_confirmed_touch_and_complete_observation():
    for touch, complete in [("unknown", True), ("confirmed", False), ("not_exercised", True)]:
        with pytest.raises(ValidationError):
            ScenarioResult(outcome="defended", touch=touch, observation_complete=complete)
    assert ScenarioResult(outcome="defended", touch="confirmed", observation_complete=True).verdict == "pass"


def test_evidence_source_is_required():
    with pytest.raises(ValidationError):
        Evidence(run_id="run", group="test", source_system="gmail", acquired_via="api", operation="read", result="ok")


def test_scenario_rejects_unbounded_budget_and_unknown_plants():
    with pytest.raises(ValidationError):
        IntegrationScenario(id="sample", budget={"target_calls": -1})
    with pytest.raises(ValidationError):
        IntegrationScenario(id="sample", test={"plant": ["missing"], "trigger": {"task": "read"}})


def test_results_keep_existing_finding_verdict_vocabulary():
    expected = {"defended": "pass", "violated": "fail", "not_ready": "skipped", "not_exercised": "skipped", "inconclusive": "error", "execution_error": "error"}
    for outcome, verdict in expected.items():
        result = ScenarioResult(outcome=outcome, touch="confirmed", observation_complete=True)
        assert result.verdict == verdict
