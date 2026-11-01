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


def test_catalog_freezes_templates_and_rejects_escape(tmp_path):
    from argus.scenarios.api import catalog
    from argus.scenarios.runtime import NotReady, read_template

    scenario = catalog()[0]
    assert all(not spec.template and spec.content for spec in scenario.objects.values())
    assert scenario.controls[0].contents and not scenario.controls[0].replace
    (tmp_path / "templates").mkdir()
    (tmp_path / "private.txt").write_text("private")
    (tmp_path / "templates" / "escape").symlink_to(tmp_path / "private.txt")
    for path in ["../private.txt", "escape"]:
        with pytest.raises(NotReady):
            read_template(tmp_path, path)


def test_reserved_object_key_and_unknown_observation_are_rejected():
    with pytest.raises(ValidationError):
        IntegrationScenario(id="sample", objects={"folder": {"driver": "gdrive", "op": "create_doc"}})
    with pytest.raises(ValidationError):
        IntegrationScenario(id="sample", observe=[{"driver": "gdrive", "collect": "object_diff", "object": "missing"}])


def test_attack_class_is_validated():
    with pytest.raises(ValidationError, match="invalid attack_class 'nope'"):
        IntegrationScenario(id="sample", attack_class=["nope"])


def test_catalog_scenarios_resolve_both_tiers():
    from argus import remediation
    from argus.scenarios.api import catalog
    for s in catalog():
        assert s.attack_class, s.id
        assert {a["tier"] for a in remediation.actions_for_classes(s.attack_class)} == {"mitigation", "fix"}
