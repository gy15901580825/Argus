"""Unit tests for orchestrator/model_router.py — pure logic."""
from __future__ import annotations


def test_classify_complexity_simple_text():
    from orchestrator.model_router import classify_complexity
    assert classify_complexity("Just a simple login form check") == "simple"


def test_classify_complexity_complex_multistep():
    from orchestrator.model_router import classify_complexity
    # multi-step + integration + workflow → complex_score=3
    # no simple indicators
    assert classify_complexity(
        "Multi-step workflow with integration between systems"
    ) == "complex"


def test_classify_complexity_cross_system_keyword():
    from orchestrator.model_router import classify_complexity
    assert classify_complexity("We have a microservice talking to another") == "cross_system"


def test_classify_complexity_cross_system_by_score():
    from orchestrator.model_router import classify_complexity
    text = "multi-step end-to-end oauth payment integration workflow checkout"
    # Many complex indicators should push us past 4 and into cross_system
    assert classify_complexity(text) == "cross_system"


def test_classify_complexity_simple_wins_with_more_simple_hits():
    from orchestrator.model_router import classify_complexity
    text = "a simple basic login form submit navigation page"
    assert classify_complexity(text) == "simple"


def test_select_models_free_plan_uses_mini():
    from orchestrator.model_router import select_models, _MINI_MODEL
    result = select_models("free", "anything")
    assert result["browser_model"] == _MINI_MODEL
    assert result["script_model"] == _MINI_MODEL
    assert result["complexity"] == "n/a"
    assert "plan=free" in result["routing_reason"]


def test_select_models_starter_plan_uses_mini():
    from orchestrator.model_router import select_models, _MINI_MODEL
    result = select_models("starter", "")
    assert result["browser_model"] == _MINI_MODEL
    assert result["script_model"] == _MINI_MODEL


def test_select_models_unknown_plan_falls_back_to_free():
    from orchestrator.model_router import select_models, _MINI_MODEL
    result = select_models("platinum-galactic", "")
    # Falls back to free → mini
    assert result["browser_model"] == _MINI_MODEL


def test_select_models_pro_simple_uses_mini():
    from orchestrator.model_router import select_models, _MINI_MODEL
    result = select_models("pro", "simple login check")
    assert result["browser_model"] == _MINI_MODEL
    assert result["complexity"] == "simple"
    assert "cost-optimized" in result["routing_reason"]


def test_select_models_pro_complex_uses_default():
    from orchestrator.model_router import select_models, _DEFAULT_MODEL
    result = select_models("pro", "multi-step integration workflow across app")
    assert result["browser_model"] == _DEFAULT_MODEL
    assert result["script_model"] == _DEFAULT_MODEL
    assert result["complexity"] == "complex"


def test_select_models_pro_cross_system_uses_default():
    from orchestrator.model_router import select_models, _DEFAULT_MODEL
    result = select_models("pro", "cross-system microservice integration")
    assert result["browser_model"] == _DEFAULT_MODEL
    assert result["complexity"] == "cross_system"


def test_select_models_enterprise_behaves_like_pro():
    from orchestrator.model_router import select_models, _DEFAULT_MODEL
    result = select_models("enterprise", "multi-step integration workflow")
    assert result["browser_model"] == _DEFAULT_MODEL
    assert result["complexity"] == "complex"


def test_select_models_pro_no_content_skips_smart_routing():
    from orchestrator.model_router import select_models, _DEFAULT_MODEL
    # Empty content — no smart routing kicks in, plan defaults used
    result = select_models("pro", "")
    assert result["browser_model"] == _DEFAULT_MODEL
    assert result["complexity"] == "n/a"
