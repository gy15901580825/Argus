"""Pure dataclass / enum tests for orchestrator/utils/content_types.py."""
from __future__ import annotations

import pytest


def test_content_type_enum_values():
    from orchestrator.utils.content_types import ContentType
    assert ContentType.TEXT.value == "text"
    assert ContentType.PRESENTATION.value == "presentation"
    assert ContentType.QUIZ.value == "quiz"
    # All 6 declared members
    assert len(list(ContentType)) == 6


def test_quality_level_enum_values():
    from orchestrator.utils.content_types import QualityLevel
    assert QualityLevel.DRAFT.value == "draft"
    assert QualityLevel.EXCELLENT.value == "excellent"
    values = {q.value for q in QualityLevel}
    assert values == {"draft", "review", "good", "excellent"}


def test_learning_objective_dataclass():
    from orchestrator.utils.content_types import LearningObjective

    obj = LearningObjective(objective="Master REST", level="intermediate", time_estimate=30)
    assert obj.objective == "Master REST"
    assert obj.level == "intermediate"
    assert obj.time_estimate == 30


def test_content_element_defaults():
    from orchestrator.utils.content_types import ContentElement, ContentType

    el = ContentElement(
        content_type=ContentType.TEXT,
        title="Intro",
        content="body",
        metadata={"k": "v"},
    )
    # Defaults
    assert el.quality_score == 0.0
    assert el.file_path is None
    assert el.metadata == {"k": "v"}


def test_content_element_custom_quality_score():
    from orchestrator.utils.content_types import ContentElement, ContentType

    el = ContentElement(
        content_type=ContentType.VIDEO,
        title="Demo",
        content="url://demo",
        metadata={},
        quality_score=4.5,
        file_path="/tmp/demo.mp4",
    )
    assert el.quality_score == 4.5
    assert el.file_path == "/tmp/demo.mp4"


def test_learning_module_wraps_elements():
    from orchestrator.utils.content_types import (
        LearningModule,
        LearningObjective,
        ContentElement,
        ContentType,
    )

    obj = LearningObjective(objective="A", level="beginner", time_estimate=10)
    el = ContentElement(ContentType.TEXT, "t", "c", {})
    mod = LearningModule(
        title="M",
        description="D",
        objectives=[obj],
        content_elements=[el],
        duration_minutes=45,
        difficulty_level="beginner",
    )
    assert mod.objectives[0].objective == "A"
    assert mod.content_elements[0].content_type is ContentType.TEXT
    assert mod.duration_minutes == 45
    # Default of optional quality_assessment field
    assert mod.quality_assessment is None


def test_content_analysis_holds_lists_and_metrics():
    from orchestrator.utils.content_types import ContentAnalysis, ContentType

    ca = ContentAnalysis(
        key_concepts=["a", "b"],
        learning_objectives=[],
        difficulty_level="advanced",
        estimated_duration=120,
        recommended_formats=[ContentType.PRESENTATION, ContentType.QUIZ],
        quality_metrics={"clarity": 0.9, "depth": 0.7},
    )
    assert ca.key_concepts == ["a", "b"]
    assert ContentType.QUIZ in ca.recommended_formats
    assert ca.quality_metrics["clarity"] == pytest.approx(0.9)
