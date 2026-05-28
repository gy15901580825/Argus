import os
from orchestrator import config


def test_planner_defaults():
    assert config.PLANNER_MODEL_PROVIDER == "anthropic"
    assert config.PLANNER_MODEL == "claude-opus-4-7"
    assert config.PLANNER_FALLBACK_MODEL == "gpt-5.4-mini"
    assert config.PLANNER_MAX_STEPS == 15
    assert config.PLANNER_HISTORY_LIMIT == 5
    assert config.PLANNER_ASK_USER_CAP == 2


def test_planner_env_override(monkeypatch):
    monkeypatch.setenv("PLANNER_MAX_STEPS", "7")
    import importlib
    importlib.reload(config)
    assert config.PLANNER_MAX_STEPS == 7
