"""
Tests for:
  - _extract_bug_report — LLM JSON parsing + severity sorting (patch the LLM)
  - _make_conftest — generated conftest.py string shape
  - _safe_name (pulled from the module — via reflection into the internal function
    defined inside the conftest template string, we instead exercise the public
    copy that appears in server.py at top-level).
"""
from __future__ import annotations

import json
import sys
import types
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest


class _FakeChatAzureOpenAI:
    """Placeholder — individual tests patch this on the fake `browser_use` module."""

    def __init__(self, *a, **kw):
        pass

    async def ainvoke(self, messages):  # pragma: no cover - overridden in tests
        raise NotImplementedError


def _install_fake_browser_use():
    """Install a stub `browser_use` module before server imports it.

    The real `browser_use` package fails to import here because it pulls in
    `psutil` (not installed in the test venv). Since `_extract_bug_report`
    imports `browser_use` lazily inside the function body, we only need the
    stub present before the call — it is safe to register it ahead of time.
    """
    mod = types.ModuleType("browser_use")
    mod.ChatAzureOpenAI = _FakeChatAzureOpenAI
    sub = types.ModuleType("browser_use.llm")
    msgs = types.ModuleType("browser_use.llm.messages")

    class _Msg:
        def __init__(self, content: str = ""):
            self.content = content

    msgs.SystemMessage = _Msg
    msgs.UserMessage = _Msg
    sys.modules["browser_use"] = mod
    sys.modules["browser_use.llm"] = sub
    sys.modules["browser_use.llm.messages"] = msgs


@pytest.fixture
def server_mod():
    _install_fake_browser_use()
    import server
    return server


# ---------------------------------------------------------------------------
# _extract_bug_report
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_extract_bug_report_happy_path_sorts_by_severity(server_mod):
    """LLM returns a JSON array; we verify parsing, sorting, counts."""
    llm_json = json.dumps([
        {"severity": "Low", "category": "UI", "title": "Typo",
         "description": "small typo", "steps_to_reproduce": ["open page"]},
        {"severity": "Critical", "category": "Security", "title": "Auth bypass",
         "description": "skip login", "steps_to_reproduce": ["bypass"]},
        {"severity": "Medium", "category": "Validation", "title": "No email validation",
         "description": "bad email ok", "steps_to_reproduce": ["fill"]},
    ])

    fake_llm = SimpleNamespace()
    fake_llm.ainvoke = AsyncMock(
        return_value=SimpleNamespace(completion=llm_json)
    )

    with patch.dict(sys.modules["browser_use"].__dict__, {"ChatAzureOpenAI": lambda *a, **k: fake_llm}):
        report = await server_mod._extract_bug_report(
            task_id="t1",
            target_url="https://ex.com",
            agent_output="some agent output",
            llm_model="gpt-5.4-mini",
        )

    assert report.task_id == "t1"
    assert report.total_bugs == 3
    # Sorted Critical → Medium → Low
    severities = [b.severity for b in report.bugs]
    assert severities == ["Critical", "Medium", "Low"]
    # IDs are assigned in the ORIGINAL input order (pre-sort). Verify IDs exist.
    assert all(b.id.startswith("BUG-") for b in report.bugs)
    assert report.critical_count == 1
    assert report.medium_count == 1
    assert report.low_count == 1
    assert "3 bugs" in report.summary


@pytest.mark.asyncio
async def test_extract_bug_report_strips_markdown_code_fences(server_mod):
    """LLM output wrapped in ```json ... ``` should still parse."""
    fenced = "```json\n" + json.dumps([
        {"severity": "High", "category": "Functional", "title": "Broken link",
         "description": "404 on click", "steps_to_reproduce": ["click"]},
    ]) + "\n```"
    fake_llm = SimpleNamespace(
        ainvoke=AsyncMock(return_value=SimpleNamespace(completion=fenced))
    )
    with patch.dict(sys.modules["browser_use"].__dict__, {"ChatAzureOpenAI": lambda *a, **k: fake_llm}):
        report = await server_mod._extract_bug_report(
            "t", "https://ex.com", "agent output", "gpt-5.4-mini"
        )
    assert report.total_bugs == 1
    assert report.bugs[0].severity == "High"


@pytest.mark.asyncio
async def test_extract_bug_report_empty_input_returns_empty_report(server_mod):
    """No agent output → skip LLM, return an empty report."""
    # Do NOT patch the LLM — the function should short-circuit first.
    report = await server_mod._extract_bug_report(
        "t", "https://ex.com", "", "gpt-5.4-mini"
    )
    assert report.total_bugs == 0
    assert report.bugs == []


@pytest.mark.asyncio
async def test_extract_bug_report_invalid_severity_defaults_to_low(server_mod):
    """Unknown severities are coerced to 'Low'."""
    out = json.dumps([
        {"severity": "Catastrophic", "category": "Security", "title": "X",
         "description": "y", "steps_to_reproduce": ["z"]},
    ])
    fake_llm = SimpleNamespace(
        ainvoke=AsyncMock(return_value=SimpleNamespace(completion=out))
    )
    with patch.dict(sys.modules["browser_use"].__dict__, {"ChatAzureOpenAI": lambda *a, **k: fake_llm}):
        report = await server_mod._extract_bug_report(
            "t", "https://ex.com", "out", "gpt-5.4-mini"
        )
    assert report.total_bugs == 1
    assert report.bugs[0].severity == "Low"


@pytest.mark.asyncio
async def test_extract_bug_report_invalid_category_defaults_to_functional(server_mod):
    out = json.dumps([
        {"severity": "Low", "category": "InventedCategory",
         "title": "X", "description": "y", "steps_to_reproduce": ["z"]},
    ])
    fake_llm = SimpleNamespace(
        ainvoke=AsyncMock(return_value=SimpleNamespace(completion=out))
    )
    with patch.dict(sys.modules["browser_use"].__dict__, {"ChatAzureOpenAI": lambda *a, **k: fake_llm}):
        report = await server_mod._extract_bug_report(
            "t", "https://ex.com", "out", "gpt-5.4-mini"
        )
    assert report.bugs[0].category == "Functional"


# ---------------------------------------------------------------------------
# _make_conftest
# ---------------------------------------------------------------------------
def test_make_conftest_without_auth_state(server_mod):
    out = server_mod._make_conftest("task-abc")
    # Must embed the task id
    assert 'TASK_ID = "task-abc"' in out
    # Guest mode: AUTH_STATE is None
    assert "AUTH_STATE = None" in out
    # Must NOT inject storage_state kwarg when no auth file
    assert "storage_state=AUTH_STATE" not in out
    # Sanity: file declares page fixture + screenshot_on_failure hook
    assert "def page(request)" in out
    assert "screenshot_on_failure" in out


def test_make_conftest_with_auth_state_includes_storage_state(server_mod, tmp_path):
    auth_path = tmp_path / "auth.json"
    auth_path.write_text("{}", encoding="utf-8")
    out = server_mod._make_conftest("task-xyz", auth_state_path=str(auth_path))
    assert "task-xyz" in out
    # Authenticated path injects the kwarg
    assert "storage_state=AUTH_STATE" in out
    # Absolute path is baked in
    assert str(auth_path.resolve()) in out


# ---------------------------------------------------------------------------
# _save_feature_record & _save_bug_report — write to configurable dirs
# ---------------------------------------------------------------------------
def test_save_feature_record_writes_json_to_features_dir(server_mod, tmp_path, monkeypatch):
    features_dir = tmp_path / "features"
    monkeypatch.setattr(server_mod, "FEATURES_DIR", features_dir)
    rec = server_mod.FeatureRecord(
        task_id="t-save",
        target_url="https://ex.com/",
    )
    out_path = server_mod._save_feature_record(rec)
    assert out_path.name == "feature_t-save.json"
    data = json.loads(out_path.read_text(encoding="utf-8"))
    assert data["task_id"] == "t-save"


def test_save_bug_report_writes_json_to_bugs_dir(server_mod, tmp_path, monkeypatch):
    monkeypatch.setattr(server_mod, "BUGS_DIR", tmp_path / "bugs")
    rep = server_mod.BugReport(
        task_id="t-bug",
        target_url="https://ex.com/",
        generated_at=123.0,
    )
    out_path = server_mod._save_bug_report(rep)
    assert out_path.exists()
    data = json.loads(out_path.read_text(encoding="utf-8"))
    assert data["task_id"] == "t-bug"
