"""L3 tests for web_ui_runner pure logic — bug counting, phase math, task
lifecycle, domain extraction, LLM proxy config. No real browser-use, no real
HTTP.
"""
from __future__ import annotations

import threading
import time
from unittest.mock import patch

import pytest


# ---------------------------------------------------------------------------
# _extract_domain
# ---------------------------------------------------------------------------

def test_extract_domain_strips_path_and_preserves_scheme():
    import web_ui_runner

    assert web_ui_runner._extract_domain("https://foo.example.com/a/b?q=1") == \
        "https://foo.example.com"
    assert web_ui_runner._extract_domain("http://x.invalid") == "http://x.invalid"


def test_extract_domain_returns_input_when_no_netloc():
    import web_ui_runner

    # A malformed URL without netloc falls back to the raw input string.
    out = web_ui_runner._extract_domain("not-a-url")
    assert out == "not-a-url"


# ---------------------------------------------------------------------------
# _count_bugs
# ---------------------------------------------------------------------------

def test_count_bugs_classifies_by_severity():
    import web_ui_runner

    report = """
    Some intro text.
    BUG-01: CRITICAL SEC Authentication bypass on /admin
    BUG-02: HIGH FUNC Form cannot submit
    BUG-03: MEDIUM VAL Missing validation
    BUG-04: LOW UX Minor label typo
    BUG-05: CRITICAL SEC Another critical issue
    NOTE-01: some observation
    NOTE-02: another observation
    VAL-1: [DONE] — tested submit
    FUNC-1: [DONE] — nav ok
    SEC-1: [DONE] — xss tested
    REDIRECT: /out → https://ext.com | FAIL | 404 destination
    """
    counts = web_ui_runner._count_bugs(report)

    assert counts["critical"] == 2
    assert counts["high"] == 1
    assert counts["medium"] == 1
    assert counts["low"] == 1
    assert counts["redirect_fail"] == 1
    assert counts["observations"] == 2
    assert counts["phase3_coverage"] == 3  # VAL-1, FUNC-1, SEC-1
    assert counts["phase3_total"] == 18


def test_count_bugs_empty_input_returns_zeros():
    import web_ui_runner

    counts = web_ui_runner._count_bugs("")
    assert counts["critical"] == 0
    assert counts["high"] == 0
    assert counts["medium"] == 0
    assert counts["low"] == 0
    assert counts["phase3_coverage"] == 0
    assert counts["observations"] == 0


def test_count_bugs_propagates_cdp_counters():
    import web_ui_runner

    counts = web_ui_runner._count_bugs("no bugs here", console_errors=4, network_errors=2)
    assert counts["console_errors"] == 4
    assert counts["network_errors"] == 2


# ---------------------------------------------------------------------------
# _get_llm_proxy_config
# ---------------------------------------------------------------------------

def test_get_llm_proxy_config_raises_when_credentials_unset():
    import web_ui_runner

    web_ui_runner._api_service_url = None
    web_ui_runner._api_access_token = None
    with pytest.raises(RuntimeError, match="API Service credentials"):
        web_ui_runner._get_llm_proxy_config()


def test_get_llm_proxy_config_normalizes_base_url_and_returns_token():
    import web_ui_runner

    web_ui_runner.set_api_credentials("http://api.invalid/", "jwt-xyz")
    base, key = web_ui_runner._get_llm_proxy_config()
    assert base == "http://api.invalid/api/v1/llm"
    assert key == "jwt-xyz"

    # When URL already contains /api/v1, it is not doubled up.
    web_ui_runner.set_api_credentials("http://api.invalid/api/v1", "jwt2")
    base2, _ = web_ui_runner._get_llm_proxy_config()
    assert base2 == "http://api.invalid/api/v1/llm"

    # Clean up module globals to avoid leaking state between tests.
    web_ui_runner._api_service_url = None
    web_ui_runner._api_access_token = None


# ---------------------------------------------------------------------------
# Task lifecycle: start / status / result / cancel
# ---------------------------------------------------------------------------

@pytest.fixture
def clean_tasks():
    """Reset web_ui_runner module-level task state before and after each test."""
    import web_ui_runner
    web_ui_runner._tasks.clear()
    web_ui_runner._cancel_events.clear()
    yield
    web_ui_runner._tasks.clear()
    web_ui_runner._cancel_events.clear()


def test_start_web_ui_test_returns_task_id_and_seeds_task_dict(clean_tasks):
    import web_ui_runner

    # Stub Thread on the real `threading` module so no background runner
    # ever fires. start_web_ui_test re-imports `threading` inside the
    # function body, so module-level patching on web_ui_runner won't help.
    class _NoRunThread:
        def __init__(self, *a, **kw):
            self.name = kw.get("name", "fake-thread")

        def start(self):
            return None

    with patch("threading.Thread", _NoRunThread):
        result = web_ui_runner.start_web_ui_test(
            url="http://t.invalid/",
            max_steps=30,
            user_persona="new_user",
        )

    assert "task_id" in result
    assert result["status"] == "pending"

    tid = result["task_id"]
    task = web_ui_runner._tasks[tid]
    assert task["url"] == "http://t.invalid/"
    assert task["status"] == "pending"
    assert task["max_steps"] == 30
    assert task["steps_done"] == 0
    assert task["script_model"]  # defaulted from env or constant


def test_get_web_ui_test_status_unknown_task_returns_error(clean_tasks):
    import web_ui_runner

    out = web_ui_runner.get_web_ui_test_status("not-a-task")
    assert out == {"error": "Task not-a-task not found"}


def test_get_web_ui_test_status_drops_test_script(clean_tasks):
    import web_ui_runner

    web_ui_runner._tasks["T"] = {
        "task_id": "T",
        "status": "completed",
        "steps_done": 5,
        "test_script": "def test_x(): pass",  # must NOT be in status
    }
    out = web_ui_runner.get_web_ui_test_status("T")
    assert "test_script" not in out
    assert out["status"] == "completed"


def test_get_web_ui_test_result_returns_full_record(clean_tasks):
    import web_ui_runner

    web_ui_runner._tasks["T"] = {
        "task_id": "T",
        "status": "completed",
        "test_script": "def test_x(): pass",
    }
    out = web_ui_runner.get_web_ui_test_result("T")
    assert out["test_script"] == "def test_x(): pass"


def test_cancel_web_ui_test_sets_event_and_marks_cancelled(clean_tasks):
    import web_ui_runner

    web_ui_runner._tasks["T"] = {
        "task_id": "T",
        "status": "running",
    }
    ev = threading.Event()
    web_ui_runner._cancel_events["T"] = ev

    out = web_ui_runner.cancel_web_ui_test("T")
    assert out == {"task_id": "T", "status": "cancelled"}
    assert ev.is_set() is True
    assert web_ui_runner._tasks["T"]["status"] == "cancelled"


def test_cancel_web_ui_test_no_op_for_non_running_task(clean_tasks):
    import web_ui_runner

    web_ui_runner._tasks["T"] = {"task_id": "T", "status": "completed"}
    out = web_ui_runner.cancel_web_ui_test("T")
    assert out["status"] == "completed"
    assert "not running" in out["message"].lower()


def test_cancel_web_ui_test_unknown_task_returns_error(clean_tasks):
    import web_ui_runner

    out = web_ui_runner.cancel_web_ui_test("ghost")
    assert "not found" in out["error"]


def test_set_api_credentials_stores_values_in_module_globals():
    import web_ui_runner

    web_ui_runner.set_api_credentials("http://foo.invalid", "tk-1")
    assert web_ui_runner._api_service_url == "http://foo.invalid"
    assert web_ui_runner._api_access_token == "tk-1"
    # Clean up
    web_ui_runner._api_service_url = None
    web_ui_runner._api_access_token = None
