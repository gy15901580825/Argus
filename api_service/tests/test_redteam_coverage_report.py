"""覆盖率清单渲染进 HTML 报告。

这张表的产品价值就是它敢显示空白——一个只有一个 probe 的 OWASP 分类、
或者因为目标类型不匹配而整类跳过的分类。渲染时把空白抹平（不显示
thin/absent，或者把 skipped 悄悄藏起来）就等于把这个功能做没了。

`get_run_report` 是显式组装字典交给 render_html() 的，不是把数据库行
整个传过去 —— Plan 1 已经在 target_spec 上踩过这个坑一次（模板里加了
`run.target_spec.kind`，`get_run_report` 忘了拷 `target_spec`，测试全绿，
生产环境却是死代码）。coverage 会一字不差地重演，所以本文件除了
render_html() 级别的测试外，必须有至少一条测试走完整路由。
"""
import json
from unittest.mock import patch
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from redteam.reports import render_html

_COV = {
    "thin_threshold": 2,
    "totals": {"probes_in_library": 5, "probes_run": 1},
    "standards": {"owasp-llm-top10": {"universe": "closed", "cells": [
        {"id": "LLM01", "name": "Prompt Injection", "probes_in_library": 4,
         "probes_run": 1, "library_status": "covered", "run_status": "tested",
         "verdicts": {"pass": 1}},
        {"id": "LLM07", "name": "System Prompt Leakage", "probes_in_library": 1,
         "probes_run": 0, "library_status": "thin", "run_status": "not_run",
         "verdicts": {}},
        {"id": "LLM10", "name": "Unbounded Consumption", "probes_in_library": 0,
         "probes_run": 0, "library_status": "absent", "run_status": "not_run",
         "verdicts": {}},
    ]}, "mitre-atlas": {"universe": "open", "cells": []},
        "nist-ai-rmf": {"universe": "open", "cells": []},
        "eu-ai-act": {"universe": "open", "cells": []}},
}


def _run(**kw):
    base = {"id": "1", "status": "completed", "findings": []}
    base.update(kw)
    return base


def test_report_shows_the_thin_and_absent_cells():
    """这张表的产品价值就是它敢显示空白 —— 空白必须出现在 HTML 里。"""
    html = render_html(_run(coverage=_COV))
    assert "LLM07" in html and "LLM10" in html
    assert "thin" in html.lower()
    assert "absent" in html.lower() or "no probe" in html.lower()


def test_open_universe_is_labelled_so_it_is_not_read_as_full_coverage():
    html = render_html(_run(coverage=_COV))
    assert "mitre-atlas" in html.lower() or "ATLAS" in html


def test_report_without_coverage_still_renders():
    """V25 之前的运行 coverage 为 NULL,报告不能因此挂掉。"""
    html = render_html(_run(coverage=None))
    assert "<html" in html.lower() or "<!doctype" in html.lower()


# ---------------------------------------------------------------------------
# Route-level test: get_run_report explicitly assembles run_dict by hand, so
# a renderer-level test alone cannot catch it forgetting to copy `coverage`
# out of the DB row. This test goes through the actual endpoint.
# ---------------------------------------------------------------------------
from server import app  # noqa: E402
from auth import get_current_user  # noqa: E402
from models import UserResponse, UserRole  # noqa: E402


@pytest.fixture
def fake_user_id():
    return uuid4()


@pytest.fixture
def authenticated_client(fake_user_id, mock_db):
    def _fake_user():
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        return UserResponse(
            id=fake_user_id, username="t", email="t@x.com",
            display_name="T", role=UserRole.ORDINARY_USER, is_active=True,
            created_at=now, updated_at=now,
        )
    app.dependency_overrides[get_current_user] = _fake_user
    yield TestClient(app)
    app.dependency_overrides.pop(get_current_user, None)


async def _noop_create_run(*args, **kwargs):
    return


async def _empty_stream(*args, **kwargs):
    return
    yield  # unreachable; makes this an async generator function


def test_get_redteam_report_html_shows_coverage_through_the_route(authenticated_client, mock_db, fake_user_id):
    """coverage comes back from the DB as a JSONB string on the run row, exactly
    like target_spec did in the bug this test exists to prevent a repeat of.
    If get_run_report doesn't copy `coverage` into run_dict, this fails while
    every render_html()-only test above stays green."""
    body = {"target": {"kind": "openai_compat", "endpoint_url": "https://x", "model": "y"}, "probe_ids": ["p1"]}
    run_uuid = uuid4()
    mock_db.fetch_one.side_effect = [
        {"id": run_uuid},
        {
            "id": run_uuid, "user_id": fake_user_id, "status": "completed",
            "coverage": json.dumps(_COV),
        },
    ]
    mock_db.fetch_all.return_value = []

    with patch("redteam.orchestrator_client.create_run", _noop_create_run), \
         patch("redteam.orchestrator_client.stream_findings", _empty_stream):
        run_resp = authenticated_client.post("/api/v1/redteam/runs", json=body)
    rid = run_resp.json()["run_id"]

    resp = authenticated_client.get(f"/api/v1/redteam/runs/{rid}/report?format=html")
    assert resp.status_code == 200
    assert "LLM07" in resp.text
    assert "thin" in resp.text.lower()
