from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from auth import get_current_user
from models import UserResponse, UserRole
from redteam import runs
from redteam.diff import compare, failing_probes
from server import app


def f(probe, verdict, severity="high"):
    return {"probe_id": probe, "verdict": verdict, "severity": severity}


def test_failing_probes_uses_any_fail_and_highest_severity():
    out = failing_probes([f("p1", "pass", "info"), f("p1", "fail", "low"), f("p1", "fail", "critical"), f("p2", "pass")])
    assert out == {"p1": "critical"}


def test_unknown_severity_ranks_as_info():
    assert failing_probes([f("p", "fail", None), f("p", "fail", "weird")]) == {"p": "info"}


def test_compare_categories():
    base = [f("a", "fail"), f("b", "fail"), f("c", "fail"), f("d", "pass")]
    head = [f("a", "fail"), f("b", "pass"), f("d", "fail", "medium"), f("e", "fail", "low")]
    out = compare(base, head)
    assert out["still_failing"] == [{"probe_id": "a", "severity": "high"}]
    assert out["fixed"] == [{"probe_id": "b", "severity": "high"}]
    assert out["not_run"] == [{"probe_id": "c", "severity": "high"}]
    assert out["new"] == [{"probe_id": "d", "severity": "medium"}, {"probe_id": "e", "severity": "low"}]


def test_no_baseline_makes_every_failure_new():
    out = compare(None, [f("a", "fail"), f("b", "pass")])
    assert out == {"new": [{"probe_id": "a", "severity": "high"}], "fixed": [], "still_failing": [], "not_run": []}


def test_both_clean():
    assert compare([f("a", "pass")], [f("a", "pass")]) == {"new": [], "fixed": [], "still_failing": [], "not_run": []}


@pytest.fixture
def fake_user_id():
    return uuid4()


@pytest.fixture
def authenticated_client(fake_user_id, mock_db):
    def _fake_user():
        now = datetime.now(timezone.utc)
        return UserResponse(
            id=fake_user_id, username="t", email="t@x.com",
            display_name="T", role=UserRole.ORDINARY_USER, is_active=True,
            created_at=now, updated_at=now,
        )
    app.dependency_overrides[get_current_user] = _fake_user
    yield TestClient(app)
    app.dependency_overrides.pop(get_current_user, None)


def test_diff_route_returns_categories(authenticated_client, fake_user_id):
    head_id, base_id = uuid4(), uuid4()
    by_run = {
        base_id: [f("a", "fail"), f("b", "fail")],
        head_id: [f("a", "fail"), f("b", "pass"), f("n", "fail", "low")],
    }
    find = AsyncMock(return_value={"id": base_id})
    with patch("redteam.runs.get_run", AsyncMock(return_value={"id": head_id, "status": "completed", "repo": "o/r", "branch": "feat"})), \
         patch("redteam.runs.find_baseline_run", find), \
         patch("redteam.runs.list_findings", AsyncMock(side_effect=lambda rid: by_run[rid])):
        resp = authenticated_client.get(f"/api/v1/redteam/runs/{head_id}/diff?base=main")
    assert resp.status_code == 200
    body = resp.json()
    assert body["base_run_id"] == str(base_id)
    assert body["run_id"] == str(head_id)
    assert body["base_branch"] == "main"
    assert body["repo"] == "o/r"
    assert body["new"] == [{"probe_id": "n", "severity": "low"}]
    assert body["fixed"] == [{"probe_id": "b", "severity": "high"}]
    assert body["still_failing"] == [{"probe_id": "a", "severity": "high"}]
    assert body["not_run"] == []
    find.assert_awaited_once_with(fake_user_id, "o/r", "main", head_id)


def test_diff_route_without_baseline(authenticated_client):
    head_id = uuid4()
    with patch("redteam.runs.get_run", AsyncMock(return_value={"id": head_id, "repo": "o/r"})), \
         patch("redteam.runs.find_baseline_run", AsyncMock(return_value=None)), \
         patch("redteam.runs.list_findings", AsyncMock(return_value=[f("a", "fail"), f("b", "pass")])):
        resp = authenticated_client.get(f"/api/v1/redteam/runs/{head_id}/diff?base=main")
    assert resp.status_code == 200
    body = resp.json()
    assert body["base_run_id"] is None
    assert body["new"] == [{"probe_id": "a", "severity": "high"}]
    assert body["fixed"] == [] and body["still_failing"] == [] and body["not_run"] == []


def test_diff_route_404_for_unknown_run(authenticated_client):
    with patch("redteam.runs.get_run", AsyncMock(return_value=None)):
        resp = authenticated_client.get(f"/api/v1/redteam/runs/{uuid4()}/diff?base=main")
    assert resp.status_code == 404


def test_diff_route_409_when_run_has_no_repo(authenticated_client):
    head_id = uuid4()
    with patch("redteam.runs.get_run", AsyncMock(return_value={"id": head_id, "status": "completed"})):
        resp = authenticated_client.get(f"/api/v1/redteam/runs/{head_id}/diff?base=main")
    assert resp.status_code == 409


async def test_find_baseline_run_filters_by_user_repo_branch_status(mock_db):
    uid, hid = uuid4(), uuid4()
    mock_db.fetch_one.return_value = None
    assert await runs.find_baseline_run(uid, "o/r", "main", hid) is None
    sql, params = mock_db.fetch_one.await_args.args
    for frag in ("user_id = :user_id", "repo = :repo", "branch = :branch",
                 "status = 'completed'", "id <> :exclude", "ORDER BY finished_at DESC"):
        assert frag in sql
    assert params == {"user_id": uid, "repo": "o/r", "branch": "main", "exclude": hid}
