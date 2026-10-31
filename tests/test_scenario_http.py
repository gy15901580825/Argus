import asyncio
import json
from uuid import uuid4

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from argus.scenarios import api
from argus.scenarios.models import ObjectRecord, object_marker
from test_scenario_runner import Driver, Target, scenario


def test_actual_sse_route_emits_phase_object_finding_and_end(monkeypatch, tmp_path):
    monkeypatch.setenv("ARGUS_SERVER_TOKEN", "server-token")
    monkeypatch.setenv("ARGUS_SCENARIO_RUN_DIR", str(tmp_path))
    driver = Driver()
    monkeypatch.setattr(api, "build_credential_provider", lambda *args: object())
    monkeypatch.setattr(api, "build_drivers", lambda *args: {"fake": driver})
    monkeypatch.setattr(api, "build_target", lambda *args: Target(driver))
    app = FastAPI()
    app.include_router(api.router)
    spec = scenario(observe=[{"driver": "fake", "collect": "drafts_diff", "window_s": 0}])
    body = {"run_id": str(uuid4()), "organization_id": str(uuid4()), "scenario": spec.model_dump(mode="json"), "target": {},
            "connections": {"operator": "op", "observer": "obs"}, "credential_provider": {"kind": "fake", "config": {}}, "run_token": "RUN-TOKEN-SENTINEL"}
    with TestClient(app) as client:
        response = client.post("/redteam/scenario/run", headers={"Authorization": "Bearer server-token"}, json=body)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    events = [json.loads(line[6:]) for line in response.text.splitlines() if line.startswith("data: ")]
    assert {e["type"] for e in events} >= {"phase", "object", "finding", "end"}
    finding = next(e["finding"] for e in events if e["type"] == "finding")
    assert finding["verdict"] == "pass"
    assert finding["evidence"]["scenario"]["outcome"] == "defended"
    assert "RUN-TOKEN-SENTINEL" not in response.text
    assert not api._active_runs


def test_actual_cleanup_route_discovers_objects_with_empty_registry(monkeypatch, tmp_path):
    monkeypatch.setenv("ARGUS_SERVER_TOKEN", "server-token")
    monkeypatch.setenv("ARGUS_SCENARIO_RUN_DIR", str(tmp_path))
    driver = Driver()
    async def recover(ctx, spec):
        obj = await driver.prepare(ctx, "seed", spec.objects["seed"])
        return [obj]
    driver.recover = recover
    monkeypatch.setattr(api, "build_credential_provider", lambda *args: object())
    monkeypatch.setattr(api, "build_drivers", lambda *args: {"fake": driver})
    body = {"run_id": str(uuid4()), "organization_id": str(uuid4()), "scenario": scenario().model_dump(mode="json"),
            "connections": {"operator": "op", "observer": "obs"}, "credential_provider": {"kind": "fake"}, "run_token": "cleanup-token", "objects": []}
    app = FastAPI()
    app.include_router(api.router)
    with TestClient(app) as client:
        response = client.post("/redteam/scenario/cleanup", headers={"Authorization": "Bearer server-token"}, json=body)
    assert response.status_code == 200
    assert response.json()["organization_id"] == body["organization_id"]
    assert response.json()["complete"] is True
    assert len(response.json()["objects"]) == 1


def test_cleanup_discovery_failure_cannot_claim_complete(monkeypatch, tmp_path):
    monkeypatch.setenv("ARGUS_SERVER_TOKEN", "server-token")
    monkeypatch.setenv("ARGUS_SCENARIO_RUN_DIR", str(tmp_path))
    driver = Driver()
    async def recover(ctx, spec):
        raise PermissionError()
    driver.recover = recover
    monkeypatch.setattr(api, "build_credential_provider", lambda *args: object())
    monkeypatch.setattr(api, "build_drivers", lambda *args: {"fake": driver})
    body = {"run_id": str(uuid4()), "organization_id": str(uuid4()), "scenario": scenario().model_dump(mode="json"),
            "connections": {"operator": "op", "observer": "obs"}, "credential_provider": {"kind": "fake"}, "run_token": "cleanup-token", "objects": []}
    app = FastAPI()
    app.include_router(api.router)
    with TestClient(app) as client:
        response = client.post("/redteam/scenario/cleanup", headers={"Authorization": "Bearer server-token"}, json=body)
    assert response.status_code == 200
    assert response.json()["complete"] is False
    assert response.json()["gaps"]


@pytest.mark.parametrize("blocked_operation, include_registry", [("recover", False), ("recover", True), ("cleanup", True)])
async def test_cleanup_timeout_returns_registry_and_cancels_driver(monkeypatch, tmp_path, blocked_operation, include_registry):
    monkeypatch.setenv("ARGUS_SERVER_TOKEN", "server-token")
    monkeypatch.setenv("ARGUS_SCENARIO_RUN_DIR", str(tmp_path))
    monkeypatch.setattr(api, "CLEANUP_RESERVE_S", 0.01)
    release = asyncio.Event()
    stopped = asyncio.Event()
    completed = []
    driver = Driver()

    async def blocked(*args):
        try:
            await release.wait()
            completed.append(blocked_operation)
        finally:
            stopped.set()

    if blocked_operation == "recover":
        driver.recover = blocked
    else:
        driver.cleanup = blocked
    monkeypatch.setattr(api, "build_credential_provider", lambda *args: object())
    monkeypatch.setattr(api, "build_drivers", lambda *args: {"fake": driver})
    run_id = str(uuid4())
    objects = [ObjectRecord(run_id=run_id, group="test", logical_key=key, provider="fake", external_id=key,
                            marker=object_marker(run_id, "test", key), owner="owner", connection_id="op",
                            cleanup_status="deleted" if key == "done" else "pending")
               for key in (["seed", "remaining", "done"] if include_registry else [])]
    body = {"run_id": run_id, "organization_id": str(uuid4()), "scenario": scenario().model_dump(mode="json"),
            "connections": {"operator": "op", "observer": "obs"}, "credential_provider": {"kind": "fake"},
            "run_token": "cleanup-token", "objects": [obj.model_dump(mode="json") for obj in objects]}
    app = FastAPI()
    app.include_router(api.router)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await asyncio.wait_for(client.post("/redteam/scenario/cleanup",
                                          headers={"Authorization": "Bearer server-token"}, json=body), timeout=1)
    assert response.status_code == 200
    result = response.json()
    assert result["complete"] is False
    assert result["gaps"]
    statuses = {obj["logical_key"]: obj["cleanup_status"] for obj in result["objects"]}
    assert statuses == ({"seed": "failed", "remaining": "failed", "done": "deleted"} if include_registry else {})
    registry_path = tmp_path / run_id / "objects.json"
    saved = json.loads(registry_path.read_text()) if registry_path.exists() else []
    assert {obj["logical_key"]: obj["cleanup_status"] for obj in saved} == statuses
    assert stopped.is_set()
    release.set()
    await asyncio.sleep(0)
    assert completed == []
