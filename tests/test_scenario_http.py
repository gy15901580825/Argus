import json
from uuid import uuid4

from fastapi import FastAPI
from fastapi.testclient import TestClient

from argus.scenarios import api
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
