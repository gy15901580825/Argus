"""Contract tests for the integration-scenario HTTP API and plugin entry-point groups.

Downstream integrations call POST /redteam/scenario/run and /redteam/scenario/cleanup, and plugin
packages register under argus.drivers and argus.credential_providers. A failure here is a breaking
change: update the fixture or test on purpose and list the change in the release notes.
"""
import json
import sys
from importlib.metadata import EntryPoint
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr

from argus.scenarios import api, credentials, runtime
from argus.scenarios.models import ObjectRecord, object_marker

FIXTURE = Path(__file__).parent / "fixtures" / "scenario_api" / "request_schemas.json"
REGENERATE = "python tests/test_scenario_api_contract.py --regenerate"
TOKEN = "server-token"
AUTH = {"Authorization": f"Bearer {TOKEN}"}
DRIVER_GROUP = "argus.drivers"
PROVIDER_GROUP = "argus.credential_providers"

EVENT_TYPES = {"phase", "object", "heartbeat", "finding", "end", "error"}
EVENT_BASE = {"type", "run_id", "organization_id", "control_name"}
EVENT_FIELDS = {
    "phase": EVENT_BASE | {"phase", "heartbeat_at"},
    "object": EVENT_BASE | {"object"},
    "finding": EVENT_BASE | {"finding"},
    "end": EVENT_BASE | {"outcome", "complete"},
    "error": EVENT_BASE | {"detail"},
    "heartbeat": {"type", "run_id", "organization_id", "phase", "heartbeat_at"},
}
PHASES = {"prepare", "readiness", "baseline", "test", "observe", "judge", "cleanup"}
OBJECT_FIELDS = {"run_id", "group", "control_name", "logical_key", "provider", "external_id", "marker", "owner",
                 "connection_id", "version", "cleanup_status", "cleanup_detail"}
FINDING_FIELDS = {"id", "probe_id", "attack_prompt", "target_response", "target_latency_ms", "probed_at", "verdict",
                  "severity", "confidence", "reasoning", "judge_model", "escalated_model", "atlas_id", "owasp_id",
                  "owasp_agentic", "nist_id", "eu_ai_act_id", "created_at", "evidence", "remediation",
                  "remediation_actions", "events"}
CLEANUP_FIELDS = {"run_id", "organization_id", "complete", "gaps", "objects"}

RUN_NOT_CONFIGURED = (422, "scenario target or integration plugins are not configured")
CLEANUP_INVALID = (422, "cleanup context or plugins are invalid")
AUTH_NOT_CONFIGURED = (503, "scenario server authentication is not configured")
AUTH_REJECTED = (401, "missing or invalid bearer token")
PROVIDER_MISSING = "credential provider is not installed or is ambiguous"


# --- request schemas ---------------------------------------------------------------------------

def normalise(node):
    """Drop documentation-only keys so wording edits don't count as contract changes."""
    if isinstance(node, dict):
        return {k: normalise(v) for k, v in node.items() if k not in {"title", "description"}}
    if isinstance(node, list):
        return [normalise(v) for v in node]
    return node


def current_schemas() -> dict:
    return {model.__name__: normalise(model.model_json_schema())
            for model in (api.ScenarioRunRequest, api.ScenarioCleanupRequest)}


def _models(schema: dict) -> dict:
    """Map every object model in a schema (top level and $defs) to its properties and required set."""
    found = {"<root>": schema}
    found.update(schema.get("$defs", {}))
    return {name: (set(m.get("properties", {})), set(m.get("required", [])))
            for name, m in found.items() if "properties" in m}


def schema_drift(name: str, pinned: dict, current: dict) -> list[str]:
    problems = []
    old, new = _models(pinned), _models(current)
    for model in sorted(old.keys() - new.keys()):
        problems.append(f"{name}: model {model} was removed (breaking for downstream integrations)")
    for model in sorted(old.keys() & new.keys()):
        (old_props, old_req), (new_props, new_req) = old[model], new[model]
        for field in sorted(old_props - new_props):
            problems.append(f"{name}.{model}: field '{field}' was removed or renamed (breaking for downstream integrations)")
        for field in sorted((new_req - old_req) & old_props):
            problems.append(f"{name}.{model}: existing field '{field}' became required (breaking for downstream integrations)")
        for field in sorted(new_props - old_props):
            kind = "required" if field in new_req else "optional"
            problems.append(f"{name}.{model}: new {kind} field '{field}'. "
                            f"Update the fixture with `{REGENERATE}` and note the change in the release notes")
    for model in sorted(new.keys() - old.keys()):
        problems.append(f"{name}: new model {model}. Update the fixture with `{REGENERATE}` and note the change in the release notes")
    if not problems and pinned != current:
        problems.append(f"{name}: field types or constraints changed. Review the diff, update the fixture with "
                        f"`{REGENERATE}` and note the change in the release notes")
    return problems


def test_request_schemas_match_pinned_fixture():
    pinned = json.loads(FIXTURE.read_text())
    current = current_schemas()
    problems = [p for name in pinned["schemas"] for p in schema_drift(name, pinned["schemas"][name], current.get(name, {}))]
    problems += [f"{name}: new request model is not pinned" for name in current.keys() - pinned["schemas"].keys()]
    assert not problems, "Scenario API request schema drift:\n" + "\n".join(problems)


def test_schema_drift_messages_classify_changes():
    base = {"properties": {"a": {}, "b": {}}, "required": ["a"]}
    assert "removed or renamed" in schema_drift("M", base, {"properties": {"a": {}}, "required": ["a"]})[0]
    assert "became required" in schema_drift("M", base, {"properties": {"a": {}, "b": {}}, "required": ["a", "b"]})[0]
    added = schema_drift("M", base, {"properties": {"a": {}, "b": {}, "c": {}}, "required": ["a"]})
    assert "new optional field 'c'" in added[0] and "release notes" in added[0]
    assert "types or constraints" in schema_drift("M", base, {"properties": {"a": {"type": "x"}, "b": {}}, "required": ["a"]})[0]


# --- stub plugins registered through entry points ---------------------------------------------

class StubProvider:
    def __init__(self, config, run_token, connections):
        self.config, self.run_token, self.connections = config, run_token, connections


class OtherStubProvider(StubProvider):
    pass


CREATED_DRIVERS: list = []


def stub_driver(config, provider):
    from test_scenario_runner import Driver
    driver = Driver()
    driver.invalid = bool(config.get("invalid"))
    CREATED_DRIVERS.append(driver)
    return driver


def _ep(group, name, value):
    return EntryPoint(name=name, value=f"{__name__}:{value}", group=group)


@pytest.fixture
def plugins(monkeypatch):
    """Replace installed entry points with stubs; only the documented group names resolve."""
    registry = {DRIVER_GROUP: [_ep(DRIVER_GROUP, "fake", "stub_driver")],
                PROVIDER_GROUP: [_ep(PROVIDER_GROUP, "stub", "StubProvider"),
                                 _ep(PROVIDER_GROUP, "twice", "StubProvider"),
                                 _ep(PROVIDER_GROUP, "twice", "OtherStubProvider")]}

    def entry_points(*, group):
        queried.append(group)
        return list(registry.get(group, []))

    queried: list[str] = []
    registry["queried"] = queried

    monkeypatch.setattr(credentials, "entry_points", entry_points)
    monkeypatch.setattr(runtime, "entry_points", entry_points)
    return registry


@pytest.fixture
def client(monkeypatch, tmp_path, plugins):
    from test_scenario_runner import Target
    monkeypatch.setenv("ARGUS_SERVER_TOKEN", TOKEN)
    monkeypatch.setenv("ARGUS_SCENARIO_RUN_DIR", str(tmp_path))
    # Targets have their own plugin mechanism; a stub target keeps these tests offline.
    monkeypatch.setattr(api, "build_target", lambda spec: Target(CREATED_DRIVERS[-1]))
    app = FastAPI()
    app.include_router(api.router)
    with TestClient(app) as test_client:
        yield test_client


def run_body(provider="stub", drivers=None, **scenario_updates):
    from test_scenario_runner import scenario
    spec = scenario(observe=[{"driver": "fake", "collect": "drafts_diff", "window_s": 0}], **scenario_updates)
    return {"run_id": str(uuid4()), "organization_id": str(uuid4()), "scenario": spec.model_dump(mode="json"),
            "target": {}, "connections": {"operator": "op", "observer": "obs"},
            "credential_provider": {"kind": provider, "config": {}, "drivers": drivers or {}}, "run_token": "run-token"}


def cleanup_body(objects=(), provider="stub"):
    from test_scenario_runner import scenario
    return {"run_id": str(uuid4()), "organization_id": str(uuid4()), "scenario": scenario().model_dump(mode="json"),
            "connections": {"operator": "op", "observer": "obs"}, "credential_provider": {"kind": provider},
            "run_token": "cleanup-token", "objects": list(objects)}


def parse_stream(text: str) -> list[dict]:
    """Parse the SSE body, asserting the framing produced by api.encode on every frame."""
    assert text.endswith("\n\n"), "every SSE frame must end with a blank line"
    events = []
    for frame in text[:-2].split("\n\n"):
        lines = frame.split("\n")
        assert len(lines) == 2 and lines[0].startswith("event: ") and lines[1].startswith("data: "), f"bad SSE frame: {frame!r}"
        event = json.loads(lines[1][len("data: "):])
        assert lines[0] == f"event: {event['type']}", "SSE event name must equal the payload type"
        events.append(event)
    return events


def assert_event_contract(events: list[dict], body: dict):
    for event in events:
        assert event["type"] in EVENT_TYPES, f"undocumented scenario event type {event['type']!r}"
        missing = EVENT_FIELDS[event["type"]] - event.keys()
        assert not missing, f"{event['type']} event lost fields {sorted(missing)}"
        assert event["run_id"] == body["run_id"] and event["organization_id"] == body["organization_id"]
        if event["type"] == "phase":
            assert event["phase"] in PHASES
        if event["type"] == "object":
            assert set(event["object"]) == OBJECT_FIELDS
        if event["type"] == "finding":
            assert set(event["finding"]) == FINDING_FIELDS


# --- run stream --------------------------------------------------------------------------------

def test_encode_framing():
    assert api.encode({"type": "end", "run_id": "r"}) == b'event: end\ndata: {"type": "end", "run_id": "r"}\n\n'


def test_run_stream_success(client):
    body = run_body()
    response = client.post("/redteam/scenario/run", headers=AUTH, json=body)
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("text/event-stream")
    events = parse_stream(response.text)
    assert_event_contract(events, body)
    assert {e["type"] for e in events} == {"phase", "object", "finding", "end"}
    assert [e["type"] for e in events][-2:] == ["finding", "end"]
    assert events[-1]["outcome"] == "defended" and events[-1]["complete"] is True
    assert events[-2]["finding"]["verdict"] == "pass"


def test_run_stream_failed_outcome(client):
    body = run_body(drivers={"fake": {"invalid": True}})
    response = client.post("/redteam/scenario/run", headers=AUTH, json=body)
    assert response.status_code == 200, response.text
    events = parse_stream(response.text)
    assert_event_contract(events, body)
    assert [e["type"] for e in events][-2:] == ["finding", "end"]
    assert events[-1]["outcome"] == "not_ready" and events[-1]["complete"] is True
    assert events[-2]["finding"]["verdict"] != "pass"


def test_run_stream_execution_error(client, monkeypatch):
    def broken(self, result):
        raise RuntimeError("boom")
    monkeypatch.setattr(api.ScenarioRunner, "finding", broken)
    body = run_body()
    events = parse_stream(client.post("/redteam/scenario/run", headers=AUTH, json=body).text)
    assert_event_contract(events, body)
    assert events[-1]["type"] == "error" and events[-1]["detail"] == "scenario execution failed"
    assert "end" not in {e["type"] for e in events}


def test_run_stream_heartbeat(client, monkeypatch):
    import asyncio

    class FastIdle:
        def __getattr__(self, name):
            return getattr(asyncio, name)

        @staticmethod
        def wait_for(awaitable, timeout):
            return asyncio.wait_for(awaitable, 0.01 if timeout == 30 else timeout)

    monkeypatch.setattr(api, "asyncio", FastIdle())
    original = stub_driver

    def slow_driver(config, provider):
        driver = original(config, provider)
        async def snapshot(ctx, scope):
            await asyncio.sleep(0.2)
            return {}
        driver.snapshot = snapshot
        return driver

    monkeypatch.setattr(sys.modules[__name__], "stub_driver", slow_driver)
    body = run_body()
    events = parse_stream(client.post("/redteam/scenario/run", headers=AUTH, json=body).text)
    assert_event_contract(events, body)
    assert "heartbeat" in {e["type"] for e in events}


# --- cleanup -----------------------------------------------------------------------------------

def test_cleanup_success_shape(client):
    body = cleanup_body()
    run_id = body["run_id"]
    obj = ObjectRecord(run_id=run_id, group="test", logical_key="seed", provider="fake", external_id="1",
                       marker=object_marker(run_id, "test", "seed"), owner="owner", connection_id="op")
    body["objects"] = [obj.model_dump(mode="json")]
    response = client.post("/redteam/scenario/cleanup", headers=AUTH, json=body)
    assert response.status_code == 200, response.text
    result = response.json()
    assert set(result) == CLEANUP_FIELDS
    assert result["run_id"] == run_id and result["organization_id"] == body["organization_id"]
    assert result["complete"] is True and result["gaps"] == []
    assert [set(o) for o in result["objects"]] == [OBJECT_FIELDS]
    assert result["objects"][0]["cleanup_status"] == "deleted"


# --- errors ------------------------------------------------------------------------------------

def _error(response):
    return response.status_code, response.json()["detail"]


def test_run_missing_driver_is_422(client, plugins):
    plugins[DRIVER_GROUP] = []
    assert _error(client.post("/redteam/scenario/run", headers=AUTH, json=run_body())) == RUN_NOT_CONFIGURED


def test_run_missing_credential_provider_is_422(client):
    assert _error(client.post("/redteam/scenario/run", headers=AUTH, json=run_body(provider="not-installed"))) == RUN_NOT_CONFIGURED


def test_cleanup_invalid_context_is_422(client):
    body = cleanup_body()
    body["objects"] = [ObjectRecord(run_id=body["run_id"], group="test", logical_key="seed", provider="fake", external_id="1",
                                    marker="argus:wrong-marker", owner="owner", connection_id="op").model_dump(mode="json")]
    assert _error(client.post("/redteam/scenario/cleanup", headers=AUTH, json=body)) == CLEANUP_INVALID


@pytest.mark.parametrize("path, body", [("/redteam/scenario/run", run_body), ("/redteam/scenario/cleanup", cleanup_body)])
def test_auth_not_configured_is_503(client, monkeypatch, path, body):
    monkeypatch.delenv("ARGUS_SERVER_TOKEN")
    assert _error(client.post(path, headers=AUTH, json=body())) == AUTH_NOT_CONFIGURED


@pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer wrong"}, {"Authorization": TOKEN}])
@pytest.mark.parametrize("path, body", [("/redteam/scenario/run", run_body), ("/redteam/scenario/cleanup", cleanup_body)])
def test_unauthenticated_request_is_401(client, path, body, headers):
    assert _error(client.post(path, headers=headers, json=body())) == AUTH_REJECTED


# --- entry points ------------------------------------------------------------------------------

def _assert_group(plugins, expected):
    assert plugins["queried"] == [expected], (
        f"loader queried entry-point group(s) {plugins['queried']}, but plugin packages register under "
        f"{expected!r}; renaming the group breaks every installed plugin")


def test_credential_provider_entry_point_group(plugins):
    token, connections = SecretStr("t"), {"operator": "op"}
    try:
        credentials.build_credential_provider("stub", {}, token, connections)
    except ValueError:
        pass
    _assert_group(plugins, PROVIDER_GROUP)
    provider = credentials.build_credential_provider("stub", {"k": "v"}, token, connections)
    assert type(provider) is StubProvider
    assert (provider.config, provider.run_token, provider.connections) == ({"k": "v"}, token, connections)
    for kind in ("unknown", "twice"):
        with pytest.raises(ValueError, match=PROVIDER_MISSING):
            credentials.build_credential_provider(kind, {}, token, connections)


def test_builtin_credential_providers_need_no_entry_point(plugins, tmp_path):
    plugins.clear()
    assert type(credentials.build_credential_provider("environment", {}, SecretStr("t"), {})) is credentials.EnvironmentCredentialProvider
    file_provider = credentials.build_credential_provider("file", {"directory": str(tmp_path)}, SecretStr("t"), {})
    assert type(file_provider) is credentials.FileCredentialProvider


def test_driver_entry_point_group(plugins):
    provider = object()
    try:
        runtime.build_drivers({"fake"}, provider)
    except ValueError:
        pass
    _assert_group(plugins, DRIVER_GROUP)
    drivers = runtime.build_drivers({"fake"}, provider, {"fake": {"invalid": True}})
    assert set(drivers) == {"fake"} and drivers["fake"].invalid is True
    with pytest.raises(ValueError, match="not installed"):
        runtime.build_drivers({"absent"}, provider)


def test_documented_group_names():
    doc = (Path(__file__).parents[1] / "docs" / "integration-scenarios.md").read_text()
    assert f"`{DRIVER_GROUP}` and `{PROVIDER_GROUP}`" in doc


if __name__ == "__main__" and "--regenerate" in sys.argv:
    tag = sys.argv[sys.argv.index("--regenerate") + 1] if len(sys.argv) > sys.argv.index("--regenerate") + 1 else "main"
    FIXTURE.parent.mkdir(parents=True, exist_ok=True)
    FIXTURE.write_text(json.dumps({"_source": f"Pinned at argus {tag}. Regenerate: {REGENERATE} <tag>",
                                   "schemas": current_schemas()}, indent=2, sort_keys=True) + "\n")
    print(f"wrote {FIXTURE}")
