import importlib
import json
import time

import jwt
import pytest
import pytest_asyncio
from aiohttp import ClientSession, web
from cryptography.hazmat.primitives.asymmetric import rsa

from testbed.memory import MemoryStore
from testbed.service import HostedService


TENANT = "11111111-1111-1111-1111-111111111111"
AUDIENCE = "api://synthetic-hosted-service"


def modules():
    try:
        return importlib.import_module("testbed.app"), importlib.import_module("testbed.auth")
    except ModuleNotFoundError:
        pytest.fail("hosted HTTP boundary has not been implemented")


@pytest_asyncio.fixture
async def client(unused_tcp_port):
    app_module, auth_module = modules()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verifier = auth_module.OwnerVerifier(TENANT, AUDIENCE, key_resolver=lambda token: key.public_key())
    service = HostedService(MemoryStore())
    runner = web.AppRunner(app_module.create_app(service, verifier, public_origin="https://synthetic.invalid"))
    await runner.setup()
    await web.TCPSite(runner, "127.0.0.1", unused_tcp_port).start()
    async with ClientSession() as session:
        def token(**overrides):
            claims = {"iss": f"https://login.microsoftonline.com/{TENANT}/v2.0", "tid": TENANT, "aud": AUDIENCE,
                      "oid": "22222222-2222-2222-2222-222222222222", "exp": int(time.time()) + 300,
                      "roles": ["HostedRun.Create", "HostedRun.Control"]}
            claims.update(overrides)
            return jwt.encode(claims, key, algorithm="RS256", headers={"kid": "synthetic-key"})
        yield session, f"http://127.0.0.1:{unused_tcp_port}", token, service
    await runner.cleanup()


@pytest.mark.asyncio
@pytest.mark.parametrize("overrides,expected", [
    ({"aud": "wrong-audience"}, 401), ({"iss": "https://synthetic.invalid"}, 401),
    ({"tid": "wrong-tenant"}, 401), ({"exp": 1}, 401), ({"roles": []}, 403),
    ({"roles": ["HostedRun.CreateExtra"]}, 403), ({"oid": None}, 401),
])
async def test_owner_jwt_claims_are_strict(client, overrides, expected):
    session, url, token, _ = client
    async with session.post(url + "/v1/runs", json={"schema_version": 1}, headers={"Authorization": "Bearer " + token(**overrides)}) as response:
        assert response.status == expected


@pytest.mark.asyncio
async def test_missing_jwt_and_control_role_cannot_create_probe(client):
    session, url, token, _ = client
    async with session.post(url + "/v1/runs", json={"schema_version": 1}) as response:
        assert response.status == 401
    create_headers = {"Authorization": "Bearer " + token(roles=["HostedRun.Create"])}
    async with session.post(url + "/v1/runs", json={"schema_version": 1}, headers=create_headers) as response:
        run = await response.json()
        assert response.status == 201
    async with session.post(url + f'/v1/runs/{run["run_id"]}/probes', json={"kind": "browser", "payload": "Synthetic", "synthetic_markers": []}, headers=create_headers) as response:
        assert response.status == 403


async def new_probe(client):
    session, url, token, svc = client
    headers = {"Authorization": "Bearer " + token()}
    async with session.post(url + "/v1/runs", json={"schema_version": 1}, headers=headers) as response:
        assert response.status == 201
        run = await response.json()
    async with session.post(url + f'/v1/runs/{run["run_id"]}/probes', json={"kind": "browser", "scenario_id": "synthetic-page", "payload": "Neutral <text>", "public_token": run["public_token"], "synthetic_markers": [{"marker_id": "m1", "value": "MARKER_ALPHA_123"}], "script": {}}, headers=headers) as response:
        assert response.status == 201
        probe = await response.json()
        assert probe["scenario_url"] == f'https://synthetic.invalid/r/{run["public_token"]}/p/{probe["probe_id"]}/scenario'
        assert probe["mcp_url"] is None and probe["a2a_url"] is None
    return run, probe, headers


@pytest.mark.asyncio
async def test_loopback_public_sink_seal_evidence_and_no_raw_input(client):
    session, url, _, svc = client
    run, probe, headers = await new_probe(client)
    prefix = f'/r/{run["public_token"]}/p/{probe["probe_id"]}'
    async with session.head(url + prefix + "/scenario") as response:
        assert response.status == 200
    async with session.get(url + prefix + "/scenario", headers={"Purpose": "prefetch"}) as response:
        assert response.status == 200
        assert "Neutral &lt;text&gt;" in await response.text()
    async with session.post(url + prefix + "/sink/PRIVATE_TAIL?input=PRIVATE_QUERY", data="MARKER_ALPHA_123 PRIVATE_BODY", headers={"Cookie": "PRIVATE_COOKIE", "Authorization": "PRIVATE_AUTH"}) as response:
        assert response.status == 204
    async with session.post(url + f'/v1/runs/{run["run_id"]}/probes/{probe["probe_id"]}/seal', json={"reason": "vendor_terminal"}, headers=headers) as response:
        assert response.status == 200
        sealed = await response.json()
        assert sealed["complete"] is True
    async with session.get(url + f'/v1/runs/{run["run_id"]}/evidence', params={"probe_id": probe["probe_id"]}, headers={"Authorization": "Bearer " + run["evidence_token"]}) as response:
        data = await response.json()
        assert response.status == 200
        assert data["summary"]["page_loads"] == 1
        assert data["summary"]["prefetch_count"] == 1
        assert data["events"][-1]["route_class"] == "/sink/other"
        assert data["events"][-1]["canary_hits"] == [{"marker_id": "m1", "location": "body"}]
        assert "PRIVATE" not in json.dumps(data)
    assert "PRIVATE" not in repr(svc.store.runs)
    async with session.post(url + prefix + "/sink/kyc", data="late") as response:
        assert response.status == 409


@pytest.mark.asyncio
async def test_public_rate_ignores_forged_forwarded_headers(client):
    session, url, _, _ = client
    run, probe, _ = await new_probe(client)
    prefix = f'/r/{run["public_token"]}/p/{probe["probe_id"]}/scenario'
    statuses = []
    for index in range(21):
        async with session.get(url + prefix, headers={"X-Forwarded-For": f"192.0.2.{index}"}) as response:
            statuses.append(response.status)
    assert statuses[-1] == 429


@pytest.mark.asyncio
async def test_oversize_body_is_unknown_and_protocol_script_rejected(client):
    session, url, _, _ = client
    run, probe, headers = await new_probe(client)
    async with session.post(url + f'/r/{run["public_token"]}/p/{probe["probe_id"]}/sink/kyc', data="x" * 65537) as response:
        assert response.status == 413
    async with session.post(url + f'/v1/runs/{run["run_id"]}/probes/{probe["probe_id"]}/seal', json={"reason": "vendor_terminal"}, headers=headers) as response:
        assert not (await response.json())["complete"]
    async with session.post(url + f'/v1/runs/{run["run_id"]}/probes', json={"kind": "browser", "payload": "x", "synthetic_markers": [], "script": {"remote_url": "https://synthetic.invalid"}}, headers=headers) as response:
        assert response.status == 400
    async with session.post(url + f'/v1/runs/{run["run_id"]}/probes/{probe["probe_id"]}/phases', json={}, headers=headers) as response:
        assert response.status == 404


def test_missing_configuration_fails_closed(monkeypatch):
    app_module, _ = modules()
    for name in ("HOSTED_ENTRA_TENANT_ID", "HOSTED_ENTRA_AUDIENCE", "HOSTED_TABLES_ENDPOINT", "HOSTED_TABLE_PREFIX"):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(ValueError):
        app_module.application_from_environment()


@pytest.mark.asyncio
async def test_public_rate_rejection_marks_live_collection_incomplete(client):
    session, url, _, _ = client
    run, probe, headers = await new_probe(client)
    prefix = f'/r/{run["public_token"]}/p/{probe["probe_id"]}/scenario'
    for _ in range(21):
        async with session.get(url + prefix) as response:
            await response.read()
    async with session.post(url + f'/v1/runs/{run["run_id"]}/probes/{probe["probe_id"]}/seal', json={"reason": "vendor_terminal"}, headers=headers) as response:
        assert not (await response.json())["complete"]


@pytest.mark.asyncio
async def test_probe_url_requires_matching_owner_supplied_public_capability(client):
    session, url, _, _ = client
    run, probe, headers = await new_probe(client)
    endpoint = url + f'/v1/runs/{run["run_id"]}/probes'
    for supplied, expected in ((None, 400), ("wrong-capability", 404)):
        data = {"kind": "browser", "payload": "Synthetic", "synthetic_markers": []}
        if supplied is not None:
            data["public_token"] = supplied
        async with session.post(endpoint, json=data, headers=headers) as response:
            assert response.status == expected
    async with session.post(url + f'/v1/runs/{run["run_id"]}/tokens/rotate', json={"scope": "public"}, headers=headers) as response:
        assert response.status == 200
    async with session.post(endpoint, json={"kind": "browser", "public_token": run["public_token"], "synthetic_markers": []}, headers=headers) as response:
        assert response.status == 410


@pytest.mark.asyncio
async def test_invalid_utf8_is_unknown_but_retains_known_ascii_hit(client):
    session, url, _, _ = client
    run, probe, headers = await new_probe(client)
    async with session.post(url + f'/r/{run["public_token"]}/p/{probe["probe_id"]}/sink/kyc', data=b"MARKER_ALPHA_123\xff") as response:
        assert response.status == 204
    async with session.post(url + f'/v1/runs/{run["run_id"]}/probes/{probe["probe_id"]}/seal', json={"reason": "vendor_terminal"}, headers=headers) as response:
        assert not (await response.json())["complete"]
    async with session.get(url + f'/v1/runs/{run["run_id"]}/evidence', params={"probe_id": probe["probe_id"]}, headers={"Authorization": "Bearer " + run["evidence_token"]}) as response:
        data = await response.json()
        assert data["events"][-1]["marker_status"] == "unknown"
        assert data["events"][-1]["canary_hits"] == [{"marker_id": "m1", "location": "body"}]


@pytest.mark.asyncio
async def test_periodic_cleanup_retries_after_transient_storage_failure(monkeypatch):
    import asyncio
    app_module, _ = modules()
    calls = [0]
    reached = asyncio.Event()
    event_loop = asyncio.get_running_loop()

    class CleanupService:
        def cleanup(self):
            calls[0] += 1
            if calls[0] == 1:
                raise RuntimeError("synthetic storage failure")
            event_loop.call_soon_threadsafe(reached.set)

    cleanup_loop = getattr(app_module, "_cleanup_forever", None)
    assert cleanup_loop is not None
    task = asyncio.create_task(cleanup_loop(CleanupService(), interval=0.01))
    try:
        await asyncio.wait_for(reached.wait(), timeout=1)
        assert calls[0] >= 2
        assert not task.done()
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task


@pytest.mark.asyncio
async def test_evidence_rate_precedes_full_snapshot_load_and_invalid_token_has_no_quota(client):
    session, url, _, svc = client
    run, probe, _ = await new_probe(client)
    endpoint = url + f'/v1/runs/{run["run_id"]}/evidence?probe_id={probe["probe_id"]}'
    count_before = len(svc.store.limits)
    async with session.get(endpoint, headers={"Authorization": "Bearer invalid-capability"}) as response:
        assert response.status == 404
    assert len(svc.store.limits) == count_before
    for _ in range(30):
        svc.rate("evidence", importlib.import_module("testbed.service").digest(run["evidence_token"]), 30, 30)
    original_get = svc.store.get
    svc.store.get = lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("full snapshot loaded after quota exhausted"))
    try:
        async with session.get(endpoint, headers={"Authorization": "Bearer " + run["evidence_token"]}) as response:
            assert response.status == 429
    finally:
        svc.store.get = original_get


@pytest.mark.asyncio
async def test_exhausted_ip_rate_does_not_scan_run_storage(client):
    session, url, _, svc = client
    run, probe, _ = await new_probe(client)
    for _ in range(60):
        svc.rate("ip", "127.0.0.1", 300, 60)
    svc.store.list_auth = lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("quota rejected requests must not scan storage"))
    async with session.get(url + f'/r/{run["public_token"]}/p/{probe["probe_id"]}/scenario') as response:
        assert response.status == 429
