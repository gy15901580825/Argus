import asyncio

import httpx
import pytest
from fastapi.testclient import TestClient

from argus.demo import servers
from argus.demo.mcp_testbed.testbed import app as mod
from argus.cli.run_json import MASK, redact
from argus.targets import build_target

INNER = {'kind': 'openai_compat', 'endpoint_url': 'http://127.0.0.1:9/v1/chat/completions', 'model': 'demo'}

@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(mod, 'CONTROL_TOKEN', 'test-control-token')
    return TestClient(mod.app)

def control_calls(client):
    sid = client.post('/sessions', json={'scenario': 'tool_poisoning'}, headers={'Authorization': 'Bearer test-control-token'}).json()['session_id']
    return [('post', '/sessions', {'scenario': 'tool_poisoning'}), ('get', f'/sessions/{sid}/evidence', None), ('delete', f'/sessions/{sid}', None)]

def test_control_endpoints_refuse_missing_token(client):
    for method, path, payload in control_calls(client):
        kw = {'json': payload} if payload else {}
        response = getattr(client, method)(path, **kw)
        assert response.status_code == 401
        assert response.headers['WWW-Authenticate'] == 'Bearer'

def test_control_endpoints_refuse_wrong_token(client):
    for method, path, payload in control_calls(client):
        kw = {'json': payload} if payload else {}
        assert getattr(client, method)(path, headers={'Authorization': 'Bearer wrong'}, **kw).status_code == 401

def test_control_endpoints_unavailable_when_token_unset(client, monkeypatch):
    calls = control_calls(client)
    monkeypatch.setattr(mod, 'CONTROL_TOKEN', '')
    for method, path, payload in calls:
        response = getattr(client, method)(path, **({'json': payload} if payload else {}))
        assert response.status_code == 503
        assert 'TESTBED_CONTROL_TOKEN is not set' in response.json()['detail']

def test_agent_endpoint_needs_no_token(client):
    sid = control_calls(client)[1][1].split('/')[2]
    assert client.post(f'/s/{sid}/mcp', json={'id': 1, 'method': 'initialize'}).status_code == 200

def test_local_testbed_mints_token_and_restores():
    previous = mod.CONTROL_TOKEN
    spec = {'kind': 'mcp_agent', 'testbed_url': 'local', 'sandbox': True, 'inner': INNER}
    with servers.local_testbed(spec) as first, servers.local_testbed(spec) as second:
        assert first['control_token'] == second['control_token'] == mod.CONTROL_TOKEN
        assert len(first['control_token']) >= 32
    assert mod.CONTROL_TOKEN == previous

def test_adapter_sends_bearer_token():
    from types import SimpleNamespace
    async def run(spec):
        target = build_target(spec)
        await target.begin_probe(SimpleNamespace(id='p', scenario_payload=''))
        assert (await target.collect_evidence())['interaction_count'] == 0
        await target._close_session()
        target = build_target({**spec, 'control_token': ''})
        with pytest.raises(ValueError, match='refused the control token'):
            await target.begin_probe(SimpleNamespace(id='p', scenario_payload=''))
    with servers.local_testbed({'kind': 'mcp_agent', 'testbed_url': 'local', 'sandbox': True, 'inner': INNER}) as spec:
        asyncio.run(run(spec))

def test_control_token_is_masked_in_run_json():
    assert redact({'kind': 'mcp_agent', 'control_token': 'abc'})['control_token'] == MASK
