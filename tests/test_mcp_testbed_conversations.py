import asyncio
import pytest
from fastapi.testclient import TestClient
from argus.demo.mcp_testbed.testbed import app as mod
from argus.demo.mcp_testbed.testbed import session as session_mod

@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(mod, 'CONTROL_TOKEN', 'test-control-token')
    return TestClient(mod.app, headers={'Authorization': 'Bearer test-control-token'})

def open_world(client, **kw):
    return client.post('/sessions', json={'scenario': 'tool_poisoning', **kw}).json()['session_id']

def rpc(client, sid, method, **params):
    return client.post(f'/s/{sid}/mcp', json={'id': 1, 'method': method, 'params': params})

def test_conversation_counter_tags_tool_calls(client):
    sid = open_world(client)
    rpc(client, sid, 'tools/call', name='read_notes')
    assert client.post(f'/sessions/{sid}/conversations').json() == {'conversation': 2}
    rpc(client, sid, 'tools/call', name='read_notes')
    ev = client.get(f'/sessions/{sid}/evidence').json()
    assert [c['conversation'] for c in ev['tool_calls']] == [1, 2]

def test_interaction_count_by_session_separates_requests_and_tool_calls(client):
    sid = open_world(client)
    rpc(client, sid, 'initialize')
    rpc(client, sid, 'tools/list')
    rpc(client, sid, 'tools/call', name='read_notes')
    assert client.get(f'/sessions/{sid}/evidence').json()['interaction_count_by_session'] == {'1': {'requests': 3, 'tool_calls': 1}}

def test_seal_freezes_evidence_and_rejects_later_requests(client):
    sid = open_world(client)
    rpc(client, sid, 'tools/call', name='read_notes')
    frozen = client.post(f'/sessions/{sid}/seal').json()
    assert frozen['sealed'] is True and frozen['seal_timeout'] is False
    assert rpc(client, sid, 'tools/list').status_code == 409
    assert client.post(f'/sessions/{sid}/conversations').status_code == 409
    assert client.get(f'/sessions/{sid}/evidence').json() == frozen
    assert client.post(f'/sessions/{sid}/seal').json() == frozen

async def test_seal_waits_for_in_flight_request(monkeypatch):
    world = session_mod.SessionStore().open(session_mod.Script())
    world.in_flight = 1
    sealing = asyncio.create_task(world.seal(grace_s=0, timeout_s=.5))
    await asyncio.sleep(.05)
    assert not sealing.done()
    world.in_flight = 0
    assert (await sealing)['seal_timeout'] is False
    world = session_mod.SessionStore().open(session_mod.Script())
    world.in_flight = 1
    monkeypatch.setattr(session_mod, 'SETTLE_TIMEOUT_S', .05)
    assert (await world.seal(grace_s=0))['seal_timeout'] is True

def test_phase_is_recorded_and_validated(client):
    sid = open_world(client, phase='clean')
    assert client.get(f'/sessions/{sid}/evidence').json()['phase'] == 'clean'
    assert client.post('/sessions', json={'phase': 'x'}).status_code == 400

def test_legacy_evidence_fields_unchanged(client):
    sid = open_world(client)
    rpc(client, sid, 'tools/call', name='read_notes')
    ev = client.get(f'/sessions/{sid}/evidence').json()
    assert ev['interaction_count'] == 1 and ev['tools_list_count'] == 0
    assert ev['descriptions_served'] == [] and ev['shadow_tool_names'] == [] and ev['canary'] is None
    assert ev['tool_calls'][0]['tool'] == 'read_notes'
    assert ev['tool_calls'][0]['after_description_change'] is False
    assert ev['session_id'] == sid
