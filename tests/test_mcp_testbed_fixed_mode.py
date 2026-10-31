import asyncio
import pytest
from fastapi.testclient import TestClient
from argus.demo.mcp_testbed.testbed import app as mod
from argus.demo.mcp_testbed.testbed import fixed
from argus.demo.mcp_testbed.testbed.session import Script, SessionStore

@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(mod, 'CONTROL_TOKEN', 'test-control-token')
    monkeypatch.setattr(mod, 'FIXED', fixed.FixedEndpoint())
    return TestClient(mod.app, headers={'Authorization': 'Bearer test-control-token'})

def world(client, scenario='tool_poisoning'):
    return client.post('/sessions', json={'scenario': scenario}).json()['session_id']

def lease(client):
    r=client.post('/lease'); assert r.status_code == 201, r.text
    return r.json()['lease_id']

def activate(client, lid, sid):
    r=client.post(f'/lease/{lid}/activate', json={'session_id':sid}); assert r.status_code == 200, r.text
    return r.json()['generation']

def call(client, method='initialize', header=None, **params):
    return client.post('/mcp', json={'id':1,'method':method,'params':params}, headers={'Mcp-Session-Id':header} if header else {})

def evidence(client,sid): return client.get(f'/sessions/{sid}/evidence').json()

def test_second_run_activation_refused_while_lease_held_and_creates_no_evidence(client):
    lid=lease(client); a=world(client); activate(client,lid,a)
    assert client.post('/lease').status_code == 409
    b=world(client)
    r=client.post('/lease/other/activate',json={'session_id':b})
    assert r.status_code == 409 and r.json()['detail']['code'] == 'lease_mismatch'
    h=call(client).headers['Mcp-Session-Id']; call(client,'tools/call',h,name='read_notes')
    assert evidence(client,a)['interaction_count'] == 2
    assert evidence(client,b)['interaction_count'] == 0 and evidence(client,b)['tool_calls'] == []

def test_initialize_issues_generation_bound_session_id(client):
    lid=lease(client); sid=world(client); generation=activate(client,lid,sid)
    assert call(client).headers['Mcp-Session-Id'].startswith(f'g{generation}-')
    assert evidence(client,sid)['generation'] == generation

def test_request_without_session_id_is_rejected_and_recorded(client):
    lid=lease(client); sid=world(client); activate(client,lid,sid)
    assert call(client,'tools/call',name='read_notes').status_code == 400
    ev=evidence(client,sid); assert ev['rejected_requests'][-1]['reason'] == 'missing_session_id'
    assert ev['tool_calls'] == []

def test_stale_generation_session_id_is_rejected_and_recorded(client):
    lid=lease(client); a=world(client); generation=activate(client,lid,a); header=call(client).headers['Mcp-Session-Id']
    b=world(client); activate(client,lid,b)
    assert call(client,'tools/call',header,name='read_notes').status_code == 404
    rejected=evidence(client,b)['rejected_requests'][-1]
    assert rejected['reason'] == 'stale_session' and rejected['presented_generation'] == generation

def test_request_after_seal_before_activation_is_rejected(client):
    lid=lease(client); a=world(client); activate(client,lid,a)
    frozen=client.post(f'/sessions/{a}/seal').json()
    assert call(client).status_code == 503
    assert client.get(f'/lease/{lid}').json()['rejected_requests'][-1]['reason'] == 'no_active_generation'
    assert evidence(client,a) == frozen

def handoff(client):
    lid=lease(client); a=world(client); activate(client,lid,a); header=call(client).headers['Mcp-Session-Id']
    assert client.delete(f'/lease/{lid}').status_code == 204
    lid=lease(client); b=world(client); activate(client,lid,b)
    return header,b

def test_interleaved_runs_stale_header_request_never_enters_b_world(client):
    header,b=handoff(client)
    assert call(client,'tools/call',header,name='read_notes').status_code == 404
    ev=evidence(client,b)
    assert ev['tool_calls'] == [] and ev['interaction_count_by_session'] == {}
    assert ev['rejected_requests'][-1]['reason'] == 'stale_session'

def test_fresh_initialize_after_handoff_enters_active_world(client):
    _,b=handoff(client)
    new=call(client).headers['Mcp-Session-Id']
    assert call(client,'tools/call',new,name='read_notes').status_code == 200
    assert [c['tool'] for c in evidence(client,b)['tool_calls']] == ['read_notes']

async def test_activation_seals_previous_generation_after_in_flight():
    endpoint=fixed.FixedEndpoint(); lid=endpoint.acquire(None,0).lease_id
    store=SessionStore(); a=store.open(Script()); b=store.open(Script())
    await endpoint.activate(lid,a,0); a.in_flight=1
    pending=asyncio.create_task(endpoint.activate(lid,b,1))
    await asyncio.sleep(.05)
    assert endpoint.route(None,'initialize').status == 503 and not pending.done()
    a.in_flight=0; await pending
    assert a.sealed and endpoint.route(None,'initialize').session is b

def test_lease_expires_and_is_renewed_by_activity():
    endpoint=fixed.FixedEndpoint(); a=endpoint.acquire(30,0)
    endpoint.touch(a.lease_id,20)
    with pytest.raises(fixed.LeaseHeld): endpoint.acquire(30,45)
    assert endpoint.acquire(30,100).lease_id != a.lease_id

def test_rug_pull_refuses_fixed_activation(client):
    lid=lease(client); sid=world(client,'rug_pull')
    r=client.post(f'/lease/{lid}/activate',json={'session_id':sid})
    assert r.status_code == 422 and r.json()['detail']['code'] == 'dynamic_only'

def test_fixed_initialize_negotiates_streamable_protocol_version(client):
    lid=lease(client); sid=world(client); activate(client,lid,sid)
    assert call(client,protocolVersion='2025-06-18').json()['result']['protocolVersion'] == '2025-06-18'
    assert call(client,protocolVersion='2024-11-05').json()['result']['protocolVersion'] == '2025-03-26'

def test_notifications_get_202_in_fixed_mode(client):
    lid=lease(client); sid=world(client); activate(client,lid,sid); header=call(client).headers['Mcp-Session-Id']
    r=client.post('/mcp',json={'method':'notifications/initialized'},headers={'Mcp-Session-Id':header})
    assert r.status_code == 202 and r.content == b''

def test_lease_endpoints_require_control_token(client):
    lid=lease(client); sid=world(client)
    for method,path,kwargs in [('post','/lease',{}),('get',f'/lease/{lid}',{}),('delete',f'/lease/{lid}',{}),('post',f'/lease/{lid}/activate',{'json':{'session_id':sid}})]:
        assert getattr(client,method)(path,headers={'Authorization':'Bearer wrong'},**kwargs).status_code == 401
