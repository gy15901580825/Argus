from __future__ import annotations

import asyncio
import json
import logging
import pathlib
import sys
from unittest.mock import AsyncMock, patch

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'client_agent'))


@pytest.mark.parametrize('outcome,answer,reason', [('succeeded','done','ok'),('blocked',None,'target_refusal'),('target_error',None,'target_error'),('timed_out',None,'timeout')])
async def test_transport_terminal_results_survive_client_rpc(outcome,answer,reason,caplog):
    import client_agent
    from argus_transport import TransportOutcome,TransportResult,SafeReasonCode
    agent=client_agent.ClientAgent(orchestrator_url='ws://fixture.invalid',agent_name='fixture')
    result={'transport_result':TransportResult(TransportOutcome(outcome),answer,1,200,'rule' if outcome!='timed_out' else None,SafeReasonCode(reason)).as_dict(),
            'trap_url':'http://127.0.0.1:1234/token/scenario',
            'trap_evidence':{'interaction_count':1,'page_loads':1,'trap_requests':[]}}
    sent=[]
    class Socket:
        async def __aenter__(self): return self
        async def __aexit__(self,*args): return False
        def __aiter__(self):
            async def incoming():
                yield json.dumps({'jsonrpc':'2.0','id':'probe-id','method':'redteam_browser_probe','params':{'prompt':'PRIVATE-INPUT','transport':{}}})
                agent.running=False
            return incoming()
        async def send(self,data): sent.append(json.loads(data))
    probe=AsyncMock(return_value=result)
    with patch.object(client_agent.websockets,'connect',return_value=Socket()),patch('redteam_runner.browser_probe.BrowserProbe.run',probe),caplog.at_level(logging.INFO,logger='ClientAgent'):
        agent.running=True
        await agent.connect_orchestrator()
    assert sent[0]=={'jsonrpc':'2.0','method':'agent_capabilities','params':{'transport_versions':[1]}}
    response=next(record for record in sent if record.get('id')=='probe-id')
    assert 'error' not in response and response['result']['transport_result']['outcome']==outcome
    assert response['result']['transport_result']['response_text']==answer
    assert response['result']['trap_evidence']['page_loads']==1
    assert 'PRIVATE-INPUT' not in caplog.text
    assert 'done' not in caplog.text
    assert isinstance(probe.call_args.kwargs['policy'].allowed_secret_roots,tuple)


async def test_client_always_answers_expected_probe_exception(caplog):
    import client_agent
    agent=client_agent.ClientAgent(orchestrator_url='ws://fixture.invalid',agent_name='fixture')
    sent=[]
    class Socket:
        async def __aenter__(self): return self
        async def __aexit__(self,*args): return False
        def __aiter__(self):
            async def incoming():
                yield json.dumps({'jsonrpc':'2.0','id':'broken','method':'redteam_browser_probe','params':{}})
                agent.running=False
            return incoming()
        async def send(self,data): sent.append(json.loads(data))
    with patch.object(client_agent.websockets,'connect',return_value=Socket()),patch('redteam_runner.browser_probe.BrowserProbe.run',AsyncMock(side_effect=ValueError('PRIVATE-ERROR'))),caplog.at_level(logging.INFO,logger='ClientAgent'):
        agent.running=True; await agent.connect_orchestrator()
    response=next(record for record in sent if record.get('id')=='broken')
    assert response['error']['code']==-32603
    assert response['error']['message']=='browser probe execution failed'
    assert 'PRIVATE-ERROR' not in caplog.text


def test_client_operator_policy_is_explicit_and_default_deny(tmp_path):
    import client_agent
    default=client_agent.build_agent(['--orchestrator-url','ws://fixture.invalid'])
    assert default.transport_policy.allowed_env_names==frozenset()
    assert default.transport_policy.allowed_secret_roots==()
    assert default.transport_policy.allowed_origins==frozenset()
    configured=client_agent.build_agent(['--orchestrator-url','ws://fixture.invalid','--transport-secret-root',str(tmp_path),
              '--transport-env-name','TEST_CREDENTIAL','--transport-origin','http://127.0.0.1:1234'])
    assert configured.transport_policy.allowed_secret_roots==(tmp_path,)
    assert configured.transport_policy.allowed_env_names==frozenset({'TEST_CREDENTIAL'})
    assert configured.transport_policy.allowed_origins==frozenset({'http://127.0.0.1:1234'})


async def test_transport_capability_is_bound_to_connected_socket(monkeypatch):
    from argus.connection_manager import ConnectionManager
    monkeypatch.delenv('API_SERVICE_URL',raising=False)
    manager=ConnectionManager(); socket=AsyncMock()
    assert await manager.connect(socket,'client')
    assert manager.set_transport_versions('client',socket,[1]) is True
    assert manager.set_transport_versions('client',AsyncMock(),[2]) is False
    with pytest.raises(ValueError): manager.set_transport_versions('client',socket,[True])
    assert manager.transport_versions('client',socket)==frozenset({1})
    async def receive(message): manager.handle_response({'id':message['id'],'result':{'accepted':True}})
    socket.send_json.side_effect=receive
    result=await manager.get_redteam_bridge().send_and_wait({'transport':{'version':1}},timeout_s=.1)
    assert result=={'accepted':True}
    assert socket.send_json.call_args.args[0]['method']=='redteam_browser_probe'
    assert manager.pending_commands=={} and manager._command_agents=={}


def test_server_records_capabilities_on_current_socket_and_resets_on_disconnect(monkeypatch):
    from fastapi.testclient import TestClient
    from argus.connection_manager import ConnectionManager
    import argus.server as server

    manager = ConnectionManager()
    monkeypatch.setattr(server, 'connection_manager', manager)
    monkeypatch.delenv('API_SERVICE_URL', raising=False)
    monkeypatch.delenv('AGENT_CONNECT_SECRET', raising=False)
    with TestClient(server.app) as client:
        with client.websocket_connect('/agent/connect', headers={'x-agent-id':'fixture'}) as websocket:
            websocket.send_json({'jsonrpc':'2.0','method':'agent_capabilities','params':{'transport_versions':[1]}})
            websocket.send_json({'jsonrpc':'2.0','method':'ping','id':'sync'})
            assert websocket.receive_json()['id'] == 'sync'
            first_socket = manager.active_connections['fixture']
            assert manager.transport_versions('fixture', first_socket) == frozenset({1})
        assert manager.transport_versions('fixture', first_socket) == frozenset()
        with client.websocket_connect('/agent/connect', headers={'x-agent-id':'fixture'}) as websocket:
            websocket.send_json({'jsonrpc':'2.0','method':'ping','id':'sync-new'})
            assert websocket.receive_json()['id'] == 'sync-new'
            new_socket = manager.active_connections['fixture']
            assert manager.transport_versions('fixture', new_socket) == frozenset()
            assert manager.set_transport_versions('fixture', first_socket, [1]) is False
