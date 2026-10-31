import json
from types import SimpleNamespace
import httpx
import pytest
from argus.targets.a2a_server import A2AServerSpec, A2AServerTarget
from argus.a2a.client import A2AClient, MutationNotAllowed
from argus.a2a.protocol import Interface, MUTATING_OPS
from argus.a2a.checks import run_check
from argus.a2a.verdicts import decide
from argus.demo.a2a_server.app import create_app

ALL_CHECKS=('unauthenticated_task','invalid_credentials','cross_client_task','extended_card_auth','card_unsigned','push_private_callback')
BAD_SPECS=[({'kind':'x'},'kind'),({'url':''},'url'),({'url':'ftp://x'},'url'),({'credentials':{'token':'x'}},'credentials'),({'credentials':{'headers':[['Authorization',3]]}},'headers'),({'second_client':{'headers':[]}},'headers'),({'second_client':{'headers':[['A','b']],'forbidden_on_primary_tasks':['delete']}},'forbidden'),({'jsonrpc_auth_error_codes':{'other':[]}},'jsonrpc'),({'jsonrpc_auth_error_codes':{'authentication':[True]}},'integer'),({'push_callback_policy':'allow'},'policy'),({'allow_send':1},'allow_send'),({'push_control_url':'http://127.0.0.1/x'},'push_control_url')]
@pytest.mark.parametrize('patch,match',BAD_SPECS)
def test_spec_rejects_invalid_fields(patch,match):
    with pytest.raises(ValueError,match=match): A2AServerSpec(**{'url':'http://127.0.0.1:8765',**patch})

def test_spec_accepts_the_design_example():
    spec=A2AServerSpec(url='https://agent.example.invalid',credentials={'headers':[['Authorization','Bearer alice']]},second_client={'headers':[['Authorization','Bearer bob']],'forbidden_on_primary_tasks':['get','list','cancel']},jsonrpc_auth_error_codes={'authentication':[-31001],'authorization':[-31003]},push_callback_policy='deny_private',allow_send=True)
    assert spec.primary_headers==(('Authorization','Bearer alice'),)
    assert spec.forbidden_on_primary_tasks==frozenset({'get','list','cancel'})

@pytest.mark.parametrize('op',sorted(MUTATING_OPS))
async def test_client_refuses_state_changing_op_without_allow_send(op):
    app=create_app('naive','JSONRPC')
    client=A2AClient(A2AServerSpec(url='http://127.0.0.1:8765'),httpx.ASGITransport(app=app))
    with pytest.raises(MutationNotAllowed): await client.call('attack',op,{},'primary',iface=Interface('http://127.0.0.1:8765/a2a/rpc','JSONRPC',''))
    assert app.state.ledger.state_changing==0 and client.interaction_count==0

async def test_every_request_carries_a2a_version_1_0():
    requests=[]
    def handler(req):
        requests.append(req)
        return httpx.Response(200,json={'result':{'name':'x'}})
    client=A2AClient(A2AServerSpec(url='http://127.0.0.1'),httpx.MockTransport(handler))
    await client.fetch_card()
    await client.fetch_legacy_card_status()
    await client.call('extended','GetExtendedAgentCard',{},'primary',iface=Interface('http://127.0.0.1/rpc','JSONRPC',''))
    assert len(requests)==3 and all(r.headers['A2A-Version']=='1.0' for r in requests)

async def test_card_is_fetched_without_credentials():
    requests=[]
    client=A2AClient(A2AServerSpec(url='http://127.0.0.1',credentials={'headers':[['Authorization','Bearer secret'],['X-Key','key']]}),httpx.MockTransport(lambda req: requests.append(req) or httpx.Response(200,json={})))
    await client.fetch_card()
    assert 'authorization' not in requests[0].headers and 'x-key' not in requests[0].headers

async def test_interaction_count_includes_the_card_fetch():
    client=A2AClient(A2AServerSpec(url='http://127.0.0.1'),httpx.MockTransport(lambda req: httpx.Response(200,json={})))
    await client.fetch_card()
    assert client.interaction_count==1

async def test_unreachable_server_records_no_interaction():
    def handler(req): raise httpx.ConnectError('no connection',request=req)
    client=A2AClient(A2AServerSpec(url='http://127.0.0.1'),httpx.MockTransport(handler))
    assert await client.fetch_card()==(None,None)
    assert client.interaction_count==0

async def test_evidence_records_selected_binding():
    card={'supportedInterfaces':[{'url':'http://127.0.0.1/rest','protocolBinding':'HTTP+JSON','protocolVersion':'1.0'},{'url':'http://127.0.0.1/rpc','protocolBinding':'JSONRPC','protocolVersion':'1.0'}]}
    spec=A2AServerSpec(url='http://127.0.0.1')
    ev=await run_check('card_unsigned',A2AClient(spec,httpx.MockTransport(lambda req:httpx.Response(200,json=card))),spec)
    assert ev['card']['binding']=='HTTP+JSON'

@pytest.mark.parametrize('check',ALL_CHECKS)
async def test_a2a_0_3_only_server_skips_every_check(check):
    spec=A2AServerSpec(url='http://127.0.0.1')
    def handler(req): return httpx.Response(200 if req.url.path.endswith('/agent.json') else 404,json={})
    ev=await run_check(check,A2AClient(spec,httpx.MockTransport(handler)),spec)
    outcome,reason=decide(check,ev)
    assert outcome=='skipped' and '0.3' in reason

@pytest.mark.parametrize('check',[c for c in ALL_CHECKS if c!='card_unsigned'])
async def test_grpc_only_card_skips_binding_checks(check):
    spec=A2AServerSpec(url='http://127.0.0.1')
    card={'supportedInterfaces':[{'protocolVersion':'1.0','protocolBinding':'GRPC','url':'http://127.0.0.1'}]}
    ev=await run_check(check,A2AClient(spec,httpx.MockTransport(lambda req:httpx.Response(200,json=card))),spec)
    outcome,reason=decide(check,ev)
    assert outcome=='skipped' and 'GRPC' in reason

async def test_missing_card_is_error_not_skipped():
    spec=A2AServerSpec(url='http://127.0.0.1')
    ev=await run_check('card_unsigned',A2AClient(spec,httpx.MockTransport(lambda req:httpx.Response(404))),spec)
    assert decide('card_unsigned',ev)[0]=='error'

async def test_begin_probe_refuses_a_probe_without_an_a2a_assertion():
    target=A2AServerTarget(A2AServerSpec(url='http://127.0.0.1'))
    with pytest.raises(ValueError): await target.begin_probe(SimpleNamespace(assertions=()))

async def test_begin_probe_refuses_deep_mode_wrappers():
    target=A2AServerTarget(A2AServerSpec(url='http://127.0.0.1'))
    with pytest.raises(ValueError): await target.begin_probe(SimpleNamespace(base=object(),assertions=({'a2a_server':'card_unsigned'},)))

async def test_protocol_headers_override_credentials_case_insensitively():
    captured=[]
    def handler(req):
        captured.append(req)
        return httpx.Response(200,json={'result':{'name':'agent','skills':[],'supportedInterfaces':[]}})
    spec=A2AServerSpec(url='http://127.0.0.1',credentials={'headers':[['a2a-version','0.3'],['content-type','text/plain']]})
    await A2AClient(spec,httpx.MockTransport(handler)).call('extended','GetExtendedAgentCard',{},'primary',iface=Interface('http://127.0.0.1/rpc','JSONRPC',''))
    assert captured[0].headers.get_list('a2a-version')==['1.0']
    assert captured[0].headers.get_list('content-type')==['application/json']

@pytest.mark.parametrize('binding',['JSONRPC','HTTP+JSON'])
@pytest.mark.parametrize('bad_url',['http://alice:card-secret@127.0.0.1:8765/a2a','ftp://127.0.0.1/a2a','http://127.0.0.1:bad/a2a','http://[broken/a2a'])
async def test_invalid_interface_url_errors_before_operation_io_without_exposing_userinfo(binding,bad_url):
    requests=[]
    card={'name':'agent','skills':[],'supportedInterfaces':[{'url':bad_url,'protocolBinding':binding,'protocolVersion':'1.0'}],'securityRequirements':[{'schemes':{'bearer':{'list':[]}}}]}
    def handler(req):
        requests.append(req)
        if req.url.path.endswith('/agent-card.json'): return httpx.Response(200,json=card)
        body={'task':{'id':'x','status':{'state':'TASK_STATE_COMPLETED'}}}
        return httpx.Response(200,json={'result':body} if binding=='JSONRPC' else body)
    spec=A2AServerSpec(url='http://127.0.0.1:8765',allow_send=True)
    ev=await run_check('unauthenticated_task',A2AClient(spec,httpx.MockTransport(handler)),spec)
    assert decide('unauthenticated_task',ev)[0]=='error'
    assert len(requests)==1 and ev['state_changing_requests']==0
    assert 'card-secret' not in json.dumps(ev) and 'alice:' not in json.dumps(ev)

@pytest.mark.parametrize('location',['credentials','second_client'])
@pytest.mark.parametrize('names',[('Authorization','Authorization'),('Authorization','authorization')])
def test_spec_rejects_duplicate_credential_header_names_case_insensitively(location,names):
    headers=[[names[0],'Bearer obsolete'],[names[1],'Bearer demo-alice']]
    with pytest.raises(ValueError,match='duplicate'):
        A2AServerSpec(url='http://127.0.0.1',**{location:{'headers':headers}})
