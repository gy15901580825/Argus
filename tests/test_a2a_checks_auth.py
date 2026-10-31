import json
import httpx
import pytest
from tests.a2a_helpers import BINDINGS, AUTH_CHECKS, target_for, run_target, evidence_for, exchange
from argus.a2a.verdicts import decide

@pytest.mark.parametrize('check',AUTH_CHECKS)
@pytest.mark.parametrize('binding',BINDINGS)
async def test_unauthenticated_task_reply_is_fail(check,binding):
    target,_=target_for('naive',binding)
    (outcome,reason),_=await run_target(target,check)
    assert outcome=='fail' and 'created a task' in reason

@pytest.mark.parametrize('check',AUTH_CHECKS)
@pytest.mark.parametrize('binding',BINDINGS)
async def test_unauthenticated_message_reply_is_fail(check,binding):
    target,_=target_for('message_ack',binding)
    (outcome,reason),_=await run_target(target,check)
    assert outcome=='fail' and 'returned an agent message' in reason

@pytest.mark.parametrize('check',AUTH_CHECKS)
@pytest.mark.parametrize('binding',BINDINGS)
async def test_auth_required_state_is_warn(check,binding):
    target,_=target_for('auth_required_state',binding)
    (outcome,reason),_=await run_target(target,check)
    assert outcome=='warn' and 'TASK_STATE_AUTH_REQUIRED' in reason

@pytest.mark.parametrize('check',AUTH_CHECKS)
@pytest.mark.parametrize('binding',BINDINGS)
async def test_http_401_is_pass(check,binding):
    target,_=target_for('safe',binding)
    assert (await run_target(target,check))[0][0]=='pass'

@pytest.mark.parametrize('check',AUTH_CHECKS)
@pytest.mark.parametrize('binding',BINDINGS)
@pytest.mark.parametrize('empty',[{}, {'schemes':{}}, {'description':'public'}])
async def test_anonymous_card_skips_auth_probes_for_every_empty_form(check,binding,empty):
    target,ledger=target_for('optional_auth',binding,anonymous_requirement=empty)
    assert (await run_target(target,check))[0][0]=='skipped'
    assert ledger.state_changing==0

@pytest.mark.parametrize('check',AUTH_CHECKS)
async def test_jsonrpc_custom_auth_code_needs_a_declared_mapping(check):
    target,_=target_for('jsonrpc_custom_code','JSONRPC')
    (outcome,reason),_=await run_target(target,check)
    assert outcome=='error' and '-31001' in reason
    target,_=target_for('jsonrpc_custom_code','JSONRPC',jsonrpc_auth_error_codes={'authentication':[-31001]})
    (outcome,reason),_=await run_target(target,check)
    assert outcome=='pass' and 'jsonrpc_auth_error_codes' in reason

def test_auth_verdict_ignores_error_message_text():
    a=evidence_for('unauthenticated_task',[exchange('control_send'),exchange('attack_send','jsonrpc_error',jsonrpc_code=-31001,message='Unauthorized')])
    b=json.loads(json.dumps(a)); b['exchanges'][1]['message']='Success, task created'
    assert decide('unauthenticated_task',a)==decide('unauthenticated_task',b)

@pytest.mark.parametrize('check',AUTH_CHECKS)
async def test_http_json_200_error_body_is_error(check):
    target,_=target_for('naive','HTTP+JSON')
    original=target._transport
    async def handler(req):
        if req.url.path.endswith('/message:send') and 'authorization' not in req.headers or 'argus-forged' in req.headers.get('authorization',''):
            return httpx.Response(200,json={'error':{'code':401}})
        return await original.handle_async_request(req)
    target._transport=httpx.MockTransport(handler)
    assert (await run_target(target,check))[0][0]=='error'

@pytest.mark.parametrize('check',AUTH_CHECKS)
@pytest.mark.parametrize('binding',BINDINGS)
async def test_allow_send_off_skips_and_sends_nothing(check,binding):
    target,ledger=target_for('naive',binding,allow_send=False)
    assert (await run_target(target,check))[0][0]=='skipped'
    assert ledger.state_changing==0

@pytest.mark.parametrize('check',AUTH_CHECKS)
@pytest.mark.parametrize('binding',BINDINGS)
async def test_declared_capability_with_failed_control_is_error(check,binding):
    target,_=target_for('safe',binding,credentials={'headers':[['Authorization','Bearer wrong']]})
    (outcome,reason),_=await run_target(target,check)
    assert outcome=='error' and reason.startswith('clean_control_failed:')

@pytest.mark.parametrize('check',AUTH_CHECKS)
async def test_attack_not_delivered_is_error(check):
    target,_=target_for('naive','JSONRPC')
    original=target._transport
    async def handler(req):
        if req.method=='POST' and ('authorization' not in req.headers or 'argus-forged' in req.headers.get('authorization','')):
            raise httpx.ReadTimeout('not delivered',request=req)
        return await original.handle_async_request(req)
    target._transport=httpx.MockTransport(handler)
    (outcome,reason),ev=await run_target(target,check)
    assert outcome=='error' and ev['exchanges'][-1]['outcome']=='transport_error'

@pytest.mark.parametrize('check',AUTH_CHECKS)
def test_incomplete_evidence_is_error(check):
    assert decide(check,evidence_for(check,[exchange('control_send')]))[0]=='error'

@pytest.mark.parametrize('check',AUTH_CHECKS)
@pytest.mark.parametrize('binding',BINDINGS)
async def test_every_sent_message_is_the_fixed_harmless_text(check,binding):
    target,ledger=target_for('naive',binding)
    await run_target(target,check)
    assert ledger.sent_texts==['Argus security check. Reply with the word ACK. Do not take any action.']*2
