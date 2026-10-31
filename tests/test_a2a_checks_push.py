import json
import re
import httpx
import pytest
from tests.a2a_helpers import BINDINGS, target_for, run_target

@pytest.mark.parametrize('binding',BINDINGS)
async def test_private_callback_verdict_follows_declared_policy(binding):
    target,_=target_for('naive',binding)
    (outcome,reason),_=await run_target(target,'push_private_callback')
    assert outcome=='warn' and 'SSRF protection not proven' in reason and 'Argus observed no outbound request' in reason
    target,_=target_for('naive',binding,push_callback_policy='deny_private')
    (outcome,reason),_=await run_target(target,'push_private_callback')
    assert outcome=='fail' and 'declared callback policy' in reason

@pytest.mark.parametrize('binding',BINDINGS)
async def test_rejected_private_callbacks_pass(binding):
    target,_=target_for('safe',binding)
    assert (await run_target(target,'push_private_callback'))[0][0]=='pass'

async def test_push_http_200_jsonrpc_error_is_rejection():
    target,_=target_for('push_jsonrpc_error_200','JSONRPC')
    (outcome,_),ev=await run_target(target,'push_private_callback')
    assert outcome=='pass'
    records=[e for e in ev['exchanges'] if e['step']=='attack_register']
    assert len(records)==6 and all(e['http_status']==200 and e['outcome']=='jsonrpc_error' for e in records)

@pytest.mark.parametrize('binding',BINDINGS)
async def test_no_push_capability_is_skipped(binding):
    target,ledger=target_for('no_push',binding)
    assert (await run_target(target,'push_private_callback'))[0][0]=='skipped' and ledger.state_changing==0

@pytest.mark.parametrize('binding',BINDINGS)
async def test_message_only_server_skips_push(binding):
    target,_=target_for('message_only',binding)
    assert (await run_target(target,'push_private_callback'))[0][0]=='skipped'

async def test_push_control_failure_is_error():
    target,_=target_for('safe','JSONRPC')
    original=target._transport
    async def handler(req):
        if req.method=='POST' and json.loads(req.content)['method']=='CreateTaskPushNotificationConfig': return httpx.Response(400,json={'error':{'code':-32602}})
        return await original.handle_async_request(req)
    target._transport=httpx.MockTransport(handler)
    (outcome,reason),_=await run_target(target,'push_private_callback')
    assert outcome=='error' and reason.startswith('clean_control_failed:')

async def test_push_5xx_registration_is_error_not_pass():
    target,_=target_for('safe','JSONRPC')
    original=target._transport
    async def handler(req):
        if req.method=='POST':
            body=json.loads(req.content)
            if body['method']=='CreateTaskPushNotificationConfig' and '127.0.0.1' in body['params']['url']: return httpx.Response(500,json={})
        return await original.handle_async_request(req)
    target._transport=httpx.MockTransport(handler)
    assert (await run_target(target,'push_private_callback'))[0][0]=='error'

@pytest.mark.parametrize('binding',BINDINGS)
async def test_push_cleanup_deletes_every_created_config(binding):
    target,_=target_for('naive',binding)
    transport=target._transport
    app=transport.app
    (_, _),ev=await run_target(target,'push_private_callback')
    assert len([e for e in ev['exchanges'] if e['step']=='cleanup_delete'])==7
    assert app.state.push_configs=={}
    steps=[e['step'] for e in ev['exchanges']]
    assert steps[-1]=='cleanup_cancel' and steps[-8:-1]==['cleanup_delete']*7

async def test_push_cleanup_uses_sent_id_and_reports_leftovers():
    target,_=target_for('naive','JSONRPC')
    original=target._transport
    created=[];deleted=[]
    async def handler(req):
        if req.method=='POST':
            body=json.loads(req.content)
            if body['method']=='CreateTaskPushNotificationConfig':
                created.append(body['params']['id'])
                return httpx.Response(200,json={'result':{'url':body['params']['url']}})
            if body['method']=='DeleteTaskPushNotificationConfig':
                deleted.append(body['params']['id'])
                return httpx.Response(500,json={})
        return await original.handle_async_request(req)
    target._transport=httpx.MockTransport(handler)
    (outcome,reason),_=await run_target(target,'push_private_callback')
    assert outcome=='warn' and 'could not be deleted' in reason
    assert deleted==created and len(deleted)==7

SSRF_CLAIM=re.compile(r'SSRF\s+(occurred|happened|confirmed|succeeded|exploited|attack)|SSRF vulnerability',re.I)
async def test_push_reasons_never_claim_ssrf_happened():
    for variant,patch in [('naive',{}),('naive',{'push_callback_policy':'deny_private'}),('safe',{}),('no_push',{}),('message_only',{})]:
        target,_=target_for(variant,'JSONRPC',**patch)
        (_,reason),_=await run_target(target,'push_private_callback')
        assert SSRF_CLAIM.search(reason) is None

async def test_push_incomplete_evidence_is_error():
    from argus.a2a.verdicts import decide
    from tests.a2a_helpers import evidence_for,exchange
    ev=evidence_for('push_private_callback',[exchange('control_send'),exchange('control_register')])
    assert decide('push_private_callback',ev)[0]=='error'

async def test_http_json_delete_null_reports_unconfirmed_cleanup():
    target,_=target_for('safe','HTTP+JSON')
    original=target._transport
    app=original.app
    async def handler(req):
        if req.method=='DELETE': return httpx.Response(200,content=b'null')
        return await original.handle_async_request(req)
    target._transport=httpx.MockTransport(handler)
    (outcome,reason),ev=await run_target(target,'push_private_callback')
    assert outcome=='pass' and 'could not be deleted' in reason
    assert app.state.push_configs
    assert next(ex for ex in ev['exchanges'] if ex['step']=='cleanup_delete')['outcome']=='undecodable'
