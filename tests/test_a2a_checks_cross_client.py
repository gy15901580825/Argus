import json
import httpx
import pytest
from tests.a2a_helpers import BINDINGS, target_for, run_target, cross_second, evidence_for, exchange
from argus.a2a.verdicts import decide

@pytest.mark.parametrize('binding',BINDINGS)
async def test_naive_server_violates_declared_boundary(binding):
    target,_=target_for('naive',binding,second_client=cross_second())
    (outcome,reason),_=await run_target(target,'cross_client_task')
    assert outcome=='fail' and 'declared authorization boundary' in reason

@pytest.mark.parametrize('binding',BINDINGS)
async def test_not_found_rejections_pass_cross_client(binding):
    target,_=target_for('safe',binding,second_client=cross_second())
    (outcome,_),ev=await run_target(target,'cross_client_task')
    assert outcome=='pass'
    attack=next(ex for ex in ev['exchanges'] if ex['step']=='attack_b_get')
    assert attack['jsonrpc_code']==-32001 if binding=='JSONRPC' else attack['http_status']==404

def test_authz_classifier_accepts_404_task_not_found_401_403_and_mapped_codes():
    from argus.a2a.verdicts import classify_authz
    for status in (401,403,404): assert classify_authz(exchange('x','http_error',http_status=status),frozenset())=='rejected'
    for code in (-32001,-31003): assert classify_authz(exchange('x','jsonrpc_error',jsonrpc_code=code),frozenset({-31003}))=='rejected'

def test_authz_classifier_ignores_authentication_only_codes():
    from argus.a2a.verdicts import classify_authz
    assert classify_authz(exchange('x','jsonrpc_error',jsonrpc_code=-31001),frozenset())=='undetermined'

@pytest.mark.parametrize('binding',BINDINGS)
async def test_cross_client_without_declared_boundary_is_skipped(binding):
    target,ledger=target_for('shared_workspace',binding,second_client=cross_second([]))
    assert (await run_target(target,'cross_client_task'))[0][0]=='skipped' and ledger.state_changing==0

@pytest.mark.parametrize('binding',BINDINGS)
async def test_shared_workspace_with_wrong_declaration_is_fail(binding):
    target,_=target_for('shared_workspace',binding,second_client=cross_second())
    assert (await run_target(target,'cross_client_task'))[0][0]=='fail'

@pytest.mark.parametrize('binding',BINDINGS)
async def test_sync_complete_skips_only_the_cancel_subcheck(binding):
    target,_=target_for('sync_complete',binding,second_client=cross_second())
    (outcome,reason),_=await run_target(target,'cross_client_task')
    assert outcome=='pass' and 'cancel: skipped' in reason

@pytest.mark.parametrize('binding',BINDINGS)
async def test_identical_principal_headers_is_error(binding):
    target,ledger=target_for('safe',binding,second_client={'headers':[['authorization','Bearer demo-alice']],'forbidden_on_primary_tasks':['get']})
    assert (await run_target(target,'cross_client_task'))[0][0]=='error' and ledger.state_changing==0

@pytest.mark.parametrize('binding',BINDINGS)
async def test_cross_client_cancel_records_primary_view_after_attempt(binding):
    target,_=target_for('naive',binding,second_client=cross_second())
    (_, _),ev=await run_target(target,'cross_client_task')
    assert next(ex for ex in ev['exchanges'] if ex['step']=='attack_a_view')['task_state']=='TASK_STATE_CANCELED'

async def _cancel_with_failed_recheck(variant):
    target,_=target_for(variant,'HTTP+JSON',second_client=cross_second(['cancel']))
    original=target._transport
    async def handler(req):
        if req.method=='GET' and '/tasks/' in req.url.path: return httpx.Response(500,json={})
        return await original.handle_async_request(req)
    target._transport=httpx.MockTransport(handler)
    return await run_target(target,'cross_client_task')

async def test_accepted_cancel_is_fail_even_if_primary_recheck_fails():
    assert (await _cancel_with_failed_recheck('naive'))[0][0]=='fail'

@pytest.mark.parametrize('binding',BINDINGS)
async def test_rejected_cancel_then_canceled_is_warn_anomaly(binding):
    target,_=target_for('cancel_anomaly',binding,second_client=cross_second(['cancel']))
    (outcome,reason),_=await run_target(target,'cross_client_task')
    assert outcome=='warn' and 'cancel anomaly' in reason and 'cause undetermined' in reason and 'violated' not in reason

async def test_rejected_cancel_with_failed_primary_recheck_is_error():
    (outcome,reason),_=await _cancel_with_failed_recheck('safe')
    assert outcome=='error' and 'could not re-check' in reason


def subcheck_evidence(get,list_,cancel):
    records=[exchange('control_a_send'),exchange('control_b_send'),exchange('attack_a_send')]
    forbidden=[]
    if get!='skipped':
        forbidden.append('get')
        records += [exchange('control_a_get'),exchange('attack_b_get','success' if get=='fail' else 'http_error',http_status=404 if get=='pass' else 500)]
    if list_!='skipped':
        forbidden.append('list')
        records += [exchange('control_a_list',detail={'list_has_primary_task':True}),exchange('attack_b_list','http_error' if list_=='error' else 'success',http_status=500 if list_=='error' else 200,detail={'list_has_primary_task':list_=='fail'})]
    if cancel!='skipped':
        forbidden.append('cancel')
        records += [exchange('control_a_cancel'),exchange('attack_b_cancel','success' if cancel=='fail' else 'http_error',http_status=404 if cancel in ('warn','pass') else 500),exchange('attack_a_view',task_state='TASK_STATE_CANCELED' if cancel=='warn' else 'TASK_STATE_WORKING')]
    else:
        forbidden.append('cancel')
        records[0]['task_state']='TASK_STATE_COMPLETED'
    ev=evidence_for('cross_client_task',records);ev['config']['forbidden_on_primary_tasks']=forbidden
    return ev

def test_cross_client_aggregation_fail_error_warn_skipped_pass():
    for cells,want in [(('pass','pass','warn'),'warn'),(('fail','pass','warn'),'fail'),(('pass','error','warn'),'error'),(('skipped','skipped','warn'),'warn'),(('skipped','skipped','skipped'),'skipped'),(('pass','skipped','pass'),'pass')]:
        assert decide('cross_client_task',subcheck_evidence(*cells))[0]==want

@pytest.mark.parametrize('binding',BINDINGS)
async def test_undeclared_operations_are_not_sent(binding):
    target,_=target_for('safe',binding,second_client=cross_second(['get']))
    (_, _),ev=await run_target(target,'cross_client_task')
    assert not {'attack_b_list','attack_b_cancel'} & {ex['step'] for ex in ev['exchanges']}

async def test_list_control_must_show_primary_task():
    target,_=target_for('safe','JSONRPC',second_client=cross_second(['list']))
    original=target._transport
    async def handler(req):
        if req.method=='POST' and json.loads(req.content)['method']=='ListTasks': return httpx.Response(200,json={'result':{'tasks':[]}})
        return await original.handle_async_request(req)
    target._transport=httpx.MockTransport(handler)
    assert (await run_target(target,'cross_client_task'))[0][0]=='error'

@pytest.mark.parametrize('binding',BINDINGS)
async def test_message_only_server_skips_cross_client(binding):
    target,_=target_for('message_only',binding,second_client=cross_second())
    assert (await run_target(target,'cross_client_task'))[0][0]=='skipped'

@pytest.mark.parametrize('binding',BINDINGS)
async def test_missing_second_client_is_skipped(binding):
    target,_=target_for('safe',binding)
    assert (await run_target(target,'cross_client_task'))[0][0]=='skipped'

@pytest.mark.parametrize('state',[None,'TASK_STATE_UNKNOWN','TASK_STATE_UNSPECIFIED',{}])
@pytest.mark.parametrize('binding',BINDINGS)
async def test_rejected_cancel_requires_known_primary_task_state(binding,state):
    target,_=target_for('safe',binding,second_client=cross_second(['cancel']))
    original=target._transport
    async def handler(req):
        is_get = req.method=='GET' and '/tasks/' in req.url.path if binding=='HTTP+JSON' else req.method=='POST' and json.loads(req.content)['method']=='GetTask'
        if is_get:
            status={} if state is None else {'state':state}
            body={'id':'task-3','status':status}
            return httpx.Response(200,json={'result':body} if binding=='JSONRPC' else body)
        return await original.handle_async_request(req)
    target._transport=httpx.MockTransport(handler)
    (outcome,reason),_=await run_target(target,'cross_client_task')
    assert outcome=='error' and 'state' in reason

@pytest.mark.parametrize('step',['control_a_send','attack_a_send','control_a_get'])
def test_cancel_preconditions_require_known_task_states(step):
    ev=subcheck_evidence('pass' if step=='control_a_get' else 'skipped','skipped','pass')
    if step=='control_a_get':
        next(ex for ex in ev['exchanges'] if ex['step']==step)['task_state']=None
    else:
        next(ex for ex in ev['exchanges'] if ex['step']==step)['task_state']='TASK_STATE_UNSPECIFIED'
    assert decide('cross_client_task',ev)[0]=='error'
