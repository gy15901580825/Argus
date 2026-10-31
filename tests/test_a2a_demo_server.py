import httpx
import pytest
from argus.demo.a2a_server.app import create_app

BINDINGS=['JSONRPC','HTTP+JSON']

async def raw_call(client,binding,op,args=None,token=None):
    headers={'A2A-Version':'1.0'}
    if token: headers['Authorization']=token
    args=args or {}
    if binding=='JSONRPC':
        return await client.post('/a2a/rpc',json={'jsonrpc':'2.0','id':1,'method':op,'params':args},headers=headers)
    task_id=args.get('taskId',args.get('id',''))
    table={'SendMessage':('POST','/message:send'),'GetTask':('GET',f'/tasks/{task_id}'),'ListTasks':('GET','/tasks'),'CancelTask':('POST',f'/tasks/{task_id}:cancel'),'CreateTaskPushNotificationConfig':('POST',f'/tasks/{task_id}/pushNotificationConfigs'),'DeleteTaskPushNotificationConfig':('DELETE',f'/tasks/{task_id}/pushNotificationConfigs/{args.get("id", "")}'),'GetExtendedAgentCard':('GET','/extendedAgentCard')}
    method,path=table[op]
    return await client.request(method,'/a2a/rest'+path,json=args if method=='POST' else None,headers=headers)

def raw_result(response,binding):
    body=response.json()
    return body['result'] if binding=='JSONRPC' else body

@pytest.mark.parametrize('binding',BINDINGS)
async def test_card_declares_only_the_requested_binding(binding):
    app=create_app('safe',binding)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://127.0.0.1:8765') as c:
        card=(await c.get('/.well-known/agent-card.json')).json()
        assert [i['protocolBinding'] for i in card['supportedInterfaces']]==[binding]
        assert card['securityRequirements']==[{'schemes':{'bearer':{'list':[]}}}]

@pytest.mark.parametrize('binding',BINDINGS)
async def test_safe_rejects_missing_and_unknown_tokens_with_401(binding):
    app=create_app('safe',binding)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://127.0.0.1:8765') as c:
        for token in (None,'Bearer forged'):
            assert (await raw_call(c,binding,'SendMessage',{'message':{'parts':[{'text':'hello'}]}},token)).status_code==401
    assert app.state.ledger.state_changing==2

@pytest.mark.parametrize('binding',BINDINGS)
async def test_safe_hides_other_principals_tasks(binding):
    app=create_app('safe',binding)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://127.0.0.1:8765') as c:
        task=raw_result(await raw_call(c,binding,'SendMessage',{'message':{'parts':[{'text':'hello'}]},'configuration':{'returnImmediately':True}},'Bearer demo-alice'),binding)['task']
        response=await raw_call(c,binding,'GetTask',{'id':task['id']},'Bearer demo-bob')
        assert response.status_code==(200 if binding=='JSONRPC' else 404)
        if binding=='JSONRPC': assert response.json()['error']['code']==-32001

@pytest.mark.parametrize('binding',BINDINGS)
async def test_ledger_counts_state_changing_requests_even_when_rejected(binding):
    app=create_app('safe',binding)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://127.0.0.1:8765') as c:
        for op in ('SendMessage','CancelTask','CreateTaskPushNotificationConfig','DeleteTaskPushNotificationConfig'):
            await raw_call(c,binding,op,{'id':'x','taskId':'x'})
    assert app.state.ledger.state_changing==4

@pytest.mark.parametrize('binding',BINDINGS)
async def test_safe_push_checks_literal_hosts_without_dns(binding):
    app=create_app('safe',binding)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://127.0.0.1:8765') as c:
        task=raw_result(await raw_call(c,binding,'SendMessage',{'message':{},'configuration':{'returnImmediately':True}},'Bearer demo-alice'),binding)['task']
        for url in ('https://callback.invalid/x','http://10.0.0.1/x','http://localhost/x','http://169.254.169.254/x'):
            r=await raw_call(c,binding,'CreateTaskPushNotificationConfig',{'taskId':task['id'],'url':url},'Bearer demo-alice')
            assert r.status_code==(200 if '.invalid' in url else 400)

def test_jsonrpc_only_variants_refuse_http_json():
    for variant in ('jsonrpc_custom_code','push_jsonrpc_error_200'):
        with pytest.raises(ValueError): create_app(variant,'HTTP+JSON')

async def test_optional_auth_card_carries_the_given_anonymous_requirement():
    app=create_app('optional_auth','JSONRPC',anonymous_requirement={'description':'public'})
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://127.0.0.1:8765') as c:
        assert (await c.get('/.well-known/agent-card.json')).json()['securityRequirements'][-1]=={'description':'public'}
