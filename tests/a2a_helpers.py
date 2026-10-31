from types import SimpleNamespace
import httpx
from argus.targets.a2a_server import A2AServerSpec, A2AServerTarget
from argus.demo.a2a_server.app import create_app, DEMO_TOKENS
from argus.a2a.verdicts import decide

BINDINGS=['JSONRPC','HTTP+JSON']
AUTH_CHECKS=['unauthenticated_task','invalid_credentials']

def target_for(variant,binding,**overrides):
    anonymous=overrides.pop('anonymous_requirement',None)
    app=create_app(variant,binding,anonymous_requirement=anonymous)
    spec=A2AServerSpec(**{'url':'http://127.0.0.1:8765','credentials':{'headers':[['Authorization',DEMO_TOKENS['primary']]]},'allow_send':True,**overrides})
    target=A2AServerTarget(spec)
    target._transport=httpx.ASGITransport(app=app)
    return target,app.state.ledger

async def run_target(target,check):
    await target.begin_probe(SimpleNamespace(assertions=({'a2a_server':check},)))
    await target.send_prompt('passive')
    evidence=await target.collect_evidence()
    return decide(check,evidence),evidence

def cross_second(forbidden=('get','list','cancel'),token=DEMO_TOKENS['second']):
    return {'headers':[['Authorization',token]],'forbidden_on_primary_tasks':list(forbidden)}

def exchange(step,outcome='success',**kwargs):
    return {'step':step,'outcome':outcome,'http_status':200,'jsonrpc_code':None,'result_kind':'task','task_id':'task-x','task_state':'TASK_STATE_WORKING','detail':{},**kwargs}

def evidence_for(check,exchanges):
    return {'check':check,'precondition':{},'card':{'signature_count':0},'config':{'forbidden_on_primary_tasks':[],'jsonrpc_auth_error_codes':{'authentication':[],'authorization':[]},'push_callback_policy':None},'exchanges':exchanges}
