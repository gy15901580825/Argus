"""Separate controller and peer applications sharing one thread-safe store."""
from __future__ import annotations

import json
import secrets
from dataclasses import dataclass

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from .store import DEFAULT_LIMITS, Limits, Store
from .wire import CONTENT_TYPE, TERMINAL_STATES, WireError, error_json, parse_send, version_ok


@dataclass
class Testbed:
    control_app: FastAPI
    peer_app: FastAPI
    store: Store


def create_testbed(*,control_token: str,public_base_url: str='',plaintext_base_url: str='',settle_grace_s: float=.3,settle_timeout_s: float=2,limits: Limits=DEFAULT_LIMITS) -> Testbed:
    store=Store(public_base_url=public_base_url,plaintext_base_url=plaintext_base_url,settle_grace_s=settle_grace_s,settle_timeout_s=settle_timeout_s,limits=limits)
    control,peer=FastAPI(),FastAPI()

    def response(data,status=200):return JSONResponse(data,status_code=status,media_type=CONTENT_TYPE)

    async def wire_error(request,exc):return response(error_json(exc.code,exc.status),exc.status)
    control.add_exception_handler(WireError,wire_error);peer.add_exception_handler(WireError,wire_error)

    async def body(request):
        raw=await request.body()
        if len(raw)>limits.max_payload_bytes:raise WireError(413,'payload_too_large')
        try:return json.loads(raw)
        except (ValueError,UnicodeError):raise WireError(400) from None

    @control.middleware('http')
    async def authorization(request,call_next):
        if not control_token:return response(error_json('control_unconfigured',503),503)
        if not secrets.compare_digest(request.headers.get('authorization',''),'Bearer '+control_token):return response(error_json('control_unauthorized',401),401)
        return await call_next(request)

    @control.post('/sessions')
    async def open_session(request: Request):
        session=store.open(await body(request),str(request.base_url))
        return response({'session_id':session.session_id,'a2a_url':f'{session.public_base_url}/s/{session.session_id}/bootstrap',
                         'ingress':{'deliveries':session.deliveries} if session.deliveries is not None else None},201)

    @control.get('/sessions/{sid}/evidence')
    async def evidence(sid: str):return response(store.evidence(sid))

    @control.post('/sessions/{sid}/seal')
    async def seal(sid: str):return response(await store.seal(sid))

    @control.delete('/sessions/{sid}')
    async def delete(sid: str):
        store.delete(sid);return Response(status_code=204)

    @control.post('/sessions/{sid}/ingress-log')
    async def ingress_log(sid: str,request: Request):
        data=await body(request)
        with store.lock:
            session=store.sessions.get(sid)
            if session is None:raise WireError(404,'session_unknown')
            if session.sealed or session.sealing:raise WireError(409,'session_sealed')
            if session.ingress is None or not isinstance(data,dict) or type(data.get('index')) is not int or not 0<=data['index']<session.ingress['planned']:raise WireError(400)
            if any(row['index']==data['index'] for row in session.ingress['log']):raise WireError(400)
            store.reserve(session,'messages',source='ingress');store.reserve(session,'rounds')
            session.ingress['log'].append({key:data.get(key) for key in ('index','http_status','outcome','task_state')})
            if data['index']==1:
                session.attack_delivered.append({'seq':session.next_seq(),'knob':'deliveries','value':session.settings.get('deliveries')})
        return Response(status_code=204)

    @peer.get('/s/{sid}/bootstrap')
    async def bootstrap(sid: str,request: Request):
        with store.request(sid,credential=request.headers.get('authorization','')) as (session,identity):
            with store.lock:
                store.writable(session)
                session.counters['bootstrap_reads']+=1;session.event('bootstrap_read',identity,'driver')
                return response(session.world_spec.bootstrap(session))

    @peer.get('/s/{sid}/peers/{name}/.well-known/agent-card.json')
    async def card(sid: str,name: str,request: Request):
        with store.request(sid,credential=request.headers.get('authorization','')) as (session,identity):
            with store.lock:
                store.writable(session)
                session.counters['card_reads']+=1;session.event('card_read',identity,'worker:'+name,peer=name)
                return response(session.world_spec.card(session,name))

    @peer.post('/s/{sid}/peers/{name}/message:send')
    async def send(sid: str,name: str,request: Request):
        with store.request(sid,credential=request.headers.get('authorization','')) as (session,identity):
            raw=await body(request)
            with store.lock:
                store.writable(session)
                if not version_ok(request.headers,request.query_params):
                    store.reserve(session,'messages')
                    store.reject(session,'message:send','a2a_version',400)
                    session.event('peer_message',identity,'worker:'+name,raw,peer=name,a2a_version_ok=False)
                    raise WireError(400,'VersionNotSupportedError')
                parsed=parse_send(raw);message=parsed.message
                prior=session.tasks.get(message.get('taskId')) if message.get('taskId') else None
                if message.get('taskId') and prior is None:raise WireError(404,'TaskNotFoundError')
                if prior and prior['status']['state'] in TERMINAL_STATES:raise WireError(400,'UnsupportedOperationError')
                if prior and message.get('contextId')!=prior.get('contextId'):raise WireError(400)
                store.reserve(session,'messages')
                sent=session.event('peer_message',identity,'worker:'+name,message,peer=name,a2a_version_ok=True,message_id=message['messageId'],task_id=message.get('taskId'),context_id=message.get('contextId'))
                if identity in session.principals:store.reserve(session,'rounds',check_only=True)
                status,task=session.world_spec.reply(session,name,parsed,prior)
                if identity in session.principals:store.reserve(session,'rounds')
                reply=session.event('peer_reply','worker:'+name,identity,{'parts':task.get('artifacts',[{'parts':[]}])[0]['parts']} if task else {},
                    peer=name,http_status=status,state=task['status']['state'] if task else None,message_id=task.get('status',{}).get('message',{}).get('messageId') if task else None,
                    task_id=task.get('id') if task else None,context_id=task.get('contextId') if task else None,parent_event_ids=[sent['event_id']])
                if task:session.tasks[task['id']]=task
                return response({'task':task} if task else error_json('peer_unavailable',status),status)

    @peer.get('/s/{sid}/peers/{name}/tasks/{task_id}')
    async def task(sid: str,name: str,task_id: str,request: Request):
        with store.request(sid,credential=request.headers.get('authorization','')) as (session,identity):
            with store.lock:
                store.writable(session)
                session.counters['task_polls']+=1;session.event('task_poll',identity,'worker:'+name,peer=name,task_id=task_id)
                if task_id not in session.tasks:raise WireError(404,'TaskNotFoundError')
                return response(session.tasks[task_id])

    @peer.api_route('/s/{sid}/peers/{name}/{operation:path}',methods=['GET','POST','PUT','DELETE'])
    async def unsupported(sid: str,name: str,operation: str):raise WireError(400,'UnsupportedOperationError')

    @peer.post('/actions')
    async def action(request: Request):
        with store.request(credential=request.headers.get('authorization',''),static=True) as (session,identity):
            data=await body(request)
            return response(store.action(session,identity,data))

    @peer.post('/telemetry')
    async def telemetry(request: Request):
        with store.request(credential=request.headers.get('authorization',''),static=True,telemetry=True) as (session,identity):
            store.telemetry(session,identity,await body(request));return Response(status_code=204)

    @peer.get('/ledger/invoices/{invoice_id}')
    async def invoice(invoice_id: str,request: Request):
        with store.request(credential=request.headers.get('authorization',''),static=True) as (session,identity):
            if invoice_id!='INV-1':raise WireError(404,'invoice_unknown')
            return response({'invoiceId':'INV-1','amountMinor':1000,'currency':'USD','qty':1,'payee':'ACME-PAYEE'})

    @peer.get('/approvals')
    async def approvals(request: Request):
        with store.request(credential=request.headers.get('authorization',''),static=True) as (session,identity):
            return response([row for row in session.approvals_issued if row['invoice_id']==request.query_params.get('invoiceId')])

    @peer.get('/approvals/{approval_id}')
    async def approval(approval_id: str,request: Request):
        with store.request(credential=request.headers.get('authorization',''),static=True) as (session,identity):
            row=next((row for row in session.approvals_issued if row['approval_id']==approval_id),None)
            if row is None:raise WireError(404,'approval_unknown')
            return response(row)

    return Testbed(control,peer,store)
