import asyncio
import json
import threading
import time
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from argus.demo.a2a_testbed.testbed.app import create_testbed
from argus.demo.a2a_testbed.testbed.store import DEFAULT_LIMITS
from test_a2a_testbed_wire import request, send, setup_peer

AUTH={'Authorization':'Bearer control'}
PRINCIPALS={'planner':'Bearer planner','reviewer':'Bearer reviewer','executor':'Bearer executor'}


def opened(**kwargs):
    tb=create_testbed(control_token='control',settle_grace_s=0,**kwargs)
    c,p=TestClient(tb.control_app),TestClient(tb.peer_app)
    response=c.post('/sessions',headers=AUTH,json={'scenario':'a2a_world','world':'invoice_delegation','phase':'attack','principals':PRINCIPALS})
    assert response.status_code==201,response.text
    p.business_record=tb.store.sessions[response.json()['session_id']].business_record
    return tb,c,p,response.json()['session_id']


def telemetry(sender,receiver,message,kind):
    return {'events':[{'kind':kind,'peer_role':receiver if kind=='message_sent' else sender,'message':message,'adopted':True}]}


def test_control_requires_token_and_fails_closed_when_unset():
    for token,want in (('',503),('control',401)):
        c=TestClient(create_testbed(control_token=token).control_app)
        assert c.post('/sessions',json={}).status_code==want
    tb,c,p,sid=opened()
    assert c.get(f'/sessions/{sid}/evidence',headers={'Authorization':'Bearer wrong'}).status_code==401


def test_control_routes_absent_from_peer_app_and_vice_versa():
    tb,c,p,sid=opened()
    assert p.post('/sessions',json={}).status_code==404
    assert c.get(f'/s/{sid}/bootstrap',headers=AUTH).status_code==404


def test_second_active_session_is_409():
    tb,c,p,sid=opened()
    assert c.post('/sessions',headers=AUTH,json={'world':'payout_inbox','phase':'clean'}).status_code==409


def test_identity_from_credentials_else_entry():
    tb,c,p,sid=opened();send(p,sid)
    p.post(f'/s/{sid}/peers/invoice-worker/message:send',headers={'A2A-Version':'1.0'},json=request('M2',parts=[{'data':p.business_record}]))
    assert [e['sender'] for e in tb.store.evidence(sid)['events'] if e['kind']=='peer_message']==['planner','entry']


def test_static_route_requires_role_credential():
    tb,c,p,sid=opened()
    assert p.post('/actions',json={'operation':'pay_invoice'}).status_code==401
    assert tb.store.evidence(sid)['rejected_requests'][-1]['reason']=='unknown_credential'


def test_static_route_without_active_session_is_rejected():
    tb,c,p,sid=opened();c.post(f'/sessions/{sid}/seal',headers=AUTH)
    assert p.post('/actions',headers={'Authorization':'Bearer planner'},json={'operation':'pay_invoice'}).status_code==503
    assert tb.store.run_log[-1]['reason']=='no_active_session'


def test_telemetry_pairs_by_digest_into_matched_edge():
    tb,c,p,sid=opened();message=request()['message']
    assert p.post('/telemetry',headers={'Authorization':PRINCIPALS['planner']},json=telemetry('planner','reviewer',message,'message_sent')).status_code==204
    assert p.post('/telemetry',headers={'Authorization':PRINCIPALS['reviewer']},json=telemetry('planner','reviewer',message,'message_received')).status_code==204
    rows=tb.store.evidence(sid)['events']
    assert len(rows)==1 and rows[0]['assurance']=='matched_observers'
    assert (rows[0]['sender'],rows[0]['receiver'])==('planner','reviewer')


def test_one_sided_telemetry_stays_unmatched():
    tb,c,p,sid=opened();p.post('/telemetry',headers={'Authorization':PRINCIPALS['reviewer']},json=telemetry('planner','reviewer',request()['message'],'message_received'))
    assert tb.store.evidence(sid)['events'][0]['assurance']=='receiver_only'


def test_telemetry_adopted_flag_is_ignored():
    tb,c,p,sid=opened();p.post('/telemetry',headers={'Authorization':PRINCIPALS['reviewer']},json=telemetry('planner','reviewer',request()['message'],'message_received'))
    assert 'adopted' not in json.dumps(tb.store.evidence(sid))


def test_actions_ledger_is_passive():
    tb,c,p,sid=opened()
    for _ in range(2):
        assert p.post('/actions',headers={'Authorization':PRINCIPALS['executor']},json={'operation':'release_payment','approvalId':'not-issued','amountMinor':1000}).status_code==200
    actions=tb.store.evidence(sid)['actions']
    assert len(actions)==2 and all(a['request_received'] and a['accepted'] and a['applied'] for a in actions)


def test_hard_budget_messages_429_and_flag():
    tb,c,p,sid=opened(limits=replace(DEFAULT_LIMITS,max_messages=2));assert send(p,sid).status_code==200
    assert send(p,sid,request('M2',parts=[{'data':p.business_record}])).status_code==200
    assert send(p,sid,request('M3',parts=[{'data':p.business_record}])).status_code==429
    assert tb.store.evidence(sid)['budget']['exhausted_by']=='messages'


def test_hard_budget_concurrency_and_rounds():
    tb,c,p,sid=opened(limits=replace(DEFAULT_LIMITS,max_concurrency=1,max_rounds=1))
    with tb.store.request(sid):assert send(p,sid).status_code==429
    assert tb.store.evidence(sid)['budget']['exhausted_by']=='concurrency'
    tb,c,p,sid=opened(limits=replace(DEFAULT_LIMITS,max_rounds=1))
    assert send(p,sid).status_code==200 and send(p,sid,request('M2',parts=[{'data':p.business_record}])).status_code==429
    assert tb.store.evidence(sid)['budget']['exhausted_by']=='rounds'


def test_phase_duration_limit():
    tb,c,p,sid=opened();session=tb.store.sessions[sid]
    tb.store.clock=lambda:session.opened_at+31
    assert send(p,sid).status_code==429
    assert tb.store.evidence(sid)['budget']['exhausted_by']=='phase_duration'


def test_telemetry_still_recorded_after_exhaustion():
    tb,c,p,sid=opened(limits=replace(DEFAULT_LIMITS,max_messages=1));send(p,sid);send(p,sid,request('M2',parts=[{'data':p.business_record}]))
    response=p.post('/telemetry',headers={'Authorization':PRINCIPALS['planner']},json=telemetry('planner','reviewer',request()['message'],'message_sent'))
    assert response.status_code==204 and tb.store.evidence(sid)['counters']['telemetry_events']==1


def test_seal_waits_for_in_flight_then_rejects_late_requests():
    tb,c,p,sid=opened(settle_timeout_s=1)
    started=threading.Event();finished=threading.Event()
    def hold():
        with tb.store.request(sid):
            started.set();finished.wait(1)
    thread=threading.Thread(target=hold);thread.start();assert started.wait(1)
    timer=threading.Timer(.03,finished.set);timer.start()
    sealed=c.post(f'/sessions/{sid}/seal',headers=AUTH).json();thread.join(1);timer.join(1)
    assert sealed['sealed'] and not sealed['seal_timeout'] and not thread.is_alive()
    assert send(p,sid).status_code==409
    before=sealed['events'];assert tb.store.evidence(sid)['events']==before


def test_seal_timeout_is_recorded():
    tb,c,p,sid=opened(settle_timeout_s=.01)
    with tb.store.request(sid):sealed=c.post(f'/sessions/{sid}/seal',headers=AUTH).json()
    assert sealed['seal_timeout'] is True


def test_evidence_never_contains_authorization_values():
    tb,c,p,sid=opened()
    message=request();message['message']['metadata']={'Authorization':PRINCIPALS['planner']}
    send(p,sid,message);p.post('/actions',headers={'Authorization':PRINCIPALS['executor']},json={'operation':'pay_invoice','invoiceId':PRINCIPALS['planner']})
    bare='synthetic-role-secret-123'
    credential='Bearer '+bare
    tb2=create_testbed(control_token='control',settle_grace_s=0)
    c2,p2=TestClient(tb2.control_app),TestClient(tb2.peer_app)
    sid2=c2.post('/sessions',headers=AUTH,json={'world':'invoice_delegation','phase':'attack','principals':{'planner':credential}}).json()['session_id']
    batch=tb2.store.sessions[sid2].canaries['batch_id']
    p2.post('/actions',headers={'Authorization':credential},json={'operation':'submit_invoice','batchId':batch,'payee':bare})
    raw=json.dumps(c.post(f'/sessions/{sid}/seal',headers=AUTH).json())
    assert all(value not in raw for value in PRINCIPALS.values()) and 'Bearer control' not in raw
    for response in (c2.get(f'/sessions/{sid2}/evidence',headers=AUTH),c2.post(f'/sessions/{sid2}/seal',headers=AUTH),c2.get(f'/sessions/{sid2}/evidence',headers=AUTH)):
        assert response.status_code==200
        assert bare not in response.text and credential not in response.text


def test_two_testbeds_in_one_process_are_isolated():
    one,c1,p1,s1=opened();two,c2,p2,s2=opened();send(p1,s1)
    assert one.store.evidence(s1)['counters']['business_sends']==1
    assert two.store.evidence(s2)['counters']['business_sends']==0 and s1!=s2

@pytest.mark.parametrize('field', ['amountMinor', 'qty'])
@pytest.mark.parametrize('value', [True, False, 1.0, 1000.0])
def test_business_integer_fields_reject_boolean_and_float(field, value):
    tb,c,p,sid=opened()
    result=p.post('/actions',headers={'Authorization':PRINCIPALS['planner']},json={'operation':'pay_invoice',field:value})
    assert result.status_code==400
    assert tb.store.evidence(sid)['actions']==[]


def test_late_in_flight_mutation_cannot_change_sealed_store():
    tb,c,p,sid=opened(settle_timeout_s=.01)
    with tb.store.request(sid) as (session,identity):
        c.post(f'/sessions/{sid}/seal',headers=AUTH)
        frozen=tb.store.evidence(sid)
        from argus.demo.a2a_testbed.testbed.wire import WireError
        with pytest.raises(WireError) as caught:
            tb.store.action(session,'planner',{'operation':'pay_invoice','approvalId':session.approvals_issued[0]['approval_id']})
        assert caught.value.status==409
        assert session.actions==[] and tb.store.evidence(sid)==frozen


def test_explicit_old_refs_block_current_parent_even_with_message_id_collision():
    tb,c,p,sid=opened()
    old=tb.store.sessions[sid].record_ref
    c.post(f'/sessions/{sid}/seal',headers=AUTH)
    result=c.post('/sessions',headers=AUTH,json={'world':'payout_inbox','phase':'attack','principals':PRINCIPALS})
    sid2=result.json()['session_id'];session=tb.store.sessions[sid2]
    session.event('peer_reply','worker:invoice-worker','planner',{'recordRef':session.record_ref},message_id='M1')
    posted=p.post('/actions',headers={'Authorization':PRINCIPALS['planner']},json={'operation':'pay_invoice','amountMinor':100000,'recordRef':old,'parentMessageIds':['M1']})
    assert posted.status_code==200
    assert len(session.actions)==1 and not session.current(session.actions[0])


def test_telemetry_sent_budget_counts_every_observation_and_blocks_business():
    tb,c,p,sid=opened(limits=replace(DEFAULT_LIMITS,max_messages=1))
    message=request()['message']
    for _ in range(2):
        assert p.post('/telemetry',headers={'Authorization':PRINCIPALS['planner']},json=telemetry('planner','reviewer',message,'message_sent')).status_code==204
    assert tb.store.evidence(sid)['budget']['exhausted_by']=='messages'
    assert send(p,sid).status_code==429


def test_delegation_depth_uses_paired_causal_edges_at_seal():
    tb,c,p,sid=opened();session=tb.store.sessions[sid]
    ref=session.record_ref
    session.claims=[{'ref':ref,'field':'amountMinor','value':100000,'truth':1000,'kind':'seed'}]
    session.event('peer_reply','worker:invoice-worker','planner',{'recordRef':ref},message_id='initial')
    parent='initial'
    for index,(sender,receiver) in enumerate([('planner','reviewer'),('reviewer','executor'),('executor','planner')]):
        message=request('M'+str(index),parts=[{'data':{'recordRef':ref}}])['message']
        body={'events':[{'kind':'message_sent','peer_role':receiver,'message':message,'parent_message_ids':[parent]}]}
        assert p.post('/telemetry',headers={'Authorization':PRINCIPALS[sender]},json=body).status_code==204
        body['events'][0].update(kind='message_received',peer_role=sender)
        assert p.post('/telemetry',headers={'Authorization':PRINCIPALS[receiver]},json=body).status_code==204
        parent=message['messageId']
    p.post('/actions',headers={'Authorization':PRINCIPALS['planner']},json={'operation':'pay_invoice','recordRef':ref,'parentMessageIds':[parent]})
    sealed=c.post(f'/sessions/{sid}/seal',headers=AUTH).json()
    assert sealed['budget']['exhausted_by']=='delegation_depth'


def test_telemetry_invalid_batch_is_rejected_atomically():
    tb,c,p,sid=opened();valid=telemetry('planner','reviewer',request()['message'],'message_sent')['events'][0]
    bad={**valid,'peer_role':'planner'}
    assert p.post('/telemetry',headers={'Authorization':PRINCIPALS['planner']},json={'events':[valid,bad]}).status_code==400
    assert tb.store.evidence(sid)['events']==[]


@pytest.mark.parametrize('message',({}, {'messageId':'M','role':'ROLE_USER','parts':[]}, {'messageId':'M','role':'wrong','parts':[{'text':'hello'}]}))
def test_telemetry_requires_well_formed_a2a_message(message):
    tb,c,p,sid=opened()
    assert p.post('/telemetry',headers={'Authorization':PRINCIPALS['planner']},json=telemetry('planner','reviewer',message,'message_sent')).status_code==400
    assert tb.store.evidence(sid)['events']==[]


def test_action_and_telemetry_limits_are_enforced():
    tb,c,p,sid=opened(limits=replace(DEFAULT_LIMITS,max_actions=1,max_telemetry_events=1))
    headers={'Authorization':PRINCIPALS['planner']}
    assert p.post('/actions',headers=headers,json={'operation':'pay_invoice'}).status_code==200
    assert p.post('/actions',headers=headers,json={'operation':'pay_invoice'}).status_code==429
    body=telemetry('planner','reviewer',request()['message'],'message_sent')
    assert p.post('/telemetry',headers=headers,json=body).status_code==204
    assert p.post('/telemetry',headers=headers,json=body).status_code==429
    evidence=tb.store.evidence(sid)
    assert len(evidence['actions'])==1 and evidence['counters']['telemetry_events']==1


def test_rejected_version_peer_messages_still_consume_public_message_budget():
    tb,c,p,sid=opened(limits=replace(DEFAULT_LIMITS,max_messages=1))
    url=f'/s/{sid}/peers/invoice-worker/message:send'
    body=request(parts=[{'data':p.business_record}])
    assert p.post(url,json=body).status_code==400
    assert p.post(url,json=body).status_code==429
    evidence=tb.store.evidence(sid)
    assert evidence['counters']['business_sends']==1
    assert evidence['budget']['exhausted_by']=='messages'


@pytest.mark.parametrize('bare',['planner','v1'])
def test_redaction_preserves_typed_public_facts_for_colliding_tokens(bare):
    credential='Bearer '+bare
    tb=create_testbed(control_token='control',settle_grace_s=0)
    c,p=TestClient(tb.control_app),TestClient(tb.peer_app)
    sid=c.post('/sessions',headers=AUTH,json={'world':'invoice_delegation','phase':'attack','principals':{'planner':credential}}).json()['session_id']
    batch=tb.store.sessions[sid].canaries['batch_id']
    result=p.post('/actions',headers={'Authorization':credential},json={'operation':'submit_invoice','batchId':batch,'payee':bare})
    assert result.status_code==200
    sealed=c.post(f'/sessions/{sid}/seal',headers=AUTH).json()
    assert sealed['schema_version']=='argus-a2a-evidence-v1'
    assert sealed['world']=='invoice_delegation' and sealed['phase']=='attack'
    assert sealed['actions'][0]['caller']=='planner'
    assert sealed['actions'][0]['operation']=='submit_invoice'
    assert sealed['actions'][0]['fields']['payee']=='[redacted]'
    assert credential not in json.dumps(sealed)


@pytest.mark.parametrize('bare',['seed','amountMinor','production_tls_policy','amount_x100'])
def test_redaction_preserves_claim_capability_and_delivery_enums(bare):
    tb=create_testbed(control_token='control',settle_grace_s=0)
    c,p=TestClient(tb.control_app),TestClient(tb.peer_app)
    sid=c.post('/sessions',headers=AUTH,json={'world':'payment_chain','phase':'attack','principals':{'planner':'Bearer '+bare},'capabilities':['production_tls_policy'],'seed':'amount_x100'}).json()['session_id']
    opened=c.get(f'/sessions/{sid}/evidence',headers=AUTH).json()
    request_ref=opened['canaries']['case_key']
    response=p.post(f'/s/{sid}/peers/invoice-records/message:send',headers={'Authorization':'Bearer '+bare,'A2A-Version':'1.0'},json={'message':{'messageId':'M1','role':'ROLE_USER','parts':[{'data':{'invoiceId':'INV-1','requestRef':request_ref,'payee':bare}}]}})
    assert response.status_code==200
    sealed=c.post(f'/sessions/{sid}/seal',headers=AUTH).json()
    assert sealed['claims'][0]['kind']=='seed'
    assert sealed['claims'][0]['field']=='amountMinor'
    assert sealed['capabilities']==['production_tls_policy']
    assert sealed['attack_delivered'][0]['knob']=='seed'
    assert sealed['attack_delivered'][0]['value']=='amount_x100'
    assert sealed['events'][0]['fields']['payee']=='[redacted]'
