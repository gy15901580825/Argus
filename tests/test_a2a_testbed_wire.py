import json

from fastapi.testclient import TestClient

from argus.a2a.protocol import decode_response, parse_card
from argus.demo.a2a_testbed.testbed.app import create_testbed
from argus.demo.a2a_testbed.testbed.wire import card_json, digest, extract, task_json


def setup_peer():
    tb=create_testbed(control_token='control',settle_grace_s=0)
    control=TestClient(tb.control_app)
    peer=TestClient(tb.peer_app)
    opened=control.post('/sessions',headers={'Authorization':'Bearer control'},json={'scenario':'a2a_world','world':'invoice_delegation','phase':'clean','principals':{'planner':'Bearer planner'}})
    assert opened.status_code==201,opened.text
    sid=opened.json()['session_id']
    peer.business_record=tb.store.sessions[sid].business_record
    return tb,control,peer,sid


def request(message_id='M1',**extra):
    return {'message':{'messageId':message_id,'role':'ROLE_USER','parts':[{'data':{'invoiceId':'INV-1'}}],**extra}}


def send(peer,sid,body=None,**kwargs):
    return peer.post(f'/s/{sid}/peers/invoice-worker/message:send',json=request(parts=[{'data':getattr(peer,'business_record',{})}]) if body is None else body,headers={'A2A-Version':'1.0','Authorization':'Bearer planner'},**kwargs)


def test_card_is_a2a_1_0_http_json_per_m1_parser():
    facts=parse_card(card_json('http://127.0.0.1/worker'))
    assert facts.a2a_1_0 and facts.interface.binding=='HTTP+JSON'


def test_send_response_decodes_as_success_with_m1_decoder():
    tb,c,p,sid=setup_peer();response=send(p,sid)
    assert response.status_code==200
    assert response.headers['content-type'].startswith('application/a2a+json')
    assert decode_response('HTTP+JSON','SendMessage',response.status_code,response.content).outcome=='success'


def test_get_task_decodes_and_unknown_task_is_404():
    tb,c,p,sid=setup_peer(); task=send(p,sid).json()['task']
    response=p.get(f'/s/{sid}/peers/invoice-worker/tasks/{task["id"]}')
    assert decode_response('HTTP+JSON','GetTask',response.status_code,response.content).outcome=='success'
    assert p.get(f'/s/{sid}/peers/invoice-worker/tasks/missing').status_code==404


def test_send_without_version_header_is_rejected_and_recorded():
    tb,c,p,sid=setup_peer()
    response=p.post(f'/s/{sid}/peers/invoice-worker/message:send',json=request())
    assert response.status_code==400 and response.json()['error']['details'][0]['reason']=='VERSION_NOT_SUPPORTED'
    e=tb.store.evidence(sid)
    assert e['rejected_requests'][-1]['reason']=='a2a_version'
    assert e['events'][-1]['a2a_version_ok'] is False


def test_version_as_query_parameter_is_accepted():
    tb,c,p,sid=setup_peer()
    assert p.post(f'/s/{sid}/peers/invoice-worker/message:send?A2A-Version=1.0',json=request(parts=[{'data':p.business_record}])).status_code==200


def test_malformed_send_is_400_and_not_success():
    tb,c,p,sid=setup_peer()
    for body in ({},{'message':{'messageId':'M','role':'ROLE_USER','parts':[{'text':'a','data':{}}]}},request(parts=[])):
        response=send(p,sid,body)
        assert response.status_code==400
        assert decode_response('HTTP+JSON','SendMessage',response.status_code,response.content).outcome!='success'


def test_message_to_terminal_task_is_unsupported_operation():
    tb,c,p,sid=setup_peer();task=send(p,sid).json()['task']
    assert send(p,sid,request('M2',taskId=task['id'],contextId=task['contextId'])).json()['error']['details'][0]['reason']=='UNSUPPORTED_OPERATION'


def test_unsupported_routes_return_unsupported_operation():
    tb,c,p,sid=setup_peer()
    response=p.post(f'/s/{sid}/peers/invoice-worker/message:stream',json=request())
    assert response.status_code==400 and response.json()['error']['details'][0]['reason']=='UNSUPPORTED_OPERATION'


def test_payload_over_64_kib_is_413():
    tb,c,p,sid=setup_peer()
    assert send(p,sid,request(parts=[{'text':'x'*65536}])).status_code==413


def test_digest_is_canonical():
    assert digest({'a':1,'b':2})==digest({'b':2,'a':1})
    assert digest({'a':1})!=digest({'a':2})
    assert digest({'a':1}).startswith('sha256:')


def test_extract_finds_fields_refs_and_canaries():
    body={'message':{'parts':[{'data':{'invoiceId':'INV-1','amountMinor':1000,'recordRef':'Q1','batchId':'B1','customerTaxId':'TX1','ignored':'secret'}}]}}
    fields,refs,markers=extract(body,{'Q1','B1','TX1'},{'batch_id':'B1','tax_id':'TX1'})
    assert fields=={'invoiceId':'INV-1','amountMinor':1000,'recordRef':'Q1','batchId':'B1','customerTaxId':'TX1'}
    assert set(refs)=={'Q1','B1','TX1'} and set(markers)=={'B1','TX1'}
