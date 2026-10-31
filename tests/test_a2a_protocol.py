import json
import pytest
from argus.a2a.protocol import auth_requirement, select_interface, parse_card, Interface, build_request, message_request, decode_response

@pytest.mark.parametrize('empty', [{}, {'schemes': {}}, {'description': 'public'}])
def test_empty_security_requirement_forms_mean_anonymous(empty):
    assert auth_requirement({'securityRequirements': [{'schemes': {'bearer': {'list': []}}}, empty]}) == ('anonymous', 'securityRequirements')

@pytest.mark.parametrize('card,expected', [({}, ('anonymous','none')), ({'securityRequirements': []}, ('anonymous','securityRequirements'))])
def test_missing_or_empty_requirement_list_means_anonymous(card, expected):
    assert auth_requirement(card) == expected

def test_non_empty_requirements_mean_required():
    assert auth_requirement({'securityRequirements': [{'schemes': {'bearer': {'list': []}}}]}) == ('required','securityRequirements')

def test_legacy_security_key_and_shape_mean_required():
    assert auth_requirement({'security': [{'google': ['openid']}]}) == ('required','security')

def test_legacy_security_empty_list_means_anonymous():
    assert auth_requirement({'security': []}) == ('anonymous','security')

def test_security_requirements_key_wins_over_legacy_security():
    assert auth_requirement({'securityRequirements':[{'schemes':{'b':[]}}], 'security':[]}) == ('required','securityRequirements')

@pytest.mark.parametrize('canonical', [[], None])
def test_present_empty_canonical_key_never_falls_back(canonical):
    assert auth_requirement({'securityRequirements':canonical,'security':[{'google':['openid']}]}) == ('anonymous','securityRequirements')

def test_malformed_canonical_key_never_falls_back():
    assert auth_requirement({'securityRequirements':'bearer','security':[{'google':['openid']}]}) == ('malformed','securityRequirements')

@pytest.mark.parametrize('value', [['bearer'], [{'schemes':[]}], [{'schemes':{'b':3}}], 'bearer', {'schemes':{}}])
def test_malformed_requirement_is_reported(value):
    assert auth_requirement({'securityRequirements':value}) == ('malformed','securityRequirements')

def test_valid_empty_member_does_not_hide_a_later_malformed_member():
    assert auth_requirement({'securityRequirements':[{'schemes':{}},'bearer']})[0] == 'malformed'

def test_malformed_legacy_security_is_reported():
    assert auth_requirement({'security':[{'google':'openid'}]}) == ('malformed','security')

def test_select_interface_takes_first_supported_entry():
    card={'supportedInterfaces':[{'url':'http://127.0.0.1','protocolBinding':b,'protocolVersion':'1.0.2'} for b in ('GRPC','JSONRPC','HTTP+JSON')]}
    assert select_interface(card)[0].binding == 'JSONRPC'

@pytest.mark.parametrize('card,reason', [({},'no_interfaces'), ({'supportedInterfaces':[{'protocolVersion':'0.3','protocolBinding':'JSONRPC'}]},'a2a_0_3_only'), ({'supportedInterfaces':[{'protocolVersion':'1.0','protocolBinding':'GRPC'}]},'unsupported_binding:GRPC')])
def test_select_interface_reports_why_nothing_fits(card,reason):
    assert select_interface(card)[1] == reason

def test_card_signature_count_ignores_malformed_entries():
    assert parse_card({'signatures':[{},None,{'protected':'a','signature':''},{'protected':'a','signature':'b'}]}).signature_count == 1

METHODS=[('SendMessage','POST','/message:send'),('GetTask','GET','/tasks/x'),('ListTasks','GET','/tasks'),('CancelTask','POST','/tasks/x:cancel'),('CreateTaskPushNotificationConfig','POST','/tasks/x/pushNotificationConfigs'),('DeleteTaskPushNotificationConfig','DELETE','/tasks/x/pushNotificationConfigs/c'),('GetExtendedAgentCard','GET','/extendedAgentCard')]
@pytest.mark.parametrize('op,method,path', METHODS)
@pytest.mark.parametrize('binding',['JSONRPC','HTTP+JSON'])
def test_build_request_method_table(binding,op,method,path):
    req=build_request(Interface('http://127.0.0.1/a2a',binding,''),op,{'id':'c' if op=='DeleteTaskPushNotificationConfig' else 'x','taskId':'x'},1)
    if binding=='JSONRPC':
        assert req.method=='POST' and req.url=='http://127.0.0.1/a2a' and req.json['method']==op
    else:
        assert (req.method,req.url)==(method,'http://127.0.0.1/a2a'+path)

def test_build_request_carries_tenant():
    assert build_request(Interface('http://127.0.0.1','HTTP+JSON','t1'),'GetTask',{'id':'x'},1).url=='http://127.0.0.1/t1/tasks/x'
    assert build_request(Interface('http://127.0.0.1','JSONRPC','t1'),'GetTask',{'id':'x'},1).json['params']['tenant']=='t1'

def test_send_message_body_is_the_fixed_harmless_text():
    req=message_request(return_immediately=True,marker='mark')
    assert req['message']=={'messageId':'argus-mark','role':'ROLE_USER','parts':[{'text':'Argus security check. Reply with the word ACK. Do not take any action.'}],'metadata':{'argusMarker':'mark'}}
    assert req['configuration']['returnImmediately'] is True

def test_decode_jsonrpc_http_200_error_is_not_success():
    assert decode_response('JSONRPC','GetTask',200,b'{"error":{"code":-32001}}').outcome=='jsonrpc_error'

def test_decode_http_json_2xx_non_result_is_undecodable():
    assert decode_response('HTTP+JSON','SendMessage',200,b'{"error":{}}').outcome=='undecodable'

@pytest.mark.parametrize('body,kind',[({'task':{'id':'x','status':{}}},'task'),({'message':{}},'message')])
def test_decode_send_message_task_vs_message(body,kind):
    assert decode_response('HTTP+JSON','SendMessage',200,json.dumps(body).encode()).result_kind==kind

SHAPES=[('SendMessage',{'task':{'id':'x','status':{}}}),('GetTask',{'id':'x','status':{}}),('CancelTask',{'id':'x','status':{}}),('ListTasks',{'tasks':[]}),('CreateTaskPushNotificationConfig',{'url':'https://callback.invalid'}),('DeleteTaskPushNotificationConfig',{}),('GetExtendedAgentCard',{'name':'agent'})]
@pytest.mark.parametrize('op,body',SHAPES)
@pytest.mark.parametrize('binding',['JSONRPC','HTTP+JSON'])
def test_decode_checks_the_result_type_per_operation(op,body,binding):
    def wire(value): return json.dumps({'result':value} if binding=='JSONRPC' else value).encode()
    assert decode_response(binding,op,200,wire(body)).outcome=='success'
    assert decode_response(binding,op,200,wire({'unexpected':True})).outcome=='undecodable'

def test_decode_drops_error_message_text():
    def decode(text): return decode_response('JSONRPC','SendMessage',200,json.dumps({'error':{'code':-31001,'message':text}}).encode())
    assert decode('Unauthorized')==decode('OK, task created')
