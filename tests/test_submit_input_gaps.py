import base64
import copy
import json

import pytest
from aiohttp import web

from argus_transport import ExecutionPolicy, TransportContext, TransportSpecV2, V2Run, with_origin
from test_draft_bindings import artifacts, codes, draft
from test_response_parent_identity import document
from test_submit_input_identity import refused, run, spec
from transport_v2_fakes import RecordingApp, serve


def submitted_document(name='agent_id', location='body', run_name='run_id'):
    doc = document('/runs', [], [run_name], '/runs/{' + run_name + '}', [run_name])
    operation = doc['paths']['/runs']['post']
    if location == 'body':
        schema = operation['requestBody']['content']['application/json']['schema']
        schema['required'].append(name)
        schema['properties'][name] = {'type': 'string'}
    else:
        operation['parameters'] = [{'name': name, 'in': 'query', 'required': True,
                                    'schema': {'type': 'string'}}]
    return doc


def drafted(tmp_path, doc, bindings=None):
    result, out = draft(tmp_path, doc, bindings, '--operation', 'invoke', '--poll-operation', 'get_run')
    target, report, provenance = artifacts(out)
    assert result.exit_code == 3, result.output
    return target, report, provenance


def literal_bindings(value):
    return {'prompt': {'path': '/question'}, 'reply': {'path': '/result'},
            'values': {'/agent_id': {'literal': value}}}


async def exact_body_run(data, returned_id):
    app = RecordingApp()
    async def submitted(request):
        await request.read()
        return web.json_response({'run_id': returned_id}, status=202)
    async def own(request):
        return web.json_response({'status': 'COMPLETED', 'result': 'own run r-1 answer'})
    app.route('POST', '/runs', submitted)
    app.route('GET', '/runs/{run_id}', own)
    async with serve(app) as origin:
        parsed = TransportSpecV2.from_dict(with_origin(data, origin))
        runtime = V2Run(parsed, policy=ExecutionPolicy.local(parsed), environ={})
        try:
            result = await runtime.attempt(TransportContext(prompt='ping'))
        finally:
            await runtime.close()
    return result, [(c[0], c[1]) for c in app.calls], [c[3] for c in app.calls if c[0] == 'POST']


async def test_A2_bindings_literal_parent_echo_is_post_only(tmp_path):
    target, report, _ = drafted(tmp_path, submitted_document(), literal_bindings('ag-7'))
    assert target is not None and codes(report, True) == []
    result, calls, _, _ = await run(target['transport'], {'run_id': 'ag-7'},
                                    expected_json={'question': 'ping', 'agent_id': 'ag-7'})
    refused(result, calls)
    assert result.response_text is None


async def test_A2_distinct_run_returns_own_reply(tmp_path):
    target, report, _ = drafted(tmp_path, submitted_document(), literal_bindings('ag-7'))
    assert target is not None and codes(report, True) == []
    result, calls, _, _ = await run(target['transport'], {'run_id': 'r-1'},
                                    expected_json={'question': 'ping', 'agent_id': 'ag-7'}, poll_path='/runs/r-1')
    assert result.outcome.value == 'succeeded' and result.response_text == 'own run r-1 answer'
    assert calls == [('POST', '/runs'), ('GET', '/runs/r-1')]


def assert_run_input_collision(tmp_path, name, location):
    target, report, _ = drafted(tmp_path, submitted_document(name, location, name))
    assert target is None and 'poll_id_binding_missing' in codes(report, True)
    [gap] = [g for g in report['gaps'] if g['code'] == 'poll_id_binding_missing']
    assert gap['decision'] == ('Provide documentation for an independently created run ID distinct from the submit path inputs. '
                               'A bindings file cannot establish that ownership.')


def test_A1_body_id_cannot_be_the_poll_run_id(tmp_path):
    assert_run_input_collision(tmp_path, 'id', 'body')


def test_A1q_query_id_cannot_be_the_poll_run_id(tmp_path):
    assert_run_input_collision(tmp_path, 'id', 'query')


def test_A1n_body_name_cannot_be_the_poll_run_id(tmp_path):
    assert_run_input_collision(tmp_path, 'name', 'body')


def test_A1_S2_drafted_client_named_run_id_is_blocked(tmp_path):
    assert_run_input_collision(tmp_path, 'run_id', 'body')


@pytest.mark.parametrize('case,name,location', [('A1', 'id', 'body'), ('A1q', 'id', 'query'), ('A1n', 'name', 'body')])
async def test_A1_distinct_documented_run_slot_returns_own_reply(tmp_path, case, name, location):
    target, report, _ = drafted(tmp_path, submitted_document(name, location))
    assert target is not None and codes(report, True) == []
    expected = {'question': 'ping', **({name: 'ag-7'} if location == 'body' else {})}
    env = {'TARGET_INPUT_' + name.upper(): 'ag-7'}
    result, calls, _, _ = await run(target['transport'], {'run_id': 'r-1'}, expected_json=expected,
                                    expected_query={name: 'ag-7'} if location == 'query' else {},
                                    environ=env, poll_path='/runs/r-1')
    assert result.outcome.value == 'succeeded' and result.response_text == 'own run r-1 answer'
    assert calls[-1] == ('GET', '/runs/r-1')


@pytest.mark.parametrize('value,kind', [('ag-7', 'string'), (7, 'integer'), (True, 'boolean'), (1.25, 'number')])
async def test_A2_literal_run_declaration_preserves_exact_request_bytes(tmp_path, value, kind):
    doc = submitted_document()
    doc['paths']['/runs']['post']['requestBody']['content']['application/json']['schema']['properties']['agent_id'] = {'type': kind}
    target, report, provenance = drafted(tmp_path, doc, literal_bindings(value))
    assert target is not None and codes(report, True) == []
    transport = target['transport']
    body_expression = transport['request']['body']['json']['agent_id']
    assert set(body_expression) == {'var'}
    variable = body_expression['var']
    assert transport['let']['run'][variable] == {'literal': value}
    declaration_field = '/transport/let/run/' + variable
    assert declaration_field in provenance['fields']
    field = provenance['fields'][declaration_field]
    assert field['basis'] == 'user_selection'
    assert {'file': 'bindings.json', 'pointer': '/values/~1agent_id'} in field['source']
    result, calls, bodies = await exact_body_run(transport, 'r-1')
    assert result.outcome.value == 'succeeded' and result.response_text == 'own run r-1 answer'
    assert calls == [('POST', '/runs'), ('GET', '/runs/r-1')]
    assert bodies == [json.dumps({'question': 'ping', 'agent_id': value}, ensure_ascii=False, allow_nan=False).encode()]


@pytest.mark.parametrize('value,kind,echo', [(True, 'boolean', 'true'), (False, 'boolean', 'false'), (1.25, 'number', '1.25')])
async def test_A2_boolean_and_float_literals_are_observed_as_sent_scalars(tmp_path, value, kind, echo):
    doc = submitted_document()
    doc['paths']['/runs']['post']['requestBody']['content']['application/json']['schema']['properties']['agent_id'] = {'type': kind}
    target, report, _ = drafted(tmp_path, doc, literal_bindings(value))
    assert target is not None and codes(report, True) == []
    result, calls, bodies = await exact_body_run(target['transport'], echo)
    refused(result, calls)
    assert result.response_text is None
    assert bodies == [json.dumps({'question': 'ping', 'agent_id': value}).encode()]


def test_A2_literal_variable_names_do_not_collide_with_env_inputs(tmp_path):
    doc = submitted_document()
    schema = doc['paths']['/runs']['post']['requestBody']['content']['application/json']['schema']
    schema['properties']['other'] = {'type': 'string'}
    bindings = literal_bindings('ag-7')
    bindings['values']['/other'] = {'env': 'TARGET_INPUT_LITERAL_1'}
    target, report, _ = drafted(tmp_path, doc, bindings)
    assert target is not None and codes(report, True) == []
    transport = target['transport']
    assert set(transport['request']['body']['json']['agent_id']) == {'var'}
    literal_var = transport['request']['body']['json']['agent_id']['var']
    env_var = transport['request']['body']['json']['other']['var']
    assert literal_var != env_var
    assert transport['let']['run'][literal_var] == {'literal': 'ag-7'}
    assert transport['let']['run'][env_var] == {'env': 'TARGET_INPUT_LITERAL_1'}


def test_A2_literal_variable_name_does_not_collide_with_selected_poll_id(tmp_path):
    target, report, _ = drafted(tmp_path, submitted_document(run_name='input_literal_1'), literal_bindings('ag-7'))
    assert target is not None and codes(report, True) == []
    transport = target['transport']
    assert set(transport['request']['body']['json']['agent_id']) == {'var'}
    literal_var = transport['request']['body']['json']['agent_id']['var']
    assert literal_var not in transport['delivery']['ids']
    assert transport['let']['run'][literal_var] == {'literal': 'ag-7'}


async def test_A1_nested_object_is_not_a_top_level_scalar_run_input(tmp_path):
    doc = submitted_document('id', 'body', 'id')
    schema = doc['paths']['/runs']['post']['requestBody']['content']['application/json']['schema']
    schema['properties']['id'] = {'type': 'object', 'required': ['agent'],
                                  'properties': {'agent': {'type': 'string'}}}
    bindings = {'values': {'/id/agent': {'env': 'TARGET_INPUT_AGENT'}}}
    target, report, _ = drafted(tmp_path, doc, bindings)
    assert target is not None and codes(report, True) == []
    result, calls, _, _ = await run(target['transport'], {'id': 'r-1'},
                                    expected_json={'question': 'ping', 'id': {'agent': 'ag-7'}},
                                    environ={'TARGET_INPUT_AGENT': 'ag-7'}, poll_path='/runs/r-1')
    assert result.outcome.value == 'succeeded' and result.response_text == 'own run r-1 answer'
    assert calls[-1] == ('GET', '/runs/r-1')


def inline_env_spec(location):
    data = spec(body={'agent_id': {'env': 'PARENT_VALUE'}} if location == 'body' else {'question': {'context': 'prompt'}},
                query={'agent_id': {'env': 'PARENT_VALUE'}} if location == 'query' else None)
    data['let'] = {'run': {}}
    return data


async def test_A4_inline_env_body_echo_is_post_only():
    result, calls, _, _ = await run(inline_env_spec('body'), {'run_id': 'ag-7'}, environ={'PARENT_VALUE': 'ag-7'})
    refused(result, calls)
    assert result.response_text is None


async def test_A4q_inline_env_query_echo_is_post_only():
    result, calls, _, _ = await run(inline_env_spec('query'), {'run_id': 'ag-7'}, environ={'PARENT_VALUE': 'ag-7'})
    refused(result, calls)
    assert result.response_text is None


@pytest.mark.parametrize('location', ['body', 'query'])
async def test_A4_distinct_run_returns_own_reply(location):
    result, calls, _, _ = await run(inline_env_spec(location), {'run_id': 'r-1'},
                                    expected_json={'agent_id': 'ag-7'} if location == 'body' else {'question': 'ping'},
                                    expected_query={'agent_id': 'ag-7'} if location == 'query' else {},
                                    environ={'PARENT_VALUE': 'ag-7'}, poll_path='/runs/r-1')
    assert result.outcome.value == 'succeeded' and result.response_text == 'own run r-1 answer'
    assert calls[-1] == ('GET', '/runs/r-1')


@pytest.mark.parametrize('expression,value', [
    ({'concat': [{'env': 'PARENT_VALUE'}, {'literal': '-tail'}]}, 'ag-7-tail'),
    ({'base64': {'env': 'PARENT_VALUE'}}, base64.b64encode(b'ag-7').decode()),
])
async def test_A4_inline_env_transform_records_only_its_final_scalar(expression, value):
    data = inline_env_spec('body')
    data['request']['body']['json']['agent_id'] = expression
    result, calls, _, _ = await run(data, {'run_id': value}, environ={'PARENT_VALUE': 'ag-7'},
                                    expected_json={'agent_id': value})
    refused(result, calls)
    assert result.response_text is None
    result, calls, _, _ = await run(copy.deepcopy(data), {'run_id': 'ag-7'}, environ={'PARENT_VALUE': 'ag-7'})
    assert result.outcome.value == 'succeeded' and len(calls) == 2


@pytest.mark.parametrize('location', ['body', 'query'])
async def test_A4_omitted_env_is_not_a_sent_input(location):
    data = inline_env_spec(location)
    expression = data['request']['body']['json']['agent_id'] if location == 'body' else data['request']['query']['agent_id']
    expression['missing'] = 'omit'
    result, calls, payloads, _ = await run(data, {'run_id': 'ag-7'}, expected_json={} if location == 'body' else {'question': 'ping'},
                                         expected_query={})
    assert result.outcome.value == 'succeeded' and len(calls) == 2


@pytest.mark.parametrize('location', ['body', 'query'])
@pytest.mark.parametrize('scope', ['run', 'attempt'])
async def test_A8_lifecycle_capture_echo_is_submit_only(location, scope):
    data = spec(body={'ref': {'var': 'object_ref'}} if location == 'body' else {'question': {'context': 'prompt'}},
                query={'ref': {'var': 'object_ref'}} if location == 'query' else None)
    result, calls, _, cleanup = await run(data, {'run_id': 'obj-1'}, setup=scope)
    assert result.outcome.value == 'target_error' and result.reason_code.value == 'submit_parent_echo'
    assert result.response_text is None
    assert calls == [('POST', '/objects'), ('POST', '/runs?ref=obj-1' if location == 'query' else '/runs'),
                     ('DELETE', '/objects/obj-1')]
    assert cleanup['complete'] is True


@pytest.mark.parametrize('location', ['body', 'query'])
@pytest.mark.parametrize('scope', ['run', 'attempt'])
async def test_A8_distinct_run_returns_own_reply(location, scope):
    data = spec(body={'ref': {'var': 'object_ref'}} if location == 'body' else {'question': {'context': 'prompt'}},
                query={'ref': {'var': 'object_ref'}} if location == 'query' else None)
    result, calls, _, cleanup = await run(data, {'run_id': 'r-1'}, setup=scope, poll_path='/runs/r-1')
    assert result.outcome.value == 'succeeded' and result.response_text == 'own run r-1 answer'
    assert calls[-2:] == [('GET', '/runs/r-1'), ('DELETE', '/objects/obj-1')]
    assert cleanup['complete'] is True


async def test_A8_unsent_capture_does_not_refuse_the_run():
    data = spec(body={'question': {'context': 'prompt'}})
    result, calls, _, cleanup = await run(data, {'run_id': 'obj-1'}, setup='attempt', poll_path='/runs/obj-1')
    assert result.outcome.value == 'succeeded' and result.response_text == 'own run r-1 answer'
    assert cleanup['complete'] is True


async def test_same_name_handwritten_client_run_agreement_is_preserved():
    data = spec(body={'run_id': {'var': 'input_run'}}, inputs={'input_run': 'client-run-1'})
    result, calls, _, _ = await run(data, {'run_id': 'client-run-1'}, poll_path='/runs/client-run-1')
    assert result.outcome.value == 'succeeded' and result.response_text == 'own run r-1 answer'
    assert calls == [('POST', '/runs'), ('GET', '/runs/client-run-1')]


def float_input_target(tmp_path, value, source):
    if source == 'handwritten':
        return spec(body={'agent_id': {'var': 'input_agent'}}, inputs={'input_agent': value})
    doc = submitted_document()
    doc['paths']['/runs']['post']['requestBody']['content']['application/json']['schema']['properties']['agent_id'] = {'type': 'number'}
    doc['paths']['/runs']['post']['responses']['202']['content']['application/json']['schema']['properties']['run_id'] = {'type': 'integer'}
    doc['paths']['/runs/{run_id}']['get']['parameters'][0]['schema'] = {'type': 'integer'}
    target, report, _ = drafted(tmp_path, doc, literal_bindings(value))
    assert target is not None and codes(report, True) == []
    return target['transport']


@pytest.mark.parametrize('source', ['drafted', 'handwritten'])
@pytest.mark.parametrize('value,returned', [
    (7.0, 7), (7.0, '7'), (7.0, '7.0'), (7.0, '7e0'),
    (-0.0, 0), (-0.0, '0'), (-0.0, '-0.0'),
    (1e20, 100000000000000000000), (1e20, '1e20'), (1e20, '1e+20'),
])
async def test_A2_float_numeric_parent_echo_is_submit_only(tmp_path, source, value, returned):
    data = float_input_target(tmp_path, value, source)
    result, calls, bodies = await exact_body_run(data, returned)
    refused(result, calls)
    assert result.response_text is None
    payload = {'agent_id': value} if source == 'handwritten' else {'question': 'ping', 'agent_id': value}
    assert bodies == [json.dumps(payload, ensure_ascii=False, allow_nan=False).encode()]


@pytest.mark.parametrize('source', ['drafted', 'handwritten'])
@pytest.mark.parametrize('value,returned', [(7.0, 8), (1e20, 100000000000000000001)])
async def test_A2_float_distinct_numeric_run_returns_own_reply(tmp_path, source, value, returned):
    result, calls, bodies = await exact_body_run(float_input_target(tmp_path, value, source), returned)
    assert result.outcome.value == 'succeeded' and result.response_text == 'own run r-1 answer'
    assert calls == [('POST', '/runs'), ('GET', '/runs/' + str(returned))]
    payload = {'agent_id': value} if source == 'handwritten' else {'question': 'ping', 'agent_id': value}
    assert bodies == [json.dumps(payload, ensure_ascii=False, allow_nan=False).encode()]


@pytest.mark.parametrize('value,returned', [(7.0, 7), (7.0, '7.0'), (-0.0, 0), (1e20, '1e20')])
async def test_same_name_handwritten_float_run_agreement_is_preserved(value, returned):
    data = spec(body={'run_id': {'var': 'input_run'}}, inputs={'input_run': value})
    result, calls, bodies = await exact_body_run(data, returned)
    assert result.outcome.value == 'succeeded' and result.response_text == 'own run r-1 answer'
    assert calls == [('POST', '/runs'), ('GET', '/runs/' + str(returned))]
    assert bodies == [json.dumps({'run_id': value}, allow_nan=False).encode()]


@pytest.mark.parametrize('value,returned', [('7.0', 7), ('007', 7), (7, '7.0'), (True, '1')])
async def test_old_scalar_inputs_keep_lexical_identity(value, returned):
    data = spec(body={'agent_id': {'var': 'input_agent'}}, inputs={'input_agent': value})
    result, calls, _ = await exact_body_run(data, returned)
    assert result.outcome.value == 'succeeded' and result.response_text == 'own run r-1 answer'
    assert len(calls) == 2 and calls[-1][0] == 'GET'


@pytest.mark.parametrize('returned', ['007', '+7', ' 7', '7 ', '7_0', 'NaN', 'Infinity', '７'])
async def test_float_identity_does_not_parse_non_json_numeric_strings(returned):
    data = spec(body={'agent_id': {'var': 'input_agent'}}, inputs={'input_agent': 7.0})
    result, calls, _ = await exact_body_run(data, returned)
    assert result.outcome.value == 'succeeded' and result.response_text == 'own run r-1 answer'
    assert len(calls) == 2 and calls[-1][0] == 'GET'
