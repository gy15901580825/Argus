import base64
from urllib.parse import urlencode

import pytest
from aiohttp import web

from argus_transport import ExecutionPolicy, TransportContext, TransportSpecV2, V2Run, with_origin
from test_draft_bindings import artifacts, codes, draft
from test_response_parent_identity import document, handwritten
from test_transport_v2_poll import with_attempt_undo
from transport_v2_fakes import RecordingApp, serve


def spec(*, body=None, query=None, inputs=None, poll_query=None, ids=None):
    data = handwritten('/runs', '/runs/{run_id}', inputs or {'input_agent': 'ag-7'}, ids or ['run_id'])
    data['request']['body'] = {'json': body or {'agent_id': {'var': 'input_agent'}}}
    if query is not None:
        data['request']['query'] = query
    if poll_query is not None:
        data['delivery']['request']['url'] = 'http://127.0.0.1/runs'
        data['delivery']['request']['query'] = poll_query
    return data


async def run(data, submitted, *, expected_json=None, expected_query=None, poll_path=None,
              environ=None, setup=False):
    app = RecordingApp()
    payloads = []
    async def submit(request):
        payloads.append(await request.json() if 'json' in data['request']['body'] else await request.text())
        if expected_json is not None:
            assert payloads[-1] == expected_json
        if expected_query is not None:
            assert dict(request.query) == expected_query
        reply = submitted(payloads[-1]) if callable(submitted) else submitted
        return web.json_response(reply, status=202)
    async def own(request):
        if poll_path is not None:
            assert request.raw_path == poll_path
        return web.json_response({'status': 'COMPLETED', 'result': 'own run r-1 answer'})
    async def abort(request):
        return web.json_response({'stopped': True})
    async def created(request):
        return web.json_response({'ref': 'obj-1'}, status=201)
    async def deleted(request):
        return web.Response(status=204)
    app.route('POST', '/runs', submit)
    app.route('GET', '/runs/{tail:.*}', own)
    app.route('GET', '/runs', own)
    app.route('DELETE', '/runs/{tail:.*}', abort)
    app.route('POST', '/objects', created)
    app.route('DELETE', '/objects/{ref}', deleted)
    async with serve(app) as origin:
        if setup:
            with_attempt_undo(data, 'http://127.0.0.1')
        data = with_origin(data, origin)
        parsed = TransportSpecV2.from_dict(data)
        runtime = V2Run(parsed, policy=ExecutionPolicy.local(parsed), environ=environ or {})
        try:
            result = await runtime.attempt(TransportContext(prompt='ping'))
        finally:
            await runtime.close()
        cleanup = runtime.cleanup_report()
    return result, [(c[0], c[1]) for c in app.calls], payloads, cleanup


def refused(result, calls, reason='submit_parent_echo'):
    assert result.outcome.value == 'target_error'
    assert result.reason_code.value == reason
    assert result.response_text != 'own run r-1 answer'
    assert len(calls) == 1 and calls[0][0] == 'POST'


@pytest.mark.parametrize('location', ['body', 'query'])
async def test_drafted_submit_input_echo_is_post_only(tmp_path, location):
    doc = document('/runs', [], ['id'], '/runs/{id}', ['id'])
    operation = doc['paths']['/runs']['post']
    if location == 'body':
        schema = operation['requestBody']['content']['application/json']['schema']
        schema['required'].append('agent_id')
        schema['properties']['agent_id'] = {'type': 'string'}
    else:
        operation['parameters'] = [{'name': 'agent_id', 'in': 'query', 'required': True,
                                    'schema': {'type': 'string'}}]
    cli, out = draft(tmp_path, doc, None, '--operation', 'invoke', '--poll-operation', 'get_run')
    target, report, _ = artifacts(out)
    assert cli.exit_code == 3 and target is not None and codes(report, True) == []
    expected = {'question': 'ping', **({'agent_id': 'ag-7'} if location == 'body' else {})}
    result, calls, _, _ = await run(target['transport'], {'id': 'ag-7'}, expected_json=expected,
                                    expected_query={'agent_id': 'ag-7'} if location == 'query' else {},
                                    environ={'TARGET_INPUT_AGENT_ID': 'ag-7'})
    refused(result, calls)


@pytest.mark.parametrize('body', [
    {'agent': {'object': {'id': {'var': 'input_agent'}}}},
    {'ids': {'array': [{'var': 'input_agent'}]}},
    {'agents': {'array': [{'object': {'id': {'var': 'input_agent'}}}]}},
    {'ids': {'array': [{'array': [{'var': 'input_agent'}]}]}},
])
async def test_nested_input_echo_is_post_only(body):
    result, calls, _, _ = await run(spec(body=body), {'run_id': 'ag-7'})
    refused(result, calls)


@pytest.mark.parametrize('location', ['body', 'query'])
async def test_distinct_child_returns_own_reply(location):
    data = spec(body={'question': {'context': 'prompt'}} if location == 'query' else None,
                query={'agent_id': {'var': 'input_agent'}} if location == 'query' else None)
    result, calls, _, _ = await run(data, {'run_id': 'r-1'}, poll_path='/runs/r-1',
                                    expected_json={'question': 'ping'} if location == 'query' else {'agent_id': 'ag-7'},
                                    expected_query={'agent_id': 'ag-7'} if location == 'query' else {})
    assert result.outcome.value == 'succeeded' and result.response_text == 'own run r-1 answer'
    assert calls == [('POST', '/runs?agent_id=ag-7' if location == 'query' else '/runs'), ('GET', '/runs/r-1')]


@pytest.mark.parametrize('location', ['body', 'query', 'nested', 'array'])
@pytest.mark.parametrize('returned,reason', [('ag-7', 'ok'), ('ag-8', 'submit_parent_changed')])
async def test_exact_poll_query_key_requires_input_agreement(location, returned, reason):
    body = {'question': {'context': 'prompt'}}
    query = None
    if location == 'body':
        body['agent_id'] = {'var': 'input_agent'}
    elif location == 'query':
        query = {'agent_id': {'var': 'input_agent'}}
    elif location == 'nested':
        body['agent'] = {'object': {'agent_id': {'var': 'input_agent'}}}
    else:
        body['agent_id'] = {'array': [{'var': 'input_agent'}]}
    data = spec(body=body, query=query, ids=['agent_id', 'run_id'],
                poll_query={'agent_id': {'var': 'agent_id'}, 'run_id': {'var': 'run_id'}})
    path = '/runs?' + urlencode({'agent_id': returned, 'run_id': 'r-1'})
    result, calls, _, _ = await run(data, {'agent_id': returned, 'run_id': 'r-1'}, poll_path=path)
    if reason == 'ok':
        assert result.outcome.value == 'succeeded' and result.response_text == 'own run r-1 answer'
        assert calls[-1] == ('GET', '/runs?agent_id=ag-7&run_id=r-1')
    else:
        refused(result, calls, reason)


@pytest.mark.parametrize('query_name', ['Agent-ID', 'AGENT_ID', 'input_agent_id'])
async def test_body_query_names_are_literal(query_name):
    data = spec(poll_query={query_name: {'var': 'run_id'}})
    result, calls, _, _ = await run(data, {'run_id': 'ag-7'})
    refused(result, calls)


@pytest.mark.parametrize('body', [
    {'agent_id': {'literal': 'ag-7'}},
    {'agent': {'literal': {'var': 'input_agent', 'id': 'ag-7'}}},
    {'agent_id': {'context': 'prompt'}},
])
async def test_constants_prompt_and_unused_input_do_not_refuse(body):
    captured = 'ping' if 'context' in next(iter(body.values())) else 'ag-7'
    result, calls, _, _ = await run(spec(body=body), {'run_id': captured})
    assert result.outcome.value == 'succeeded' and result.response_text == 'own run r-1 answer'
    assert len(calls) == 2


@pytest.mark.parametrize('location', ['body', 'query'])
@pytest.mark.parametrize('parent,captured', [(7, '7'), ('7', 7), ('a/b', 'a/b'), ('a%2Fb', 'a%2Fb')])
async def test_inputs_compare_transmitted_semantic_string(location, parent, captured):
    data = spec(inputs={'input_agent': parent}, body={'question': {'context': 'prompt'}} if location == 'query' else None,
                query={'agent_id': {'var': 'input_agent'}} if location == 'query' else None)
    result, calls, _, _ = await run(data, {'run_id': captured},
                                    expected_query={'agent_id': str(parent)} if location == 'query' else {})
    refused(result, calls)


@pytest.mark.parametrize('expression,transmitted', [
    ({'concat': [{'var': 'input_agent'}, {'literal': '-tail'}]}, 'ag-7-tail'),
    ({'base64': {'var': 'input_agent'}}, base64.b64encode(b'ag-7').decode()),
])
@pytest.mark.parametrize('echo_final', [True, False])
async def test_transform_compares_only_final_scalar(expression, transmitted, echo_final):
    result, calls, _, _ = await run(spec(body={'agent_id': expression}),
                                    {'run_id': transmitted if echo_final else 'ag-7'},
                                    expected_json={'agent_id': transmitted})
    if echo_final:
        refused(result, calls)
    else:
        assert result.outcome.value == 'succeeded' and len(calls) == 2


async def test_generated_component_is_bound_once(monkeypatch):
    import argus_transport.engine_v2 as engine
    tokens = iter(['token1', 'token2'])
    monkeypatch.setattr(engine.uuid, 'uuid4', lambda: next(tokens))
    data = spec(body={'agent_id': {'concat': [{'var': 'input_agent'}, {'generate': 'uuid4'}]}})
    result, calls, _, _ = await run(data, lambda payload: {'run_id': payload['agent_id']},
                                    expected_json={'agent_id': 'ag-7token1'})
    refused(result, calls)
    assert next(tokens) == 'token2'


async def test_omitted_and_unused_inputs_supply_no_receipt():
    data = spec(body={'question': {'context': 'prompt'},
                      'agent_id': {'concat': [{'var': 'input_agent'}, {'env': 'OPTIONAL_REF', 'missing': 'omit'}]}},
                query={'agent_id': {'env': 'OPTIONAL_REF', 'missing': 'omit'}})
    result, calls, _, _ = await run(data, {'run_id': 'ag-7'}, expected_json={'question': 'ping'}, expected_query={})
    assert result.outcome.value == 'succeeded' and len(calls) == 2


@pytest.mark.parametrize('expression', [
    {'context': 'prompt'},
    {'concat': [{'context': 'prompt'}, {'literal': '-tail'}]},
    {'base64': {'context': 'prompt'}},
    {'var': 'prompt_source'},
])
async def test_prompt_only_run_aliases_are_not_inputs(expression):
    data = spec(body={'value': {'var': 'alias'}})
    data['let']['run'] = {'prompt_source': {'context': 'prompt'}, 'alias': expression}
    result, calls, _, _ = await run(data, lambda payload: {'run_id': payload['value']})
    assert result.outcome.value == 'succeeded' and len(calls) == 2


async def test_mixed_prompt_and_input_alias_remains_input():
    data = spec(body={'value': {'var': 'mixed'}})
    data['let']['run']['mixed'] = {'concat': [{'var': 'input_agent'}, {'context': 'prompt'}]}
    result, calls, _, _ = await run(data, {'run_id': 'ag-7ping'}, expected_json={'value': 'ag-7ping'})
    refused(result, calls)


async def test_conflicting_same_named_input_occurrences_fail_closed():
    data = spec(body={'left': {'object': {'agent_id': {'var': 'input_agent'}}},
                      'right': {'object': {'agent_id': {'var': 'second'}}}},
                inputs={'input_agent': 'ag-7', 'second': 'ag-8'},
                poll_query={'agent_id': {'var': 'run_id'}})
    result, calls, _, _ = await run(data, {'run_id': 'ag-7'})
    refused(result, calls, 'submit_parent_changed')


@pytest.mark.parametrize('location', ['body', 'query'])
async def test_attempt_capture_is_not_a_run_input(location):
    data = spec(body={'ref': {'var': 'object_ref'}} if location == 'body' else {'question': {'context': 'prompt'}},
                query={'ref': {'var': 'object_ref'}} if location == 'query' else None)
    result, calls, _, cleanup = await run(data, {'run_id': 'obj-1'}, setup=True)
    assert result.outcome.value == 'succeeded'
    assert calls == [('POST', '/objects'), ('POST', '/runs?ref=obj-1' if location == 'query' else '/runs'),
                     ('GET', '/runs/obj-1'), ('DELETE', '/objects/obj-1')]
    assert cleanup['complete'] is True


@pytest.mark.parametrize('location', ['body', 'query'])
async def test_refused_input_never_arms_captured_id_abort(location):
    data = spec(body={'question': {'context': 'prompt'}} if location == 'query' else None,
                query={'agent_id': {'var': 'input_agent'}} if location == 'query' else None)
    data['delivery']['abort'] = {
        'request': {'method': 'DELETE', 'url': 'http://127.0.0.1/runs/{run_id}', 'body': {'none': True}},
        'expect': {'http_status': [200], 'when': {'path': '$.stopped', 'equals': True}},
    }
    result, calls, _, cleanup = await run(data, {'run_id': 'ag-7'}, setup=True)
    assert result.reason_code.value == 'submit_parent_echo'
    assert calls == [('POST', '/objects'), ('POST', '/runs?agent_id=ag-7' if location == 'query' else '/runs'),
                     ('DELETE', '/objects/obj-1')]
    assert cleanup['complete'] is True and cleanup['done'] == 1 and cleanup['open'] == []


async def test_text_body_does_not_extend_json_policy():
    data = spec()
    data['request']['body'] = {'text': {'var': 'input_agent'}}
    result, calls, payloads, _ = await run(data, {'run_id': 'ag-7'})
    assert payloads == ['ag-7'] and result.outcome.value == 'succeeded' and len(calls) == 2
