import base64
import json
from urllib.parse import quote, urlencode

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
              environ=None, setup=False, submit_path='/runs'):
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
            expected_path = poll_path(payloads[-1]) if callable(poll_path) else poll_path
            assert request.raw_path == expected_path
        return web.json_response({'status': 'COMPLETED', 'result': 'own run r-1 answer'})
    async def abort(request):
        return web.json_response({'stopped': True})
    async def created(request):
        return web.json_response({'ref': 'obj-1'}, status=201)
    async def deleted(request):
        return web.Response(status=204)
    app.route('POST', submit_path, submit)
    app.route('GET', '/{tail:.*}', own)
    app.route('DELETE', '/runs/{tail:.*}', abort)
    app.route('POST', '/objects', created)
    app.route('DELETE', '/objects/{ref}', deleted)
    async with serve(app) as origin:
        if setup:
            with_attempt_undo(data, 'http://127.0.0.1')
            if setup == 'run':
                data['lifecycle']['run'] = data['lifecycle'].pop('attempt')
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


@pytest.mark.parametrize('location', ['body', 'query'])
@pytest.mark.parametrize('returned,reason', [('ag-7', 'ok'), ('ag-8', 'submit_parent_changed')])
async def test_exact_poll_query_key_requires_input_agreement(location, returned, reason):
    body = {'question': {'context': 'prompt'}}
    query = None
    if location == 'body':
        body['agent_id'] = {'var': 'input_agent'}
    elif location == 'query':
        query = {'agent_id': {'var': 'input_agent'}}
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
    refused(result, calls)


@pytest.mark.parametrize('location', ['body', 'query'])
@pytest.mark.parametrize('scope', ['run', 'attempt'])
async def test_lifecycle_capture_is_not_a_run_input(location, scope):
    data = spec(body={'ref': {'var': 'object_ref'}} if location == 'body' else {'question': {'context': 'prompt'}},
                query={'ref': {'var': 'object_ref'}} if location == 'query' else None)
    result, calls, _, cleanup = await run(data, {'run_id': 'obj-1'}, setup=scope)
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


async def test_s1_honest_top_level_body_parent_returns_own_reply():
    data = spec(body={'thread_id': {'var': 'input_thread_id'}, 'q': {'context': 'prompt'}},
                inputs={'input_thread_id': 't-1'}, ids=['thread_id', 'id'])
    data['delivery']['request']['url'] = 'http://127.0.0.1/threads/{thread_id}/runs/{id}'
    result, calls, _, _ = await run(data, {'thread_id': 't-1', 'id': 'r-1'},
                                    expected_json={'thread_id': 't-1', 'q': 'ping'},
                                    poll_path='/threads/t-1/runs/r-1')
    assert result.outcome.value == 'succeeded' and result.response_text == 'own run r-1 answer'
    assert calls == [('POST', '/runs'), ('GET', '/threads/t-1/runs/r-1')]


async def test_s1b_changed_top_level_body_parent_is_post_only():
    data = spec(body={'thread_id': {'var': 'input_thread_id'}, 'q': {'context': 'prompt'}},
                inputs={'input_thread_id': 't-1'}, ids=['thread_id', 'id'])
    data['delivery']['request']['url'] = 'http://127.0.0.1/threads/{thread_id}/runs/{id}'
    result, calls, _, _ = await run(data, {'thread_id': 't-9', 'id': 'r-1'},
                                    expected_json={'thread_id': 't-1', 'q': 'ping'})
    refused(result, calls, 'submit_parent_changed')


async def test_s2_client_named_run_id_returns_own_reply():
    data = spec(body={'run_id': {'var': 'input_run'}}, inputs={'input_run': 'client-run-1'})
    result, calls, _, _ = await run(data, {'run_id': 'client-run-1'},
                                    expected_json={'run_id': 'client-run-1'},
                                    poll_path='/runs/client-run-1')
    assert result.outcome.value == 'succeeded' and result.response_text == 'own run r-1 answer'
    assert calls == [('POST', '/runs'), ('GET', '/runs/client-run-1')]


async def test_s3_renamed_body_parent_echo_remains_post_only():
    data = spec(body={'agent_id': {'var': 'input_agent'}}, ids=['agent', 'id'])
    data['delivery']['request']['url'] = 'http://127.0.0.1/agents/{agent}/runs/{id}'
    result, calls, _, _ = await run(data, {'agent': 'ag-7', 'id': 'r-1'},
                                    expected_json={'agent_id': 'ag-7'})
    refused(result, calls)


async def test_nested_body_id_echo_into_id_path_slot_remains_post_only():
    data = spec(body={'agent': {'object': {'id': {'var': 'input_agent'}}}}, ids=['id'])
    data['delivery']['request']['url'] = 'http://127.0.0.1/runs/{id}'
    result, calls, _, _ = await run(data, {'id': 'ag-7'}, expected_json={'agent': {'id': 'ag-7'}})
    refused(result, calls)


@pytest.mark.parametrize('returned', ['t-1', 't-9'])
async def test_top_level_submit_query_agrees_with_path_placeholder(returned):
    data = spec(body={'q': {'context': 'prompt'}}, query={'thread_id': {'var': 'input_thread'}},
                inputs={'input_thread': 't-1'}, ids=['thread_id', 'id'])
    data['delivery']['request']['url'] = 'http://127.0.0.1/threads/{thread_id}/runs/{id}'
    result, calls, _, _ = await run(data, {'thread_id': returned, 'id': 'r-1'},
                                    expected_json={'q': 'ping'}, expected_query={'thread_id': 't-1'},
                                    poll_path='/threads/t-1/runs/r-1')
    if returned == 't-1':
        assert result.outcome.value == 'succeeded' and result.response_text == 'own run r-1 answer'
        assert calls[-1] == ('GET', '/threads/t-1/runs/r-1')
    else:
        refused(result, calls, 'submit_parent_changed')


@pytest.mark.parametrize('kind', ['uuid4', 'now_iso8601', 'now_unix_ms'])
@pytest.mark.parametrize('same_name', [True, False])
async def test_generated_run_input_echo_follows_destination_name(kind, same_name):
    destination = 'run_id' if same_name else 'id'
    data = spec(body={'run_id': {'var': 'client_run'}}, ids=[destination])
    data['let']['run'] = {'client_run': {'generate': kind}}
    data['delivery']['request']['url'] = 'http://127.0.0.1/runs/{' + destination + '}'
    result, calls, payloads, _ = await run(data, lambda payload: {destination: payload['run_id']},
                                          poll_path=lambda payload: '/runs/' + quote(str(payload['run_id']), safe=''))
    if same_name:
        assert result.outcome.value == 'succeeded' and result.response_text == 'own run r-1 answer'
        assert calls == [('POST', '/runs'), ('GET', '/runs/' + quote(str(payloads[0]['run_id']), safe=''))]
    else:
        refused(result, calls)


@pytest.mark.parametrize('same_name', [True, False])
async def test_env_run_input_echo_follows_destination_name(same_name):
    destination = 'run_id' if same_name else 'id'
    data = spec(body={'run_id': {'var': 'client_run'}}, ids=[destination])
    data['let']['run'] = {'client_run': {'env': 'TARGET_INPUT_RUN_ID'}}
    data['delivery']['request']['url'] = 'http://127.0.0.1/runs/{' + destination + '}'
    result, calls, _, _ = await run(data, {destination: 'client-run-1'},
                                    environ={'TARGET_INPUT_RUN_ID': 'client-run-1'},
                                    expected_json={'run_id': 'client-run-1'}, poll_path='/runs/client-run-1')
    if same_name:
        assert result.outcome.value == 'succeeded' and result.response_text == 'own run r-1 answer'
        assert calls == [('POST', '/runs'), ('GET', '/runs/client-run-1')]
    else:
        refused(result, calls)


@pytest.mark.parametrize('location', ['nested', 'array'])
@pytest.mark.parametrize('returned', ['ag-7', 'ag-8'])
async def test_nested_values_never_have_top_level_query_name_agreement(location, returned):
    body = ({'agent': {'object': {'agent_id': {'var': 'input_agent'}}}} if location == 'nested' else
            {'agent_id': {'array': [{'var': 'input_agent'}]}})
    data = spec(body=body, ids=['agent_id', 'run_id'],
                poll_query={'agent_id': {'var': 'agent_id'}, 'run_id': {'var': 'run_id'}})
    path = '/runs?' + urlencode({'agent_id': returned, 'run_id': 'r-1'})
    result, calls, _, _ = await run(data, {'agent_id': returned, 'run_id': 'r-1'}, poll_path=path)
    if returned == 'ag-7':
        refused(result, calls)
    else:
        assert result.outcome.value == 'succeeded' and calls[-1] == ('GET', path)


@pytest.mark.parametrize('body_key,poll_name', [('input_run_id', 'run_id'), ('run_id', 'input_run_id'),
                                             ('RunId', 'runid'), ('run-id', 'run_id')])
async def test_path_destination_names_preserve_literal_spelling(body_key, poll_name):
    data = spec(body={body_key: {'var': 'input_agent'}}, ids=[poll_name])
    data['delivery']['request']['url'] = 'http://127.0.0.1/runs/{' + poll_name + '}'
    result, calls, _, _ = await run(data, {poll_name: 'ag-7'}, expected_json={body_key: 'ag-7'})
    refused(result, calls)


@pytest.mark.parametrize('key', ['agent.id', 'agent/id', 'agent_id'])
async def test_top_level_json_keys_match_query_names_literally(key):
    data = spec(body={key: {'var': 'input_agent'}}, poll_query={key: {'var': 'run_id'}})
    path = '/runs?' + urlencode({key: 'ag-7'})
    result, calls, _, _ = await run(data, {'run_id': 'ag-7'}, expected_json={key: 'ag-7'}, poll_path=path)
    assert result.outcome.value == 'succeeded' and calls[-1] == ('GET', path)


def test_json_observation_records_complete_paths_and_transmitted_array_indices():
    from argus_transport.engine_v2 import render_body_v2
    data = spec(body={'agent.id': {'var': 'input_agent'},
                      'agents': {'array': [{'env': 'OPTIONAL', 'missing': 'omit'},
                                           {'object': {'id': {'var': 'input_agent'}}},
                                           {'array': [{'var': 'input_agent'}]}]}})
    request = TransportSpecV2.from_dict(data).request
    observed = []
    encoded = render_body_v2(request, TransportContext(prompt='ping'), {'input_agent': 'ag-7'}, {},
                             _observe_scalar=lambda path, expression, item: observed.append((path, item)))
    assert json.loads(encoded) == {'agent.id': 'ag-7', 'agents': [{'id': 'ag-7'}, ['ag-7']]}
    assert observed == [(('agent.id',), 'ag-7'), (('agents', 0, 'id'), 'ag-7'),
                        (('agents', 1, 0), 'ag-7')]


@pytest.mark.parametrize('path_parent', [False, True], ids=['dd4-body', 'dd2-path'])
async def test_drafted_agreed_parent_with_nested_copy_returns_own_reply(tmp_path, path_parent):
    submit_template = '/threads/{thread_id}/runs' if path_parent else '/runs'
    doc = document(submit_template, ['thread_id'] if path_parent else [], ['thread_id', 'run_id'],
                   '/threads/{thread_id}/runs/{run_id}', ['thread_id', 'run_id'])
    schema = doc['paths'][submit_template]['post']['requestBody']['content']['application/json']['schema']
    schema['properties']['config'] = {'type': 'object', 'properties': {
        'configurable': {'type': 'object', 'properties': {'thread_id': {'type': 'string'}}}}}
    if not path_parent:
        schema['required'].append('thread_id')
        schema['properties']['thread_id'] = {'type': 'string'}
    bindings = {'prompt': {'path': '/question'}, 'reply': {'path': '/result'},
                'values': {'/config/configurable/thread_id': {'env': 'TARGET_INPUT_CFG_THREAD'}}}
    cli, out = draft(tmp_path, doc, bindings, '--operation', 'invoke', '--poll-operation', 'get_run')
    target, report, _ = artifacts(out)
    assert cli.exit_code == 3 and target is not None and codes(report, True) == []
    expected = {'question': 'ping', 'config': {'configurable': {'thread_id': 't-1'}}}
    if not path_parent:
        expected['thread_id'] = 't-1'
    submit_path = '/threads/t-1/runs' if path_parent else '/runs'
    result, calls, _, _ = await run(target['transport'], {'thread_id': 't-1', 'run_id': 'r-1'},
                                    expected_json=expected, expected_query={}, submit_path=submit_path,
                                    environ={'TARGET_INPUT_THREAD_ID': 't-1', 'TARGET_INPUT_CFG_THREAD': 't-1'},
                                    poll_path='/threads/t-1/runs/r-1')
    assert result.outcome.value == 'succeeded' and result.response_text == 'own run r-1 answer'
    assert calls == [('POST', submit_path), ('GET', '/threads/t-1/runs/r-1')]


@pytest.mark.parametrize('returned', ['t-1', 't-9'])
async def test_path_agreed_parent_with_nested_copy_returns_own_reply(returned):
    data = spec(body={'config': {'object': {'configurable': {'object': {
        'thread_id': {'var': 'input_thread'}}}}}}, inputs={'input_thread': 't-1'},
                ids=['thread_id', 'run_id'])
    data['request']['url'] = 'http://127.0.0.1/threads/{input_thread}/runs'
    data['delivery']['request']['url'] = 'http://127.0.0.1/threads/{thread_id}/runs/{run_id}'
    result, calls, _, _ = await run(data, {'thread_id': returned, 'run_id': 'r-1'},
                                    expected_json={'config': {'configurable': {'thread_id': 't-1'}}},
                                    expected_query={}, submit_path='/threads/t-1/runs',
                                    poll_path='/threads/t-1/runs/r-1')
    if returned == 't-1':
        assert result.outcome.value == 'succeeded' and result.response_text == 'own run r-1 answer'
        assert calls == [('POST', '/threads/t-1/runs'), ('GET', '/threads/t-1/runs/r-1')]
    else:
        refused(result, calls, 'submit_parent_changed')


@pytest.mark.parametrize('destination', ['path', 'query'])
@pytest.mark.parametrize('copy_first', [False, True])
@pytest.mark.parametrize('copy_shape', ['nested', 'other_name'])
async def test_named_agreed_parent_with_duplicate_returns_own_reply(copy_first, copy_shape, destination):
    copy = ('config', {'object': {'configurable': {'object': {'thread_id': {'var': 'input_thread'}}}}})
    expected_copy = ('config', {'configurable': {'thread_id': 't-1'}})
    if copy_shape == 'other_name':
        copy, expected_copy = ('thread', {'var': 'input_thread'}), ('thread', 't-1')
    fields = [('thread_id', {'var': 'input_thread'}), copy]
    expected_fields = [('thread_id', 't-1'), expected_copy]
    if copy_first:
        fields.reverse()
        expected_fields.reverse()
    data = spec(body=dict(fields), inputs={'input_thread': 't-1'}, ids=['thread_id', 'run_id'])
    data['delivery']['request']['url'] = 'http://127.0.0.1/threads/{thread_id}/runs/{run_id}'
    poll_path = '/threads/t-1/runs/r-1'
    if destination == 'query':
        data['delivery']['request']['url'] = 'http://127.0.0.1/runs'
        data['delivery']['request']['query'] = {'thread_id': {'var': 'thread_id'}, 'run_id': {'var': 'run_id'}}
        poll_path = '/runs?thread_id=t-1&run_id=r-1'
    result, calls, _, _ = await run(data, {'thread_id': 't-1', 'run_id': 'r-1'},
                                    expected_json=dict(expected_fields), expected_query={}, poll_path=poll_path)
    assert result.outcome.value == 'succeeded' and result.response_text == 'own run r-1 answer'
    assert calls == [('POST', '/runs'), ('GET', poll_path)]


@pytest.mark.parametrize('copy_first', [False, True])
@pytest.mark.parametrize('matching_source', ['body', 'query'])
async def test_agreement_and_copy_cannot_hide_conflicting_same_name(copy_first, matching_source):
    fields = [('thread_id', {'var': 'matching' if matching_source == 'body' else 'changed'}),
              ('copy', {'var': 'matching'})]
    if copy_first:
        fields.reverse()
    query_value = 'changed' if matching_source == 'body' else 'matching'
    data = spec(body=dict(fields), query={'thread_id': {'var': query_value}},
                inputs={'matching': 't-1', 'changed': 't-9'}, ids=['thread_id', 'run_id'])
    data['delivery']['request']['url'] = 'http://127.0.0.1/threads/{thread_id}/runs/{run_id}'
    result, calls, _, _ = await run(data, {'thread_id': 't-1', 'run_id': 'r-1'},
                                    expected_json={'thread_id': 't-1' if matching_source == 'body' else 't-9',
                                                   'copy': 't-1'},
                                    expected_query={'thread_id': 't-9' if matching_source == 'body' else 't-1'})
    refused(result, calls, 'submit_parent_changed')


@pytest.mark.parametrize('agreement', ['body', 'path'])
@pytest.mark.parametrize('echo_first', [False, True])
async def test_agreed_parent_does_not_settle_other_captured_run_id(agreement, echo_first):
    ids = ['run_id', 'thread_id'] if echo_first else ['thread_id', 'run_id']
    data = spec(body={'thread_id': {'var': 'input_thread'}, 'copy': {'var': 'input_thread'}},
                inputs={'input_thread': 't-1'}, ids=ids)
    submit_path = '/runs'
    if agreement == 'path':
        data['request']['url'] = 'http://127.0.0.1/threads/{input_thread}/runs'
        submit_path = '/threads/t-1/runs'
    data['delivery']['request']['url'] = 'http://127.0.0.1/threads/{thread_id}/runs/{run_id}'
    result, calls, _, _ = await run(data, {'thread_id': 't-1', 'run_id': 't-1'},
                                    expected_json={'thread_id': 't-1', 'copy': 't-1'}, expected_query={},
                                    submit_path=submit_path)
    refused(result, calls)


@pytest.mark.parametrize('echo_final', [False, True])
async def test_generated_value_with_prompt_alias_is_input(monkeypatch, echo_final):
    import argus_transport.engine_v2 as engine
    monkeypatch.setattr(engine.uuid, 'uuid4', lambda: 'client-1')
    data = spec(body={'value': {'var': 'mixed'}})
    data['let']['run'] = {'mixed': {'concat': [{'generate': 'uuid4'}, {'context': 'prompt'}]}}
    result, calls, _, _ = await run(data, {'run_id': 'client-1ping' if echo_final else 'client-1'},
                                    expected_json={'value': 'client-1ping'}, expected_query={},
                                    poll_path='/runs/client-1')
    if echo_final:
        refused(result, calls)
    else:
        assert result.outcome.value == 'succeeded' and result.response_text == 'own run r-1 answer'
        assert calls == [('POST', '/runs'), ('GET', '/runs/client-1')]


async def test_body_agreement_settles_earlier_different_path_slot_echo():
    data = spec(body={'thread_id': {'var': 'input_thread'}}, inputs={'input_thread': 't-1'},
                ids=['thread_id', 'run_id'])
    data['request']['url'] = 'http://127.0.0.1/parents/{input_thread}/runs'
    data['delivery']['request']['url'] = 'http://127.0.0.1/threads/{thread_id}/runs/{run_id}'
    result, calls, _, _ = await run(data, {'thread_id': 't-1', 'run_id': 'r-1'},
                                    expected_json={'thread_id': 't-1'}, expected_query={},
                                    submit_path='/parents/t-1/runs', poll_path='/threads/t-1/runs/r-1')
    assert result.outcome.value == 'succeeded' and result.response_text == 'own run r-1 answer'
    assert calls == [('POST', '/parents/t-1/runs'), ('GET', '/threads/t-1/runs/r-1')]


async def test_agreed_path_slot_cannot_hide_later_conflicting_path_slot():
    data = spec(body={'copy': {'var': 'first'}}, inputs={'first': 't-1', 'second': 't-9'},
                ids=['thread_id', 'run_id'])
    data['request']['url'] = 'http://127.0.0.1/threads/{first}/scopes/threads/{second}/runs'
    data['delivery']['request']['url'] = 'http://127.0.0.1/threads/{thread_id}/runs/{run_id}'
    result, calls, _, _ = await run(data, {'thread_id': 't-1', 'run_id': 'r-1'},
                                    expected_json={'copy': 't-1'}, expected_query={},
                                    submit_path='/threads/t-1/scopes/threads/t-9/runs')
    refused(result, calls, 'submit_parent_changed')


@pytest.mark.parametrize('returned,body_parent', [('t-1', 't-9'), ('t-9', 't-9')])
async def test_path_and_named_body_disagreements_precede_settlement(returned, body_parent):
    data = spec(body={'thread_id': {'var': 'body_parent'}, 'copy': {'var': 'path_parent'}},
                inputs={'path_parent': 't-1', 'body_parent': body_parent}, ids=['thread_id', 'run_id'])
    data['request']['url'] = 'http://127.0.0.1/threads/{path_parent}/runs'
    data['delivery']['request']['url'] = 'http://127.0.0.1/threads/{thread_id}/runs/{run_id}'
    result, calls, _, _ = await run(data, {'thread_id': returned, 'run_id': 'r-1'},
                                    expected_json={'thread_id': body_parent, 'copy': 't-1'}, expected_query={},
                                    submit_path='/threads/t-1/runs')
    refused(result, calls, 'submit_parent_changed')
