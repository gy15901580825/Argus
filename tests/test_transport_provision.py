from __future__ import annotations

import copy
import json

import pytest
from aiohttp import web

from argus.targets.custom_http import CustomHTTPSpec, CustomHTTPTarget
from argus_transport import TransportContext, local_transport_mode
from argus_transport.runtime_v2 import TargetRunStopped
from argus_transport.spec_v2 import TransportSpecV2, iter_requests, with_origin
from test_transport_v2_engine import completed, runtime, v2_dict
from transport_v2_fakes import RecordingApp, serve


def provision_dict(origin):
    data = v2_dict(origin + '/automations/{automation_id}:invoke')
    data['lifecycle'] = {'provision': {'find': [
        {'id': 'organization', 'request': {'method': 'GET', 'url': origin + '/organizations'},
         'expect': {'http_status': [200]},
         'capture': {'org_id': {'items': '$.organizations', 'where': {'path': '$.name', 'exists': True},
                                'take': '$.name', 'last_segment': True}}},
        {'id': 'workspace', 'request': {'method': 'GET', 'url': origin + '/organizations/{org_id}/workspaces'},
         'expect': {'http_status': [200]},
         'capture': {'ws_id': {'items': '$.workspaces', 'where': {'path': '$.name', 'exists': True},
                               'take': '$.name', 'last_segment': True,
                               'expect_prefix': {'concat': [{'literal': 'organizations/'}, {'var': 'org_id'}, {'literal': '/workspaces/'}]}}}},
        {'id': 'automation', 'request': {'method': 'GET', 'url': origin + '/organizations/{org_id}/workspaces/{ws_id}/automations'},
         'expect': {'http_status': [200], 'when': {'not': {'path': '$.next_page_token', 'exists': True}}},
         'capture': {'automation_id': {'items': '$.automations', 'where': {'path': '$.display_name', 'equals': 'Example'},
                                      'take': '$.name', 'last_segment': True,
                                      'expect_prefix': {'literal': 'organizations/o1/workspaces/w1/automations/'}}},
         'given': {'automation_id': {'env': 'EXAMPLE_AUTOMATION_ID', 'missing': 'omit'}},
         'hint': 'Build the example or supply its ID.'},
    ], 'manual': {'title': 'Prepare the example', 'steps': ['Build the example.', 'Set the selected ID.']}}}
    data['request']['body'] = {'json': {'inputs': {'object': {'question': {'object': {'text': {'context': 'prompt'}}}}}}}
    return data


def provision_app(*, count=1, paginated=False, raw=None):
    app = RecordingApp()
    state = {'count': count}
    async def organizations(request):
        return web.json_response({'organizations': [{'name': 'organizations/o1'}]})
    async def workspaces(request):
        return web.json_response({'workspaces': [{'name': 'organizations/o1/workspaces/w1'}]})
    async def automations(request):
        result = {'automations': [{'name': raw or 'organizations/o1/workspaces/w1/automations/a1', 'display_name': 'Example'} for _ in range(state['count'])]}
        if paginated:
            result['next_page_token'] = 'another-page'
        return web.json_response(result)
    async def create(request):
        state['count'] = 1
        return web.json_response({'name': 'created'}, status=201)
    app.route('GET', '/organizations', organizations)
    app.route('GET', '/organizations/{org}/workspaces', workspaces)
    app.route('GET', '/organizations/{org}/workspaces/{ws}/automations', automations)
    app.route('POST', '/create', create)
    app.route('POST', '/automations/{ident}:invoke', completed)
    return app


async def test_find_runs_every_run_without_cache():
    app = provision_app()
    async with serve(app) as origin:
        for _ in range(2):
            target = CustomHTTPTarget(CustomHTTPSpec(transport=provision_dict(origin)))
            with local_transport_mode():
                assert (await target.send_prompt('normal'))[0] == 'done'
                assert (await target.send_prompt('normal'))[0] == 'done'
                await target.aclose()
        assert [call[0] for call in app.calls] == ['GET'] * 3 + ['POST'] * 2 + ['GET'] * 3 + ['POST'] * 2


@pytest.mark.parametrize('count,reason', [(0, 'not_provisioned'), (2, 'ambiguous')])
async def test_find_where_exactly_one_else_ambiguous(count, reason):
    app = provision_app(count=count)
    async with serve(app) as origin:
        run = runtime(provision_dict(origin))
        with pytest.raises(TargetRunStopped) as caught:
            await run.attempt(TransportContext(prompt='normal'))
        assert caught.value.reason == reason
        assert 'automation' in caught.value.detail
        assert run.ledger.counts['provision'] == 3
        assert run.ledger.counts['submit'] == 0
        assert all(call[0] == 'GET' for call in app.calls)
        if count == 2:
            assert '2 items' in caught.value.detail


async def test_find_paginated_response_fails_closed():
    app = provision_app(paginated=True)
    async with serve(app) as origin:
        with pytest.raises(TargetRunStopped) as caught:
            await runtime(provision_dict(origin)).attempt(TransportContext(prompt='normal'))
        assert caught.value.reason == 'setup_failed_run'
        assert all(call[0] == 'GET' for call in app.calls)


async def test_last_segment_extracts_resource_id():
    app = provision_app()
    async with serve(app) as origin:
        run = runtime(provision_dict(origin))
        assert (await run.attempt(TransportContext(prompt='normal'))).response_text == 'done'
        assert dict(run.run_vars) == {'org_id': 'o1', 'ws_id': 'w1', 'automation_id': 'a1'}
        assert app.calls[-1][1] == '/automations/a1:invoke'


async def test_given_skips_find_request_when_env_set(monkeypatch):
    monkeypatch.setenv('EXAMPLE_AUTOMATION_ID', 'supplied-id')
    app = provision_app(count=0)
    async with serve(app) as origin:
        run = runtime(provision_dict(origin))
        assert (await run.attempt(TransportContext(prompt='normal'))).response_text == 'done'
        assert [call[1] for call in app.calls] == ['/organizations', '/organizations/o1/workspaces', '/automations/supplied-id:invoke']
        assert run.ledger.counts['provision'] == 2


async def test_where_env_reference_omitted_finds_nothing():
    app = provision_app()
    async with serve(app) as origin:
        data = provision_dict(origin)
        data['lifecycle']['provision']['find'][-1]['capture']['automation_id']['where']['equals'] = {'env': 'EXAMPLE_NAME', 'missing': 'omit'}
        with pytest.raises(TargetRunStopped) as caught:
            await runtime(data).attempt(TransportContext(prompt='normal'))
        assert caught.value.reason == 'not_provisioned'
        assert all(call[0] == 'GET' for call in app.calls)


async def test_create_runs_only_when_absent_then_refinds():
    app = provision_app(count=0)
    async with serve(app) as origin:
        data = provision_dict(origin)
        data['lifecycle']['provision']['create'] = [{'id': 'prepare', 'request': {'method': 'POST', 'url': origin + '/create', 'body': {'json': {'workspace': {'var': 'ws_id'}}}}, 'expect': {'http_status': [201]}}]
        run = runtime(data)
        assert (await run.attempt(TransportContext(prompt='normal'))).response_text == 'done'
        assert [call[0] for call in app.calls] == ['GET'] * 3 + ['POST'] + ['GET'] * 3 + ['POST']
        assert run.ledger.counts['provision'] == 7
        await run.close()
        assert run.run_undos.intents == []
        assert all(call[0] != 'DELETE' for call in app.calls)
        second = runtime(data)
        assert (await second.attempt(TransportContext(prompt='normal'))).response_text == 'done'
        assert sum(call[1] == '/create' for call in app.calls) == 1


async def test_created_objects_never_enter_undo_stack():
    app = provision_app(count=0)
    async with serve(app) as origin:
        data = provision_dict(origin)
        data['lifecycle']['provision']['create'] = [{
            'id': 'prepare', 'request': {'method': 'POST', 'url': origin + '/create', 'body': {'none': True}},
            'expect': {'http_status': [201]},
        }]
        target = CustomHTTPTarget(CustomHTTPSpec(transport=data))
        with local_transport_mode():
            assert (await target.send_prompt('normal'))[0] == 'done'
            await target.aclose()
            await target.aclose()
        assert all(call[0] != 'DELETE' for call in app.calls)
        assert target.cleanup_report() is None


async def test_not_provisioned_prints_checklist_and_sends_no_business_request():
    from argus_transport.spec_v2 import provision_checklist
    app = provision_app(count=0)
    async with serve(app) as origin:
        run = runtime(provision_dict(origin))
        with pytest.raises(TargetRunStopped) as caught:
            await run.attempt(TransportContext(prompt='normal'))
        assert list(caught.value.checklist) == provision_checklist(run.spec, step_id='automation', hint='Build the example or supply its ID.')
        with pytest.raises(TargetRunStopped):
            await run.attempt(TransportContext(prompt='normal'))
        assert len(app.calls) == 3


def test_mcp_step_is_rejected_for_now():
    data = provision_dict('http://127.0.0.1:1')
    data['lifecycle']['provision']['create'] = [{'id': 'prepare', 'mcp': {}}]
    with pytest.raises(ValueError, match='MCP provision steps are not supported yet'):
        TransportSpecV2.from_dict(data)


def test_provision_checklist_derives_where_and_binding_lines():
    from argus_transport.spec_v2 import provision_checklist
    data = provision_dict('http://127.0.0.1:1')
    data['lifecycle']['provision']['find'][-1]['capture']['automation_id']['where']['equals'] = {'env': 'EXAMPLE_NAME', 'missing': 'omit'}
    spec = TransportSpecV2.from_dict(data)
    assert provision_checklist(spec, step_id='automation', hint='Build first.') == [
        "NOT PROVISIONED: find step 'automation' matched no item (0 business requests sent)",
        'Hint: Build first.', 'Prepare the example', '[ ] Build the example.', '[ ] Set the selected ID.',
        'Derived from the config:',
        '[ ] Exactly one item in $.automations has $.display_name = $EXAMPLE_NAME (skipped when $EXAMPLE_AUTOMATION_ID is set)',
        '[ ] Argus sends the prompt to inputs.question.text.',
    ]
    assert provision_checklist(spec, step_id=None, hint='Ignored') == provision_checklist(spec, step_id='automation', hint='Build first.')[2:]


def test_provision_roundtrip_traversal_and_origin_override():
    data = provision_dict('http://127.0.0.1:1')
    spec = TransportSpecV2.from_dict(data)
    assert TransportSpecV2.from_dict(spec.to_dict()) == spec
    assert [owner for owner, _ in iter_requests(spec)] == ['submit', 'provision', 'provision', 'provision']
    updated = TransportSpecV2.from_dict(with_origin(data, 'http://127.0.0.1:2'))
    assert all(request.url.startswith('http://127.0.0.1:2/') for _, request in iter_requests(updated))


@pytest.mark.parametrize('invalid', [
    'find_post', 'find_undo', 'empty_find', 'given_names', 'self_prefix', 'future_where',
    'duplicate_capture', 'create_delete', 'create_undo', 'foreign_origin', 'auth_conflict',
    'capture_mixed', 'capture_incomplete', 'last_segment_type', 'manual_type',
])
def test_provision_schema_fails_closed(invalid):
    data = provision_dict('http://127.0.0.1:1')
    provision = data['lifecycle']['provision']
    step = provision['find'][-1]
    capture = step['capture']['automation_id']
    if invalid == 'find_post':
        step['request'].update(method='POST', body={'none': True})
    elif invalid == 'find_undo':
        step['undo'] = {}
    elif invalid == 'empty_find':
        provision['find'] = []
    elif invalid == 'given_names':
        step['given'] = {'other_id': {'literal': 'x'}}
    elif invalid == 'self_prefix':
        capture['expect_prefix'] = {'var': 'automation_id'}
    elif invalid == 'future_where':
        provision['find'][0]['capture']['org_id']['where'] = {'path': '$.name', 'equals': {'var': 'ws_id'}}
    elif invalid == 'duplicate_capture':
        step['capture'] = {'org_id': capture}
    elif invalid == 'create_delete':
        provision['create'] = [{'id': 'prepare', 'request': {'method': 'DELETE', 'url': 'http://127.0.0.1:1/create'}, 'expect': {'http_status': [200]}}]
    elif invalid == 'create_undo':
        provision['create'] = [{'id': 'prepare', 'undo': {}}]
    elif invalid == 'foreign_origin':
        step['request']['url'] = 'http://127.0.0.1:2/automations'
    elif invalid == 'auth_conflict':
        data['auth'] = {'kind': 'bearer', 'secret': {'source': 'env', 'name': 'EXAMPLE_PAT'}}
        step['request']['headers'] = {'Authorization': 'dummy-not-a-key'}
    elif invalid == 'capture_mixed':
        capture['path'] = '$.name'
    elif invalid == 'capture_incomplete':
        capture.pop('take')
    elif invalid == 'last_segment_type':
        capture['last_segment'] = 1
    elif invalid == 'manual_type':
        provision['manual']['steps'] = 'Build first'
    with pytest.raises(ValueError):
        TransportSpecV2.from_dict(data)


@pytest.mark.parametrize('invalid', ['prefix', 'suffix', 'array', 'missing_take', 'expect', 'create_failure', 'still_absent'])
async def test_provision_failure_does_not_send_submit_or_retry_startup(invalid):
    app = provision_app(raw='foreign/items/a1' if invalid == 'prefix' else 'organizations/o1/workspaces/w1/automations/unsafe space' if invalid == 'suffix' else None,
                        count=0 if invalid in {'create_failure', 'still_absent'} else 1)
    async with serve(app) as origin:
        data = provision_dict(origin)
        provision = data['lifecycle']['provision']
        step = provision['find'][-1]
        capture = step['capture']['automation_id']
        if invalid == 'array':
            capture['items'] = '$'
        elif invalid == 'missing_take':
            capture['take'] = '$.absent'
        elif invalid == 'expect':
            step['expect']['http_status'] = [201]
        provision['create'] = [{'id': 'prepare', 'request': {'method': 'POST', 'url': origin + '/create', 'body': {'none': True}}, 'expect': {'http_status': [200] if invalid == 'create_failure' else [201]}}]
        if invalid == 'still_absent':
            capture['where']['equals'] = 'Absent'
        run = runtime(data)
        reason = 'id_prefix_mismatch' if invalid in {'prefix', 'suffix'} else 'not_provisioned' if invalid in {'missing_take', 'still_absent'} else 'setup_failed_run'
        with pytest.raises(TargetRunStopped) as caught:
            await run.attempt(TransportContext(prompt='normal'))
        assert caught.value.reason == reason
        count = len(app.calls)
        with pytest.raises(TargetRunStopped):
            await run.attempt(TransportContext(prompt='normal'))
        assert len(app.calls) == count
        assert not any(':invoke' in call[1] for call in app.calls)
        assert run.ledger.stopped is None
        if invalid not in {'create_failure', 'still_absent', 'missing_take'}:
            assert not any(call[1] == '/create' for call in app.calls)


async def test_only_last_missing_find_can_create():
    app = provision_app()
    async with serve(app) as origin:
        data = provision_dict(origin)
        data['lifecycle']['provision']['find'][0]['capture']['org_id']['where'] = {'path': '$.name', 'equals': 'Absent'}
        data['lifecycle']['provision']['create'] = [{'id': 'prepare', 'request': {'method': 'POST', 'url': origin + '/create', 'body': {'none': True}}, 'expect': {'http_status': [201]}}]
        with pytest.raises(TargetRunStopped) as caught:
            await runtime(data).attempt(TransportContext(prompt='normal'))
        assert caught.value.reason == 'not_provisioned'
        assert [call[1] for call in app.calls] == ['/organizations']


@pytest.mark.parametrize('given', ['with/slash', 'space value', '', True, 'x' * 257])
async def test_given_final_suffix_rejects_unsafe_values(given):
    app = provision_app()
    async with serve(app) as origin:
        data = provision_dict(origin)
        data['lifecycle']['provision']['find'][-1]['given'] = {'automation_id': {'literal': given}}
        run = runtime(data)
        if given == '':
            assert (await run.attempt(TransportContext(prompt='normal'))).response_text == 'done'
            assert len(app.calls) == 4
        else:
            with pytest.raises(TargetRunStopped) as caught:
                await run.attempt(TransportContext(prompt='normal'))
            assert caught.value.reason == 'id_prefix_mismatch'
            assert len(app.calls) == 2


async def test_given_prefix_only_keeps_full_resource_name():
    app = provision_app()
    async with serve(app) as origin:
        data = provision_dict(origin)
        step = data['lifecycle']['provision']['find'][-1]
        step['capture']['automation_id'].pop('last_segment')
        full_name = 'organizations/o1/workspaces/w1/automations/full name'
        step['given'] = {'automation_id': {'literal': full_name}}
        data['request']['url'] = origin + '/automations/a1:invoke'
        data['request']['body'] = {'json': {'selected': {'var': 'automation_id'}}}
        run = runtime(data)
        assert (await run.attempt(TransportContext(prompt='normal'))).response_text == 'done'
        assert json.loads(app.calls[-1][3]) == {'selected': full_name}
        assert len(app.calls) == 3


@pytest.mark.parametrize('where', [
    {'path': '$.display_name', 'one_of': [{'env': 'EXAMPLE_NAME', 'missing': 'omit'}, 'Example']},
    {'not': {'path': '$.display_name', 'equals': {'env': 'EXAMPLE_NAME', 'missing': 'omit'}}},
    {'any': [{'path': '$.display_name', 'equals': {'var': 'selected_name'}}, {'path': '$.display_name', 'equals': 'Example'}]},
])
async def test_omitted_where_reference_fails_closed_through_logic(where):
    app = provision_app()
    async with serve(app) as origin:
        data = provision_dict(origin)
        data['let'] = {'run': {'selected_name': {'env': 'EXAMPLE_NAME', 'missing': 'omit'}}}
        data['lifecycle']['provision']['find'][-1]['capture']['automation_id']['where'] = where
        with pytest.raises(TargetRunStopped) as caught:
            await runtime(data).attempt(TransportContext(prompt='normal'))
        assert caught.value.reason == 'not_provisioned'
        assert len(app.calls) == 3


async def test_where_only_direct_comparison_objects_are_references():
    app = RecordingApp()
    async def items(request):
        return web.json_response({'items': [{'info': {'nested': {'env': 'EXAMPLE_NAME'}}, 'id': 'a1'}]})
    app.route('GET', '/items', items)
    app.route('POST', '/run', completed)
    async with serve(app) as origin:
        data = v2_dict(origin + '/run')
        data['lifecycle'] = {'provision': {'find': [{'id': 'select_item', 'request': {'method': 'GET', 'url': origin + '/items'},
            'expect': {'http_status': [200]}, 'capture': {'item_id': {'items': '$.items', 'where': {'path': '$.info', 'equals': {'nested': {'env': 'EXAMPLE_NAME'}}}, 'take': '$.id'}}}]}}
        run = runtime(data)
        assert (await run.attempt(TransportContext(prompt='normal'))).response_text == 'done'
        assert run.run_vars['item_id'] == 'a1'


async def test_provision_order_and_shared_run_attempt_namespace():
    app = provision_app()
    async with serve(app) as origin:
        data = provision_dict(origin)
        data['let'] = {'run': {'region': {'literal': 'west'}}, 'attempt': {'selected': {'var': 'automation_id'}}}
        data['lifecycle']['run'] = [{'id': 'check_run', 'request': {'method': 'GET', 'url': origin + '/organizations', 'query': {'selected': {'var': 'automation_id'}, 'region': {'var': 'region'}}}, 'expect': {'http_status': [200]}}]
        data['request']['body'] = {'json': {'selected': {'var': 'selected'}}}
        run = runtime(data)
        assert (await run.attempt(TransportContext(prompt='normal'))).response_text == 'done'
        assert app.calls[-2][1] == '/organizations?selected=a1&region=west'
        assert json.loads(app.calls[-1][3]) == {'selected': 'a1'}


async def test_provision_budget_stops_before_extra_request():
    app = provision_app()
    async with serve(app) as origin:
        data = provision_dict(origin)
        data['budget'] = {'max_requests': 2}
        run = runtime(data)
        with pytest.raises(TargetRunStopped) as caught:
            await run.attempt(TransportContext(prompt='normal'))
        assert caught.value.reason == 'request_budget'
        assert len(app.calls) == 2
        assert run.ledger.counts['provision'] == 2


async def test_provision_prefix_env_snapshot_and_policy():
    app = provision_app()
    async with serve(app) as origin:
        data = provision_dict(origin)
        data['lifecycle']['provision']['find'][-1]['capture']['automation_id']['expect_prefix'] = {'env': 'EXAMPLE_PREFIX', 'missing': 'omit'}
        run = runtime(data)
        with pytest.raises(TargetRunStopped) as caught:
            await run.attempt(TransportContext(prompt='normal'))
        assert caught.value.reason == 'id_prefix_mismatch'
        assert len(app.calls) == 3


@pytest.mark.parametrize('status,accepted', [(500, True), (404, False)])
async def test_provision_expect_owns_status_decision(status, accepted):
    app = RecordingApp()
    async def found(request):
        return web.json_response({'id': 'a1'}, status=status)
    app.route('GET', '/find', found)
    app.route('POST', '/run', completed)
    async with serve(app) as origin:
        data = v2_dict(origin + '/run')
        data['lifecycle'] = {'provision': {'find': [{'id': 'selected', 'request': {'method': 'GET', 'url': origin + '/find'}, 'expect': {'http_status': [status] if accepted else [200]}, 'capture': {'item_id': {'path': '$.id'}}}]}}
        run = runtime(data)
        if accepted:
            assert (await run.attempt(TransportContext(prompt='normal'))).response_text == 'done'
            assert run.run_vars['item_id'] == 'a1'
        else:
            with pytest.raises(TargetRunStopped) as caught:
                await run.attempt(TransportContext(prompt='normal'))
            assert caught.value.reason == 'setup_failed_run'
            assert len(app.calls) == 1
        assert run.ledger.counts['provision'] == 1


@pytest.mark.parametrize('trigger', ['status', 'alert', 'echo'])
async def test_provision_exchange_preserves_stop_checks(trigger, monkeypatch):
    monkeypatch.setenv('EXAMPLE_PAT', 'dummy-not-a-key')
    app = RecordingApp()
    async def found(request):
        return web.json_response({'id': 'dummy-not-a-key' if trigger == 'echo' else 'a1'}, status=429 if trigger == 'status' else 200,
                                 headers={'X-Example-Alert': 'present'} if trigger == 'alert' else {})
    app.route('GET', '/find', found)
    app.route('POST', '/run', completed)
    async with serve(app) as origin:
        data = v2_dict(origin + '/run')
        data['auth'] = {'kind': 'bearer', 'secret': {'source': 'env', 'name': 'EXAMPLE_PAT'}}
        data['budget'] = {'stop_on': {'alert_names': ['X-Example-Alert']}}
        data['lifecycle'] = {'provision': {'find': [{'id': 'selected', 'request': {'method': 'GET', 'url': origin + '/find'}, 'expect': {'http_status': [200, 429]}, 'capture': {'item_id': {'path': '$.id'}}}]}}
        run = runtime(data)
        with pytest.raises(TargetRunStopped) as caught:
            await run.attempt(TransportContext(prompt='normal'))
        assert caught.value.reason == {'status': 'stop_on_status', 'alert': 'alert', 'echo': 'credential_echo'}[trigger]
        assert run.ledger.stopped == caught.value.reason
        assert len(app.calls) == 1
        assert run.ledger.counts['provision'] == 1


async def test_given_partial_omission_uses_atomic_network_capture():
    app = provision_app()
    async with serve(app) as origin:
        data = provision_dict(origin)
        step = data['lifecycle']['provision']['find'][-1]
        step['capture']['selected_name'] = copy.deepcopy(step['capture']['automation_id'])
        step['given']['automation_id'] = {'literal': 'not-published'}
        step['given']['selected_name'] = {'env': 'EXAMPLE_OTHER_ID', 'missing': 'omit'}
        run = runtime(data)
        assert (await run.attempt(TransportContext(prompt='normal'))).response_text == 'done'
        assert run.run_vars['automation_id'] == run.run_vars['selected_name'] == 'a1'
        assert len(app.calls) == 4


async def test_multiple_captures_do_not_publish_partial_values_on_prefix_failure():
    app = provision_app()
    async with serve(app) as origin:
        data = provision_dict(origin)
        step = data['lifecycle']['provision']['find'][-1]
        step.pop('given')
        step['capture']['selected_name'] = copy.deepcopy(step['capture']['automation_id'])
        step['capture']['selected_name']['expect_prefix'] = {'literal': 'foreign/'}
        run = runtime(data)
        with pytest.raises(TargetRunStopped) as caught:
            await run.attempt(TransportContext(prompt='normal'))
        assert caught.value.reason == 'id_prefix_mismatch'
        assert 'automation_id' not in run.run_vars
        assert 'selected_name' not in run.run_vars
        assert len(app.calls) == 3


def test_where_expression_owners_retain_exact_config_paths():
    from argus_transport.spec_v2 import _iter_expressions
    data = provision_dict('http://127.0.0.1:1')
    capture = data['lifecycle']['provision']['find'][-1]['capture']['automation_id']
    capture['where'] = {'all': [
        {'path': '$.display_name', 'equals': {'env': 'EXAMPLE_NAME', 'missing': 'omit'}},
        {'path': '$.display_name', 'one_of': ['Example', {'env': 'EXAMPLE_OTHER_NAME', 'missing': 'omit'}]},
    ]}
    expressions = [item for item in _iter_expressions(TransportSpecV2.from_dict(data)) if item.expression.get('env') in {'EXAMPLE_NAME', 'EXAMPLE_OTHER_NAME'}]
    prefix = ('lifecycle', 'provision', 'find', 2, 'capture', 'automation_id', 'where')
    assert [item.path for item in expressions] == [prefix + ('all', 0, 'equals'), prefix + ('all', 1, 'one_of', 1)]
