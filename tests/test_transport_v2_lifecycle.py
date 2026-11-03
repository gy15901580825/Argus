from __future__ import annotations

import json
from collections.abc import Mapping

import pytest
from aiohttp import web

from argus.targets._base import TargetTransportError
from argus.targets.custom_http import CustomHTTPSpec, CustomHTTPTarget
from argus_transport import ExecutionPolicy, TransportContext, local_transport_mode
from argus_transport.runtime_v2 import V2Run
from argus_transport.spec_v2 import TransportSpecV2
from test_transport_lifecycle import deletes, lifecycle_dict, recording_lifecycle
from test_transport_v2_engine import completed, runtime, v2_dict
from transport_v2_fakes import RecordingApp, serve


def capture_dict(origin, capture, *, scope='attempt'):
    data = v2_dict(origin + '/run')
    data['lifecycle'] = {scope: [{
        'id': 'select_item', 'request': {'method': 'GET', 'url': origin + '/select'},
        'expect': {'http_status': [200]}, 'capture': capture,
        'undo': {'request': {'method': 'DELETE', 'url': origin + '/items/{item_id}'}, 'expect': {'http_status': [204]}},
    }]}
    data['request']['body'] = {'json': {'selected': {'var': 'item_id'}}}
    return data


def capture_app(value):
    app = RecordingApp()
    async def selected(request):
        return web.json_response({'name': value})
    async def undone(request):
        return web.Response(status=204)
    app.route('GET', '/select', selected)
    app.route('DELETE', '/items/{ident:.*}', undone)
    app.route('POST', '/run', completed)
    return app


@pytest.mark.parametrize('raw,want', [
    ('organizations/' + 'x' * 140 + '/workspaces/part-one', 'part-one'),
    ('part-one', 'part-one'), ('a/..', '..'), ('a/.', '.'),
    ('a/' + 'x' * 256, 'x' * 256),
])
async def test_last_segment_binds_suffix_to_business_and_undo(raw, want):
    app = capture_app(raw)
    async with serve(app) as origin:
        data = capture_dict(origin, {'item_id': {'path': '$.name', 'last_segment': True}})
        run = runtime(data)
        result = await run.attempt(TransportContext(prompt='normal'))
        assert result.response_text == 'done'
        assert json.loads(app.calls[1][3]) == {'selected': want}
        assert deletes(app) == ['/items/' + (want.replace('.', '%2E') if want in {'.', '..'} else want)]


@pytest.mark.parametrize('raw', ['', None, 12, True, 'a/', 'a/with space', 'a/%2e', 'a/é', 'a/' + 'x' * 257])
async def test_invalid_segment_fails_one_attempt_without_business_request(raw):
    app = capture_app(raw)
    async with serve(app) as origin:
        data = capture_dict(origin, {'item_id': {'path': '$.name', 'last_segment': True}})
        target = CustomHTTPTarget(CustomHTTPSpec(transport=data))
        with local_transport_mode():
            for _ in range(2):
                with pytest.raises(TargetTransportError, match='id_prefix_mismatch'):
                    await target.send_prompt('normal')
            await target.aclose()
        assert [call[0] for call in app.calls] == ['GET', 'GET']
        assert [item['status'] for item in target.cleanup_report()['open']] == ['unbound', 'unbound']


@pytest.mark.parametrize('prefix', ['', None, 10, 'Organizations/', 'wrong/'])
async def test_prefix_must_be_nonempty_exact_string(prefix):
    app = capture_app('organizations/one/items/item-one')
    async with serve(app) as origin:
        data = capture_dict(origin, {'item_id': {'path': '$.name', 'last_segment': True, 'expect_prefix': {'literal': prefix}}})
        result = await runtime(data).attempt(TransportContext(prompt='normal'))
        assert result.reason_code.value == 'id_prefix_mismatch'
        assert [call[0] for call in app.calls] == ['GET']


async def test_prefix_only_retains_long_full_name_without_suffix_validation():
    raw = 'organizations/' + 'x' * 300 + '/items/name with spaces'
    app = capture_app(raw)
    async with serve(app) as origin:
        data = capture_dict(origin, {'item_id': {'path': '$.name', 'expect_prefix': {'literal': 'organizations/'}}})
        result = await runtime(data).attempt(TransportContext(prompt='normal'))
        assert result.response_text == 'done'
        assert json.loads(app.calls[1][3]) == {'selected': raw}


async def test_capture_prefix_env_is_snapshotted_once(monkeypatch):
    monkeypatch.setenv('RESOURCE_PREFIX', 'organizations/')
    app = capture_app('organizations/one/item-one')
    async with serve(app) as origin:
        data = capture_dict(origin, {'item_id': {'path': '$.name', 'last_segment': True, 'expect_prefix': {'env': 'RESOURCE_PREFIX'}}})
        run = runtime(data)
        assert (await run.attempt(TransportContext(prompt='normal'))).response_text == 'done'
        monkeypatch.setenv('RESOURCE_PREFIX', 'other/')
        assert (await run.attempt(TransportContext(prompt='normal'))).response_text == 'done'


async def test_run_prefix_mismatch_aborts_startup_once_and_keeps_bound_undo():
    app = capture_app('wrong/item-one')
    async with serve(app) as origin:
        data = capture_dict(origin, {'item_id': {'path': '$.name', 'last_segment': True, 'expect_prefix': {'literal': 'organizations/'}}}, scope='run')
        data['lifecycle']['run'][0]['undo']['request']['url'] = origin + '/items/known'
        run = runtime(data)
        for _ in range(2):
            with pytest.raises(Exception) as caught:
                await run.attempt(TransportContext(prompt='normal'))
            assert caught.value.reason == 'id_prefix_mismatch'
            assert caught.value.detail == "step 'select_item'"
        await run.close()
        assert [call[0] for call in app.calls] == ['GET', 'DELETE']
        assert run.cleanup_report()['complete']


async def test_captures_publish_atomically_before_binding_undo():
    app = capture_app('wrong/item-one')
    async with serve(app) as origin:
        data = capture_dict(origin, {
            'first_id': {'path': '$.name'},
            'item_id': {'path': '$.name', 'last_segment': True, 'expect_prefix': {'literal': 'organizations/'}},
        }, scope='run')
        data['lifecycle']['run'][0]['undo']['request']['url'] = origin + '/items/{first_id}'
        run = runtime(data)
        with pytest.raises(Exception) as caught:
            await run.attempt(TransportContext(prompt='normal'))
        assert caught.value.reason == 'id_prefix_mismatch'
        await run.close()
        assert run.cleanup_report()['open'][0]['status'] == 'unbound'
        assert deletes(app) == []


async def test_inactive_guard_does_not_require_its_environment(monkeypatch):
    monkeypatch.delenv('OPTIONAL_MATERIAL', raising=False)
    monkeypatch.delenv('INACTIVE_VALUE', raising=False)
    app = recording_lifecycle()
    async with serve(app) as origin:
        data = lifecycle_dict(origin)
        data['let']['run'] = {'material_ref': {'env': 'OPTIONAL_MATERIAL', 'missing': 'omit'}}
        step = data['lifecycle']['attempt'][0]
        step['if_present'] = 'material_ref'
        step['request']['body'] = {'json': {'item': {'env': 'INACTIVE_VALUE'}}}
        step['capture'] = {'selected_id': {'path': '$.id', 'expect_prefix': {'env': 'INACTIVE_VALUE'}}}
        run = runtime(data)
        assert (await run.attempt(TransportContext(prompt='normal'))).response_text == 'done'
        await run.close()
        assert not any('/v1/messages' in call[1] for call in app.calls)


async def test_required_submit_environment_missing_fails_before_startup_http(monkeypatch):
    monkeypatch.delenv('REQUIRED_VALUE', raising=False)
    app = recording_lifecycle()
    async with serve(app) as origin:
        data = lifecycle_dict(origin)
        data['request']['body'] = {'json': {'item': {'env': 'REQUIRED_VALUE'}}}
        result = await runtime(data).attempt(TransportContext(prompt='normal'))
        assert result.reason_code.value == 'binding_error'
        assert app.calls == []


async def test_default_policy_denies_prefix_environment_before_mapping_access():
    class Unreadable(Mapping):
        def __getitem__(self, name):
            raise AssertionError('environment accessed')
        def __iter__(self):
            raise AssertionError('environment accessed')
        def __len__(self):
            raise AssertionError('environment accessed')
    data = capture_dict('http://127.0.0.1:1', {'item_id': {'path': '$.name', 'expect_prefix': {'env': 'RESOURCE_PREFIX'}}})
    spec = TransportSpecV2.from_dict(data)
    result = await V2Run(spec, policy=ExecutionPolicy(), environ=Unreadable()).attempt(TransportContext(prompt='normal'))
    assert result.reason_code.value == 'binding_error'


async def test_unsupported_sse_skips_lifecycle_http():
    app = recording_lifecycle()
    async with serve(app) as origin:
        data = lifecycle_dict(origin)
        data['delivery'] = {'kind': 'sse', 'event_names': ['message'], 'data_format': 'json', 'terminal': {'path': '$.done', 'equals': True}, 'accumulation': 'final_value', 'idle_timeout_s': 10, 'reconnect': False}
        result = await runtime(data).attempt(TransportContext(prompt='normal'))
        assert result.reason_code.value == 'unsupported_delivery'
        assert app.calls == []


async def test_startup_and_first_attempt_have_separate_deadlines():
    import asyncio
    app = RecordingApp()
    async def slow_source(request):
        await asyncio.sleep(.12)
        return web.json_response({'id': 'source-one'}, status=201)
    async def slow_submit(request):
        await asyncio.sleep(.12)
        return await completed(request)
    app.route('POST', '/v1/sources', slow_source)
    app.route('POST', '/run', slow_submit)
    async with serve(app) as origin:
        data = lifecycle_dict(origin, attempt=False)
        data['lifecycle']['run'][0].pop('undo')
        data['timeout'] = {'total_deadline_s': .2}
        result = await runtime(data).attempt(TransportContext(prompt='normal'))
        assert result.response_text == 'done'
        assert [call[0] for call in app.calls] == ['POST', 'POST']


async def test_private_bound_cleanup_sends_original_url_and_reports_redacted_url():
    app = recording_lifecycle(undo_status=500)
    async with serve(app) as origin:
        run = runtime(lifecycle_dict(origin, attempt=False))
        run.redactor.add('source-one')
        await run.attempt(TransportContext(prompt='normal'))
        await run.close()
        assert deletes(app) == ['/v1/sources/source-one']
        assert 'source-one' not in run.cleanup_report()['open'][0]['url']
        assert run.cleanup_report()['open'][0]['status'] == 'failed'


async def test_stop_cleanup_aliases_update_after_close():
    app = recording_lifecycle()
    async with serve(app) as origin:
        data = lifecycle_dict(origin, attempt=False)
        data['budget'] = {'max_requests': 1}
        run = runtime(data)
        with pytest.raises(Exception) as caught:
            await run.attempt(TransportContext(prompt='normal'))
        exc = caught.value
        assert exc.reason == 'request_budget'
        before_close = exc.cleanup
        assert before_close['complete'] is False
        await run.close()
        assert exc.cleanup is before_close
        assert exc.cleanup is exc.target_cleanup
        assert exc.transport_diagnostics['cleanup'] is exc.cleanup
        assert exc.cleanup['complete']
        assert deletes(app) == ['/v1/sources/source-one']


async def test_prefix_omitted_env_reference_fails_as_identifier_mismatch(monkeypatch):
    monkeypatch.delenv('RESOURCE_PREFIX', raising=False)
    app = capture_app('organizations/one/item-one')
    async with serve(app) as origin:
        data = capture_dict(origin, {'item_id': {'path': '$.name', 'expect_prefix': {'env': 'RESOURCE_PREFIX', 'missing': 'omit'}}})
        result = await runtime(data).attempt(TransportContext(prompt='normal'))
        assert result.reason_code.value == 'id_prefix_mismatch'
        assert [call[0] for call in app.calls] == ['GET']
