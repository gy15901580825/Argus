import asyncio
import copy
import json
import os
import signal
import subprocess
import sys
import threading
from dataclasses import replace

import pytest
from aiohttp import web
from click.testing import CliRunner

from argus_transport import ExecutionPolicy, TransportContext
from argus_transport.runtime_v2 import TargetRunStopped, V2Run
from argus_transport.spec_v2 import TransportContextV2, TransportSpecV2, iter_requests, material_binding, with_origin
from test_transport_v2_poll import poll_spec, runtime, wait_spec, with_attempt_undo
from transport_v2_fakes import RecordingApp, serve, serve_in_thread


def abort_spec(url):
    data = poll_spec(url)
    data['delivery']['abort'] = {
        'request': {'method': 'POST', 'url': url.rsplit('/', 1)[0] + '/runs/{run_id}:stop',
                    'body': {'none': True}},
        'expect': {'http_status': [200], 'when': {'path': '$.stopped', 'equals': True}},
    }
    return data


def abort_app(mode='poll_limit', *, abort_status=200, stopped=True, abort_delay=0, undo_delay=0,
              submit_headers=None):
    app = RecordingApp()
    app.poll_started = asyncio.Event()
    app.abort_started = asyncio.Event()
    app.undo_completed = asyncio.Event()
    app.mode = mode

    async def submitted(request):
        body = {'run_id': 'job-1', 'status': 'PENDING'}
        if mode.startswith('submit_'):
            body.update(status=mode.removeprefix('submit_'), result='done')
            if mode == 'submit_BLOCKED':
                body['error'] = {'code': 'POLICY_REFUSAL'}
        return web.json_response(body, status=200 if mode == 'unsafe_location' else 202,
                                 headers=submit_headers)

    async def polled(request):
        mode = app.mode
        app.poll_started.set()
        if mode == 'network_error':
            request.transport.close()
            return web.Response()
        if mode in {'timeout', 'cancel'}:
            await asyncio.sleep(10)
        if mode == 'parse_error':
            return web.Response(body=b'{')
        if mode == 'response_limit':
            return web.Response(body=b'x' * 257)
        if mode == 'http_error':
            return web.Response(status=500)
        if mode == 'stop_on_status':
            return web.Response(status=429)
        if mode == 'alert':
            return web.json_response({}, headers={'X-Alert': 'stop'})
        if mode == 'unsafe_location':
            return web.json_response({}, status=202, headers={'Location': '/runs/other'})
        body = {'run_id': 'other' if mode == 'poll_identity_changed' else 'job-1',
                'status': 'PENDING'}
        if mode in {'COMPLETED', 'FAILED', 'BLOCKED', 'unknown_status', 'mapping_error'}:
            body.update(status='UNSEEN' if mode == 'unknown_status' else
                        'COMPLETED' if mode == 'mapping_error' else mode, result='done')
            if mode == 'BLOCKED':
                body['error'] = {'code': 'POLICY_REFUSAL'}
        if mode == 'credential_echo':
            body['echo'] = 'public-mock-auth'
        return web.json_response(body)

    async def aborted(request):
        app.abort_started.set()
        await asyncio.sleep(abort_delay)
        return web.json_response({'stopped': stopped}, status=abort_status)

    async def created(request):
        return web.json_response({'ref': 'obj-1'}, status=201)

    async def deleted(request):
        await asyncio.sleep(undo_delay)
        app.undo_completed.set()
        return web.Response(status=204)

    app.route('POST', '/run', submitted)
    app.route('GET', '/runs/{tail:.*}', polled)
    app.route('POST', '/runs/{ident}:stop', aborted)
    app.route('POST', '/objects', created)
    app.route('DELETE', '/objects/{ref}', deleted)
    return app


def assert_abort_requests(app, origin, count):
    requests = [call for call in app.calls if call[0] == 'POST' and call[1].endswith(':stop')]
    assert len(requests) == count
    if count:
        assert requests[0][1] == '/runs/job-1:stop'
        assert requests[0][2]['Host'] == origin.removeprefix('http://')


@pytest.mark.parametrize('mode', ['poll_limit', 'timeout', 'parse_error', 'response_limit',
                                  'http_error', 'poll_identity_changed', 'unknown_status',
                                  'poll_wait_limit', 'network_error', 'mapping_before_terminal'])
async def test_abort_abnormal_reason_matrix(mode, monkeypatch):
    app = abort_app(mode)
    async with serve(app) as origin:
        data = abort_spec(origin + '/run')
        if mode == 'timeout':
            data['timeout']['total_deadline_s'] = 0.1
        if mode == 'response_limit':
            data['limits']['response_bytes'] = 256
        if mode == 'poll_wait_limit':
            wait_spec(data, default=3, maximum=2)
        if mode == 'mapping_before_terminal':
            from argus_transport.engine_v2 import outcome_match
            def mapping(outcome, status, body):
                if status == 200:
                    raise ValueError('Cannot map response')
                return outcome_match(outcome, status, body)
            monkeypatch.setattr('argus_transport.engine_v2.outcome_match', mapping)
        run = runtime(data)
        result = await run.attempt(TransportContext(prompt='task'))
        assert result.reason_code.value == ('mapping_error' if mode == 'mapping_before_terminal' else mode)
        assert_abort_requests(app, origin, 1)
        report = run.cleanup_report()
        assert report['complete'] is True
        assert report['done'] == 1
        assert report['aborts'][0]['status'] == 'done'


@pytest.mark.parametrize('mode', ['COMPLETED', 'FAILED', 'BLOCKED', 'submit_COMPLETED',
                                  'submit_FAILED', 'submit_BLOCKED', 'mapping_error', 'submit_mapping_error'])
@pytest.mark.parametrize('verify', [False, True])
async def test_matched_terminal_outcomes_do_not_abort(mode, verify):
    app = abort_app('submit_COMPLETED' if mode == 'submit_mapping_error' else mode,
                    submit_headers={'Location': '/runs/job-1'} if verify else None)
    async with serve(app) as origin:
        data = abort_spec(origin + '/run')
        if verify:
            data['delivery']['location'] = 'verify'
        if mode in {'mapping_error', 'submit_mapping_error'}:
            data['response']['text']['paths'] = ['$.missing']
        run = runtime(data)
        result = await run.attempt(TransportContext(prompt='task'))
        expected = ('mapping_error' if 'mapping_error' in mode else 'ok' if 'COMPLETED' in mode else
                    'target_error' if 'FAILED' in mode else 'target_refusal')
        assert result.reason_code.value == expected
        assert_abort_requests(app, origin, 0)
        assert run.cleanup_report()['aborts'][0]['status'] == 'not_needed'


@pytest.mark.parametrize('mode', ['stop_on_status', 'alert', 'credential_echo', 'unsafe_location'])
async def test_security_stop_skips_abort(mode, monkeypatch):
    app = abort_app(mode)
    async with serve(app) as origin:
        data = abort_spec(origin + '/run')
        if mode == 'alert':
            data['budget'] = {'stop_on': {'alert_names': ['X-Alert']}}
        if mode == 'unsafe_location':
            data['delivery']['location'] = 'verify'
        if mode == 'credential_echo':
            data['auth'] = {'kind': 'bearer', 'secret': {'source': 'env', 'name': 'PUBLIC_MOCK_AUTH'}}
            monkeypatch.setattr('argus_transport.engine_v2.resolve_secret', lambda *_: 'public-mock-auth')
        run = runtime(data)
        with pytest.raises(TargetRunStopped) as caught:
            await run.attempt(TransportContext(prompt='task'))
        assert caught.value.reason == mode
        assert_abort_requests(app, origin, 0)
        assert run.cleanup_report()['aborts'][0]['status'] == 'skipped_stopped'


@pytest.mark.parametrize('method', ['GET', 'DELETE', 'POST'])
async def test_abort_request_methods_and_no_redirect(method):
    app = RecordingApp()
    async def submitted(request):
        return web.json_response({'run_id': 'job-1', 'status': 'PENDING'}, status=202)
    async def polled(request):
        return web.json_response({'status': 'PENDING'})
    async def aborted(request):
        return web.Response(status=302, headers={'Location': '/unexpected'})
    async def unexpected(request):
        pytest.fail('Abort redirect was followed')
    app.route('POST', '/run', submitted)
    app.route(method, '/runs/{ident}:stop', aborted)
    app.route('GET', '/runs/{ident}', polled)
    app.route('GET', '/unexpected', unexpected)
    async with serve(app) as origin:
        data = abort_spec(origin + '/run')
        data['delivery']['abort']['request']['method'] = method
        run = runtime(data)
        result = await run.attempt(TransportContext(prompt='task'))
        assert result.reason_code.value == 'poll_limit'
        aborts = [call for call in app.calls if call[1].endswith(':stop')]
        assert [(call[0], call[1], call[3]) for call in aborts] == [(method, '/runs/job-1:stop', b'')]
        assert aborts[0][2]['Host'] == origin.removeprefix('http://')
        assert run.cleanup_report()['aborts'][0]['status'] == 'failed'


def test_abort_auth_public_header_conflict_rejected():
    data = abort_spec('http://127.0.0.1/run')
    data['auth'] = {'kind': 'bearer', 'secret': {'source': 'env', 'name': 'PUBLIC_MOCK_AUTH'}}
    data['delivery']['abort']['request']['headers'] = {'Authorization': 'public-header'}
    with pytest.raises(ValueError, match='Auth and public headers conflict'):
        TransportSpecV2.from_dict(data)


async def test_request_budget_allows_reserved_abort():
    app = abort_app()
    async with serve(app) as origin:
        data = abort_spec(origin + '/run')
        data['budget'] = {'max_requests': 1, 'cleanup_reserve': 1}
        run = runtime(data)
        with pytest.raises(TargetRunStopped) as caught:
            await run.attempt(TransportContext(prompt='task'))
        assert caught.value.reason == 'request_budget'
        assert_abort_requests(app, origin, 1)
        assert run.ledger.counts['cleanup'] == 1


@pytest.mark.parametrize('status,stopped,expected', [(200, True, 'done'), (200, False, 'unconfirmed'),
                                                   (500, True, 'failed')])
async def test_abort_status_done_unconfirmed_failed(status, stopped, expected):
    app = abort_app(abort_status=status, stopped=stopped)
    async with serve(app) as origin:
        run = runtime(abort_spec(origin + '/run'))
        result = await run.attempt(TransportContext(prompt='task'))
        assert result.reason_code.value == 'poll_limit'
        assert_abort_requests(app, origin, 1)
        report = run.cleanup_report()
        assert report['aborts'][0]['status'] == expected
        assert report['complete'] is (expected == 'done')
        assert report['done'] == int(expected == 'done')
        assert len(report['open']) == int(expected != 'done')


def test_abort_roundtrip_and_validation():
    data = abort_spec('http://127.0.0.1/run')
    spec = TransportSpecV2.from_dict(data)
    assert TransportSpecV2.from_dict(spec.to_dict()) == spec
    assert with_origin(data, 'http://127.0.0.1:8123')['delivery']['abort']['request']['url'] == \
        'http://127.0.0.1:8123/runs/{run_id}:stop'
    for request in [{'url': 'http://127.0.0.1/runs/{run_id}:stop', 'body': {'none': True}},
                    {'method': 'PUT', 'url': 'http://127.0.0.1/stop', 'body': {'none': True}},
                    {'method': 'GET', 'url': 'http://127.0.0.1/stop', 'body': {'json': {}}},
                    {'method': 'POST', 'url': 'http://127.0.0.2/stop', 'body': {'none': True}},
                    {'method': 'POST', 'url': 'http://127.0.0.1/stop', 'body': {'multipart': {}}}]:
        invalid = copy.deepcopy(data)
        invalid['delivery']['abort']['request'] = request
        with pytest.raises(ValueError):
            TransportSpecV2.from_dict(invalid)
    for method in ['GET', 'DELETE']:
        valid = copy.deepcopy(data)
        valid['delivery']['abort']['request']['method'] = method
        TransportSpecV2.from_dict(valid)
    for kind in ['sync', 'sse']:
        invalid = copy.deepcopy(data)
        invalid['delivery']['kind'] = kind
        with pytest.raises(ValueError):
            TransportSpecV2.from_dict(invalid)
    from argus_transport.spec_v2 import UndoSpec
    with pytest.raises(ValueError, match='Undo method must be DELETE or GET'):
        UndoSpec.from_dict(data['delivery']['abort'], visible=frozenset({'run_id'}))


@pytest.mark.parametrize('variant', ['query', 'json', 'text'])
def test_abort_request_traverses_context_origin_and_offline_validation(tmp_path, variant):
    from argus.cli.__main__ import main
    from argus.targets.custom_http import CustomHTTPSpec
    data = abort_spec('http://127.0.0.1/run')
    request = data['delivery']['abort']['request']
    expression = {'base64': {'context': 'material'}}
    if variant == 'query':
        request['query'] = {'sample': expression}
    else:
        request['body'] = {'json': {'sample': expression}} if variant == 'json' else {'text': expression}
    spec = TransportSpecV2.from_dict(data)
    assert material_binding(spec) == 'required'
    assert [phase for phase, _ in iter_requests(spec)] == ['submit', 'poll', 'cleanup']
    assert with_origin(data, 'http://127.0.0.1:8111')['delivery']['abort']['request']['url'] == \
        'http://127.0.0.1:8111/runs/{run_id}:stop'
    target = tmp_path / 'target.json'
    target.write_text(json.dumps({'kind': 'custom_http', 'transport': data}))
    result = CliRunner().invoke(main, ['validate-target', '--target', str(target), '--offline'])
    assert result.exit_code == 0, result.output
    expression['base64']['context'] = 'scenario_url'
    with pytest.raises(ValueError, match='scenario_url context requires a browser target'):
        CustomHTTPSpec(transport=data)


async def test_abort_environment_snapshot_and_policy():
    app = abort_app()
    async with serve(app) as origin:
        data = abort_spec(origin + '/run')
        data['delivery']['abort']['request']['body'] = {'text': {'env': 'PUBLIC_LABEL'}}
        env = {'PUBLIC_LABEL': 'public-original'}
        spec = TransportSpecV2.from_dict(data)
        denied = V2Run(spec, policy=replace(ExecutionPolicy.local(spec), allowed_env_names=frozenset()), environ=env)
        result = await denied.attempt(TransportContext(prompt='task'))
        assert result.reason_code.value == 'binding_error'
        assert app.calls == []
        run = runtime(data, environ=env)
        await run.attempt(TransportContext(prompt='task'))
        env['PUBLIC_LABEL'] = 'public-changed'
        await run.attempt(TransportContext(prompt='next task'))
        aborts = [call for call in app.calls if call[1] == '/runs/job-1:stop']
        assert len(aborts) == 2
        assert [call[3] for call in aborts] == [b'public-original', b'public-original']


async def test_abort_armed_before_first_post_capture_await(monkeypatch):
    ready = asyncio.Event()
    never = asyncio.Event()
    original = ExecutionPolicy.endpoint_ip
    async def endpoint_ip(policy, url):
        if url.endswith('/runs/job-1'):
            ready.set()
            await never.wait()
        return await original(policy, url)
    monkeypatch.setattr(ExecutionPolicy, 'endpoint_ip', endpoint_ip)
    app = abort_app()
    async with serve(app) as origin:
        data = abort_spec(origin + '/run')
        data['delivery']['abort']['request']['body'] = {'text': {'context': 'material'}}
        run = runtime(data)
        context = TransportContextV2(prompt='task', material='public-original')
        task = asyncio.create_task(run.attempt(context))
        await asyncio.wait_for(ready.wait(), 3)
        object.__setattr__(context, 'material', 'public-changed')
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert_abort_requests(app, origin, 1)
        assert [(call[0], call[1]) for call in app.calls] == [('POST', '/run'), ('POST', '/runs/job-1:stop')]
        assert app.calls[-1][3] == b'public-original'


async def test_old_target_cleanup_shape_unchanged():
    app = abort_app('COMPLETED')
    async with serve(app) as origin:
        run = runtime(with_attempt_undo(poll_spec(origin + '/run'), origin))
        await run.attempt(TransportContext(prompt='task'))
        assert run.cleanup_report() == {'complete': True, 'done': 1, 'open': [],
                                        'stop_reason': None, 'leftover': []}
        assert_abort_requests(app, origin, 0)


@pytest.mark.parametrize('reserve,expected', [(0, 'failed'), (1, 'done')])
async def test_abort_cleanup_reserve_is_optional(reserve, expected):
    app = abort_app('COMPLETED')
    async with serve(app) as origin:
        data = abort_spec(origin + '/run')
        data['budget'] = {'cleanup_reserve': reserve}
        run = runtime(data)
        await run.attempt(TransportContext(prompt='task'))
        assert run.ledger.counts['cleanup'] == 0
        assert_abort_requests(app, origin, 0)
        app.mode = 'poll_limit'
        result = await run.attempt(TransportContext(prompt='next task'))
        assert result.reason_code.value == 'poll_limit'
        assert_abort_requests(app, origin, reserve)
        assert [item['status'] for item in run.cleanup_report()['aborts']] == ['not_needed', expected]
        if not reserve:
            assert run.cleanup_report()['aborts'][1]['failure_reason'] == 'budget'


@pytest.mark.parametrize('reserve', [1, 2])
async def test_abort_preserves_step_undo_reservation(reserve):
    app = abort_app()
    async with serve(app) as origin:
        data = with_attempt_undo(abort_spec(origin + '/run'), origin)
        data['budget'] = {'max_requests': 2, 'cleanup_reserve': reserve}
        run = runtime(data)
        with pytest.raises(TargetRunStopped) as caught:
            await run.attempt(TransportContext(prompt='task'))
        assert caught.value.reason == 'request_budget'
        assert_abort_requests(app, origin, reserve - 1)
        expected = [('POST', '/objects'), ('POST', '/run')]
        if reserve == 2:
            expected.append(('POST', '/runs/job-1:stop'))
        expected.append(('DELETE', '/objects/obj-1'))
        assert [(call[0], call[1]) for call in app.calls] == expected
        assert run.cleanup_report()['done'] == reserve


@pytest.mark.parametrize('abort_delay,undo_count', [(0.2, 1), (0.5, 0)])
async def test_abort_and_undos_share_deadline(abort_delay, undo_count):
    app = abort_app(abort_delay=abort_delay, undo_delay=0.2)
    async with serve(app) as origin:
        data = with_attempt_undo(abort_spec(origin + '/run'), origin)
        data['timeout']['cleanup_s'] = 0.3
        run = runtime(data)
        result = await run.attempt(TransportContext(prompt='task'))
        assert result.reason_code.value == 'poll_limit'
        assert_abort_requests(app, origin, 1)
        undos = [call for call in app.calls if call[0] == 'DELETE']
        assert [call[1] for call in undos] == ['/objects/obj-1'] * undo_count
        assert app.undo_completed.is_set() is False
        assert run.cleanup_report()['complete'] is False


async def test_abort_freezes_submit_auth_ids_and_own_headers(monkeypatch):
    resolved = []
    def resolve(*_):
        resolved.append('public-mock-auth')
        return 'public-mock-auth' if len(resolved) == 1 else 'public-changed-auth'
    monkeypatch.setattr('argus_transport.engine_v2.resolve_secret', resolve)
    app = abort_app('poll_identity_changed')
    async with serve(app) as origin:
        data = abort_spec(origin + '/run')
        data['auth'] = {'kind': 'bearer', 'secret': {'source': 'env', 'name': 'PUBLIC_MOCK_AUTH'}}
        data['delivery']['ids'] = {'job_id': data['delivery']['ids']['run_id']}
        data['delivery']['request']['url'] = origin + '/runs/{job_id}'
        data['request']['headers'] = {'X-Submit': 'public-submit', 'Content-Type': 'application/json; charset=utf-8'}
        data['delivery']['abort']['request'].update(
            url=origin + '/runs/{job_id}:stop', headers={'X-Abort': 'public-abort'},
            body={'json': {'id': {'var': 'job_id'}}})
        run = runtime(data)
        result = await run.attempt(TransportContext(prompt='task'))
        assert result.reason_code.value == 'poll_identity_changed'
        assert_abort_requests(app, origin, 1)
        abort = app.calls[-1]
        assert abort[2]['Authorization'] == 'Bearer public-mock-auth'
        assert abort[2]['Content-Type'] == 'application/json'
        assert abort[2]['X-Abort'] == 'public-abort'
        assert 'X-Submit' not in abort[2]
        assert json.loads(abort[3]) == {'id': 'job-1'}
        assert resolved == ['public-mock-auth']


@pytest.mark.parametrize('valid_second_id', [True, False])
async def test_abort_arms_only_after_all_ids_validate(valid_second_id):
    app = RecordingApp()
    async def submitted(request):
        return web.json_response({'run_id': 'job-1', 'thread': 'thread-1' if valid_second_id else None,
                                  'status': 'PENDING'}, status=202)
    async def polled(request):
        return web.json_response({'status': 'PENDING'})
    async def aborted(request):
        return web.json_response({'stopped': True})
    app.route('POST', '/run', submitted)
    app.route('GET', '/threads/{thread}/runs/{ident}', polled)
    app.route('POST', '/runs/{ident}:stop', aborted)
    async with serve(app) as origin:
        data = abort_spec(origin + '/run')
        data['delivery']['ids']['thread'] = {'path': '$.thread'}
        data['delivery']['request']['url'] = origin + '/threads/{thread}/runs/{run_id}'
        run = runtime(data)
        result = await run.attempt(TransportContext(prompt='task'))
        assert result.reason_code.value == ('poll_limit' if valid_second_id else 'missing_id')
        assert_abort_requests(app, origin, int(valid_second_id))
        assert run.cleanup_report()['aborts'][0]['status'] == ('done' if valid_second_id else 'not_needed')


@pytest.mark.parametrize('abort_status', [429, 500])
@pytest.mark.parametrize('primary', ['poll_limit', 'request_budget', 'cancel'])
async def test_abort_cleanup_preserves_primary_result(primary, abort_status):
    app = abort_app(primary, abort_status=abort_status)
    async with serve(app) as origin:
        data = with_attempt_undo(abort_spec(origin + '/run'), origin)
        if primary == 'request_budget':
            data['budget'] = {'max_requests': 2}
        run = runtime(data)
        if primary == 'request_budget':
            with pytest.raises(TargetRunStopped) as caught:
                await run.attempt(TransportContext(prompt='task'))
            assert caught.value.reason == primary
        elif primary == 'cancel':
            task = asyncio.create_task(run.attempt(TransportContext(prompt='task')))
            await asyncio.wait_for(app.poll_started.wait(), 3)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        else:
            result = await run.attempt(TransportContext(prompt='task'))
            assert result.reason_code.value == primary
        assert_abort_requests(app, origin, 1)
        assert run.cleanup_report()['aborts'][0]['status'] == ('skipped_stopped' if abort_status == 429 else 'failed')
        undos = [call for call in app.calls if call[0] == 'DELETE']
        assert [call[1] for call in undos] == ([] if abort_status == 429 else ['/objects/obj-1'])


async def test_second_cancellation_records_interrupted_abort():
    app = abort_app('cancel', abort_delay=10)
    async with serve(app) as origin:
        run = runtime(abort_spec(origin + '/run'))
        task = asyncio.create_task(run.attempt(TransportContext(prompt='task')))
        await asyncio.wait_for(app.poll_started.wait(), 3)
        task.cancel('first')
        await asyncio.wait_for(app.abort_started.wait(), 3)
        task.cancel('second')
        with pytest.raises(asyncio.CancelledError) as caught:
            await task
        assert caught.value.args == ('first',)
        assert_abort_requests(app, origin, 1)
        assert run.cleanup_report()['aborts'][0]['status'] == 'interrupted'


@pytest.mark.parametrize('signum,exit_code', [(signal.SIGINT, 130), (signal.SIGTERM, 143)])
def test_abort_first_signal(tmp_path, signum, exit_code):
    ready = threading.Event()
    app = RecordingApp()
    async def submitted(request):
        return web.json_response({'run_id': 'job-1', 'status': 'PENDING'}, status=202)
    async def polled(request):
        ready.set()
        await asyncio.sleep(30)
        return web.json_response({'status': 'PENDING'})
    async def aborted(request):
        return web.json_response({'stopped': True})
    app.route('POST', '/run', submitted)
    app.route('GET', '/runs/{ident}', polled)
    app.route('POST', '/runs/{ident}:stop', aborted)
    pack = tmp_path / 'probe_pack'
    pack.mkdir()
    (pack / 'signal.yaml').write_text(
        'id: abort_signal_probe\nname: Abort signal probe\ntarget_class: [llm_chat]\n'
        'attack_class: [prompt-injection]\nseverity: info\nprompts: [Read a public sample.]\n'
        'assertions:\n  - no_call_to_tool: unused\nrequires_interaction: false\n')
    (tmp_path / 'abort_signal_pack.py').write_text(
        'from pathlib import Path\ndef probes_dir():\n    return Path(__file__).parent / "probe_pack"\n')
    metadata = tmp_path / 'abort_signal_pack-1.0.dist-info'
    metadata.mkdir()
    (metadata / 'METADATA').write_text('Metadata-Version: 2.1\nName: abort-signal-pack\nVersion: 1.0\n')
    (metadata / 'entry_points.txt').write_text('[argus.probe_packs]\nabort_signal_pack = abort_signal_pack:probes_dir\n')
    with serve_in_thread(app) as origin:
        data = abort_spec(origin + '/run')
        target = tmp_path / 'target.json'
        target.write_text(json.dumps({'kind': 'custom_http', 'transport': data}))
        output = tmp_path / 'run.json'
        env = {**os.environ, 'PYTHONPATH': os.pathsep.join(filter(None, (str(tmp_path), os.environ.get('PYTHONPATH'))))}
        process = subprocess.Popen([sys.executable, '-m', 'argus.cli', 'run', '--local', '--target',
                                    str(target), '--probes', 'abort_signal_probe', '--format', 'json',
                                    '--out', str(output)], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True)
        try:
            assert ready.wait(15), 'Native CLI did not reach polling'
            process.send_signal(signum)
            stdout, stderr = process.communicate(timeout=15)
            assert process.returncode == exit_code, stdout + stderr
            assert output.exists() is False
            assert_abort_requests(app, origin, 1)
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=5)
