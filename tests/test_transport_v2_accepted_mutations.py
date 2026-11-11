from __future__ import annotations

import asyncio

import httpx
import pytest
from aiohttp import web

from argus_transport import TransportContext
from argus_transport.runtime_v2 import TargetRunStopped
from test_transport_v2_engine import completed, runtime
from test_transport_v2_lifecycle import confirmation_data
from transport_v2_fakes import RecordingApp, serve


def creation_data(origin, scope, undo):
    data = confirmation_data(origin, undo=undo)
    step = data['lifecycle']['attempt'][0]
    if undo:
        step['undo']['request']['url'] = origin + '/files/known'
        step['undo'].pop('confirm')
    data['lifecycle'] = {scope: [step]}
    data['limits']['response_bytes'] = 100
    return data


def creation_app(created):
    app = RecordingApp()
    async def deleted(request):
        return web.Response(status=500)
    app.route('POST', '/files', created)
    app.route('DELETE', '/files/known', deleted)
    app.route('POST', '/run', completed)
    return app


async def assert_leftover(run, app, origin, undo, stopped=False):
    await run.close()
    report = run.cleanup_report()
    assert report is not None
    assert report['leftover'] == ["step 'upload_sample' POST " + origin + '/<redacted>']
    assert report['complete'] is not undo
    assert [item['status'] for item in report['open']] == (
        ['skipped_stopped' if stopped else 'failed'] if undo else [])
    assert run.run_vars == {}
    assert run.ledger.counts == {
        'provision': 0, 'setup': 1, 'submit': 0, 'poll': 0,
        'cleanup': int(undo and not stopped),
    }
    assert [(call[0], call[1]) for call in app.calls] == (
        [('POST', '/files')] + ([('DELETE', '/files/known')] if undo and not stopped else []))
    await run.close()
    assert run.cleanup_report() == report


@pytest.mark.parametrize('scope', ['attempt', 'run'])
@pytest.mark.parametrize('undo', [False, True])
@pytest.mark.parametrize('mode,reason', [
    ('invalid_utf8', 'parse_error'), ('encoding', 'parse_error'),
    ('oversized', 'response_limit'), ('interrupted', 'network_error'),
    ('alert', 'alert'), ('echo', 'credential_echo'), ('status', 'stop_on_status'),
])
async def test_accepted_mutation_retains_generic_leftover_through_response_failure(scope, undo, mode, reason):
    body = b'{"name":"organizations/one/files/sample--one.txt"}'
    async def created(request):
        if mode == 'interrupted':
            response = web.StreamResponse(status=201, headers={'Content-Length': str(len(body) + 20)})
            await response.prepare(request)
            await response.write(body)
            request.transport.close()
            return response
        headers = {'Content-Encoding': 'unsupported'} if mode == 'encoding' else {}
        if mode == 'alert':
            headers['X-Stop'] = 'yes'
        content = body + (b'\xff' if mode == 'invalid_utf8' else
                          b' ' * 101 if mode == 'oversized' else
                          b'dummy-not-a-key' if mode == 'echo' else b'')
        return web.Response(status=201, body=content, headers=headers)
    app = creation_app(created)
    async with serve(app) as origin:
        data = creation_data(origin, scope, undo)
        data['budget']['stop_on'] = {'alert_names': ['X-Stop'], 'http_status': [201] if mode == 'status' else [429],
                                     'credential_echo': mode == 'echo'}
        run = runtime(data)
        run.redactor.add('files')
        if mode == 'echo':
            run.redactor.add('dummy-not-a-key')
        stopped = mode in {'alert', 'echo', 'status'}
        if scope == 'run' or stopped:
            with pytest.raises(TargetRunStopped) as caught:
                await run.attempt(TransportContext(prompt='Read the sample.'))
            assert caught.value.reason == (reason if stopped else 'setup_failed_run')
        else:
            result = await run.attempt(TransportContext(prompt='Read the sample.'))
            assert result.reason_code.value == reason
        await assert_leftover(run, app, origin, undo, stopped)
        if scope == 'attempt' and not stopped:
            assert list(result.diagnostics['cleanup']['leftover']) == [
                "step 'upload_sample' POST " + origin + '/<redacted>']
        assert run.cleanup_report()['stop_reason'] == (
            reason if stopped else 'setup_failed_run' if scope == 'run' else None)


@pytest.mark.parametrize('scope', ['attempt', 'run'])
@pytest.mark.parametrize('undo', [False, True])
@pytest.mark.parametrize('interrupt', ['cancel', 'timeout'])
async def test_accepted_headers_retain_leftover_when_body_read_is_interrupted(scope, undo, interrupt):
    headers_seen = asyncio.Event()
    release = asyncio.Event()
    async def created(request):
        response = web.StreamResponse(status=201)
        await response.prepare(request)
        await release.wait()
        return response
    async def received(response):
        if response.status_code == 201:
            headers_seen.set()
    app = creation_app(created)
    async with serve(app) as origin:
        data = creation_data(origin, scope, undo)
        if interrupt == 'timeout':
            data['timeout'] = {'read_s': .5}
        async with httpx.AsyncClient(event_hooks={'response': [received]}) as client:
            run = runtime(data, client=client)
            run.redactor.add('files')
            pending = asyncio.create_task(run.attempt(TransportContext(prompt='Read the sample.')))
            try:
                await asyncio.wait_for(headers_seen.wait(), 1)
                if interrupt == 'cancel':
                    pending.cancel()
                    with pytest.raises(asyncio.CancelledError):
                        await pending
                elif scope == 'run':
                    with pytest.raises(TargetRunStopped) as caught:
                        await pending
                    assert caught.value.reason == 'setup_failed_run'
                else:
                    assert (await pending).reason_code.value == 'timeout'
                await assert_leftover(run, app, origin, undo)
            finally:
                release.set()
                if not pending.done():
                    pending.cancel()
                await asyncio.gather(pending, return_exceptions=True)


@pytest.mark.parametrize('scope', ['attempt', 'run'])
@pytest.mark.parametrize('mode', ['rejected', 'no_headers'])
async def test_unaccepted_mutation_has_no_creation_descriptor(scope, mode):
    async def created(request):
        if mode == 'no_headers':
            request.transport.close()
        return web.Response(status=400, body=b'{}')
    app = creation_app(created)
    async with serve(app) as origin:
        run = runtime(creation_data(origin, scope, False))
        if scope == 'run':
            with pytest.raises(TargetRunStopped) as caught:
                await run.attempt(TransportContext(prompt='Read the sample.'))
            assert caught.value.reason == 'setup_failed_run'
        else:
            result = await run.attempt(TransportContext(prompt='Read the sample.'))
            assert result.reason_code.value == ('network_error' if mode == 'no_headers' else 'setup_failed')
        await run.close()
        assert run.cleanup_report() is None
        assert [(call[0], call[1]) for call in app.calls] == [('POST', '/files')]
