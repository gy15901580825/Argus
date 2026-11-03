import asyncio
import time

import httpx
import pytest
from aiohttp import web

from argus.targets._base import TargetTransportError
from argus.targets.custom_http import CustomHTTPSpec, CustomHTTPTarget
from argus_transport import ExecutionPolicy, TransportContext, local_transport_mode
from argus_transport.engine_v2 import TransportEngineV2
from argus_transport.runtime_v2 import RequestLedger, TargetRunStopped, UndoIntent, UndoStack, V2Run
from argus_transport.spec_v2 import TransportSpecV2
from test_transport_lifecycle import lifecycle_dict, recording_lifecycle
from test_transport_v2_engine import runtime, v2_dict
from transport_v2_fakes import RecordingApp, serve


async def limited(request):
    return web.Response(status=429, body=b'{', headers={'Content-Encoding': 'gzip'})


async def test_429_trips_stop_and_no_request_follows_including_undo():
    app = recording_lifecycle()
    app.route('POST', '/limited', limited)
    async with serve(app) as origin:
        data = lifecycle_dict(origin)
        data['request']['url'] = origin + '/limited'
        target = CustomHTTPTarget(CustomHTTPSpec(transport=data))
        with local_transport_mode():
            stopped = None
            for _ in range(2):
                with pytest.raises(TargetRunStopped) as caught:
                    await target.send_prompt('normal task')
                assert caught.value.reason == 'stop_on_status'
                assert not hasattr(caught.value, 'status_code')
                if stopped is None:
                    stopped = caught.value
            await target.aclose()
        assert [(call[0], call[1]) for call in app.calls] == [
            ('POST', '/v1/sources'), ('POST', '/v1/messages'), ('POST', '/limited'),
        ]
        report = target.cleanup_report()
        assert [(item['step'], item['status']) for item in report['open']] == [
            ('source', 'skipped_stopped'), ('ingest', 'skipped_stopped'),
        ]
        assert report['stop_reason'] == 'stop_on_status'
        assert stopped.cleanup == report


async def test_stop_defaults_apply_when_budget_absent():
    app = RecordingApp()
    app.route('POST', '/run', limited)
    async with serve(app) as origin:
        run = runtime(v2_dict(origin + '/run'))
        for _ in range(2):
            with pytest.raises(TargetRunStopped, match='^stop_on_status$'):
                await run.attempt(TransportContext(prompt='normal task'))
        await run.close()
        assert len(app.calls) == 1


@pytest.mark.parametrize('status', [200, 503])
@pytest.mark.parametrize('alert_name', ['X-Security-Alert', 'Content-Length'])
async def test_alert_name_trips_stop_before_body_handling(status, alert_name):
    app = RecordingApp()
    async def alert(request):
        return web.Response(status=status, body=b'{', headers={
            'x-security-alert': '', 'Content-Encoding': 'gzip',
        })
    app.route('POST', '/run', alert)
    async with serve(app) as origin:
        data = v2_dict(origin + '/run')
        data['budget'] = {'stop_on': {'alert_names': [alert_name]}}
        run = runtime(data)
        for _ in range(2):
            with pytest.raises(TargetRunStopped, match='^alert$'):
                await run.attempt(TransportContext(prompt='normal task'))
        await run.close()
        assert len(app.calls) == 1


@pytest.mark.parametrize('status,valid_json', [(200, True), (200, False), (503, False)])
async def test_credential_echo_trips_stop_before_parsing(monkeypatch, status, valid_json):
    monkeypatch.setenv('DUMMY_ACCESS', 'dummy-not-a-key')
    app = RecordingApp()
    async def echo(request):
        value = request.headers['Authorization'].removeprefix('Bearer ')
        if valid_json:
            return web.json_response({'status': 'COMPLETED', 'result': value}, status=status)
        return web.Response(text=value + '{', status=status)
    app.route('POST', '/run', echo)
    async with serve(app) as origin:
        data = v2_dict(origin + '/run')
        data['auth'] = {'kind': 'bearer', 'secret': {'source': 'env', 'name': 'DUMMY_ACCESS'}}
        run = runtime(data)
        with pytest.raises(TargetRunStopped) as caught:
            await run.attempt(TransportContext(prompt='normal task'))
        assert caught.value.reason == 'credential_echo'
        assert 'dummy-not-a-key' not in str(caught.value)
        assert 'dummy-not-a-key' not in str(caught.value.transport_diagnostics)
        with pytest.raises(TargetRunStopped, match='^credential_echo$'):
            await run.attempt(TransportContext(prompt='next task'))
        await run.close()
        assert len(app.calls) == 1


async def test_stop_on_empty_list_disables_status_trip():
    app = RecordingApp()
    app.route('POST', '/run', limited)
    async with serve(app) as origin:
        data = v2_dict(origin + '/run')
        data['budget'] = {'stop_on': {'http_status': [], 'credential_echo': False}}
        target = CustomHTTPTarget(CustomHTTPSpec(transport=data))
        with local_transport_mode():
            for _ in range(2):
                with pytest.raises(TargetTransportError, match='target_error: http_error'):
                    await target.send_prompt('normal task')
            await target.aclose()
        assert len(app.calls) == 2


@pytest.mark.parametrize('stop_on', [
    {'http_status': [True]}, {'http_status': [99]}, {'http_status': [600]},
    {'http_status': '429'}, {'alert_names': 'X-Alert'}, {'alert_names': ['bad name']},
    {'alert_names': [1]}, {'credential_echo': 1}, {'extra': True},
])
def test_invalid_stop_configuration_is_rejected(stop_on):
    data = v2_dict('http://127.0.0.1/run')
    data['budget'] = {'stop_on': stop_on}
    with pytest.raises(ValueError):
        TransportSpecV2.from_dict(data)


def test_stop_configuration_roundtrips_as_json_lists():
    data = v2_dict('http://127.0.0.1/run')
    data['budget'] = {'max_requests': 8, 'cleanup_reserve': 2, 'stop_on': {
        'http_status': [429, 503], 'alert_names': ['X-Security-Alert'], 'credential_echo': False,
    }}
    spec = TransportSpecV2.from_dict(data)
    serialized = spec.to_dict()
    assert serialized['budget'] == data['budget']
    assert TransportSpecV2.from_dict(serialized) == spec


@pytest.mark.parametrize('historical', ['done', 'failed', 'unbound', 'blocked_by_inner'])
async def test_stopped_unwind_preserves_historical_cleanup_status(historical):
    spec = TransportSpecV2.from_dict(lifecycle_dict('http://127.0.0.1'))
    ledger = RequestLedger(None, 2)
    stack = UndoStack(ledger)
    for status in [historical, 'pending']:
        intent = UndoIntent('attempt', 'ingest', spec.lifecycle.attempt[0].undo,
                            frozenset(), frozenset(), status=status)
        stack.register(intent)
    async def forbidden_send(intent):
        pytest.fail('stopped cleanup emitted a request')
    ledger.trip('alert')
    ledger.trip('credential_echo')
    await stack.unwind(forbidden_send, timeout_s=1)
    assert [intent.status for intent in stack.intents] == [historical, 'skipped_stopped']
    assert ledger.stopped == 'alert'
    for operation in [lambda: ledger.charge('submit'), ledger.spend_cleanup]:
        with pytest.raises(TargetRunStopped, match='^alert$'):
            operation()


@pytest.mark.parametrize('undo_status', [204, 500])
async def test_later_stop_preserves_earlier_attempt_cleanup(undo_status):
    app = recording_lifecycle(undo_status=undo_status)
    attempts = 0
    async def submitted(request):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return web.json_response({'status': 'COMPLETED', 'result': 'done'})
        return await limited(request)
    app.route('POST', '/submit', submitted)
    async with serve(app) as origin:
        data = lifecycle_dict(origin)
        data['request']['url'] = origin + '/submit'
        run = runtime(data)
        assert (await run.attempt(TransportContext(prompt='first task'))).response_text == 'done'
        with pytest.raises(TargetRunStopped, match='^stop_on_status$'):
            await run.attempt(TransportContext(prompt='next task'))
        requests_before_close = len(app.calls)
        await run.close()
        assert len(app.calls) == requests_before_close
        report = run.cleanup_report()
        assert report['done'] == (1 if undo_status == 204 else 0)
        assert [(item['step'], item['status'], item['http_status']) for item in report['open']] == (
            [('source', 'skipped_stopped', None)]
            + ([] if undo_status == 204 else [('ingest', 'failed', 500)])
            + [('ingest', 'skipped_stopped', None)]
        )


async def test_cleanup_response_can_trip_stop_and_prevent_outer_undo():
    app = recording_lifecycle(undo_status=429)
    async with serve(app) as origin:
        run = runtime(lifecycle_dict(origin))
        with pytest.raises(TargetRunStopped, match='^stop_on_status$'):
            await run.attempt(TransportContext(prompt='normal task'))
        await run.close()
        assert [call[0] for call in app.calls] == ['POST', 'POST', 'POST', 'DELETE']
        assert {item['status'] for item in run.cleanup_report()['open']} == {'skipped_stopped'}


async def test_run_close_response_stop_keeps_exception_cleanup_aliases():
    app = recording_lifecycle(undo_status=429)
    async with serve(app) as origin:
        run = runtime(lifecycle_dict(origin, attempt=False))
        assert (await run.attempt(TransportContext(prompt='normal task'))).response_text == 'done'
        with pytest.raises(TargetRunStopped, match='^stop_on_status$') as caught:
            await run.close()
        await run.close()
        assert [call[0] for call in app.calls] == ['POST', 'POST', 'DELETE']
        report = run.cleanup_report()
        assert report['stop_reason'] == 'stop_on_status'
        assert report['open'][0]['status'] == 'skipped_stopped'
        assert caught.value.cleanup is caught.value.target_cleanup
        assert caught.value.cleanup == report


async def test_stop_during_admitted_setup_resolution_sends_nothing():
    resolving = asyncio.Event()
    resume = asyncio.Event()
    class PausedPolicy(ExecutionPolicy):
        async def endpoint_ip(self, url):
            resolving.set()
            await resume.wait()
            return await super().endpoint_ip(url)
    app = recording_lifecycle()
    async with serve(app) as origin:
        spec = TransportSpecV2.from_dict(lifecycle_dict(origin))
        run = V2Run(spec, policy=PausedPolicy.local(spec))
        task = asyncio.create_task(run.attempt(TransportContext(prompt='normal task')))
        try:
            await asyncio.wait_for(resolving.wait(), 1)
            run.ledger.trip('alert')
            resume.set()
            with pytest.raises(TargetRunStopped, match='^alert$'):
                await task
            await run.close()
            assert app.calls == []
        finally:
            resume.set()
            if not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)


async def test_exchange_retains_only_controlled_response_headers():
    app = RecordingApp()
    async def completed(request):
        return web.json_response({'status': 'COMPLETED', 'result': 'done'}, headers={
            'Location': '/runs/job-1', 'Retry-After': '1', 'X-Unrelated': 'discard',
        })
    app.route('POST', '/run', completed)
    async with serve(app) as origin:
        data = v2_dict(origin + '/run')
        data['budget'] = {'stop_on': {'alert_names': ['X-Configured']}}
        run = runtime(data)
        engine = TransportEngineV2(run.spec, run=run)
        async with httpx.AsyncClient(trust_env=False) as client:
            response = await engine._exchange(client, run.spec.request, {}, b'', time.monotonic(),
                                              run.redactor, {'requests': {'submit': 0}}, phase='submit')
        assert response.headers == {'location': '/runs/job-1', 'retry-after': '1'}
        await run.close()
