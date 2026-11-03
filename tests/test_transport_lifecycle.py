from __future__ import annotations

import asyncio
from dataclasses import replace

import httpx
import pytest
from aiohttp import web

from argus.targets._base import TargetTransportError
from argus.targets.custom_http import CustomHTTPSpec, CustomHTTPTarget
from argus_transport import TransportContext, local_transport_mode
from argus_transport import runtime_v2
from test_transport_v2_engine import completed, runtime, v2_dict
from transport_v2_fakes import RecordingApp, serve


def lifecycle_dict(origin, *, attempt=True):
    data = v2_dict(origin + '/run')
    data['let'] = {'attempt': {'ref': {'literal': 'local-ref'}}}
    source = {
        'id': 'source', 'request': {'method': 'POST', 'url': origin + '/v1/sources', 'body': {'none': True}},
        'expect': {'http_status': [201]}, 'capture': {'source_id': {'path': '$.id'}},
        'undo': {'request': {'method': 'DELETE', 'url': origin + '/v1/sources/{source_id}'}, 'expect': {'http_status': [204, 404]}},
    }
    ingest = {
        'id': 'ingest', 'request': {'method': 'POST', 'url': origin + '/v1/messages', 'body': {'none': True}},
        'expect': {'http_status': [201]},
        'undo': {'request': {'method': 'DELETE', 'url': origin + '/v1/messages', 'query': {'remoteId': {'var': 'ref'}, 'sourceId': {'var': 'source_id'}}}, 'expect': {'http_status': [204, 404]}},
    }
    data['lifecycle'] = {'run': [source], 'attempt': [ingest] if attempt else []}
    return data


def recording_lifecycle(*, undo_status=204, undo_disconnect=False, ingest=None, source=None):
    app = RecordingApp()
    async def created(request):
        return web.json_response({'id': 'source-one'}, status=201)
    async def ingested(request):
        return web.json_response({}, status=201)
    async def undone(request):
        if undo_disconnect:
            request.transport.close()
            return web.Response()
        return web.Response(status=undo_status)
    app.route('POST', '/v1/sources', source or created)
    app.route('POST', '/v1/messages', ingest or ingested)
    app.route('DELETE', '/v1/messages', undone)
    app.route('DELETE', '/v1/sources/{ident}', undone)
    app.route('POST', '/run', completed)
    return app


def deletes(app):
    return [call[1] for call in app.calls if call[0] == 'DELETE']


async def test_request_budget_abort_still_runs_undos():
    app = recording_lifecycle()
    async with serve(app) as origin:
        data = lifecycle_dict(origin)
        data['budget'] = {'max_requests': 3}
        target = CustomHTTPTarget(CustomHTTPSpec(transport=data))
        with local_transport_mode():
            await target.send_prompt('first')
            with pytest.raises(Exception) as caught:
                await target.send_prompt('second')
            assert caught.value.reason == 'request_budget'
            await target.aclose()
        assert deletes(app) == ['/v1/messages?remoteId=local-ref&sourceId=source-one', '/v1/sources/source-one']
        assert target.cleanup_report()['complete'] is True


async def test_total_deadline_interrupts_blocked_poll_then_runs_undos():
    from test_transport_poll import poll_dict
    app = recording_lifecycle()
    async def blocked(request):
        await asyncio.sleep(10)
        return web.json_response({})
    app.route('GET', '/jobs/{ident}', blocked)
    async def accepted(request):
        return web.json_response({'run_id': 'job-one'}, status=202)
    app.route('POST', '/submit', accepted)
    async with serve(app) as origin:
        data = lifecycle_dict(origin)
        polling = poll_dict(origin + '/run')
        data['delivery'] = polling['delivery']
        data['delivery']['request']['url'] = origin + '/jobs/{run_id}'
        data['timeout'] = {'total_deadline_s': .3, 'cleanup_s': .2}
        data['request']['url'] = origin + '/submit'
        target = CustomHTTPTarget(CustomHTTPSpec(transport=data))
        with local_transport_mode():
            with pytest.raises(TimeoutError):
                await asyncio.wait_for(target.send_prompt('normal'), 3)
            assert deletes(app) == ['/v1/messages?remoteId=local-ref&sourceId=source-one']
            await target.aclose()


async def test_cancellation_waits_for_undos_without_background_task():
    submitted = asyncio.Event()
    app = recording_lifecycle()
    async def blocked(request):
        submitted.set()
        await asyncio.sleep(10)
        return web.json_response({})
    app.route('POST', '/submit', blocked)
    async with serve(app) as origin:
        data = lifecycle_dict(origin)
        data['request']['url'] = origin + '/submit'
        target = CustomHTTPTarget(CustomHTTPSpec(transport=data))
        with local_transport_mode():
            task = asyncio.create_task(target.send_prompt('normal'))
            await asyncio.wait_for(submitted.wait(), 1)
            task.cancel()
            with pytest.raises(asyncio.CancelledError) as caught:
                await task
            assert deletes(app) == ['/v1/messages?remoteId=local-ref&sourceId=source-one']
            assert caught.value.transport_diagnostics['cleanup']['complete']
            assert task.done()
            await target.aclose()
    assert asyncio.all_tasks() == {asyncio.current_task()}


async def test_run_log_mapping_error_preserves_failed_attempt_cleanup():
    app = recording_lifecycle(undo_status=500)

    async def invalid_run_log(request):
        return web.json_response({
            'status': 'COMPLETED', 'result': 'done', 'run_log': {'events': 7},
        })

    app.route('POST', '/submit', invalid_run_log)
    async with serve(app) as origin:
        data = lifecycle_dict(origin)
        data['request']['url'] = origin + '/submit'
        data['response']['metadata'] = {'run_log': {'path': '$.run_log'}}
        target = CustomHTTPTarget(CustomHTTPSpec(transport=data))
        with local_transport_mode():
            try:
                with pytest.raises(TargetTransportError, match='mapping_error'):
                    await target.send_prompt('normal')
                assert deletes(app) == ['/v1/messages?remoteId=local-ref&sourceId=source-one']
                assert target.cleanup_report()['complete'] is False
                transport = (await target.collect_evidence())['transport']
                assert transport['reason_code'] == 'mapping_error'
                assert transport['outcome'] == 'target_error'
                assert transport['http_status'] == 200
                assert transport['cleanup']['complete'] is False
                assert [(item['scope'], item['step'], item['status'], item['http_status'])
                        for item in transport['cleanup']['open']] == [('attempt', 'ingest', 'failed', 500)]
            finally:
                await target.aclose()


@pytest.mark.parametrize('undo_status,disconnect', [(500, False), (204, True)])
async def test_undo_failures_remain_visible(undo_status, disconnect):
    app = recording_lifecycle(undo_status=undo_status, undo_disconnect=disconnect)
    async with serve(app) as origin:
        run = runtime(lifecycle_dict(origin, attempt=False))
        await run.attempt(TransportContext(prompt='normal'))
        await run.close()
        report = run.cleanup_report()
        assert report['open'][0]['status'] == 'failed'
        assert report['complete'] is False


async def test_cleanup_timeout_cannot_claim_complete():
    app = RecordingApp()
    async def created(request):
        return web.json_response({'id': 'one'}, status=201)
    async def blocked(request):
        await asyncio.sleep(5)
        return web.Response(status=204)
    app.route('POST', '/v1/sources', created)
    app.route('DELETE', '/v1/sources/{ident}', blocked)
    app.route('POST', '/run', completed)
    async with serve(app) as origin:
        data = lifecycle_dict(origin, attempt=False)
        data['timeout'] = {'cleanup_s': .05}
        run = runtime(data)
        await run.attempt(TransportContext(prompt='normal'))
        await asyncio.wait_for(run.close(), 1)
        assert run.cleanup_report()['complete'] is False


async def test_cleanup_timeout_reports_pending_and_cancels_undo():
    app = RecordingApp()
    entered = asyncio.Event()
    async def created(request):
        return web.json_response({}, status=201)
    async def blocked(request):
        entered.set()
        await asyncio.sleep(5)
        return web.Response(status=204)
    app.route('POST', '/objects/{ident}', created)
    app.route('DELETE', '/objects/{ident}', blocked)
    app.route('POST', '/run', completed)
    async with serve(app) as origin:
        data = v2_dict(origin + '/run')
        data['timeout'] = {'cleanup_s': .05}
        data['lifecycle'] = {'run': [
            {'id': ident, 'request': {'method': 'POST', 'url': origin + '/objects/' + ident, 'body': {'none': True}}, 'expect': {'http_status': [201]}, 'undo': {'request': {'method': 'DELETE', 'url': origin + '/objects/' + ident}, 'expect': {'http_status': [204]}}}
            for ident in ('a', 'b')
        ]}
        run = runtime(data)
        await run.attempt(TransportContext(prompt='normal'))
        await run.close()
        assert entered.is_set()
        assert [(item['step'], item['status']) for item in run.cleanup_report()['open']] == [('a', 'failed'), ('b', 'failed')]
        assert deletes(app) == ['/objects/b']
        assert run.cleanup_report()['done'] == 0
    assert asyncio.all_tasks() == {asyncio.current_task()}


async def test_intent_registered_before_create_survives_lost_response():
    async def lost(request):
        request.transport.close()
        return web.Response()
    app = recording_lifecycle(ingest=lost)
    async with serve(app) as origin:
        run = runtime(lifecycle_dict(origin))
        result = await run.attempt(TransportContext(prompt='normal'))
        assert result.outcome.value == 'target_error'
        assert deletes(app) == ['/v1/messages?remoteId=local-ref&sourceId=source-one']
        await run.close()


async def test_unbound_undo_is_reported_not_guessed():
    async def missing(request):
        return web.json_response({}, status=201)
    app = recording_lifecycle(source=missing)
    async with serve(app) as origin:
        run = runtime(lifecycle_dict(origin))
        with pytest.raises(Exception) as caught:
            await run.attempt(TransportContext(prompt='normal'))
        assert caught.value.reason == 'setup_failed_run'
        await run.close()
        assert run.cleanup_report()['open'][0]['status'] == 'unbound'
        assert deletes(app) == []


async def test_cleanup_gate_rejects_non_read_delete_methods():
    app = recording_lifecycle()
    async with serve(app) as origin:
        run = runtime(lifecycle_dict(origin, attempt=False))
        await run.attempt(TransportContext(prompt='normal'))
        intent = run.run_undos.intents[0]
        intent.spec = replace(intent.spec, request=replace(intent.spec.request, method='POST'))
        await run.close()
        assert deletes(app) == []
        assert run.cleanup_report()['open'][0]['status'] == 'failed'
        assert [call[0] for call in app.calls] == ['POST', 'POST']


async def test_undo_404_counts_as_done():
    app = recording_lifecycle(undo_status=404)
    async with serve(app) as origin:
        run = runtime(lifecycle_dict(origin))
        await run.attempt(TransportContext(prompt='normal'))
        await run.close()
        assert run.cleanup_report() == {'complete': True, 'done': 2, 'open': [], 'stop_reason': None}
        await run.close()
        assert len(deletes(app)) == 2


async def test_outer_undo_blocked_while_inner_dependent_pending():
    app = recording_lifecycle(undo_status=500)
    async with serve(app) as origin:
        run = runtime(lifecycle_dict(origin))
        await run.attempt(TransportContext(prompt='normal'))
        await run.close()
        assert deletes(app) == ['/v1/messages?remoteId=local-ref&sourceId=source-one']
        assert run.cleanup_report()['open'][0]['status'] == 'blocked_by_inner'


async def test_if_present_skips_step_and_its_undo(monkeypatch):
    monkeypatch.delenv('OPTIONAL_MATERIAL', raising=False)
    app = recording_lifecycle()
    async with serve(app) as origin:
        data = lifecycle_dict(origin)
        data['let']['run'] = {'material_ref': {'env': 'OPTIONAL_MATERIAL', 'missing': 'omit'}}
        data['lifecycle']['attempt'][0]['if_present'] = 'material_ref'
        run = runtime(data)
        result = await run.attempt(TransportContext(prompt='normal'))
        assert result.response_text == 'done'
        await run.close()
        assert not any('/v1/messages' in call[1] for call in app.calls)


async def test_teardown_failure_keeps_primary_result():
    app = recording_lifecycle(undo_status=500)
    async with serve(app) as origin:
        target = CustomHTTPTarget(CustomHTTPSpec(transport=lifecycle_dict(origin)))
        with local_transport_mode():
            assert (await target.send_prompt('normal'))[0] == 'done'
            assert (await target.collect_evidence())['transport']['cleanup']['open'][0]['status'] == 'failed'
            await target.aclose()


async def test_request_counts_add_keys_only_when_configured():
    app = recording_lifecycle()
    async with serve(app) as origin:
        plain = await runtime(v2_dict(origin + '/run')).attempt(TransportContext(prompt='normal'))
        assert plain.diagnostics['requests'] == {'submit': 1, 'poll': 0, 'retry': 0}
        run = runtime(lifecycle_dict(origin))
        result = await run.attempt(TransportContext(prompt='normal'))
        assert result.diagnostics['requests'] == {'submit': 1, 'poll': 0, 'retry': 0, 'setup': 1, 'cleanup': 1}
        await run.close()


async def test_max_requests_spans_probes():
    app = recording_lifecycle()
    async with serve(app) as origin:
        data = v2_dict(origin + '/run')
        data['budget'] = {'max_requests': 2}
        target = CustomHTTPTarget(CustomHTTPSpec(transport=data))
        with local_transport_mode():
            for _ in range(2):
                await target.begin_probe(None)
                await target.send_prompt('normal')
            await target.begin_probe(None)
            with pytest.raises(Exception) as caught:
                await target.send_prompt('normal')
            assert caught.value.reason == 'request_budget'
            assert len(app.calls) == 2
            await target.aclose()


async def test_cleanup_reserve_is_reserved_before_create():
    app = recording_lifecycle()
    async with serve(app) as origin:
        data = lifecycle_dict(origin, attempt=False)
        second = dict(data['lifecycle']['run'][0])
        second['id'] = 'other'
        second.pop('capture')
        data['lifecycle']['run'].append(second)
        data['budget'] = {'cleanup_reserve': 1}
        run = runtime(data)
        with pytest.raises(Exception) as caught:
            await run.attempt(TransportContext(prompt='normal'))
        assert caught.value.reason == 'cleanup_reserve'
        await run.close()
        assert [call[0] for call in app.calls] == ['POST', 'DELETE']
        assert run.cleanup_report()['done'] == 1
        assert run.ledger.counts['setup'] == 1


async def test_attempt_setup_failure_errors_one_probe():
    count = 0
    async def ingestion(request):
        nonlocal count
        count += 1
        return web.json_response({}, status=400 if count == 1 else 201)
    app = recording_lifecycle(ingest=ingestion)
    async with serve(app) as origin:
        target = CustomHTTPTarget(CustomHTTPSpec(transport=lifecycle_dict(origin)))
        with local_transport_mode():
            with pytest.raises(TargetTransportError, match='target_error: setup_failed'):
                await target.send_prompt('first')
            assert (await target.send_prompt('second'))[0] == 'done'
            await target.aclose()
        assert len(deletes(app)) == 3


def test_stop_exception_has_no_status_code():
    from argus.runner import _send_failure
    exc = runtime_v2.TargetRunStopped('request_budget')
    assert not hasattr(exc, 'status_code')
    assert _send_failure(exc) is None
    assert not isinstance(exc, (ValueError, OSError, httpx.HTTPError))
    assert str(exc) == 'request_budget'
    assert exc.checklist == ()


async def test_second_cancel_during_undo_marks_remaining_failed():
    entered = asyncio.Event()
    app = RecordingApp()
    async def created(request):
        return web.json_response({}, status=201)
    async def blocked(request):
        entered.set()
        await asyncio.sleep(10)
        return web.Response(status=204)
    app.route('POST', '/objects/{ident}', created)
    app.route('DELETE', '/objects/{ident}', blocked)
    app.route('POST', '/run', completed)
    async with serve(app) as origin:
        data = v2_dict(origin + '/run')
        data['lifecycle'] = {'run': [
            {'id': ident, 'request': {'method': 'POST', 'url': origin + '/objects/' + ident, 'body': {'none': True}}, 'expect': {'http_status': [201]}, 'undo': {'request': {'method': 'DELETE', 'url': origin + '/objects/' + ident}, 'expect': {'http_status': [204]}}}
            for ident in ('a', 'b')
        ]}
        run = runtime(data)
        await run.attempt(TransportContext(prompt='normal'))
        async def cancelled_owner():
            try:
                await asyncio.sleep(10)
            finally:
                await run.close()
        task = asyncio.create_task(cancelled_owner())
        await asyncio.sleep(0)
        task.cancel()
        await asyncio.wait_for(entered.wait(), 1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 1)
        assert [item['status'] for item in run.cleanup_report()['open']] == ['failed', 'failed']
    assert asyncio.all_tasks() == {asyncio.current_task()}


async def test_second_cancel_during_attempt_undo_attaches_failed_cleanup():
    submitted = asyncio.Event()
    deleting = asyncio.Event()
    app = RecordingApp()
    async def created(request):
        return web.json_response({}, status=201)
    async def blocked_submit(request):
        submitted.set()
        await asyncio.sleep(10)
        return web.json_response({})
    async def blocked_undo(request):
        deleting.set()
        await asyncio.sleep(10)
        return web.Response(status=204)
    app.route('POST', '/objects/{ident}', created)
    app.route('DELETE', '/objects/{ident}', blocked_undo)
    app.route('POST', '/run', blocked_submit)
    async with serve(app) as origin:
        from test_transport_v2_engine import v2_dict
        data = v2_dict(origin + '/run')
        data['lifecycle'] = {'attempt': [
            {'id': ident, 'request': {'method': 'POST', 'url': origin + '/objects/' + ident, 'body': {'none': True}}, 'expect': {'http_status': [201]}, 'undo': {'request': {'method': 'DELETE', 'url': origin + '/objects/' + ident}, 'expect': {'http_status': [204]}}}
            for ident in ('a', 'b')
        ]}
        run = runtime(data)
        task = asyncio.create_task(run.attempt(TransportContext(prompt='normal')))
        await asyncio.wait_for(submitted.wait(), 1)
        task.cancel()
        await asyncio.wait_for(deleting.wait(), 1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError) as caught:
            await asyncio.wait_for(task, 1)
        assert [item['status'] for item in caught.value.transport_diagnostics['cleanup']['open']] == ['failed', 'failed']
        assert deletes(app) == ['/objects/b']
        await run.close()
    assert asyncio.all_tasks() == {asyncio.current_task()}
