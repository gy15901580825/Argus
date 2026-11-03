from datetime import datetime, timezone
from email.utils import format_datetime

import pytest
from aiohttp import web

from argus_transport import ExecutionPolicy, TransportContext
from argus_transport.runtime_v2 import TargetRunStopped, V2Run
from argus_transport.spec_v2 import TransportSpecV2
from test_transport_poll import poll_dict
from transport_v2_fakes import RecordingApp, serve


def poll_spec(url, *, explicit=True):
    data = poll_dict(url)
    data['version'] = 2
    if explicit:
        data['delivery']['ids'] = {'run_id': data['delivery'].pop('run_id')}
    return data


def runtime(data, **kwargs):
    spec = TransportSpecV2.from_dict(data)
    return V2Run(spec, policy=ExecutionPolicy.local(spec), **kwargs)


def responses(submit=None, polls=None, *, submit_headers=None, poll_headers=None,
              submit_status=202, poll_status=200):
    app = RecordingApp()
    submit = {'run_id': 'job-1', 'status': 'PENDING'} if submit is None else submit
    polls = [{'status': 'COMPLETED', 'result': 'done'}] if polls is None else polls
    index = 0

    async def submitted(request):
        return web.json_response(submit, status=submit_status, headers=submit_headers)

    async def polled(request):
        nonlocal index
        body = polls[min(index, len(polls) - 1)]
        index += 1
        return web.json_response(body, status=poll_status, headers=poll_headers)

    app.route('POST', '/run', submitted)
    app.route('GET', '/runs/{tail:.*}', polled)
    return app


def wait_spec(data, default=1, maximum=5):
    data['delivery'].pop('interval_s')
    data['delivery']['wait'] = {'from': 'Retry-After', 'default_s': default, 'max_s': maximum}
    return data


def test_ids_and_run_id_together_are_rejected():
    data = poll_spec('http://127.0.0.1/run')
    data['delivery']['run_id'] = {'path': '$.run_id'}
    with pytest.raises(ValueError):
        TransportSpecV2.from_dict(data)


def test_wait_and_interval_are_exclusive():
    data = poll_spec('http://127.0.0.1/run', explicit=False)
    data['delivery']['wait'] = {'from': 'Retry-After', 'default_s': 1, 'max_s': 5}
    with pytest.raises(ValueError):
        TransportSpecV2.from_dict(data)


def test_location_follow_is_rejected_for_now():
    data = poll_spec('http://127.0.0.1/run', explicit=False)
    data['delivery']['location'] = 'follow'
    with pytest.raises(ValueError, match='location follow is not supported yet'):
        TransportSpecV2.from_dict(data)


@pytest.mark.parametrize('ids', [{}, {f'job{i}': {'path': '$.id'} for i in range(5)},
                              {'prompt': {'path': '$.id'}}, {'access_key': {'path': '$.id'}}])
def test_invalid_delivery_id_declarations_are_rejected(ids):
    data = poll_spec('http://127.0.0.1/run')
    data['delivery']['ids'] = ids
    with pytest.raises(ValueError):
        TransportSpecV2.from_dict(data)


@pytest.mark.parametrize('url', ['/runs/job', '/runs/{run_id}/{run_id}'])
def test_every_delivery_id_requires_one_placeholder(url):
    data = poll_spec('http://127.0.0.1/run')
    data['delivery']['request']['url'] = 'http://127.0.0.1' + url
    with pytest.raises(ValueError):
        TransportSpecV2.from_dict(data)


@pytest.mark.parametrize('field,value', [('last_segment', 1), ('expect_prefix', {'var': 'run_id'})])
def test_delivery_transform_validation_uses_submit_scope(field, value):
    data = poll_spec('http://127.0.0.1/run')
    data['delivery']['ids']['run_id'][field] = value
    with pytest.raises(ValueError):
        TransportSpecV2.from_dict(data)


def test_delivery_roundtrip_preserves_ids_wait_and_location():
    data = wait_spec(poll_spec('http://127.0.0.1/run'))
    data['delivery']['ids']['run_id'].update(last_segment=True, expect_prefix={'env': 'SOURCE_REF'})
    data['delivery']['location'] = 'verify'
    spec = TransportSpecV2.from_dict(data)
    serialized = spec.to_dict()
    assert serialized['delivery']['ids'] == data['delivery']['ids']
    assert serialized['delivery']['wait'] == data['delivery']['wait']
    assert serialized['delivery']['location'] == 'verify'
    assert 'run_id' not in serialized['delivery']
    assert 'interval_s' not in serialized['delivery']
    assert TransportSpecV2.from_dict(serialized) == spec


async def test_two_ids_encoded_as_separate_segments():
    app = responses({'group': 'a/b', 'job': '.', 'status': 'PENDING'})
    async with serve(app) as origin:
        data = poll_spec(origin + '/run')
        data['delivery']['ids'] = {'group': {'path': '$.group'}, 'job': {'path': '$.job'}}
        data['delivery']['request']['url'] = origin + '/runs/{group}/{job}'
        result = await runtime(data).attempt(TransportContext(prompt='normal task'))
        assert result.response_text == 'done'
        assert 'run_id' not in result.metadata
        assert [call[1] for call in app.calls] == ['/run', '/runs/a%2Fb/%2E']


async def test_missing_one_id_sends_no_poll():
    app = responses({'group': 'a', 'status': 'PENDING'})
    async with serve(app) as origin:
        data = poll_spec(origin + '/run')
        data['delivery']['ids'] = {'group': {'path': '$.group'}, 'job': {'path': '$.job'}}
        data['delivery']['request']['url'] = origin + '/runs/{group}/{job}'
        result = await runtime(data).attempt(TransportContext(prompt='normal task'))
        assert result.reason_code.value == 'missing_id'
        assert [call[0] for call in app.calls] == ['POST']


async def test_poll_identity_change_is_target_error():
    app = responses(polls=[{'run_id': 'job-2', 'status': 'COMPLETED', 'result': 'done'}])
    async with serve(app) as origin:
        run = runtime(poll_spec(origin + '/run'))
        for _ in range(2):
            result = await run.attempt(TransportContext(prompt='normal task'))
            assert result.reason_code.value == 'poll_identity_changed'
            assert result.outcome.value == 'target_error'
        assert [call[0] for call in app.calls] == ['POST', 'GET'] * 2


async def test_run_id_sugar_behaves_like_ids_run_id():
    app = responses()
    async with serve(app) as origin:
        results, sequences = [], []
        for explicit in (False, True):
            results.append(await runtime(poll_spec(origin + '/run', explicit=explicit)).attempt(
                TransportContext(prompt='normal task')))
            sequences.append([(call[0], call[1]) for call in app.calls])
            app.calls.clear()
        assert sequences[0] == sequences[1] == [('POST', '/run'), ('GET', '/runs/job-1')]
        assert results[0].metadata == results[1].metadata == {'run_id': 'job-1'}


@pytest.mark.parametrize('date', [False, True])
async def test_retry_after_seconds_and_http_date_set_the_wait(monkeypatch, date):
    import argus_transport.engine_v2 as engine
    now = 1800000000
    monkeypatch.setattr(engine.time, 'time', lambda: now)
    value = format_datetime(datetime.fromtimestamp(now + 2, timezone.utc), usegmt=True) if date else '2'
    sleeps = []
    async def sleep(delay):
        sleeps.append(delay)
    monkeypatch.setattr(engine.asyncio, 'sleep', sleep)
    app = responses(submit_headers={'Retry-After': value})
    async with serve(app) as origin:
        result = await runtime(wait_spec(poll_spec(origin + '/run'))).attempt(TransportContext(prompt='normal task'))
        assert result.response_text == 'done'
        assert sleeps == [2]


@pytest.mark.parametrize('value', [None, 'invalid', '-2', 'nan', 'inf'])
async def test_retry_after_missing_uses_default(monkeypatch, value):
    import argus_transport.engine_v2 as engine
    sleeps = []
    async def sleep(delay):
        sleeps.append(delay)
    monkeypatch.setattr(engine.asyncio, 'sleep', sleep)
    app = responses(submit_headers={} if value is None else {'Retry-After': value})
    async with serve(app) as origin:
        result = await runtime(wait_spec(poll_spec(origin + '/run'), default=0.25)).attempt(TransportContext(prompt='normal task'))
        assert result.response_text == 'done'
        assert sleeps == [0.25]


@pytest.mark.parametrize('on_submit', [False, True])
async def test_retry_after_above_cap_fails_without_polling(monkeypatch, on_submit):
    import argus_transport.engine_v2 as engine
    sleeps = []
    async def sleep(delay):
        sleeps.append(delay)
    monkeypatch.setattr(engine.asyncio, 'sleep', sleep)
    app = responses(polls=[{'status': 'RUNNING'}],
                    submit_headers={'Retry-After': '6' if on_submit else '0'},
                    poll_headers={'Retry-After': '6'})
    async with serve(app) as origin:
        result = await runtime(wait_spec(poll_spec(origin + '/run'))).attempt(TransportContext(prompt='normal task'))
        assert result.reason_code.value == 'poll_wait_limit'
        assert len(app.calls) == (1 if on_submit else 2)
        assert not any(delay > 0 for delay in sleeps)


async def test_wait_past_deadline_times_out_without_sleeping(monkeypatch):
    import argus_transport.engine_v2 as engine
    sleeps = []
    async def sleep(delay):
        sleeps.append(delay)
    monkeypatch.setattr(engine.asyncio, 'sleep', sleep)
    app = responses(submit_headers={'Retry-After': '2'})
    async with serve(app) as origin:
        data = wait_spec(poll_spec(origin + '/run'))
        data['timeout']['total_deadline_s'] = 1
        result = await runtime(data).attempt(TransportContext(prompt='normal task'))
        assert result.outcome.value == 'timed_out'
        assert sleeps == []
        assert len(app.calls) == 1


@pytest.mark.parametrize('location', ['/runs/job-1', 'runs/job-1'])
async def test_location_verify_accepts_exact_template_url(location):
    app = responses(submit_headers={'Location': location}, poll_headers={'Location': '/runs/job-1'}, poll_status=202)
    async with serve(app) as origin:
        data = poll_spec(origin + '/run')
        data['delivery']['location'] = 'verify'
        for rule in data['outcome']['rules']:
            rule['http_status'].append(202)
        result = await runtime(data).attempt(TransportContext(prompt='normal task'))
        assert result.response_text == 'done'
        assert len(app.calls) == 2


async def test_location_missing_is_attempt_error():
    app = responses()
    async with serve(app) as origin:
        data = poll_spec(origin + '/run')
        data['delivery']['location'] = 'verify'
        run = runtime(data)
        for _ in range(2):
            result = await run.attempt(TransportContext(prompt='normal task'))
            assert result.reason_code.value == 'location_missing'
        assert [call[0] for call in app.calls] == ['POST', 'POST']


@pytest.mark.parametrize('location', ['http://127.0.0.1:1/runs/job-1', '/runs/other',
                                     '/runs/job-1?ref=1', '/runs/job-1#part',
                                     'http://person@127.0.0.1/runs/job-1'])
async def test_unsafe_location_stops_business_and_skips_undo(location):
    app = responses(submit_headers={'Location': location})
    async def created(request):
        return web.json_response({'ref': 'obj-1'}, status=201)
    async def deleted(request):
        return web.Response(status=204)
    app.route('POST', '/objects', created)
    app.route('DELETE', '/objects/{ref}', deleted)
    async with serve(app) as origin:
        data = poll_spec(origin + '/run')
        data['delivery']['location'] = 'verify'
        data['lifecycle'] = {scope: [{
            'id': 'make_' + scope,
            'request': {'url': origin + '/objects', 'body': {'json': {}}},
            'expect': {'http_status': [201]},
            'capture': {scope + '_ref': {'path': '$.ref'}},
            'undo': {'request': {'method': 'DELETE', 'url': origin + '/objects/{' + scope + '_ref}'},
                     'expect': {'http_status': [204]}},
        }] for scope in ('run', 'attempt')}
        run = runtime(data)
        with pytest.raises(TargetRunStopped) as caught:
            await run.attempt(TransportContext(prompt='normal task'))
        assert caught.value.reason == 'unsafe_location'
        with pytest.raises(TargetRunStopped):
            await run.attempt(TransportContext(prompt='next task'))
        await run.close()
        assert [(call[0], call[1]) for call in app.calls] == [('POST', '/objects'), ('POST', '/objects'), ('POST', '/run')]
        report = run.cleanup_report()
        assert {item['status'] for item in report['open']} == {'skipped_stopped'}
        assert report['stop_reason'] == 'unsafe_location'


async def test_429_is_never_retried():
    app = responses(submit_status=429, submit_headers={'Retry-After': '0'})
    async with serve(app) as origin:
        result = await runtime(wait_spec(poll_spec(origin + '/run'))).attempt(TransportContext(prompt='normal task'))
        assert result.reason_code.value == 'http_error'
        assert [call[0] for call in app.calls] == ['POST']


@pytest.mark.parametrize('location,reason', [(None, 'location_missing'), ('/runs/other', 'unsafe_location')])
async def test_terminal_submit_202_still_verifies_location(location, reason):
    app = responses({'run_id': 'job-1', 'status': 'COMPLETED', 'result': 'done'},
                    submit_headers={} if location is None else {'Location': location})
    async with serve(app) as origin:
        data = poll_spec(origin + '/run')
        data['delivery']['location'] = 'verify'
        run = runtime(data)
        if reason == 'unsafe_location':
            with pytest.raises(TargetRunStopped) as caught:
                await run.attempt(TransportContext(prompt='normal task'))
            assert caught.value.reason == reason
        else:
            result = await run.attempt(TransportContext(prompt='normal task'))
            assert result.reason_code.value == reason
        assert [call[0] for call in app.calls] == ['POST']


async def test_unsafe_poll_202_stops_before_later_poll():
    app = responses(polls=[{'status': 'RUNNING'}], submit_headers={'Location': '/runs/job-1'},
                    poll_headers={'Location': '/runs/other'}, poll_status=202)
    async with serve(app) as origin:
        data = poll_spec(origin + '/run')
        data['delivery']['location'] = 'verify'
        with pytest.raises(TargetRunStopped) as caught:
            await runtime(data).attempt(TransportContext(prompt='normal task'))
        assert caught.value.reason == 'unsafe_location'
        assert [call[0] for call in app.calls] == ['POST', 'GET']


def invalid_delivery_response(phase, body_kind, location):
    app = RecordingApp()
    headers = {} if location is None else {'Location': location}
    body = b'{' if body_kind == 'malformed' else b'x' * 257
    if body_kind == 'encoded':
        headers['Content-Encoding'] = 'gzip'
    if body_kind == 'missing_id':
        body = b'{"status":"PENDING"}'

    async def invalid(request):
        return web.Response(body=body, status=202, headers=headers)

    async def submitted(request):
        return web.json_response({'run_id': 'job-1', 'status': 'PENDING'}, status=202,
                                 headers={'Location': '/runs/job-1'})

    async def created(request):
        return web.json_response({'ref': 'obj-1'}, status=201)

    async def deleted(request):
        return web.Response(status=204)

    app.route('POST', '/run', invalid if phase == 'submit' else submitted)
    app.route('GET', '/runs/{tail:.*}', invalid)
    app.route('POST', '/objects', created)
    app.route('DELETE', '/objects/{ref}', deleted)
    return app


def with_attempt_undo(data, origin):
    data['lifecycle'] = {'attempt': [{
        'id': 'make_object',
        'request': {'url': origin + '/objects', 'body': {'json': {}}},
        'expect': {'http_status': [201]},
        'capture': {'object_ref': {'path': '$.ref'}},
        'undo': {'request': {'method': 'DELETE', 'url': origin + '/objects/{object_ref}'},
                 'expect': {'http_status': [204]}},
    }]}
    return data


@pytest.mark.parametrize('phase', ['submit', 'poll'])
@pytest.mark.parametrize('body_kind', ['malformed', 'encoded', 'oversized'])
@pytest.mark.parametrize('location', ['http://127.0.0.1:1/runs/job-1',
                                     '/runs/job-1?ref=1', '/runs/job-1#part',
                                     'http://person@127.0.0.1/runs/job-1'])
async def test_unsafe_202_location_stops_before_body_failure(phase, body_kind, location):
    app = invalid_delivery_response(phase, body_kind, location)
    async with serve(app) as origin:
        data = with_attempt_undo(poll_spec(origin + '/run'), origin)
        data['delivery']['location'] = 'verify'
        data['limits']['response_bytes'] = 256
        run = runtime(data)
        with pytest.raises(TargetRunStopped) as caught:
            await run.attempt(TransportContext(prompt='normal task'))
        assert caught.value.reason == 'unsafe_location'
        with pytest.raises(TargetRunStopped) as later:
            await run.attempt(TransportContext(prompt='next task'))
        assert later.value.reason == 'unsafe_location'
        await run.close()
        expected = [('POST', '/objects'), ('POST', '/run')]
        if phase == 'poll':
            expected.append(('GET', '/runs/job-1'))
        assert [(call[0], call[1]) for call in app.calls] == expected
        report = run.cleanup_report()
        assert {item['status'] for item in report['open']} == {'skipped_stopped'}
        assert report['stop_reason'] == 'unsafe_location'


@pytest.mark.parametrize('body_kind', ['malformed', 'encoded', 'oversized'])
async def test_unsafe_poll_path_stops_before_body_failure(body_kind):
    app = invalid_delivery_response('poll', body_kind, '/runs/other')
    async with serve(app) as origin:
        data = poll_spec(origin + '/run')
        data['delivery']['location'] = 'verify'
        data['limits']['response_bytes'] = 256
        run = runtime(data)
        with pytest.raises(TargetRunStopped) as caught:
            await run.attempt(TransportContext(prompt='normal task'))
        assert caught.value.reason == 'unsafe_location'
        with pytest.raises(TargetRunStopped):
            await run.attempt(TransportContext(prompt='next task'))
        await run.close()
        assert [(call[0], call[1]) for call in app.calls] == [('POST', '/run'), ('GET', '/runs/job-1')]


@pytest.mark.parametrize('phase', ['submit', 'poll'])
@pytest.mark.parametrize('body_kind', ['malformed', 'encoded', 'oversized'])
async def test_missing_202_location_precedes_body_failure_without_stopping(phase, body_kind):
    app = invalid_delivery_response(phase, body_kind, None)
    async with serve(app) as origin:
        data = with_attempt_undo(poll_spec(origin + '/run'), origin)
        data['delivery']['location'] = 'verify'
        data['limits']['response_bytes'] = 256
        run = runtime(data)
        for _ in range(2):
            result = await run.attempt(TransportContext(prompt='normal task'))
            assert result.reason_code.value == 'location_missing'
        await run.close()
        expected = [('POST', '/objects'), ('POST', '/run')]
        if phase == 'poll':
            expected.append(('GET', '/runs/job-1'))
        expected.append(('DELETE', '/objects/obj-1'))
        assert [(call[0], call[1]) for call in app.calls] == expected * 2


@pytest.mark.parametrize('location', ['http://127.0.0.1:1/runs/job-1',
                                     '/runs/job-1?ref=1', '/runs/job-1#part',
                                     'http://person@127.0.0.1/runs/job-1'])
async def test_unsafe_submit_location_stops_before_missing_id(location):
    app = invalid_delivery_response('submit', 'missing_id', location)
    async with serve(app) as origin:
        data = with_attempt_undo(poll_spec(origin + '/run'), origin)
        data['delivery']['location'] = 'verify'
        run = runtime(data)
        with pytest.raises(TargetRunStopped) as caught:
            await run.attempt(TransportContext(prompt='normal task'))
        assert caught.value.reason == 'unsafe_location'
        with pytest.raises(TargetRunStopped):
            await run.attempt(TransportContext(prompt='next task'))
        await run.close()
        assert [(call[0], call[1]) for call in app.calls] == [('POST', '/objects'), ('POST', '/run')]
        assert {item['status'] for item in run.cleanup_report()['open']} == {'skipped_stopped'}


@pytest.mark.parametrize('phase', ['submit', 'poll'])
@pytest.mark.parametrize('body_kind,reason', [('malformed', 'parse_error'), ('encoded', 'parse_error'),
                                             ('oversized', 'response_limit')])
async def test_safe_202_location_preserves_body_failure(phase, body_kind, reason):
    app = invalid_delivery_response(phase, body_kind, '/runs/job-1')
    async with serve(app) as origin:
        data = poll_spec(origin + '/run')
        data['delivery']['location'] = 'verify'
        data['limits']['response_bytes'] = 256
        run = runtime(data)
        for _ in range(2):
            result = await run.attempt(TransportContext(prompt='normal task'))
            assert result.reason_code.value == reason
        await run.close()
        assert [call[0] for call in app.calls] == (['POST'] if phase == 'submit' else ['POST', 'GET']) * 2


@pytest.mark.parametrize('body_kind,reason', [('malformed', 'parse_error'), ('missing_id', 'missing_id')])
async def test_submit_location_path_remains_unverified_without_ids(body_kind, reason):
    app = invalid_delivery_response('submit', body_kind, '/runs/other')
    async with serve(app) as origin:
        data = poll_spec(origin + '/run')
        data['delivery']['location'] = 'verify'
        run = runtime(data)
        for _ in range(2):
            result = await run.attempt(TransportContext(prompt='normal task'))
            assert result.reason_code.value == reason
        await run.close()
        assert [call[0] for call in app.calls] == ['POST', 'POST']


@pytest.mark.parametrize('wait', [None, {}, {'from': 'Other', 'default_s': 1, 'max_s': 2},
                                {'from': 'Retry-After', 'default_s': True, 'max_s': 2}])
def test_invalid_wait_configuration_is_rejected(wait):
    data = wait_spec(poll_spec('http://127.0.0.1/run'))
    data['delivery']['wait'] = wait
    with pytest.raises(ValueError):
        TransportSpecV2.from_dict(data)


async def test_default_wait_above_cap_fails_without_polling():
    app = responses()
    async with serve(app) as origin:
        result = await runtime(wait_spec(poll_spec(origin + '/run'), default=3, maximum=2)).attempt(
            TransportContext(prompt='normal task'))
        assert result.reason_code.value == 'poll_wait_limit'
        assert [call[0] for call in app.calls] == ['POST']
