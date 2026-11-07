import pytest

from argus_transport import TransportContext
from test_transport_v2_poll import poll_spec, responses, runtime
from transport_v2_fakes import serve


def transformed(data, *, prefix='organizations/o1/runs/', last_segment=True):
    selector = data['delivery']['ids']['run_id']
    if last_segment:
        selector['last_segment'] = True
    if prefix is not None:
        selector['expect_prefix'] = {'literal': prefix}
    return data


async def test_ids_full_resource_name_polls_last_segment():
    prefix = 'organizations/o1/workspaces/' + 'w' * 130 + '/runs/'
    app = responses({'run_id': prefix + 'job--1.pdf', 'status': 'PENDING'},
                    polls=[{'run_id': prefix + 'job--1.pdf', 'status': 'COMPLETED', 'result': 'done'}])
    async with serve(app) as origin:
        result = await runtime(transformed(poll_spec(origin + '/run'), prefix=prefix)).attempt(TransportContext(prompt='normal task'))
        assert result.response_text == 'done'
        assert result.metadata['run_id'] == 'job--1.pdf'
        assert [call[1] for call in app.calls] == ['/run', '/runs/job--1.pdf']


async def test_ids_prefix_mismatch_rejects_without_poll():
    app = responses({'run_id': 'organizations/o2/runs/job-1', 'status': 'PENDING'})
    async with serve(app) as origin:
        run = runtime(transformed(poll_spec(origin + '/run')))
        for _ in range(2):
            result = await run.attempt(TransportContext(prompt='normal task'))
            assert result.reason_code.value == 'id_prefix_mismatch'
        assert [call[0] for call in app.calls] == ['POST', 'POST']


@pytest.mark.parametrize('value', ['organizations/o1/runs/', 'organizations/o1/runs/a b',
                                 'organizations/o1/runs/a%2Fb', 'organizations/o1/runs/' + 'a' * 257,
                                 123, True, None])
async def test_ids_last_segment_rejects_unsafe_characters(value):
    app = responses({'run_id': value, 'status': 'PENDING'})
    async with serve(app) as origin:
        result = await runtime(transformed(poll_spec(origin + '/run'))).attempt(TransportContext(prompt='normal task'))
        assert result.reason_code.value == 'id_prefix_mismatch'
        assert len(app.calls) == 1


async def test_prefix_only_keeps_full_delivery_id():
    value = 'organizations/o1/runs/' + 'x' * 300
    app = responses({'run_id': value, 'status': 'PENDING'})
    async with serve(app) as origin:
        result = await runtime(transformed(poll_spec(origin + '/run'), last_segment=False)).attempt(TransportContext(prompt='normal task'))
        assert result.metadata['run_id'] == value
        assert [call[1] for call in app.calls] == ['/run', '/runs/organizations%2Fo1%2Fruns%2F' + 'x' * 300]


async def test_same_suffix_changed_raw_identity_is_rejected():
    app = responses({'run_id': 'organizations/o1/runs/job-1', 'status': 'PENDING'},
                    polls=[{'run_id': 'organizations/o1/other/job-1', 'status': 'COMPLETED', 'result': 'done'}])
    async with serve(app) as origin:
        result = await runtime(transformed(poll_spec(origin + '/run'), prefix=None)).attempt(TransportContext(prompt='normal task'))
        assert result.reason_code.value == 'poll_identity_changed'
        assert len(app.calls) == 2


async def test_poll_transform_failure_precedes_identity_change():
    app = responses({'run_id': 'organizations/o1/runs/job-1', 'status': 'PENDING'},
                    polls=[{'run_id': 'organizations/o2/runs/job-1', 'status': 'COMPLETED', 'result': 'done'}])
    async with serve(app) as origin:
        result = await runtime(transformed(poll_spec(origin + '/run'))).attempt(TransportContext(prompt='normal task'))
        assert result.reason_code.value == 'id_prefix_mismatch'


@pytest.mark.parametrize('prefix', [None, '', 42])
async def test_invalid_resolved_prefix_fails_this_attempt(prefix):
    app = responses({'run_id': 'organizations/o1/runs/job-1', 'status': 'PENDING'})
    async with serve(app) as origin:
        data = transformed(poll_spec(origin + '/run'))
        data['delivery']['ids']['run_id']['expect_prefix'] = {'literal': prefix}
        result = await runtime(data).attempt(TransportContext(prompt='normal task'))
        assert result.reason_code.value == 'id_prefix_mismatch'
        assert len(app.calls) == 1


async def test_prefix_environment_snapshot_is_discovered_and_not_startup_required():
    app = responses({'run_id': 'organizations/o1/runs/job-1', 'status': 'PENDING'})
    async with serve(app) as origin:
        data = transformed(poll_spec(origin + '/run'))
        data['delivery']['ids']['run_id']['expect_prefix'] = {'env': 'SOURCE_REF'}
        values = {'SOURCE_REF': 'organizations/o1/runs/'}
        run = runtime(data, environ=values)
        for _ in range(2):
            result = await run.attempt(TransportContext(prompt='normal task'))
            assert result.metadata['run_id'] == 'job-1'
            values['SOURCE_REF'] = 'changed/'
        missing = runtime(data, environ={})
        for _ in range(2):
            result = await missing.attempt(TransportContext(prompt='normal task'))
            assert result.reason_code.value == 'id_prefix_mismatch'
        assert [call[0] for call in app.calls] == ['POST', 'GET', 'POST', 'GET', 'POST', 'POST']


async def test_delivery_prefix_failure_runs_cleanup_and_later_attempt_succeeds():
    from aiohttp import web
    from transport_v2_fakes import RecordingApp
    app = RecordingApp()
    index = 0
    async def created(request):
        return web.json_response({'ref': 'obj-1'}, status=201)
    async def submitted(request):
        nonlocal index
        index += 1
        return web.json_response({'run_id': 'organizations/' + ('o2' if index == 1 else 'o1') + '/runs/job-1',
                                  'status': 'PENDING'}, status=202)
    async def completed(request):
        return web.json_response({'status': 'COMPLETED', 'result': 'done'})
    async def deleted(request):
        return web.Response(status=204)
    app.route('POST', '/objects', created)
    app.route('POST', '/run', submitted)
    app.route('GET', '/runs/{tail:.*}', completed)
    app.route('DELETE', '/objects/{ref}', deleted)
    async with serve(app) as origin:
        data = transformed(poll_spec(origin + '/run'))
        data['lifecycle'] = {'attempt': [{
            'id': 'make', 'request': {'url': origin + '/objects', 'body': {'json': {}}},
            'expect': {'http_status': [201]}, 'capture': {'object_ref': {'path': '$.ref'}},
            'undo': {'request': {'method': 'DELETE', 'url': origin + '/objects/{object_ref}'},
                     'expect': {'http_status': [204]}},
        }]}
        run = runtime(data)
        first = await run.attempt(TransportContext(prompt='normal task'))
        second = await run.attempt(TransportContext(prompt='next task'))
        assert first.reason_code.value == 'id_prefix_mismatch'
        assert second.response_text == 'done'
        assert [(call[0], call[1]) for call in app.calls] == [
            ('POST', '/objects'), ('POST', '/run'), ('DELETE', '/objects/obj-1'),
            ('POST', '/objects'), ('POST', '/run'), ('GET', '/runs/job-1'), ('DELETE', '/objects/obj-1'),
        ]
        assert run.cleanup_report()['complete'] is True
