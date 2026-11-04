import json
from dataclasses import replace
from pathlib import Path

import pytest
from click.testing import CliRunner
from aiohttp import web

from argus.cli.__main__ import main
from argus_transport import ExecutionPolicy, TransportContext
from argus_transport.runtime_v2 import V2Run
from argus_transport.spec_v2 import TransportSpecV2, with_origin
from test_transport_v2_poll import poll_spec, responses, runtime
from transport_v2_fakes import RecordingApp, VendorBAutomationFake, serve, serve_in_thread


def declared(data, selector=None):
    data['auth'] = {'kind': 'none'}
    data['delivery']['ids']['run_id']['poll'] = selector or {
        'path': '$.name', 'last_segment': True,
        'expect_prefix': {'literal': 'runs/'},
    }
    return data


@pytest.mark.parametrize('value,want', [
    ('runs/job-1', 'done'), ('runs/job-2', 'poll_identity_changed'),
    ('foreign/job-1', 'poll_identity_changed'),
    ('runs/other/job-1', 'poll_identity_changed'),
    ('runs/job-1/', 'poll_identity_changed'),
    (None, 'poll_identity_changed'), (0, 'poll_identity_changed'),
    (True, 'poll_identity_changed'), ({}, 'poll_identity_changed'),
    ([], 'poll_identity_changed'),
])
@pytest.mark.parametrize('state', ['RUNNING', 'COMPLETED'])
async def test_declared_poll_identity_matrix(value, want, state):
    app = responses(polls=[{'name': value, 'status': state, 'result': 'done'},
                           {'name': 'runs/job-1', 'status': 'COMPLETED', 'result': 'done'}])
    async with serve(app) as origin:
        result = await runtime(declared(poll_spec(origin + '/run'))).attempt(
            TransportContext(prompt='normal task'))
    if want == 'done':
        assert result.response_text == 'done'
        assert len(app.calls) == (3 if state == 'RUNNING' else 2)
    else:
        assert result.reason_code.value == want
        assert result.outcome.value == 'target_error'
        assert len(app.calls) == 2


async def test_declared_poll_identity_missing_path():
    app = responses()
    async with serve(app) as origin:
        result = await runtime(declared(poll_spec(origin + '/run'))).attempt(
            TransportContext(prompt='normal task'))
    assert result.reason_code.value == 'poll_identity_changed'
    assert len(app.calls) == 2


@pytest.mark.parametrize('prefix,value,want', [
    ('runs', 'runsjob-1', 'done'), ('', 'job-1', 'poll_identity_changed'),
    (1, '1job-1', 'poll_identity_changed'),
])
async def test_declared_poll_prefix_exact_concatenation(prefix, value, want):
    app = responses(polls=[{'name': value, 'status': 'COMPLETED', 'result': 'done'}])
    async with serve(app) as origin:
        data = declared(poll_spec(origin + '/run'))
        data['delivery']['ids']['run_id']['poll']['expect_prefix'] = {'literal': prefix}
        result = await runtime(data).attempt(TransportContext(prompt='normal task'))
    assert (result.response_text if want == 'done' else result.reason_code.value) == want


@pytest.mark.parametrize('name,want', [
    ('runs/job-1', 'done'), ('runs/job-2', 'poll_identity_changed'),
    ('foreign/job-1', 'poll_identity_changed'), (1, 'poll_identity_changed'),
])
async def test_declared_full_name_poll_identity(name, want):
    app = responses({'run_id': 'runs/job-1', 'status': 'PENDING'},
                    [{'name': name, 'status': 'COMPLETED', 'result': 'done'}])
    async with serve(app) as origin:
        data = declared(poll_spec(origin + '/run'), {
            'path': '$.name', 'expect_prefix': {'literal': 'runs/'}})
        result = await runtime(data).attempt(TransportContext(prompt='normal task'))
    assert (result.response_text if want == 'done' else result.reason_code.value) == want


@pytest.mark.parametrize('status,payload,want', [
    (500, b'{', 'http_error'), (200, b'{', 'parse_error'),
    (200, b'x' * 257, 'response_limit'),
])
async def test_declared_poll_preserves_raw_error_precedence(status, payload, want):
    app = RecordingApp()
    async def submitted(request):
        return web.json_response({'run_id': 'job-1', 'status': 'PENDING'}, status=202)
    async def polled(request):
        return web.Response(status=status, body=payload)
    app.route('POST', '/run', submitted)
    app.route('GET', '/runs/{ident}', polled)
    async with serve(app) as origin:
        data = declared(poll_spec(origin + '/run'))
        data['limits']['response_bytes'] = 256
        result = await runtime(data).attempt(TransportContext(prompt='normal task'))
    assert result.reason_code.value == want
    assert len(app.calls) == 2


@pytest.mark.parametrize('group,job,want', [
    ('group-a', 0, 'done'), ('group-b', 0, 'poll_identity_changed'),
    ('group-a', '0', 'poll_identity_changed'),
    ('group-a', None, 'poll_identity_changed'),
])
async def test_multi_id_poll_identity(group, job, want):
    app = responses({'group': 'group-a', 'job': 0, 'status': 'PENDING'},
                    [{'identity': {'group': group, 'job': job},
                      'status': 'COMPLETED', 'result': 'done'}])
    async with serve(app) as origin:
        data = poll_spec(origin + '/run')
        data['auth'] = {'kind': 'none'}
        data['delivery']['request']['headers'] = {}
        data['delivery']['ids'] = {
            'group': {'path': '$.group', 'poll': {'path': '$.identity.group'}},
            'job': {'path': '$.job', 'poll': {'path': '$.identity.job'}},
        }
        data['delivery']['request']['url'] = origin + '/runs/{group}/{job}'
        result = await runtime(data).attempt(TransportContext(prompt='normal task'))
    assert (result.response_text if want == 'done' else result.reason_code.value) == want
    assert [call[1] for call in app.calls] == ['/run', '/runs/group-a/0']


@pytest.mark.parametrize('explicit', [False, True])
async def test_legacy_poll_roundtrip_and_missing_path(explicit):
    app = responses()
    async with serve(app) as origin:
        data = poll_spec(origin + '/run', explicit=explicit)
        data['auth'] = {'kind': 'none'}
        data['delivery']['request']['headers'] = {}
        spec = TransportSpecV2.from_dict(data)
        assert spec.to_dict()['delivery'] == data['delivery']
        result = await runtime(spec.to_dict()).attempt(TransportContext(prompt='normal task'))
    assert result.response_text == 'done'
    assert result.metadata == {'run_id': 'job-1'}


@pytest.mark.parametrize('selector', [
    {}, None, 'name', {'last_segment': True}, {'path': '$.name', 'extra': True},
    {'path': '$.name', 'last_segment': 1},
    {'path': '$.name', 'last_segment': None},
    {'path': '$.name', 'last_segment': True},
    {'path': '$.name', 'expect_prefix': None},
    {'path': '$.name', 'expect_prefix': 'runs/'},
    {'path': '$.name', 'expect_prefix': {'var': 'run_id'}},
    {'path': '$.name', 'expect_prefix': {'env': 'invalid_name'}},
])
def test_selector_shape_scope_and_env_policy(selector):
    data = poll_spec('http://127.0.0.1/run')
    data['delivery']['ids']['run_id']['poll'] = selector
    with pytest.raises(ValueError):
        TransportSpecV2.from_dict(data)


def test_poll_selector_forbidden_in_run_id_shorthand():
    data = poll_spec('http://127.0.0.1/run', explicit=False)
    data['delivery']['run_id']['poll'] = {'path': '$.name'}
    with pytest.raises(ValueError):
        TransportSpecV2.from_dict(data)


async def test_poll_selector_roundtrip_offline_and_nested_context(tmp_path):
    from argus.targets.custom_http import CustomHTTPTarget, CustomHTTPSpec
    data = declared(poll_spec('http://127.0.0.1/run'), {
        'path': '$.name', 'expect_prefix': {'concat': [
            {'literal': 'runs/'}, {'var': 'group'}, {'context': 'prompt'}]},
    })
    data['let'] = {'run': {'group': {'literal': 'a'}}}
    spec = TransportSpecV2.from_dict(data)
    assert spec.to_dict()['delivery']['ids'] == data['delivery']['ids']
    assert TransportSpecV2.from_dict(spec.to_dict()) == spec
    overridden = with_origin(spec.to_dict(), 'http://127.0.0.1:12345')
    assert overridden['request']['url'] == 'http://127.0.0.1:12345/run'
    assert overridden['delivery']['request']['url'] == 'http://127.0.0.1:12345/runs/{run_id}'
    assert overridden['delivery']['ids'] == data['delivery']['ids']
    target = tmp_path / 'target.json'
    target.write_text(json.dumps({'kind': 'custom_http', 'transport': spec.to_dict()}))
    result = CliRunner().invoke(main, ['validate-target', '--target', str(target), '--offline'])
    assert result.exit_code == 0, result.output
    assert 'requests.submit=0 requests.poll=0 requests.retry=0' in result.output
    data['delivery']['ids']['run_id']['poll']['expect_prefix'] = {
        'concat': [{'literal': 'runs/'}, {'context': 'scenario_url'}]}
    with pytest.raises(ValueError):
        CustomHTTPTarget(CustomHTTPSpec(transport=data))


async def test_nested_poll_prefix_env_is_snapshotted_and_policy_checked():
    app = responses(polls=[{'name': 'runs/job-1', 'status': 'COMPLETED', 'result': 'done'}])
    async with serve(app) as origin:
        data = declared(poll_spec(origin + '/run'))
        data['delivery']['ids']['run_id']['poll']['expect_prefix'] = {
            'concat': [{'env': 'POLL_PREFIX'}, {'literal': '/'}]}
        env = {'POLL_PREFIX': 'runs'}
        run = runtime(data, environ=env)
        assert (await run.attempt(TransportContext(prompt='normal task'))).response_text == 'done'
        env['POLL_PREFIX'] = 'foreign'
        assert (await run.attempt(TransportContext(prompt='normal task'))).response_text == 'done'
        spec = TransportSpecV2.from_dict(data)
        denied = V2Run(spec, policy=replace(ExecutionPolicy.local(spec), allowed_env_names=frozenset()), environ=env)
        result = await denied.attempt(TransportContext(prompt='normal task'))
        assert result.reason_code.value == 'binding_error'
        assert len(app.calls) == 4


async def test_nested_poll_prefix_missing_env_fails_before_submit():
    app = responses()
    async with serve(app) as origin:
        data = declared(poll_spec(origin + '/run'))
        data['delivery']['ids']['run_id']['poll']['expect_prefix'] = {'env': 'POLL_PREFIX'}
        result = await runtime(data, environ={}).attempt(TransportContext(prompt='normal task'))
    assert result.reason_code.value == 'binding_error'
    assert app.calls == []


@pytest.mark.parametrize('forged', [False, True])
def test_vendor_b_canonical_poll_name_real_cli(tmp_path, monkeypatch, forged):
    monkeypatch.setenv('VENDOR_B_AUTOMATION_NAME', 'Neutral invoice reader')
    monkeypatch.delenv('VENDOR_B_AUTOMATION_ID', raising=False)
    app = VendorBAutomationFake(poll_name='forged' if forged else 'canonical')
    fixture = Path(__file__).parent / 'fixtures' / 'transport_v2' / 'vendor_b_automation.json'
    data = json.loads(fixture.read_text())
    with serve_in_thread(app) as origin:
        data['transport'] = with_origin(data['transport'], origin)
        data['transport']['auth'] = {'kind': 'none'}
        selector = data['transport']['delivery']['ids']['run_id']
        selector['poll'] = {'path': '$.name', 'last_segment': True,
                            'expect_prefix': selector['expect_prefix']}
        target = tmp_path / 'target.json'
        target.write_text(json.dumps(data))
        result = CliRunner().invoke(main, ['validate-target', '--target', str(target), '--execute'])
    assert result.exit_code == int(forged), result.output
    if forged:
        assert 'transport.poll_identity_changed: target_error' in result.output
    else:
        assert 'outcome.selected: completed -> succeeded' in result.output
    polls = [call for call in app.calls if call[0] == 'GET' and '/runs/' in call[1]]
    assert len(polls) == (1 if forged else 2)
    assert all(call[1] == app.automation_path + '/runs/run--1' for call in polls)
    assert len([call for call in app.calls if call[0] == 'DELETE']) == 1
