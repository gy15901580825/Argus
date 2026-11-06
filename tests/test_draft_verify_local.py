import asyncio
import copy
import importlib
import json
import socket
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from click.testing import CliRunner

from argus.cli.__main__ import main
from argus.drafting.draft import choose_without_model, compile_draft
from argus.drafting.openapi import catalog_operations, load_openapi
from test_draft_target import agent_document, input_file
from test_transport_v2_engine import v2_dict
from test_transport_v2_poll import poll_spec


def api(tmp_path):
    return catalog_operations(load_openapi(input_file(tmp_path)))


def operation(id='ask', method='POST', path='/ask', role='invoke', checks=None, replies=None, count=1):
    return {'id': id, 'method': method, 'path': path, 'role': role,
            'calls': {'min': count, 'max': count}, 'request': checks or [],
            'replies': replies or [{'status': 200, 'body': {'status': 'COMPLETED', 'result': 'done'}, 'effects': []}]}


def check(label='prompt_bound', kind='json', pointer='/goal', equals='ping', **selector):
    at = {'kind': kind, **selector}
    if kind == 'json': at['pointer'] = pointer
    return {'check': label, 'at': at, 'equals': equals}


def scenario(operations=None, resources=None, final=None, gaps=None, outcome='succeeded', reply='done'):
    return {'version': 1, 'source': {'document': 'independent.json', 'pointers': ['/paths']},
            'resources': resources or [], 'operations': operations or [operation(checks=[check()])],
            'expect': {'outcome': outcome, 'reply': reply, 'resources': final or [], 'required_gaps': gaps or []}}


def target(data=None):
    return {'kind': 'custom_http', 'transport': data or v2_dict('https://service.invalid/ask')}


async def verify(spec, raw=None, *, catalog=None, gaps=()):
    module = importlib.import_module('argus.cli.verify_local')
    parser = importlib.import_module('argus.drafting.scenario')
    return await module.verify_local(spec, catalog=catalog,
        scenario=parser.parse_scenario(raw, catalog=catalog) if raw is not None else None, gaps=gaps)


def test_cli_verify_flag_schema_mock_never_success(tmp_path):
    source = input_file(tmp_path)
    out = tmp_path / 'target.json'
    result = CliRunner().invoke(main, ['draft-target', '--openapi', str(source), '--out', str(out), '--no-model', '--verify-local'])
    assert result.exit_code == 3, result.output
    provenance = json.loads(out.with_suffix('.provenance.json').read_text())
    assert provenance['validation']['local']['status'] == 'schema_mock_only'
    assert provenance['validation']['local']['semantic_success'] is False
    assert json.loads(out.read_text())['transport']['request']['url'] == 'http://127.0.0.1:8123/ask'


async def test_independent_sync_rewrites_auth_and_preserves_original(tmp_path, monkeypatch):
    from argus_transport import security
    spec = target()
    spec['transport']['auth'] = {'kind': 'bearer', 'secret': {'source': 'env', 'name': 'UNRESOLVED_TARGET_AUTH'}}
    original = copy.deepcopy(spec)
    def no_secret(*args, **kwargs): raise AssertionError('original credential was read')
    monkeypatch.setattr(security, 'resolve_secret', no_secret)
    result = await verify(spec, scenario())
    assert result.status == 'verified', result.as_dict()
    assert result.semantic_success and result.cleanup_complete
    assert result.as_dict()['execution']['requests']['submit'] == 1
    assert spec == original


@pytest.mark.parametrize('body,name', [({'goal': {'literal': 'wrong'}}, 'prompt_not_bound'),
                                      ({'goal': {'context': 'prompt'}, 'doc': {'literal': 'wrong'}}, 'material_not_bound')])
async def test_wrong_business_binding_fails(body, name):
    spec = target()
    spec['transport']['request']['body'] = {'json': body}
    checks = [check()]
    if name == 'material_not_bound': checks.append(check('material_bound', pointer='/doc', equals='Argus validation sample.'))
    result = await verify(spec, scenario([operation(checks=checks)]))
    assert result.status == 'failed'
    assert name in result.as_dict()['checks']


async def test_arbitrary_success_endpoint_does_not_count_as_invoke():
    spec = target()
    spec['transport']['request']['url'] = 'https://service.invalid/other'
    result = await verify(spec, scenario())
    assert not result.semantic_success
    assert 'invoke_not_called' in result.as_dict()['checks']


def dual_case():
    data = poll_spec('https://service.invalid/ask')
    data['delivery']['ids'] = {'group': {'path': '$.group'}, 'job': {'path': '$.job'}}
    data['delivery']['request']['url'] = 'https://service.invalid/jobs/{group}/{job}'
    ops = [operation(replies=[{'status': 202, 'body': {'group': 'g1', 'job': 'j1', 'status': 'PENDING'}, 'effects': []}], checks=[check()]),
           operation('poll', 'GET', '/jobs/{group}/{job}', 'poll',
               [check('poll_identity', 'path', equals='g1', name='group'), check('poll_identity', 'path', equals='j1', name='job')],
               [{'status': 200, 'body': {'group': 'g1', 'job': 'j1', 'status': 'PENDING'}, 'effects': []},
                {'status': 200, 'body': {'group': 'g1', 'job': 'j1', 'status': 'COMPLETED', 'result': 'done'}, 'effects': []}], count=2)]
    return target(data), scenario(ops)


async def test_async_two_ids_pending_then_completed():
    spec, raw = dual_case()
    result = await verify(spec, raw)
    assert result.status == 'verified', result.as_dict()
    assert result.as_dict()['execution']['requests']['poll'] == 2


async def test_wrong_second_poll_identity_is_named():
    spec, raw = dual_case()
    raw['operations'][1]['request'][1]['equals'] = 'other-job'
    result = await verify(spec, raw)
    assert result.status == 'failed'
    assert 'poll_identity_changed' in result.as_dict()['checks']


def upload_case(cleanup='delete'):
    spec = target()
    data = spec['transport']
    data['request']['body'] = {'json': {'goal': {'context': 'prompt'}, 'file': {'var': 'file_ref'}}}
    step = {'id': 'upload', 'request': {'method': 'POST', 'url': 'https://service.invalid/files:upload',
        'body': {'multipart': {'file': {'filename': {'literal': 'sample.txt'}, 'content_type': 'text/plain', 'content': {'context': 'material'}}}}},
        'expect': {'http_status': [200]}, 'capture': {'file_ref': {'path': '$.name'}}}
    if cleanup == 'delete':
        step['undo'] = {'request': {'method': 'DELETE', 'url': 'https://service.invalid/files/remove', 'query': {'id': {'var': 'file_ref'}}},
            'expect': {'http_status': [200]}, 'confirm': {'request': {'method': 'GET', 'url': 'https://service.invalid/files/metadata', 'query': {'id': {'var': 'file_ref'}}}, 'gone_status': [404]}}
    data['lifecycle'] = {'attempt': [step]}
    live = {'resource': 'file', 'from': 'absent', 'to': 'live'}
    gone = {'resource': 'file', 'from': 'live', 'to': 'absent'}
    ops = [operation('upload', 'POST', '/files:upload', 'upload',
        [check('material_bound', 'multipart_file', equals='Argus validation sample.', name='file', filename='sample.txt')],
        [{'status': 200, 'body': {'name': 'files/file-a'}, 'effects': [live]}]),
        operation(checks=[check(), check('resource_identity', pointer='/file', equals='files/file-a')])]
    if cleanup == 'delete':
        ops += [operation('remove', 'DELETE', '/files/remove', 'delete', [check('resource_identity', 'query', equals='files/file-a', name='id')],
            [{'status': 500, 'body': {}, 'effects': [gone]}]),
            operation('metadata', 'GET', '/files/metadata', 'confirm', [check('resource_identity', 'query', equals='files/file-a', name='id')],
            [{'status': 404, 'body': {}, 'effects': []}])]
    final = 'absent' if cleanup == 'delete' else 'live'
    return spec, scenario(ops, [{'id': 'file', 'initial': 'absent', 'cleanup': cleanup}], [{'id': 'file', 'final': final}],
        ['cleanup_endpoint_missing'] if cleanup == 'documented_no_delete' else [])


async def test_upload_full_resource_query_delete_and_confirm():
    spec, raw = upload_case()
    result = await verify(spec, raw)
    assert result.status == 'verified', result.as_dict()
    assert result.cleanup_complete
    assert [row['role'] for row in result.as_dict()['trace']] == ['upload', 'invoke', 'delete', 'confirm']
    assert result.as_dict()['execution']['requests']['cleanup'] == 2


async def test_no_delete_reports_residue_without_invented_request():
    spec, raw = upload_case('documented_no_delete')
    result = await verify(spec, raw, gaps=['cleanup_endpoint_missing'])
    assert result.status == 'business_only', result.as_dict()
    assert result.semantic_success and not result.cleanup_complete
    assert result.as_dict()['resources'] == [{'id': 'file', 'state': 'live', 'cleanup': 'documented_no_delete'}]
    assert [row['role'] for row in result.as_dict()['trace']] == ['upload', 'invoke']


async def test_unexpected_leftover_fails_even_transport_complete():
    spec, raw = upload_case()
    spec['transport']['lifecycle']['attempt'][0].pop('undo')
    result = await verify(spec, raw)
    assert result.status == 'failed'
    assert 'cleanup_left_resources' in result.as_dict()['checks']


async def test_no_delete_missing_required_gap_fails():
    spec, raw = upload_case('documented_no_delete')
    result = await verify(spec, raw)
    assert result.status == 'failed'
    assert 'cleanup_gap_missing' in result.as_dict()['checks']


async def test_strict_policy_rejects_other_ports_and_hosts_before_dns(monkeypatch):
    module = importlib.import_module('argus.cli.verify_local')
    def forbidden(*args, **kwargs): raise AssertionError('DNS performed')
    monkeypatch.setattr(socket, 'getaddrinfo', forbidden)
    policy = module.StrictLoopbackPolicy('http://127.0.0.1:8123')
    assert await policy.endpoint_ip('http://127.0.0.1:8123/ask') == '127.0.0.1'
    for url in ['http://127.0.0.1:8124/ask', 'http://localhost:8123/ask', 'https://127.0.0.1:8123/ask',
                'http://global.invalid/ask', 'http://user@127.0.0.1:8123/ask', 'http://127.1:8123/ask']:
        with pytest.raises(ValueError): await policy.endpoint_ip(url)


async def test_no_spec_does_not_start_server(monkeypatch):
    module = importlib.import_module('argus.cli.verify_local')
    async def forbidden(*args, **kwargs): raise AssertionError('fake started')
    monkeypatch.setattr(module.LocalFake, '__aenter__', forbidden)
    result = await verify(None)
    assert result.status == 'not_run' and not result.semantic_success


@pytest.mark.parametrize('mutation', [lambda r: r.update(version=2), lambda r: r.update(code='pass'),
    lambda r: r['operations'][0].update(path='https://global.invalid/ask'),
    lambda r: r['operations'][0]['request'][0]['at'].update(pointer='/bad~2'),
    lambda r: r['operations'][0]['calls'].update(max=65), lambda r: r['expect'].update(reply={'x': 'a' * 65537}),
    lambda r: r['operations'].append(copy.deepcopy(r['operations'][0])),
    lambda r: r['operations'][0].update(request=[]),
    lambda r: r['operations'][0]['replies'][0].update(effects=[{'resource': 'missing', 'from': 'absent', 'to': 'live'}])])
def test_scenario_boundary_rejects_unsafe_or_unverifiable_data(mutation):
    parser = importlib.import_module('argus.drafting.scenario')
    raw = scenario()
    mutation(raw)
    with pytest.raises(ValueError, match='scenario_invalid'): parser.parse_scenario(raw)


def test_scenario_requires_verify_flag(tmp_path):
    source = input_file(tmp_path)
    path = tmp_path / 'scene.json'
    path.write_text(json.dumps(scenario()))
    result = CliRunner().invoke(main, ['draft-target', '--openapi', str(source), '--out', str(tmp_path / 'target.json'), '--no-model', '--scenario', str(path)])
    assert result.exit_code == 2
    assert '--verify-local' in result.output


async def test_material_binding_cannot_pass_without_independent_material_oracle():
    spec = target()
    spec['transport']['request']['body']['json']['doc'] = {'context': 'material'}
    result = await verify(spec, scenario())
    assert result.status == 'failed'
    assert 'material_not_bound' in result.checks


@pytest.mark.parametrize('constraint', [{'not': {'type': 'string'}}, {'patternProperties': {'^a': {'type': 'string'}}},
                                      {'if': {'type': 'string'}}, {'contains': {'type': 'string'}}])
async def test_unsupported_schema_constraints_are_explicit(tmp_path, constraint):
    original_catalog = api(tmp_path)
    spec = compile_draft(original_catalog, choose_without_model(original_catalog)).spec
    document = agent_document()
    schema = document['paths']['/ask']['post']['requestBody']['content']['application/json']['schema']['properties']['question']
    schema.update(constraint)
    catalog = catalog_operations(load_openapi(input_file(tmp_path, document)))
    result = await verify(spec, catalog=catalog)
    assert result.status == 'failed'
    assert 'schema_mock_unsupported' in result.checks


async def test_scenario_reply_must_satisfy_documented_response_schema(tmp_path):
    catalog = api(tmp_path)
    draft = compile_draft(catalog, choose_without_model(catalog))
    raw = scenario([operation(checks=[check(pointer='/question')], replies=[{'status': 200, 'body': {'status': 'completed', 'answer': 42}, 'effects': []}])], reply='42')
    result = await verify(draft.spec, raw, catalog=catalog)
    assert result.status == 'failed'
    assert 'response_schema_invalid' in result.checks


async def test_unknown_transport_leftover_cannot_hide_behind_declared_residue(monkeypatch):
    module = importlib.import_module('argus.cli.verify_local')
    execute = module.execute_transport
    async def with_unknown(*args, **kwargs):
        evidence = await execute(*args, **kwargs)
        evidence.cleanup['leftover'].append("step 'unknown' POST http://127.0.0.1:1/unknown")
        return evidence
    monkeypatch.setattr(module, 'execute_transport', with_unknown)
    spec, raw = upload_case('documented_no_delete')
    result = await verify(spec, raw, gaps=['cleanup_endpoint_missing'])
    assert result.status == 'failed'
    assert 'cleanup_left_resources' in result.checks


async def test_surviving_external_url_is_blocked_before_dns(monkeypatch):
    module = importlib.import_module('argus.cli.verify_local')
    dns = []
    def forbidden(*args, **kwargs):
        dns.append(args)
        raise AssertionError('external DNS')
    monkeypatch.setattr(socket, 'getaddrinfo', forbidden)
    monkeypatch.setattr(module, 'with_origin', lambda value, origin: value)
    result = await verify(target(), scenario())
    assert result.status == 'failed'
    assert 'unsafe_location' in result.checks
    assert dns == [] and result.trace == ()


async def test_full_lifetime_deadline_reports_partial_counts_and_closes_fake(monkeypatch):
    module = importlib.import_module('argus.cli.verify_local')
    handle, exited = module.LocalFake.handle, []
    async def slow(self, request):
        response = await handle(self, request)
        await asyncio.sleep(5)
        return response
    original_exit = module.LocalFake.__aexit__
    async def exited_fake(self, *args):
        await original_exit(self, *args)
        exited.append(self.origin)
    monkeypatch.setattr(module.LocalFake, 'handle', slow)
    monkeypatch.setattr(module.LocalFake, '__aexit__', exited_fake)
    monkeypatch.setattr(module, 'VERIFY_DEADLINE_S', .1)
    start = asyncio.get_running_loop().time()
    result = await verify(target(), scenario())
    assert asyncio.get_running_loop().time() - start < .5
    assert result.status == 'failed' and 'verification_budget_exceeded' in result.checks
    assert result.execution['requests']['submit'] == 1
    assert len(exited) == 1


def test_cli_business_only_ready_artifact_still_requires_review(tmp_path, monkeypatch):
    import argus.cli.cmd_draft_target as command
    from dataclasses import replace
    from argus.drafting.draft import DraftState
    real_compile = command.compile_draft
    def ready(*args, **kwargs): return replace(real_compile(*args, **kwargs), state=DraftState.READY)
    async def only_business(*args, **kwargs):
        from argus.cli.verify_local import VerificationResult
        return VerificationResult('independent_scenario', 'business_only', True, False, (), {}, (), (), ())
    monkeypatch.setattr(command, 'compile_draft', ready)
    monkeypatch.setattr(command, 'verify_draft_local', only_business)
    source = input_file(tmp_path)
    result = CliRunner().invoke(main, ['draft-target', '--openapi', str(source), '--out', str(tmp_path / 'target.json'), '--no-model', '--verify-local'])
    assert result.exit_code == 3, result.output


async def test_optional_unused_material_oracle_does_not_prove_consumption():
    spec = target()
    spec['transport']['request']['body']['json']['doc'] = {'context': 'material'}
    raw = scenario([operation(checks=[check()]), operation('unused', 'POST', '/unused', 'setup',
        [check('material_bound', pointer='/doc', equals='Argus validation sample.')])])
    raw['operations'][1]['calls']['min'] = 0
    result = await verify(spec, raw)
    assert result.status == 'failed'
    assert 'material_not_bound' in result.checks


async def test_policy_caps_all_phase_dispatches():
    module = importlib.import_module('argus.cli.verify_local')
    policy = module.StrictLoopbackPolicy('http://127.0.0.1:8123')
    for _ in range(64): await policy.endpoint_ip('http://127.0.0.1:8123/ask')
    with pytest.raises(ValueError, match='verification_budget_exceeded'):
        await policy.endpoint_ip('http://127.0.0.1:8123/cleanup')


async def test_paused_branch_is_not_business_success():
    spec, raw = dual_case()
    spec['transport']['delivery']['abort'] = {'request': {'method': 'POST', 'url': 'https://service.invalid/jobs/{group}/{job}:pause', 'body': {'none': True}}, 'expect': {'http_status': [200]}}
    spec['transport']['delivery']['max_polls'] = 1
    raw['operations'][0]['replies'][0]['effects'] = [{'resource': 'run', 'from': 'absent', 'to': 'live'}]
    raw['operations'][1]['calls'] = {'min': 1, 'max': 1}
    raw['operations'][1]['replies'] = raw['operations'][1]['replies'][:1]
    raw['operations'].append(operation('pause', 'POST', '/jobs/{group}/{job}:pause', 'pause', [], [{'status': 200, 'body': {}, 'effects': [{'resource': 'run', 'from': 'live', 'to': 'paused'}]}]))
    raw['resources'] = [{'id': 'run', 'initial': 'absent', 'cleanup': 'pause'}]
    raw['expect'] = {'outcome': 'target_error', 'reply': None, 'resources': [{'id': 'run', 'final': 'paused'}], 'required_gaps': []}
    result = await verify(spec, raw)
    assert result.status == 'business_only', result.as_dict()
    assert not result.semantic_success and not result.cleanup_complete
    assert result.resources[0]['state'] == 'paused'
    assert [row['role'] for row in result.trace] == ['invoke', 'poll', 'pause']


async def test_cleanup_is_inside_same_wall_deadline(monkeypatch):
    from contextlib import asynccontextmanager
    from types import SimpleNamespace
    from argus_transport.runtime_v2 import RequestLedger
    module = importlib.import_module('argus.cli.verify_local')
    loop = asyncio.get_running_loop()
    call_at, handle = loop.call_at, module.LocalFake.handle
    scopes, expiries = [], []

    @asynccontextmanager
    async def controlled_timeout(when):
        timeout = asyncio.Timeout(None)
        scope = {'when': when, 'timeout': timeout, 'active': True}
        scopes.append(scope)
        try:
            async with timeout:
                yield timeout
        finally:
            scope['active'] = False

    def controlled_call_at(when, callback, *args, context=None):
        if isinstance(getattr(callback, '__self__', None), RequestLedger) and args == ('verification_budget_exceeded',):
            expiry = {'when': when, 'callback': callback, 'args': args, 'cancelled': False}
            expiries.append(expiry)
            return SimpleNamespace(cancel=lambda: expiry.update(cancelled=True))
        return call_at(when, callback, *args, context=context)

    async def blocked_delete(self, request):
        response = await handle(self, request)
        if request.method == 'DELETE':
            assert len(scopes) == 2 and scopes[-1]['active'], 'cleanup must share the active execution deadline'
            assert len(expiries) == 1
            expiry = expiries[0]
            expiry['callback'](*expiry['args'])
            scopes[-1]['timeout'].reschedule(loop.time())
            await asyncio.Event().wait()
        return response

    controlled_asyncio = SimpleNamespace(**{**vars(asyncio), 'timeout_at': controlled_timeout})
    monkeypatch.setattr(module, 'asyncio', controlled_asyncio)
    monkeypatch.setattr(importlib.import_module('argus.cli.validate_transport_v2'), 'asyncio', controlled_asyncio)
    monkeypatch.setattr(loop, 'call_at', controlled_call_at)
    monkeypatch.setattr(module.LocalFake, 'handle', blocked_delete)
    monkeypatch.setattr(module, 'VERIFY_DEADLINE_S', .1)
    spec, raw = upload_case()
    spec['transport']['lifecycle']['run'] = spec['transport']['lifecycle'].pop('attempt')
    result = await verify(spec, raw)
    assert len(scopes) == 3
    assert scopes[0]['when'] == scopes[1]['when'] == expiries[0]['when']
    assert scopes[2]['when'] > scopes[1]['when']
    assert expiries[0]['cancelled'] and not any(scope['active'] for scope in scopes)
    assert result.status == 'failed'
    assert 'verification_budget_exceeded' in result.checks
    assert result.execution['close_stop'] == 'verification_budget_exceeded'
    assert result.execution['requests']['setup'] == result.execution['requests']['submit'] == 1
    assert result.execution['requests']['cleanup'] == 1
    assert [row['role'] for row in result.trace] == ['upload', 'invoke', 'delete']


async def test_interrupted_bootstrap_closes_partial_runner(monkeypatch):
    module = importlib.import_module('argus.cli.verify_local')
    enter, exit = module.LocalFake.__aenter__, module.LocalFake.__aexit__
    closed = []
    async def slow_enter(self):
        await enter(self)
        await asyncio.sleep(5)
        return self
    async def tracked_exit(self, *args):
        await exit(self, *args)
        closed.append(self.origin)
    monkeypatch.setattr(module.LocalFake, '__aenter__', slow_enter)
    monkeypatch.setattr(module.LocalFake, '__aexit__', tracked_exit)
    monkeypatch.setattr(module, 'VERIFY_DEADLINE_S', .1)
    result = await verify(target(), scenario())
    assert result.status == 'failed' and 'verification_budget_exceeded' in result.checks
    assert len(closed) == 1


@pytest.mark.parametrize('kind,format,good,bad', [('string', 'uuid', '00000000-0000-4000-8000-000000000001', 'bad'),
    ('string', 'date-time', '2026-11-05T00:00:00Z', 'today'), ('integer', 'int64', 10, 2**64)])
def test_schema_standard_formats_are_checked(kind, format, good, bad):
    module = importlib.import_module('argus.cli.verify_local')
    schema = {'type': kind, 'format': format, 'nullable': True}
    assert module._schema_supported(schema)
    assert module._schema_valid(good, schema)
    assert module._schema_valid(None, schema)
    assert not module._schema_valid(bad, schema)


async def test_independent_relative_location_verifies_two_ids():
    spec, raw = dual_case()
    spec['transport']['delivery']['location'] = 'verify'
    raw['operations'][0]['replies'][0]['headers'] = {'Location': '/jobs/g1/j1'}
    raw['operations'][1]['replies'][0]['headers'] = {'Location': '/jobs/g1/j1', 'Retry-After': '0'}
    result = await verify(spec, raw)
    assert result.status == 'verified', result.as_dict()


async def test_mismatched_location_stops_before_poll():
    spec, raw = dual_case()
    spec['transport']['delivery']['location'] = 'verify'
    raw['operations'][0]['replies'][0]['headers'] = {'Location': '/jobs/g1/other'}
    result = await verify(spec, raw)
    assert result.status == 'failed'
    assert result.execution['reason'] == 'unsafe_location'
    assert result.execution['requests']['poll'] == 0


@pytest.mark.parametrize('headers', [{'Location': 'https://global.invalid/jobs/a'}, {'Location': '//global.invalid/a'},
    {'Location': '/jobs/{run_id}'}, {'Location': '/jobs/a#fragment'}, {'Location': '/jobs/a\r\nX-Extra: x'},
    {'Retry-After': '11'}, {'Retry-After': '-1'}, {'Authorization': 'anything'},
    {'location': '/jobs/a', 'Location': '/jobs/a'}])
def test_scenario_response_headers_reject_authority_or_unbounded_values(headers):
    parser = importlib.import_module('argus.drafting.scenario')
    raw = scenario()
    raw['operations'][0]['replies'][0]['headers'] = headers
    with pytest.raises(ValueError, match='scenario_invalid'):
        parser.parse_scenario(raw)


def test_failed_local_cli_keeps_original_artifacts_and_names_failure(tmp_path):
    document = agent_document()
    source = input_file(tmp_path, document)
    path = tmp_path / 'scene.json'
    raw = scenario([operation(checks=[check(pointer='/question'), check('material_bound', pointer='/doc', equals='Argus validation sample.')],
        replies=[{'status': 200, 'body': {'answer': 'done', 'status': 'completed'}, 'effects': []}])])
    path.write_text(json.dumps(raw))
    out = tmp_path / 'target.json'
    result = CliRunner().invoke(main, ['draft-target', '--openapi', str(source), '--out', str(out), '--no-model', '--verify-local', '--scenario', str(path)])
    assert result.exit_code == 1, result.output
    assert 'material_not_bound' in result.output
    assert json.loads(out.read_text())['transport']['request']['url'] == 'http://127.0.0.1:8123/ask'
    assert json.loads(out.with_suffix('.provenance.json').read_text())['validation']['local']['status'] == 'failed'


async def test_every_request_owner_is_rewritten_before_execution(monkeypatch):
    module = importlib.import_module('argus.cli.verify_local')
    from argus_transport.spec_v2 import iter_requests
    from test_transport_provision import provision_dict
    spec, _ = dual_case()
    upload, _ = upload_case()
    spec['transport']['lifecycle'] = upload['transport']['lifecycle']
    spec['transport']['lifecycle']['provision'] = provision_dict('https://service.invalid')['lifecycle']['provision']
    spec['transport']['lifecycle']['provision']['create'] = [{'id': 'prepare',
        'request': {'method': 'POST', 'url': 'https://service.invalid/prepare', 'body': {'json': {}}},
        'expect': {'http_status': [200]}}]
    spec['transport']['lifecycle']['run'] = [{'id': 'run_setup',
        'request': {'method': 'POST', 'url': 'https://service.invalid/session', 'body': {'json': {}}},
        'expect': {'http_status': [200]}, 'undo': {'request': {'method': 'DELETE', 'url': 'https://service.invalid/session'}, 'expect': {'http_status': [200]}}}]
    spec['transport']['delivery']['abort'] = {'request': {'method': 'POST', 'url': 'https://service.invalid/jobs/{group}/{job}:pause', 'body': {'none': True}}, 'expect': {'http_status': [200]}}
    execute, observed = module.execute_transport, []
    async def inspect(transport, **kwargs):
        requests = list(iter_requests(transport))
        origins = {urlsplit(request.url).netloc for _, request in requests}
        assert len(origins) == 1 and next(iter(origins)).startswith('127.0.0.1:')
        assert len(requests) == 12
        assert transport.auth.kind == 'none'
        assert kwargs['environ'] == {}
        assert kwargs['policy'].allowed_secret_roots == ()
        observed.append(True)
        return await execute(transport, **kwargs)
    monkeypatch.setattr(module, 'execute_transport', inspect)
    original = copy.deepcopy(spec)
    result = await verify(spec)
    assert observed == [True]
    assert spec == original
    assert not result.semantic_success


@pytest.mark.parametrize('present', [False, True])
async def test_only_present_recursive_schema_branches_are_checked(tmp_path, present):
    document = agent_document()
    body_schema = document['paths']['/ask']['post']['requestBody']['content']['application/json']['schema']
    body_schema['properties']['unused'] = {'$ref': '#/components/schemas/Recursive'}
    document['components'] = {'schemas': {'Recursive': {'type': 'object', 'properties': {'next': {'$ref': '#/components/schemas/Recursive'}}}}}
    catalog = catalog_operations(load_openapi(input_file(tmp_path, document)))
    spec = target()
    spec['transport']['request']['body'] = {'json': {'question': {'context': 'prompt'}}}
    spec['transport']['response']['text']['paths'] = ['$.answer']
    spec['transport']['outcome']['rules'][-1]['when']['equals'] = 'completed'
    if present: spec['transport']['request']['body']['json']['unused'] = {'literal': {'next': {}}}
    raw = scenario([operation(checks=[check(pointer='/question')], replies=[{'status': 200, 'body': {'status': 'completed', 'answer': 'done'}, 'effects': []}])])
    result = await verify(spec, raw, catalog=catalog)
    if present:
        assert result.status == 'failed'
        assert 'schema_mock_unsupported' in result.checks
    else:
        assert result.status == 'verified', result.as_dict()


@pytest.mark.parametrize('provided', [False, True])
async def test_documented_header_parameter_is_validated(tmp_path, provided):
    document = agent_document()
    document['paths']['/ask']['post']['parameters'] = [{'in': 'header', 'name': 'X-Fixture-Version', 'required': True,
        'schema': {'type': 'string', 'enum': ['fixture-v1']}}]
    catalog = catalog_operations(load_openapi(input_file(tmp_path, document)))
    spec = target()
    spec['transport']['request']['body'] = {'json': {'question': {'context': 'prompt'}}}
    spec['transport']['response']['text']['paths'] = ['$.answer']
    spec['transport']['outcome']['rules'][-1]['when']['equals'] = 'completed'
    if provided: spec['transport']['request']['headers']['X-Fixture-Version'] = 'fixture-v1'
    raw = scenario([operation(checks=[check(pointer='/question')], replies=[{'status': 200, 'body': {'status': 'completed', 'answer': 'done'}, 'effects': []}])])
    result = await verify(spec, raw, catalog=catalog)
    assert result.status == ('verified' if provided else 'failed'), result.as_dict()
    if not provided: assert 'request_schema_invalid' in result.checks


@pytest.mark.parametrize('mutation', [lambda raw: raw['expect'].update(outcome=[]),
    lambda raw: raw['operations'][0].update(role=[]), lambda raw: raw['operations'][0].update(method=[]),
    lambda raw: raw['operations'][0]['request'][0]['at'].update(kind=[])])
def test_non_scalar_enum_fields_raise_named_scenario_error(mutation):
    parser = importlib.import_module('argus.drafting.scenario')
    raw = scenario()
    mutation(raw)
    with pytest.raises(ValueError, match='scenario_invalid'):
        parser.parse_scenario(raw)


async def test_original_environment_bindings_are_never_read(monkeypatch):
    monkeypatch.setenv('FIXTURE_PROMPT', 'ping')
    spec = target()
    spec['transport']['request']['body'] = {'json': {'goal': {'env': 'FIXTURE_PROMPT'}}}
    result = await verify(spec, scenario())
    assert result.status == 'failed'
    assert result.execution['requests']['submit'] == 0


@pytest.mark.parametrize('cleanup,mutation', [
    ('delete', lambda raw: raw['expect']['resources'][0].update(final='live')),
    ('delete', lambda raw: raw['operations'][1]['request'].pop()),
    ('documented_no_delete', lambda raw: raw['expect'].update(required_gaps=[])),
    ('delete', lambda raw: raw['operations'][0].update(request=[
        check for check in raw['operations'][0]['request'] if check['check'] != 'material_bound']))])
def test_cleanup_and_upload_oracles_cannot_be_weakened(cleanup, mutation):
    parser = importlib.import_module('argus.drafting.scenario')
    _, raw = upload_case(cleanup)
    mutation(raw)
    with pytest.raises(ValueError, match='scenario_invalid'):
        parser.parse_scenario(raw)


async def test_unbounded_existing_execute_does_not_reclassify_timeout(monkeypatch):
    from argus.cli.validate_transport_v2 import execute_transport
    from argus_transport.runtime_v2 import V2Run
    from argus_transport.spec_v2 import TransportSpecV2
    async def timeout(self, context): raise TimeoutError('existing error')
    monkeypatch.setattr(V2Run, 'attempt', timeout)
    with pytest.raises(TimeoutError, match='existing error'):
        await execute_transport(TransportSpecV2.from_dict(target()['transport']))


def many_operations(count):
    return scenario([operation(id=f'ask{i}', path=f'/ask{i}', checks=[check()]) for i in range(count)])


@pytest.mark.parametrize('size_kind', ['operations', 'replies', 'predicates', 'bytes', 'depth', 'finite_replies'])
def test_independent_scenario_limits_are_enforced(size_kind):
    parser = importlib.import_module('argus.drafting.scenario')
    raw = many_operations(33) if size_kind == 'operations' else many_operations(14) if size_kind == 'bytes' else scenario()
    if size_kind == 'replies': raw['operations'][0]['replies'] *= 65
    if size_kind == 'predicates': raw['operations'][0]['request'] *= 33
    if size_kind == 'bytes':
        for op in raw['operations']: op['replies'][0]['body'] = 'x' * 19000
    if size_kind == 'depth':
        body = 'leaf'
        for _ in range(17): body = {'nested': body}
        raw['operations'][0]['replies'][0]['body'] = body
    if size_kind == 'finite_replies': raw['operations'][0]['calls']['max'] = 2
    with pytest.raises(ValueError, match='scenario_invalid'):
        parser.parse_scenario(raw)


async def test_missing_independent_required_operation_fails():
    raw = scenario([operation(checks=[check()]), operation('setup', 'POST', '/setup', 'setup')])
    result = await verify(target(), raw)
    assert result.status == 'failed'
    assert 'operation_call_count' in result.checks


async def test_independent_terminal_reply_must_match_actual_selection():
    result = await verify(target(), scenario(reply='independent other answer'))
    assert result.status == 'failed' and 'reply_mismatch' in result.checks


async def test_independent_terminal_outcome_must_match_actual_selection():
    result = await verify(target(), scenario(outcome='blocked'))
    assert result.status == 'failed'
    assert 'terminal_outcome_mismatch' in result.checks
    assert not result.semantic_success


async def test_independent_resource_state_cannot_hide_without_transport_cleanup():
    raw = scenario([operation(checks=[check()], replies=[{'status': 200,
        'body': {'status': 'COMPLETED', 'result': 'done'},
        'effects': [{'resource': 'task', 'from': 'absent', 'to': 'live'}]}])],
        resources=[{'id': 'task', 'initial': 'absent', 'cleanup': 'delete'}],
        final=[{'id': 'task', 'final': 'absent'}])
    result = await verify(target(), raw)
    assert result.execution['cleanup'] is None
    assert result.status == 'failed'
    assert 'cleanup_left_resources' in result.checks
    assert result.resources == ({'id': 'task', 'state': 'live', 'cleanup': 'delete'},)


async def test_deadline_stops_new_cleanup_dispatches(monkeypatch):
    module = importlib.import_module('argus.cli.verify_local')
    handle = module.LocalFake.handle
    async def slow_invoke(self, request):
        response = await handle(self, request)
        if request.path == '/ask': await asyncio.sleep(5)
        return response
    monkeypatch.setattr(module.LocalFake, 'handle', slow_invoke)
    monkeypatch.setattr(module, 'VERIFY_DEADLINE_S', .15)
    spec, raw = upload_case()
    spec['transport']['lifecycle']['run'] = spec['transport']['lifecycle'].pop('attempt')
    result = await verify(spec, raw)
    assert result.status == 'failed' and 'verification_budget_exceeded' in result.checks
    assert result.execution['requests']['cleanup'] == 0
    assert all(row['role'] not in {'delete', 'confirm'} for row in result.trace)


@pytest.mark.parametrize('uploaded', [False, True])
async def test_draft_cannot_remove_independent_material_obligation(uploaded):
    spec, raw = upload_case()
    for op in raw['operations']:
        if op['role'] != 'invoke': op['calls']['min'] = 0
    if not uploaded:
        spec['transport'].pop('lifecycle')
        spec['transport']['request']['body']['json']['file'] = {'literal': 'files/file-a'}
    result = await verify(spec, raw)
    assert result.status == ('verified' if uploaded else 'failed'), result.as_dict()
    if not uploaded:
        assert 'material_not_bound' in result.checks
        assert [row['role'] for row in result.trace] == ['invoke']


async def test_each_independent_material_predicate_must_be_observed():
    spec, raw = upload_case()
    unused = operation('unused', 'POST', '/unused', 'setup',
        [check('material_bound', pointer='/doc', equals='Argus validation sample.')])
    unused['calls']['min'] = 0
    raw['operations'].append(unused)
    result = await verify(spec, raw)
    assert result.status == 'failed', result.as_dict()
    assert 'material_not_bound' in result.checks


@pytest.mark.parametrize('payload', [
    '{"question":"ping"}',
    '{"question":"wrong","question":"ping"}',
    '{"question":"ping","extra":{"value":"wrong","value":"last"}}',
    '{"question":"ping","extra":NaN}',
    '{"question":"ping","extra":Infinity}',
    '{"question":"ping","extra":-Infinity}',
    '{"question":"ping","extra":1e999}',
    '{"question":"ping","extra":' + '[' * 17 + '0' + ']' * 17 + '}',
    '{"question":"ping"',
])
async def test_request_json_is_unambiguous_finite_and_bounded(tmp_path, payload):
    catalog = catalog_operations(load_openapi(input_file(tmp_path)))
    spec = target()
    spec['transport']['request']['body'] = {'text': {'literal': payload}}
    spec['transport']['request']['headers']['Content-Type'] = 'application/json'
    spec['transport']['response']['text']['paths'] = ['$.answer']
    spec['transport']['outcome']['rules'][-1]['when']['equals'] = 'completed'
    raw = scenario([operation(checks=[check(pointer='/question')],
        replies=[{'status': 200, 'body': {'status': 'completed', 'answer': 'done'}, 'effects': []}])])
    result = await verify(spec, raw, catalog=catalog)
    valid = payload == '{"question":"ping"}'
    assert result.status == ('verified' if valid else 'failed'), result.as_dict()
    if not valid:
        assert 'request_body_invalid' in result.checks


def schema_verification_case(tmp_path, content, *, required=True, parameters=()):
    document = agent_document()
    document['paths']['/ask']['post']['requestBody'] = {'required': required, 'content': content}
    document['paths']['/ask']['post']['parameters'] = list(parameters)
    catalog = catalog_operations(load_openapi(input_file(tmp_path, document)))
    spec = target()
    spec['transport']['request']['body'] = {'json': {'question': {'context': 'prompt'}}}
    spec['transport']['response']['text']['paths'] = ['$.answer']
    spec['transport']['outcome']['rules'][-1]['when']['equals'] = 'completed'
    raw = scenario([operation(checks=[check(pointer='/question')],
        replies=[{'status': 200, 'body': {'status': 'completed', 'answer': 'done'}, 'effects': []}])])
    return spec, raw, catalog


@pytest.mark.parametrize('declared,required,failure', [
    ('text/plain', True, 'schema_mock_unsupported'),
    ('application/json', False, 'request_schema_invalid'),
])
async def test_nonempty_wrong_or_unsupported_media_never_looks_absent(tmp_path, declared, required, failure):
    schema = {'type': 'string', 'minLength': 5} if declared == 'text/plain' else {'type': 'object'}
    spec, raw, catalog = schema_verification_case(tmp_path, {declared: {'schema': schema}}, required=required)
    spec['transport']['request']['headers']['Content-Type'] = 'text/plain'
    spec['transport']['request']['body'] = {'text': {'context': 'prompt'}}
    raw['operations'][0]['request'] = [check(kind='raw_utf8')]
    result = await verify(spec, raw, catalog=catalog)
    assert result.status == 'failed', result.as_dict()
    assert failure in result.checks
    assert not result.semantic_success


@pytest.mark.parametrize('required', [False, True])
async def test_empty_documented_body_respects_required_flag(tmp_path, required):
    spec, raw, catalog = schema_verification_case(tmp_path,
        agent_document()['paths']['/ask']['post']['requestBody']['content'], required=required,
        parameters=[{'in': 'query', 'name': 'question', 'required': True, 'schema': {'type': 'string'}}])
    spec['transport']['request']['body'] = {'none': True}
    spec['transport']['request']['query'] = {'question': {'context': 'prompt'}}
    raw['operations'][0]['request'] = [check(kind='query', name='question')]
    result = await verify(spec, raw, catalog=catalog)
    assert result.status == ('failed' if required else 'verified'), result.as_dict()
    if required: assert 'request_schema_invalid' in result.checks


async def test_documented_multiple_media_selects_actual_multipart(tmp_path):
    spec, raw, catalog = schema_verification_case(tmp_path, {
        'application/json': {'schema': {'type': 'object', 'required': ['unrelated']}},
        'multipart/form-data': {'schema': {'type': 'object', 'required': ['question'],
            'properties': {'question': {'type': 'string', 'format': 'binary'}}}},
    })
    spec['transport']['request']['body'] = {'multipart': {'question': {
        'filename': {'literal': 'question.txt'}, 'content_type': 'text/plain', 'content': {'context': 'prompt'}}}}
    raw['operations'][0]['request'] = [check(kind='multipart_file', name='question', filename='question.txt')]
    result = await verify(spec, raw, catalog=catalog)
    assert result.status == 'verified', result.as_dict()
    assert result.semantic_success


@pytest.mark.parametrize('keyword', ['enum', 'const'])
@pytest.mark.parametrize('expected,actual,valid', [
    (1, True, False), (True, 1, False), (1, 1.0, True), (True, True, True),
    ({'choice': 1}, {'choice': True}, False),
    ({'choice': [1]}, {'choice': [True]}, False),
    ({'choice': [1]}, {'choice': [1.0]}, True),
])
async def test_schema_enum_and_const_use_json_equality(tmp_path, keyword, expected, actual, valid):
    constraint = {keyword: [expected] if keyword == 'enum' else expected}
    body_schema = {'type': 'object', 'required': ['question', 'approved'],
        'properties': {'question': {'type': 'string'}, 'approved': constraint}}
    spec, raw, catalog = schema_verification_case(tmp_path, {'application/json': {'schema': body_schema}})
    spec['transport']['request']['body']['json']['approved'] = {'literal': actual}
    result = await verify(spec, raw, catalog=catalog)
    assert result.status == ('verified' if valid else 'failed'), result.as_dict()
    if not valid:
        assert 'request_schema_invalid' in result.checks
        assert not result.semantic_success


@pytest.mark.parametrize('composition', [None, 'allOf', 'anyOf', 'oneOf'])
async def test_nullable_extends_type_without_bypassing_other_constraints(tmp_path, composition):
    constraint = {'type': 'string', 'nullable': True}
    if composition: constraint[composition] = [{'enum': ['allowed']}]
    body_schema = {'type': 'object', 'required': ['question', 'approved'],
        'properties': {'question': {'type': 'string'}, 'approved': constraint}}
    spec, raw, catalog = schema_verification_case(tmp_path, {'application/json': {'schema': body_schema}})
    spec['transport']['request']['body']['json']['approved'] = {'literal': None}
    result = await verify(spec, raw, catalog=catalog)
    assert result.status == ('failed' if composition else 'verified'), result.as_dict()
    if composition: assert 'request_schema_invalid' in result.checks


@pytest.mark.parametrize('value', ['NaN', 'Infinity', '-Infinity', '1e999', '1.0'])
async def test_converted_query_numbers_must_be_finite(tmp_path, value):
    content = agent_document()['paths']['/ask']['post']['requestBody']['content']
    spec, raw, catalog = schema_verification_case(tmp_path, content, parameters=[
        {'in': 'query', 'name': 'score', 'required': True, 'schema': {'type': 'number'}}])
    spec['transport']['request']['query'] = {'score': {'literal': value}}
    result = await verify(spec, raw, catalog=catalog)
    assert result.status == ('verified' if value == '1.0' else 'failed'), result.as_dict()
    if value != '1.0': assert 'request_schema_invalid' in result.checks


async def test_independent_json_reply_cannot_ignore_declared_other_media(tmp_path):
    document = agent_document()
    document['paths']['/ask']['post']['responses']['200']['content'] = {
        'text/plain': {'schema': {'type': 'string', 'minLength': 100}}}
    content = document['paths']['/ask']['post']['requestBody']['content']
    spec, raw, _ = schema_verification_case(tmp_path, content)
    catalog = catalog_operations(load_openapi(input_file(tmp_path, document)))
    result = await verify(spec, raw, catalog=catalog)
    assert result.status == 'failed', result.as_dict()
    assert 'schema_mock_unsupported' in result.checks
    assert not result.semantic_success


@pytest.mark.parametrize('malformed', [False, True])
async def test_absent_response_schema_is_distinct_from_invalid_null(tmp_path, malformed):
    document = agent_document()
    document['paths']['/ask']['post']['responses']['200']['content']['application/json'] = {'schema': None} if malformed else {}
    content = document['paths']['/ask']['post']['requestBody']['content']
    spec, raw, _ = schema_verification_case(tmp_path, content)
    catalog = catalog_operations(load_openapi(input_file(tmp_path, document)))
    result = await verify(spec, raw, catalog=catalog)
    assert result.status == ('failed' if malformed else 'verified'), result.as_dict()
    if malformed: assert 'response_schema_invalid' in result.checks


@pytest.mark.parametrize('changed', ['id', 'method', 'path'])
def test_scenario_operations_must_agree_with_independent_catalog(tmp_path, changed):
    parser = importlib.import_module('argus.drafting.scenario')
    catalog = api(tmp_path)
    raw = scenario()
    assert parser.parse_scenario(raw, catalog=catalog).operations[0].id == 'ask'
    raw['operations'][0][changed] = {'id': 'other', 'method': 'GET', 'path': '/other'}[changed]
    with pytest.raises(ValueError, match='scenario_invalid'):
        parser.parse_scenario(raw, catalog=catalog)


def test_scenario_operation_ids_are_unique_across_distinct_routes():
    parser = importlib.import_module('argus.drafting.scenario')
    raw = scenario([operation(checks=[check()]), operation('prepare', 'GET', '/prepare', 'setup')])
    assert len(parser.parse_scenario(raw).operations) == 2
    raw['operations'][1]['id'] = 'ask'
    with pytest.raises(ValueError, match='scenario_invalid'):
        parser.parse_scenario(raw)


def test_scenario_routes_are_unique_after_parameter_normalization():
    parser = importlib.import_module('argus.drafting.scenario')
    raw = scenario([operation(path='/tasks/{first}', checks=[check()]),
                    operation('prepare', 'GET', '/tasks/{second}', 'setup')])
    assert len(parser.parse_scenario(raw).operations) == 2
    raw['operations'][1]['method'] = 'POST'
    with pytest.raises(ValueError, match='scenario_invalid'):
        parser.parse_scenario(raw)


@pytest.mark.parametrize('duplicate', ['resources', 'finals', 'missing_final', 'extra_final'])
def test_scenario_resource_and_final_tables_have_unique_matching_identities(duplicate):
    parser = importlib.import_module('argus.drafting.scenario')
    raw = scenario(resources=[{'id': 'item', 'initial': 'live', 'cleanup': 'pause'}],
                   final=[{'id': 'item', 'final': 'live'}])
    assert parser.parse_scenario(raw).resources[0].id == 'item'
    if duplicate == 'resources': raw['resources'].append(copy.deepcopy(raw['resources'][0]))
    if duplicate == 'finals': raw['expect']['resources'].append(copy.deepcopy(raw['expect']['resources'][0]))
    if duplicate == 'missing_final': raw['expect']['resources'] = []
    if duplicate == 'extra_final': raw['expect']['resources'].append({'id': 'other', 'final': 'absent'})
    error = None
    try:
        parser.parse_scenario(raw)
    except Exception as exc:
        error = exc
    assert isinstance(error, ValueError) and 'scenario_invalid' in str(error)


@pytest.mark.parametrize('kind', ['query', 'multipart_text', 'multipart_file'])
async def test_independent_request_selectors_reject_duplicate_values(kind):
    from aiohttp import ClientSession, FormData
    module = importlib.import_module('argus.cli.verify_local')
    parser = importlib.import_module('argus.drafting.scenario')
    selector = {'name': 'goal'}
    if kind == 'multipart_file': selector['filename'] = 'sample.txt'
    raw = scenario([operation(checks=[check(kind=kind, **selector)])])
    for copies, expected in [(1, 200), (2, 400)]:
        async with module.LocalFake(None, parser.parse_scenario(raw)) as fake:
            async with ClientSession() as session:
                if kind == 'query':
                    request = session.post(fake.origin + '/ask', params=[('goal', 'ping')] * copies)
                else:
                    form = FormData()
                    for _ in range(copies):
                        if kind == 'multipart_file': form.add_field('goal', b'ping', filename='sample.txt')
                        else: form.add_field('goal', 'ping', content_type='text/plain')
                    request = session.post(fake.origin + '/ask', data=form)
                async with request as response:
                    assert response.status == expected
                    await response.read()
            assert fake.failures == ([] if copies == 1 else ['prompt_not_bound'])


@pytest.mark.parametrize('kind', ['symlink', 'directory', 'oversized'])
def test_scenario_file_admission_rejects_before_open(tmp_path, monkeypatch, kind):
    parser = importlib.import_module('argus.drafting.scenario')
    valid = tmp_path / 'scene.json'
    valid.write_text(json.dumps(scenario()))
    assert parser.read_scenario(valid).operations[0].id == 'ask'
    rejected = tmp_path / 'rejected.json'
    if kind == 'symlink': rejected.symlink_to(valid)
    elif kind == 'directory': rejected.mkdir()
    else: rejected.write_bytes(valid.read_bytes() + b' ' * parser.MAX_SCENARIO_BYTES)
    original_open = Path.open
    def bounded_open(path, *args, **kwargs):
        assert path != rejected, 'rejected scenario must not be opened'
        return original_open(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'open', bounded_open)
    with pytest.raises(ValueError, match='scenario_invalid'):
        parser.read_scenario(rejected)


def test_scenario_file_actual_read_bound_survives_stale_size_metadata(tmp_path, monkeypatch):
    from types import SimpleNamespace
    parser = importlib.import_module('argus.drafting.scenario')
    path = tmp_path / 'scene.json'
    encoded = json.dumps(scenario()).encode()
    path.write_bytes(encoded)
    assert parser.read_scenario(path).operations[0].id == 'ask'
    path.write_bytes(encoded + b' ' * parser.MAX_SCENARIO_BYTES)
    original_stat = Path.stat
    def stale_stat(item, *args, **kwargs):
        actual = original_stat(item, *args, **kwargs)
        return SimpleNamespace(st_mode=actual.st_mode, st_size=len(encoded)) if item == path else actual
    monkeypatch.setattr(Path, 'stat', stale_stat)
    with pytest.raises(ValueError, match='scenario_invalid'):
        parser.read_scenario(path)


def test_scenario_file_duplicate_json_keys_are_rejected(tmp_path):
    parser = importlib.import_module('argus.drafting.scenario')
    path = tmp_path / 'scene.json'
    encoded = json.dumps(scenario())
    path.write_text(encoded)
    assert parser.read_scenario(path).operations[0].id == 'ask'
    path.write_text(encoded.replace('"version": 1', '"version": 1, "version": 1', 1))
    with pytest.raises(ValueError, match='scenario_invalid'):
        parser.read_scenario(path)


@pytest.mark.parametrize('bad', ['', 'Upper', 'bad-name', 'a' * 65])
def test_scenario_internal_names_are_bounded_and_valid(bad):
    parser = importlib.import_module('argus.drafting.scenario')
    good = 'a' * 64
    raw = scenario(resources=[{'id': good, 'initial': 'live', 'cleanup': 'pause'}],
                   final=[{'id': good, 'final': 'live'}])
    assert parser.parse_scenario(raw).resources[0].id == good
    raw['resources'][0]['id'] = raw['expect']['resources'][0]['id'] = bad
    with pytest.raises(ValueError, match='scenario_invalid'):
        parser.parse_scenario(raw)


@pytest.mark.parametrize('bad', ['', 1, 'line\nbreak', 'é' * 1025])
def test_scenario_text_is_nonempty_printable_and_utf8_bounded(bad):
    parser = importlib.import_module('argus.drafting.scenario')
    raw = scenario()
    raw['source']['document'] = 'é' * 1024
    assert parser.parse_scenario(raw).source['document'] == 'é' * 1024
    raw['source']['document'] = bad
    with pytest.raises(ValueError, match='scenario_invalid'):
        parser.parse_scenario(raw)


@pytest.mark.parametrize('field,bad', [('min', True), ('min', -1), ('status', 99), ('status', 600)])
def test_scenario_integer_fields_use_exact_types_and_closed_bounds(field, bad):
    parser = importlib.import_module('argus.drafting.scenario')
    raw = scenario()
    for status in (100, 599):
        raw['operations'][0]['replies'][0]['status'] = status
        assert parser.parse_scenario(raw).operations[0].replies[0].status == status
    if field == 'status': raw['operations'][0]['replies'][0]['status'] = bad
    else: raw['operations'][0]['calls'][field] = bad
    with pytest.raises(ValueError, match='scenario_invalid'):
        parser.parse_scenario(raw)
