import copy
import json

import pytest
from aiohttp import web
from click.testing import CliRunner

from argus.cli.__main__ import main
from argus_transport import ExecutionPolicy, TransportContext, TransportSpecV2, V2Run, with_origin
from test_draft_bindings import artifacts, codes, draft
from transport_v2_fakes import RecordingApp, serve

SUBMIT = '/orgs/{o}/ws/{w}/autos/{a}:invoke'
POLL = '/orgs/{o}/ws/{w}/autos/{a}/runs/{r}'
FORMAT = 'orgs/{organization}/ws/{workspace}/autos/{automation}/runs/{run}'
NAME = 'orgs/org-1/ws/ws-1/autos/auto-1/runs/run-1'


def parameter(name, kind='string'):
    return {'name': name, 'in': 'path', 'required': True, 'schema': {'type': kind}}


def document(*, resource=True, extra=False):
    submit, poll = SUBMIT, POLL
    names = ['o', 'w', 'a']
    if extra:
        submit, poll = '/regions/{region}' + submit, '/regions/{region}' + poll
        names = ['region', *names]
    def response(fields, status='200'):
        return {status: {'description': 'Result', 'content': {'application/json': {'schema': {
            'type': 'object', 'properties': fields}}}}}
    fields = {'status': {'type': 'string', 'enum': ['PENDING', 'COMPLETED', 'FAILED']},
              'result': {'type': 'string'}}
    if resource:
        fields['name'] = {'type': 'string', 'description': 'Format: ' + ('regions/{region}/' if extra else '') + FORMAT}
    else:
        fields['r'] = {'type': 'string'}
    return {'openapi': '3.0.3', 'info': {'title': 'Neutral path runner', 'version': '1'},
            'servers': [{'url': 'http://127.0.0.1:8123'}], 'paths': {
                submit: {'post': {'operationId': 'invoke', 'parameters': [parameter(n) for n in names],
                    'requestBody': {'required': True, 'content': {'application/json': {'schema': {
                        'type': 'object', 'required': ['question'], 'properties': {'question': {'type': 'string'}}}}}},
                    'responses': response({'r': {'type': 'string'}}, '202')}},
                poll: {'get': {'operationId': 'get_run', 'parameters': [parameter(n) for n in [*names, 'r']],
                              'responses': response(fields)}}}}


def poll_fields(doc):
    op = next(v['get'] for v in doc['paths'].values() if 'get' in v)
    return op['responses']['200']['content']['application/json']['schema']['properties']


def run(tmp_path, doc=None, bindings=None, *opts):
    return draft(tmp_path, doc or document(), bindings, '--operation', 'invoke', '--poll-operation', 'get_run', *opts)




def run_with_explicit_parents(tmp_path, doc=None, bindings=None, *opts):
    doc = doc or document()
    supplied = copy.deepcopy(bindings or {})
    poll = supplied.get('poll', {'operation': 'get_run'})
    if isinstance(poll, str): poll = {'operation': poll}
    present = {parameter['name'] for path in doc['paths'].values() for parameter in path.get('get', {}).get('parameters', [])}
    parents = {name: name for name in ('o', 'w', 'a', 'region', 'input_o') if name in present}
    supplied['poll'] = {**poll, 'parameters': {**parents, **poll.get('parameters', {})}}
    return run(tmp_path, doc, supplied, *opts)


def single_id_document():
    doc = document(resource=False)
    submit = doc['paths'][SUBMIT]['post']
    submit['parameters'] = []
    poll = doc['paths'][POLL]['get']
    poll['parameters'] = [parameter('r')]
    doc['paths'] = {'/runs': {'post': submit}, '/runs/{r}': {'get': poll}}
    return doc


def explicit_choices(tmp_path, doc=None):
    from argus.drafting.bindings import read_bindings
    from argus.drafting.draft import choose_without_model
    from test_draft_async import catalog_for
    catalog = catalog_for(tmp_path, doc or document())
    path = tmp_path / 'explicit-bindings.json'
    path.write_text(json.dumps({'version': 1, 'poll': {'operation': 'get_run', 'parameters': {
        name: name for name in ('o', 'w', 'a')}}}))
    return catalog, choose_without_model(catalog, operation='invoke', poll_operation='get_run', inputs=read_bindings(path))


def test_same_named_parent_parameters_require_explicit_mappings(tmp_path):
    result, out = run(tmp_path)
    assert result.exit_code == 3, result.output
    spec, report, provenance = artifacts(out)
    assert spec is None and 'poll_id_binding_missing' in codes(report, True)


def test_many_parent_parameters_require_explicit_mappings(tmp_path):
    result, out = run(tmp_path, document(extra=True))
    assert result.exit_code == 3, result.output
    spec, report, _ = artifacts(out)
    assert spec is None and 'poll_id_binding_missing' in codes(report, True)


def renamed(doc):
    op = doc['paths'].pop(POLL)['get']
    for p in op['parameters']:
        if p['name'] == 'o': p['name'] = 'organization'
    doc['paths'][POLL.replace('{o}', '{organization}')] = {'get': op}
    return doc


def test_explicit_mapping_and_extraction_have_file_provenance(tmp_path):
    bindings = {'poll': {'operation': 'get_run', 'parameters': {'organization': 'o'}},
                'ids': {'r': {'last_segment': True, 'origin': 'gold_derived'}}}
    result, out = run_with_explicit_parents(tmp_path, renamed(document()), bindings)
    assert result.exit_code == 3, result.output
    spec, report, provenance = artifacts(out)
    assert spec is not None and codes(report, True) == []
    assert '{input_o}' in spec['transport']['delivery']['request']['url']
    records = provenance['fields']
    assert records['/transport/delivery/ids/r/last_segment']['origin'] == 'gold_derived'
    assert records['/transport/delivery/request/url/organization']['basis'] == 'user_selection'
    assert {'file': 'bindings.json', 'pointer': '/poll/parameters/organization'} in records['/transport/delivery/request/url/organization']['source']


def test_file_poll_string_selects_the_operation(tmp_path):
    result, out = draft(tmp_path, single_id_document(), {'poll': 'get_run'}, '--operation', 'invoke')
    assert result.exit_code == 3, result.output
    spec, report, _ = artifacts(out)
    assert spec is not None and 'poll_proposed' not in codes(report)


@pytest.mark.parametrize('bindings,pointer', [
    ({'poll': None}, '/poll'), ({'poll': ''}, '/poll'), ({'poll': '  '}, '/poll'), ({'poll': {}}, '/poll'),
    ({'poll': {'operation': 1}}, '/poll'),
    ({'poll': {'operation': 'get_run', 'parameters': {'': 'o'}}}, '/poll/parameters/'),
    ({'poll': {'operation': 'get_run', 'parameters': {'o': ''}}}, '/poll/parameters/o'),
    ({'ids': {'': {'last_segment': True}}}, '/ids/'),
    ({'poll': {'operation': 'get_run', 'parameters': None}}, '/poll/parameters'),
    ({'poll': {'operation': 'get_run', 'parameters': {'o': 1}}}, '/poll/parameters/o'),
    ({'poll': {'operation': 'get_run', 'parameters': {'token': 'o'}}}, '/poll/parameters/token'),
    ({'poll': {'operation': 'get_run', 'parameters': {'o': 'secret'}}}, '/poll/parameters/o'),
    ({'poll': {'operation': 'get_run', 'extra': True}}, '/poll'),
    ({'ids': None}, '/ids'), ({'ids': {'r': None}}, '/ids/r'),
    ({'ids': {'r': {'last_segment': 1}}}, '/ids/r'),
    ({'ids': {'r': {'last_segment': None}}}, '/ids/r'),
    ({'ids': {'r': {}}}, '/ids/r'),
    ({'ids': {'r': {'last_segment': True, 'origin': 1}}}, '/ids/r'),
    ({'ids': {'r': {'last_segment': True, 'prefix': 'x'}}}, '/ids/r'),
    ({'ids': {'token': {'last_segment': True}}}, '/ids/token'),
])
def test_malformed_new_binding_entries_are_usage_errors(tmp_path, bindings, pointer):
    result, out = run(tmp_path, bindings=bindings)
    assert result.exit_code == 2
    assert pointer in result.output and 'only version' not in result.output
    assert not out.exists() and not out.with_suffix('.gaps.json').exists()


@pytest.mark.parametrize('bindings,pointer', [
    ({'poll': 'missing'}, '/poll'),
    ({'poll': {'operation': 'get_run', 'parameters': {'o': 'missing'}}}, '/poll/parameters/o'),
    ({'poll': {'operation': 'get_run', 'parameters': {'missing': 'o'}}}, '/poll/parameters/missing'),
    ({'ids': {'missing': {'last_segment': True}}}, '/ids/missing'),
    ({'poll': 'another'}, '/poll'),
])
def test_document_relative_bindings_block_with_file_pointer(tmp_path, bindings, pointer):
    result, out = run(tmp_path, bindings=bindings)
    assert result.exit_code == 3, result.output
    spec, report, _ = artifacts(out)
    assert spec is None and 'binding_unresolved' in codes(report, True)
    assert any({'file': 'bindings.json', 'pointer': pointer} in gap['source'] for gap in report['gaps'] if gap['blocking'])


def test_incompatible_same_named_path_does_not_fall_back_to_response(tmp_path):
    doc = document(resource=False)
    doc['paths'][SUBMIT]['post']['responses']['202']['content']['application/json']['schema']['properties']['o'] = {'type': 'string'}
    doc['paths'][SUBMIT]['post']['parameters'][0]['schema']['type'] = 'integer'
    result, out = run_with_explicit_parents(tmp_path, doc)
    assert result.exit_code == 3, result.output
    assert artifacts(out)[0] is None and 'poll_id_binding_missing' in codes(artifacts(out)[1], True)


def test_unmappable_poll_parameter_blocks(tmp_path):
    result, out = run(tmp_path, renamed(document()))
    assert result.exit_code == 3
    assert artifacts(out)[0] is None and 'poll_id_binding_missing' in codes(artifacts(out)[1], True)


def test_all_carried_get_cannot_identify_submitted_job(tmp_path):
    doc = document(resource=False)
    op = doc['paths'].pop(POLL)['get']
    op['parameters'].pop()
    doc['paths']['/orgs/{o}/ws/{w}/autos/{a}'] = {'get': op}
    result, out = run(tmp_path, doc)
    assert result.exit_code == 3
    assert artifacts(out)[0] is None and 'poll_id_binding_missing' in codes(artifacts(out)[1], True)


@pytest.mark.parametrize('fmt', ['foreign/{o}/runs/{r}', 'orgs/{o}/ws/{w}/autos/{a}/runs/{r}/extra',
                                 'orgs/{o}/ws/{w}/autos/{a}/runs/', 'orgs/{o}/ws/{w}/autos/{a}/runs/{r',
                                 'https://127.0.0.1/orgs/{o}/ws/{w}/autos/{a}/runs/{r}',
                                 '../orgs/{o}/ws/{w}/autos/{a}/runs/{r}', ''])
def test_a_claimed_but_unusable_resource_format_blocks(tmp_path, fmt):
    doc = document()
    poll_fields(doc)['name']['description'] = 'Format: ' + fmt
    result, out = run_with_explicit_parents(tmp_path, doc)
    assert result.exit_code == 3, result.output
    assert artifacts(out)[0] is None and 'poll_resource_format_unsupported' in codes(artifacts(out)[1], True)


def test_conflicting_documented_resource_formats_block(tmp_path):
    doc = document()
    poll_fields(doc)['name']['title'] = 'Format: ws/{w}/autos/{a}/runs/{r}'
    result, out = run_with_explicit_parents(tmp_path, doc)
    assert result.exit_code == 3
    assert artifacts(out)[0] is None and 'poll_resource_format_unsupported' in codes(artifacts(out)[1], True)


def test_integer_id_cannot_use_resource_extraction(tmp_path):
    doc = document()
    doc['paths'][SUBMIT]['post']['responses']['202']['content']['application/json']['schema']['properties']['r']['type'] = 'integer'
    doc['paths'][POLL]['get']['parameters'][-1]['schema']['type'] = 'integer'
    result, out = run_with_explicit_parents(tmp_path, doc, {'ids': {'r': {'last_segment': True}}})
    assert result.exit_code == 3
    assert artifacts(out)[0] is None and 'binding_unresolved' in codes(artifacts(out)[1], True)


def test_ordinary_ids_do_not_gain_last_segment_and_unchecked_identity_is_reported(tmp_path):
    doc = document(resource=False)
    del poll_fields(doc)['r']
    result, out = run_with_explicit_parents(tmp_path, doc)
    assert result.exit_code == 3
    spec, report, _ = artifacts(out)
    assert spec is not None and spec['transport']['delivery']['ids']['r'] == {'path': '$.r'}
    assert 'poll_identity_unchecked' in codes(report, False)


def test_explicit_false_preserves_raw_capture_and_documented_identity(tmp_path):
    result, out = run_with_explicit_parents(tmp_path, bindings={'ids': {'r': {'last_segment': False}}})
    assert result.exit_code == 3, result.output
    selector = artifacts(out)[0]['transport']['delivery']['ids']['r']
    assert not selector.get('last_segment', False) and 'expect_prefix' not in selector
    assert selector['poll']['last_segment'] is True


def test_presence_completion_remains_the_only_blocker_after_pairing(tmp_path):
    doc = document()
    fields = poll_fields(doc)
    del fields['status']; del fields['result']
    fields['state'] = {'type': 'object', 'properties': {'completed': {'type': 'object', 'properties': {'outputs': {'type': 'string'}}}}}
    result, out = run_with_explicit_parents(tmp_path, doc, {'reply': {'path': '/state/completed/outputs'}})
    assert result.exit_code == 3, result.output
    spec, report, provenance = artifacts(out)
    assert spec is None and codes(report, True) == ['async_shape_unsupported']
    assert provenance['fields']['/transport/response/text']['basis'] == 'user_selection'


def scenario():
    checks = [{'check': 'poll_identity', 'at': {'kind': 'path', 'name': name}, 'equals': value}
              for name, value in [('o', 'org-1'), ('w', 'ws-1'), ('a', 'auto-1'), ('r', 'run-1')]]
    return {'version': 2, 'environment': {'TARGET_INPUT_O': 'org-1', 'TARGET_INPUT_W': 'ws-1', 'TARGET_INPUT_A': 'auto-1'},
            'source': {'document': 'Independent neutral scenario', 'pointers': ['/paths']}, 'resources': [],
            'operations': [
                {'id': 'invoke', 'method': 'POST', 'path': SUBMIT, 'role': 'invoke', 'calls': {'min': 1, 'max': 1},
                 'request': [{'check': 'prompt_bound', 'at': {'kind': 'json', 'pointer': '/question'}, 'equals': 'ping'}],
                 'replies': [{'status': 202, 'body': {'r': NAME}, 'effects': []}]},
                {'id': 'get_run', 'method': 'GET', 'path': POLL, 'role': 'poll', 'calls': {'min': 1, 'max': 1}, 'request': checks,
                 'replies': [{'status': 200, 'body': {'name': NAME, 'status': 'COMPLETED', 'result': 'pong'}, 'effects': []}]}],
            'expect': {'outcome': 'succeeded', 'reply': 'pong', 'resources': [], 'required_gaps': []}}


def test_verify_local_does_not_run_implicit_nested_carries(tmp_path):
    p = tmp_path / 'scenario.json'; p.write_text(json.dumps(scenario()))
    result, out = run(tmp_path, None, None, '--verify-local', '--scenario', str(p))
    assert result.exit_code == 3, result.output
    local = artifacts(out)[2]['validation']['local']
    assert local['semantic_success'] is False and local['status'] == 'not_run'
    assert artifacts(out)[0] is None


@pytest.mark.parametrize('resource,value,poll_name,outcome,reason,tail', [
    (True, NAME, NAME, 'succeeded', '', '/runs/run-1'),
    (True, NAME, NAME.replace('org-1', 'foreign'), 'target_error', 'poll_identity_changed', '/runs/run-1'),
    (True, NAME, NAME.replace('run-1', 'run-2'), 'target_error', 'poll_identity_changed', '/runs/run-1'),
    (False, 'run/part', 'run/part', 'succeeded', '', '/runs/run%2Fpart'),
])
async def test_runtime_identity_and_encoded_id(tmp_path, resource, value, poll_name, outcome, reason, tail):
    result, out = run_with_explicit_parents(tmp_path, document(resource=resource))
    assert result.exit_code == 3, result.output
    spec = artifacts(out)[0]
    assert spec is not None
    seen = []
    app = RecordingApp()
    async def submitted(request): return web.json_response({'r': value}, status=202)
    async def polled(request):
        seen.append(request.raw_path)
        return web.json_response({'name' if resource else 'r': poll_name, 'status': 'COMPLETED', 'result': 'pong'})
    app.route('POST', '/{tail:.*}', submitted); app.route('GET', '/{tail:.*}', polled)
    async with serve(app) as origin:
        data = with_origin(copy.deepcopy(spec['transport']), origin)
        parsed = TransportSpecV2.from_dict(data)
        runtime = V2Run(parsed, policy=ExecutionPolicy.local(parsed), environ=scenario()['environment'])
        try:
            response = await runtime.attempt(TransportContext(prompt='ping'))
        finally:
            await runtime.close()
    assert response.outcome == outcome
    if reason: assert response.reason_code.value == reason
    assert seen == ['/orgs/org-1/ws/ws-1/autos/auto-1' + tail]


def test_unconsumed_id_entry_on_a_synchronous_document_blocks(tmp_path):
    doc = document(resource=False)
    del doc['paths'][POLL]
    body = doc['paths'][SUBMIT]['post']['responses']
    body['200'] = body.pop('202')
    body['200']['content']['application/json']['schema']['properties']['result'] = {'type': 'string'}
    result, out = draft(tmp_path, doc, {'ids': {'r': {'last_segment': True}}}, '--operation', 'invoke')
    assert result.exit_code == 3
    assert artifacts(out)[0] is None and 'binding_unresolved' in codes(artifacts(out)[1], True)


@pytest.mark.parametrize('change', ['read_only_name', 'object_name', 'prefix_uses_response', 'five_response_ids', 'duplicate_response_id'])
def test_identity_and_capture_guards_block_unsupported_shapes(tmp_path, change):
    doc = document()
    submit = doc['paths'][SUBMIT]['post']
    poll = doc['paths'][POLL]['get']
    fields = poll_fields(doc)
    if change == 'read_only_name': fields['name']['writeOnly'] = True
    if change == 'object_name': fields['name']['type'] = 'object'
    if change == 'prefix_uses_response':
        submit['parameters'].pop(1)
        submit['responses']['202']['content']['application/json']['schema']['properties']['w'] = {'type': 'string'}
        doc['paths'][SUBMIT.replace('/ws/{w}', '/ws')] = doc['paths'].pop(SUBMIT)
    if change == 'five_response_ids':
        fields.pop('name')
        original = doc['paths'].pop(POLL)
        path = POLL
        for index in range(4):
            name = 'job' + str(index)
            path += '/{' + name + '}'
            poll['parameters'].append(parameter(name))
            submit['responses']['202']['content']['application/json']['schema']['properties'][name] = {'type': 'string'}
        doc['paths'][path] = original
    if change == 'duplicate_response_id':
        fields.pop('name')
        original = doc['paths'].pop(POLL)
        poll['parameters'][-1]['name'] = 'id'
        poll['parameters'].append(parameter('job_id'))
        submit['responses']['202']['content']['application/json']['schema']['properties'] = {'job_id': {'type': 'string'}}
        doc['paths'][POLL.replace('{r}', '{id}') + '/{job_id}'] = original
    result, out = run_with_explicit_parents(tmp_path, doc)
    assert result.exit_code == 3, result.output
    assert artifacts(out)[0] is None
    assert set(codes(artifacts(out)[1], True)) & {'poll_resource_format_unsupported', 'poll_id_binding_missing'}


def test_one_response_parent_does_not_supply_missing_other_parents(tmp_path):
    doc = document(resource=False)
    doc['paths'][SUBMIT]['post']['responses']['202']['content']['application/json']['schema']['properties']['o'] = {'type': 'string'}
    result, out = run(tmp_path, doc)
    assert result.exit_code == 3
    spec, report, _ = artifacts(out)
    assert spec is None and 'poll_id_binding_missing' in codes(report, True)
    why = next(gap['why'] for gap in report['gaps'] if gap['code'] == 'poll_id_binding_missing')
    assert '{o}' not in why and '{w}' in why and '{a}' in why


def test_renamed_id_placeholder_is_not_rewritten_as_a_carried_placeholder(tmp_path):
    doc = document(resource=False)
    submit = doc['paths'].pop(SUBMIT)['post']
    submit['parameters'].append(parameter('run_id'))
    submit['responses']['202']['content']['application/json']['schema']['properties'] = {'job_id': {'type': 'string'}}
    doc['paths'][SUBMIT + '/{run_id}'] = {'post': submit}
    poll = doc['paths'].pop(POLL)['get']
    poll['parameters'][-1]['name'] = 'id'
    poll['parameters'].append(parameter('job_id'))
    submit['parameters'][-1]['name'] = 'job_id'
    doc['paths'][SUBMIT + '/{job_id}'] = doc['paths'].pop(SUBMIT + '/{run_id}')
    doc['paths'][POLL.replace('{r}', '{id}') + '/{job_id}'] = {'get': poll}
    result, out = run(tmp_path, doc)
    assert result.exit_code == 3, result.output
    spec, report, _ = artifacts(out)
    assert spec is None and 'poll_id_binding_missing' in codes(report, True)


def test_compile_rejects_a_forged_carried_binding(tmp_path):
    from dataclasses import replace
    from argus.drafting.draft import compile_draft
    catalog, choices = explicit_choices(tmp_path)
    carry = choices.delivery.carried
    broken = replace(carry[0], submit_parameter='w')
    with pytest.raises(ValueError, match='Carried poll parameter'):
        compile_draft(catalog, replace(choices, delivery=replace(choices.delivery, carried=(broken, *carry[1:]))))


def test_an_unsupported_identity_schema_is_in_the_read_set(tmp_path):
    doc = document()
    poll_fields(doc)['name']['not'] = {'const': 'foreign'}
    result, out = run_with_explicit_parents(tmp_path, doc)
    assert result.exit_code == 3
    spec, report, _ = artifacts(out)
    assert spec is None and 'operation_unsupported' in codes(report, True)


def test_two_presence_style_polls_remain_ambiguous(tmp_path):
    doc = single_id_document()
    fields = poll_fields(doc)
    fields.pop('status');fields['state'] = {'type': 'object'}
    other = copy.deepcopy(doc['paths']['/runs/{r}']);other['get']['operationId'] = 'get_other'
    doc['paths']['/runs/{r}/detail'] = other
    result, out = draft(tmp_path, doc, {'reply': {'path': '/result'}}, '--operation', 'invoke')
    assert result.exit_code == 3
    assert artifacts(out)[0] is None and 'poll_ambiguous' in codes(artifacts(out)[1], True)


def test_response_capture_type_mismatch_blocks(tmp_path):
    doc = document(resource=False)
    doc['paths'][POLL]['get']['parameters'][-1]['schema']['type'] = 'integer'
    result, out = run_with_explicit_parents(tmp_path, doc)
    assert result.exit_code == 3
    assert artifacts(out)[0] is None and 'poll_id_binding_missing' in codes(artifacts(out)[1], True)


def test_unknown_file_poll_without_cli_selection_blocks_at_file(tmp_path):
    result, out = draft(tmp_path, document(), {'poll': 'missing'}, '--operation', 'invoke')
    assert result.exit_code == 3
    spec, report, _ = artifacts(out)
    assert spec is None and 'binding_unresolved' in codes(report, True)
    assert any(gap['source'] == [{'file': 'bindings.json', 'pointer': '/poll'}] for gap in report['gaps'] if gap['code'] == 'binding_unresolved')


def test_conflicting_file_and_cli_polls_are_both_documented(tmp_path):
    doc = document(resource=False)
    other = copy.deepcopy(doc['paths'][POLL]);other['get']['operationId'] = 'get_other'
    doc['paths'][POLL + '/detail'] = other
    result, out = run(tmp_path, doc, {'poll': 'get_other'})
    assert result.exit_code == 3
    spec, report, _ = artifacts(out)
    assert spec is None and 'binding_unresolved' in codes(report, True)
    assert any(gap['source'] == [{'file': 'bindings.json', 'pointer': '/poll'}] for gap in report['gaps'] if gap['code'] == 'binding_unresolved')


def test_unsafe_literal_resource_segment_is_rejected_before_compiling(tmp_path):
    doc = document()
    poll = doc['paths'].pop(POLL)
    poll['get']['responses']['200']['content']['application/json']['schema']['properties']['name']['description'] = 'Format: @' + FORMAT
    doc['paths']['/@' + POLL.lstrip('/')] = poll
    result, out = run_with_explicit_parents(tmp_path, doc)
    assert result.exit_code == 3
    assert artifacts(out)[0] is None and 'poll_resource_format_unsupported' in codes(artifacts(out)[1], True)


def test_submit_and_poll_keep_distinct_shadowed_path_variables(tmp_path):
    doc = document(resource=False)
    submit = doc['paths'].pop(SUBMIT)
    submit['post']['parameters'].append(parameter('input_o'))
    doc['paths'][SUBMIT.replace('/orgs/{o}', '/orgs/{o}/shadows/{input_o}')] = submit
    poll = doc['paths'].pop(POLL)
    poll['get']['parameters'].append(parameter('input_o'))
    doc['paths'][POLL.replace('/orgs/{o}', '/orgs/{o}/shadows/{input_o}')] = poll
    result, out = run_with_explicit_parents(tmp_path, doc)
    assert result.exit_code == 3
    spec, report, _ = artifacts(out)
    assert spec is not None and codes(report, True) == []
    prefix = 'http://127.0.0.1:8123/orgs/{input_o}/shadows/{input_input_o}/ws/{input_w}/autos/{input_a}'
    assert spec['transport']['request']['url'] == prefix + ':invoke'
    assert spec['transport']['delivery']['request']['url'] == prefix + '/runs/{r}'


def test_enum_and_presence_style_polls_remain_ambiguous(tmp_path):
    doc = single_id_document()
    other = copy.deepcopy(doc['paths']['/runs/{r}'])
    other['get']['operationId'] = 'get_other'
    fields = other['get']['responses']['200']['content']['application/json']['schema']['properties']
    fields.pop('status')
    fields['state'] = {'type': 'object'}
    doc['paths']['/runs/{r}/detail'] = other
    result, out = draft(tmp_path, doc, {'reply': {'path': '/result'}}, '--operation', 'invoke')
    assert result.exit_code == 3
    spec, report, _ = artifacts(out)
    assert spec is None and 'poll_ambiguous' in codes(report, True)


@pytest.mark.parametrize('schema', [
    {'type': 'string', 'writeOnly': True},
    {'type': 'object'},
    {'type': 'integer'},
])
def test_incompatible_same_field_identity_is_reported_unchecked(tmp_path, schema):
    doc = document(resource=False)
    poll_fields(doc)['r'] = schema
    result, out = run_with_explicit_parents(tmp_path, doc)
    assert result.exit_code == 3
    spec, report, _ = artifacts(out)
    assert spec is not None and codes(report, True) == []
    assert 'poll_identity_unchecked' in codes(report)


def test_unsupported_same_field_identity_schema_blocks(tmp_path):
    doc = document(resource=False)
    poll_fields(doc)['r']['not'] = {'const': 'foreign'}
    result, out = run_with_explicit_parents(tmp_path, doc)
    assert result.exit_code == 3
    spec, report, _ = artifacts(out)
    assert spec is None and 'operation_unsupported' in codes(report, True)


def test_resource_format_without_prefix_blocks_with_named_gap(tmp_path):
    doc = document()
    poll_fields(doc)['name']['description'] = 'Format: {r}'
    result, out = run_with_explicit_parents(tmp_path, doc)
    assert result.exit_code == 3, result.output
    spec, report, _ = artifacts(out)
    assert spec is None and 'poll_resource_format_unsupported' in codes(report, True)


def test_submit_selector_uses_documented_poll_prefix(tmp_path):
    result, out = run_with_explicit_parents(tmp_path)
    assert result.exit_code == 3, result.output
    selector = artifacts(out)[0]['transport']['delivery']['ids']['r']
    assert selector['expect_prefix'] == {'concat': [
        {'literal': 'orgs/'}, {'var': 'input_o'}, {'literal': '/ws/'}, {'var': 'input_w'},
        {'literal': '/autos/'}, {'var': 'input_a'}, {'literal': '/runs/'}]}


async def submit_capture_attempt(tmp_path, value, *, bindings=None, force_prefix=False):
    result, out = run_with_explicit_parents(tmp_path, bindings=bindings)
    assert result.exit_code == 3, result.output
    spec = artifacts(out)[0]
    assert spec is not None
    data = copy.deepcopy(spec['transport'])
    if force_prefix:
        selector = data['delivery']['ids']['r']
        selector['expect_prefix'] = selector['poll']['expect_prefix']
    seen = []
    app = RecordingApp()
    async def submitted(request):
        seen.append(('POST', request.raw_path))
        return web.json_response({'r': value}, status=202)
    async def polled(request):
        seen.append(('GET', request.raw_path))
        return web.json_response({'name': request.path.lstrip('/'), 'status': 'COMPLETED', 'result': 'pong'})
    app.route('POST', '/{tail:.*}', submitted)
    app.route('GET', '/{tail:.*}', polled)
    async with serve(app) as origin:
        parsed = TransportSpecV2.from_dict(with_origin(data, origin))
        runtime = V2Run(parsed, policy=ExecutionPolicy.local(parsed), environ=scenario()['environment'])
        try:
            response = await runtime.attempt(TransportContext(prompt='ping'))
        finally:
            await runtime.close()
    return response, seen


@pytest.mark.parametrize('value', [
    NAME.replace('org-1', 'foreign'), NAME.replace('auto-1', 'foreign'),
    NAME + '/steps/7', 'run-1/7', 'run-1',
])
async def test_foreign_or_multi_segment_submit_cannot_succeed(tmp_path, value):
    response, seen = await submit_capture_attempt(tmp_path, value)
    assert response.outcome == 'target_error'
    assert response.reason_code.value == 'id_prefix_mismatch'
    assert seen == [('POST', '/orgs/org-1/ws/ws-1/autos/auto-1:invoke')]


async def test_own_full_submit_identity_still_succeeds(tmp_path):
    response, seen = await submit_capture_attempt(tmp_path, NAME)
    assert response.outcome == 'succeeded' and response.response_text == 'pong'
    assert seen == [('POST', '/orgs/org-1/ws/ws-1/autos/auto-1:invoke'),
                    ('GET', '/orgs/org-1/ws/ws-1/autos/auto-1/runs/run-1')]


async def test_explicit_false_bare_submit_succeeds_with_full_poll_identity(tmp_path):
    response, seen = await submit_capture_attempt(tmp_path, 'run-1', bindings={'ids': {'r': {'last_segment': False}}})
    assert response.outcome == 'succeeded' and response.response_text == 'pong'
    assert seen[-1] == ('GET', '/orgs/org-1/ws/ws-1/autos/auto-1/runs/run-1')


@pytest.mark.parametrize('suffix', ['run-1/steps/7', 'run-1/7', 'run%2F1', '', '!'])
async def test_prefixed_submit_capture_requires_one_id_segment(tmp_path, suffix):
    response, seen = await submit_capture_attempt(tmp_path, NAME.rsplit('/', 1)[0] + '/' + suffix, force_prefix=True)
    assert response.outcome == 'target_error'
    assert response.reason_code.value == 'id_prefix_mismatch'
    assert len(seen) == 1


def test_integer_id_cannot_use_inferred_resource_extraction(tmp_path):
    doc = document()
    doc['paths'][SUBMIT]['post']['responses']['202']['content']['application/json']['schema']['properties']['r']['type'] = 'integer'
    doc['paths'][POLL]['get']['parameters'][-1]['schema']['type'] = 'integer'
    result, out = run_with_explicit_parents(tmp_path, doc)
    assert result.exit_code == 3
    spec, report, _ = artifacts(out)
    assert spec is None
    assert 'poll_resource_id_type_unsupported' in codes(report, True)


@pytest.mark.parametrize('code', ['poll_id_extraction_proposed', 'poll_identity_unchecked', 'poll_resource_format_unsupported'])
def test_f4_gaps_give_specific_review_decisions(tmp_path, code):
    doc = document(resource=code != 'poll_identity_unchecked')
    if code == 'poll_identity_unchecked':
        del poll_fields(doc)['r']
    if code == 'poll_resource_format_unsupported':
        poll_fields(doc)['name']['description'] = 'Format: free text.'
    result, out = run_with_explicit_parents(tmp_path, doc)
    assert result.exit_code == 3
    report = artifacts(out)[1]
    entry = next(gap for gap in report['gaps'] if gap['code'] == code)
    assert 'before compiling the flow' not in entry['decision']
    assert entry['decision'].startswith(('Confirm', 'Review', 'Correct'))


@pytest.mark.parametrize('poll_id_documented', [True, False])
def test_explicit_extraction_without_documented_format_blocks(tmp_path, poll_id_documented):
    doc = document(resource=False)
    if not poll_id_documented:
        del poll_fields(doc)['r']
    result, out = run_with_explicit_parents(tmp_path, doc, {'ids': {'r': {'last_segment': True}}})
    assert result.exit_code == 3, result.output
    spec, report, _ = artifacts(out)
    assert spec is None
    gap = next(gap for gap in report['gaps'] if gap['code'] == 'binding_unresolved')
    assert gap['blocking'] is True
    assert gap['source'] == [{'file': 'bindings.json', 'pointer': '/ids/r'}]
    assert 'resource-name format is not documented' in gap['why']
    assert 'submit identity cannot be checked' in gap['why']
    assert gap['decision'].startswith('Correct the bindings file entry')


def test_explicit_extraction_with_documented_format_keeps_submit_prefix(tmp_path):
    result, out = run_with_explicit_parents(tmp_path, bindings={'ids': {'r': {'last_segment': True}}})
    assert result.exit_code == 3, result.output
    spec, report, _ = artifacts(out)
    assert spec is not None and codes(report, True) == []
    selector = spec['transport']['delivery']['ids']['r']
    assert selector['last_segment'] is True
    assert selector['expect_prefix'] == selector['poll']['expect_prefix']


async def test_explicit_false_without_format_accepts_bare_id(tmp_path):
    result, out = run_with_explicit_parents(tmp_path, document(resource=False), {'ids': {'r': {'last_segment': False}}})
    assert result.exit_code == 3, result.output
    spec, report, _ = artifacts(out)
    assert spec is not None and codes(report, True) == []
    assert spec['transport']['delivery']['ids']['r'] == {'path': '$.r'}
    seen = []
    app = RecordingApp()
    async def submitted(request):
        seen.append(('POST', request.raw_path))
        return web.json_response({'r': 'run-1'}, status=202)
    async def polled(request):
        seen.append(('GET', request.raw_path))
        return web.json_response({'r': 'run-1', 'status': 'COMPLETED', 'result': 'pong'})
    app.route('POST', '/{tail:.*}', submitted)
    app.route('GET', '/{tail:.*}', polled)
    async with serve(app) as origin:
        parsed = TransportSpecV2.from_dict(with_origin(copy.deepcopy(spec['transport']), origin))
        runtime = V2Run(parsed, policy=ExecutionPolicy.local(parsed), environ=scenario()['environment'])
        try:
            response = await runtime.attempt(TransportContext(prompt='ping'))
        finally:
            await runtime.close()
    assert response.outcome == 'succeeded' and response.response_text == 'pong'
    assert seen == [('POST', '/orgs/org-1/ws/ws-1/autos/auto-1:invoke'),
                    ('GET', '/orgs/org-1/ws/ws-1/autos/auto-1/runs/run-1')]


def test_shared_schema_constraints_have_unique_sources(tmp_path):
    doc = document(resource=False)
    doc['components'] = {'schemas': {'RunId': {'type': 'string', 'minLength': 1}}}
    schema = {'$ref': '#/components/schemas/RunId'}
    doc['paths'][SUBMIT]['post']['responses']['202']['content']['application/json']['schema']['properties']['r'] = schema
    poll_fields(doc)['r'] = copy.deepcopy(schema)
    result, out = run_with_explicit_parents(tmp_path, doc)
    assert result.exit_code == 3, result.output
    spec, report, _ = artifacts(out)
    assert spec is not None and codes(report, True) == []
    gap = next(gap for gap in report['gaps'] if gap['code'] == 'schema_constraints_unchecked')
    assert gap['source'] == [{'file': 'api.json', 'pointer': '/components/schemas/RunId'}]


@pytest.mark.parametrize('submit_id', ['run-1/7', NAME.replace('org-1', 'foreign')])
def test_unchecked_override_attack_scenarios_cannot_produce_specs(tmp_path, submit_id):
    attack = scenario()
    attack['operations'][0]['replies'][0]['body']['r'] = submit_id
    poll = attack['operations'][1]
    poll['request'][-1]['equals'] = submit_id.rsplit('/', 1)[-1]
    poll['replies'][0]['body'] = {'status': 'COMPLETED', 'result': 'pong'}
    path = tmp_path / 'attack-scenario.json'
    path.write_text(json.dumps(attack))
    result, out = run_with_explicit_parents(tmp_path, document(resource=False), {'ids': {'r': {'last_segment': True}}},
                      '--verify-local', '--scenario', str(path))
    spec, report, provenance = artifacts(out)
    assert spec is None
    assert result.exit_code == 3, result.output
    assert 'binding_unresolved' in codes(report, True)
    local = provenance['validation']['local']
    assert local['status'] == 'not_run' and local['semantic_success'] is False
    assert local['execution'] == {} and local['trace'] == []


def nested_parent_echo_document(has_run_id=True, suffix=''):
    doc = document(resource=False)
    submit = doc['paths'].pop(SUBMIT)['post']
    submit['parameters'] = [parameter('id')]
    fields = {'agentId': {'type': 'string'}}
    if has_run_id:
        fields['id'] = {'type': 'string'}
    submit['responses']['202']['content']['application/json']['schema']['properties'] = fields
    poll = doc['paths'].pop(POLL)['get']
    poll['parameters'] = [parameter('agentId'), parameter('id')]
    fields = poll['responses']['200']['content']['application/json']['schema']['properties']
    del fields['r']
    fields.update({'agentId': {'type': 'string'}, 'id': {'type': 'string'}})
    doc['paths']['/agents/{id}/runs'] = {'post': submit}
    doc['paths']['/agents/{agentId}/runs/{id}' + suffix] = {'get': poll}
    return doc


def parent_heuristic_document(poll_documents_parent=True):
    doc = document(resource=False)
    submit = doc['paths'].pop(SUBMIT)['post']
    submit['parameters'][-1]['name'] = 'auto_id'
    submit['responses']['202']['content']['application/json']['schema']['properties'] = {'auto_id': {'type': 'string'}}
    poll = doc['paths'].pop(POLL)['get']
    poll['parameters'][-2]['name'] = 'auto_id'
    poll['parameters'][-1]['name'] = 'id'
    fields = poll['responses']['200']['content']['application/json']['schema']['properties']
    del fields['r']
    if poll_documents_parent:
        fields['auto_id'] = {'type': 'string'}
    doc['paths']['/orgs/{o}/ws/{w}/autos/{auto_id}:invoke'] = {'post': submit}
    doc['paths']['/orgs/{o}/ws/{w}/autos/{auto_id}/runs/{id}'] = {'get': poll}
    return doc


def response_parent_and_run_document():
    doc = document(resource=False)
    submit = doc['paths'][SUBMIT]['post']
    submit['responses']['202']['content']['application/json']['schema']['properties']['q'] = {'type': 'string'}
    poll = doc['paths'].pop(POLL)['get']
    poll['parameters'].insert(-1, parameter('q'))
    poll['responses']['200']['content']['application/json']['schema']['properties']['q'] = {'type': 'string'}
    doc['paths'][POLL.replace('/runs/', '/q/{q}/runs/')] = {'get': poll}
    return doc


@pytest.mark.parametrize('has_run_id', [True, False])
def test_parent_name_collision_cannot_fill_run_slot(tmp_path, has_run_id):
    result, out = run(tmp_path, nested_parent_echo_document(has_run_id))
    assert result.exit_code == 3, result.output
    spec, report, _ = artifacts(out)
    assert spec is None and 'poll_id_binding_missing' in codes(report, True)


@pytest.mark.parametrize('poll_documents_parent', [True, False])
def test_parent_echo_heuristic_cannot_fill_run_slot(tmp_path, poll_documents_parent):
    result, out = run(tmp_path, parent_heuristic_document(poll_documents_parent))
    assert result.exit_code == 3, result.output
    spec, report, _ = artifacts(out)
    assert spec is None and 'poll_id_binding_missing' in codes(report, True)


def test_mapping_environment_input_into_run_slot_blocks(tmp_path):
    binding = {'poll': {'operation': 'get_run', 'parameters': {'r': 'a'}}}
    result, out = run(tmp_path, response_parent_and_run_document(), binding)
    assert result.exit_code == 3, result.output
    spec, report, _ = artifacts(out)
    assert spec is None and 'poll_id_binding_missing' in codes(report, True)
    assert any({'file': 'bindings.json', 'pointer': '/poll/parameters/r'} in gap['source']
               for gap in report['gaps'] if gap['blocking'])


@pytest.mark.parametrize('suffix', ['', '/result'])
def test_run_slot_collision_uses_url_order_not_parameter_order(tmp_path, suffix):
    doc = nested_parent_echo_document(suffix=suffix)
    poll = next(path['get'] for path in doc['paths'].values() if 'get' in path)
    poll['parameters'].reverse()
    result, out = run(tmp_path, doc)
    assert result.exit_code == 3, result.output
    spec, report, _ = artifacts(out)
    assert spec is None and 'poll_id_binding_missing' in codes(report, True)


@pytest.mark.parametrize('suffix', ['', '/result'])
def test_implicit_parent_carries_block_with_reordered_parameters(tmp_path, suffix):
    doc = document(resource=False)
    poll = doc['paths'].pop(POLL)['get']
    poll['parameters'].reverse()
    doc['paths'][POLL + suffix] = {'get': poll}
    result, out = run(tmp_path, doc)
    assert result.exit_code == 3, result.output
    spec, report, _ = artifacts(out)
    assert spec is None and 'poll_id_binding_missing' in codes(report, True)


def test_compile_rejects_forged_carried_run_slot(tmp_path):
    from dataclasses import replace
    from argus.drafting.draft import CarriedBinding, compile_draft
    catalog, choices = explicit_choices(tmp_path, document(resource=False))
    delivery = choices.delivery
    parent = next(item for item in delivery.carried if item.parameter == 'a')
    run = next(item for item in delivery.ids if item.parameter == 'r')
    poll = next(op for op in catalog.operations if op.id == 'get_run')
    at = next(index for index, parameter in enumerate(poll.data['parameters']) if parameter['name'] == 'r')
    carry = CarriedBinding('r', 'a', parent.submit_pointer, poll.pointer + '/parameters/' + str(at))
    forged = replace(delivery, ids=tuple(item for item in delivery.ids if item != run),
                     carried=(*delivery.carried, carry))
    with pytest.raises(ValueError, match='run slot'):
        compile_draft(catalog, replace(choices, delivery=forged))


def test_compile_rejects_forged_parent_echo_run_id(tmp_path):
    from dataclasses import replace
    from argus.drafting.draft import compile_draft
    doc = document(resource=False)
    doc['paths'][SUBMIT]['post']['responses']['202']['content']['application/json']['schema']['properties']['a'] = {'type': 'string'}
    catalog, choices = explicit_choices(tmp_path, doc)
    run = choices.delivery.ids[0]
    parent = replace(run.submit, path=('a',), pointer=run.submit.pointer.rsplit('/', 1)[0] + '/a')
    forged = replace(choices.delivery, ids=(replace(run, name='a', submit=parent),))
    with pytest.raises(ValueError, match='run slot'):
        compile_draft(catalog, replace(choices, delivery=forged))


def test_nested_id_named_heuristic_is_not_used(tmp_path):
    doc = document(resource=False)
    doc['paths'][SUBMIT]['post']['responses']['202']['content']['application/json']['schema']['properties'] = {'job_id': {'type': 'string'}}
    poll = doc['paths'].pop(POLL)['get']
    poll['parameters'][-1]['name'] = 'id'
    fields = poll['responses']['200']['content']['application/json']['schema']['properties']
    fields['job_id'] = fields.pop('r')
    doc['paths'][POLL.replace('{r}', '{id}')] = {'get': poll}
    result, out = run(tmp_path, doc)
    assert result.exit_code == 3, result.output
    spec, report, _ = artifacts(out)
    assert spec is None and 'poll_id_binding_missing' in codes(report, True)


def test_integer_resource_id_has_type_specific_review_text(tmp_path):
    doc = document()
    doc['paths'][SUBMIT]['post']['responses']['202']['content']['application/json']['schema']['properties']['r']['type'] = 'integer'
    doc['paths'][POLL]['get']['parameters'][-1]['schema']['type'] = 'integer'
    result, out = run_with_explicit_parents(tmp_path, doc)
    assert result.exit_code == 3, result.output
    spec, report, _ = artifacts(out)
    assert spec is None
    gap = next(gap for gap in report['gaps'] if gap['why'] == 'Resource-name extraction requires a string submit ID.')
    assert gap['code'] == 'poll_resource_id_type_unsupported'
    assert 'string' in gap['decision'] and 'Format' not in gap['decision']


def spelled_parent_document(case):
    doc = nested_parent_echo_document(False)
    submit = next(path['post'] for path in doc['paths'].values() if 'post' in path)
    poll = next(path['get'] for path in doc['paths'].values() if 'get' in path)
    if case.startswith('HP'):
        name = {'HP1': 'agent_id', 'HP1b': 'agent_id', 'HP2': 'AgentId', 'HP3': 'project'}[case]
        resource = 'projects' if case == 'HP3' else 'agents'
        field = 'project_id' if case == 'HP3' else 'agentId'
        submit['parameters'] = [parameter(name)]
        submit['responses']['202']['content']['application/json']['schema']['properties'] = {
            field: {'type': 'string'}, **({'run': {'type': 'string'}} if case == 'HP1b' else {})}
        poll['parameters'] = [parameter(name), parameter('id')]
        response = {'status': {'type': 'string', 'enum': ['PENDING', 'COMPLETED', 'FAILED']},
                    'result': {'type': 'string'}}
        if case != 'HP3': response[field] = {'type': 'string'}
        poll['responses']['200']['content']['application/json']['schema']['properties'] = response
        doc['paths'] = {'/' + resource + '/{' + name + '}/runs': {'post': submit},
                        '/' + resource + '/{' + name + '}/runs/{id}': {'get': poll}}
    else:
        submit['parameters'] = [parameter('id')]
        submit['responses']['202']['content']['application/json']['schema']['properties'] = {
            'message_id': {'type': 'string'}, **({'id': {'type': 'string'}} if case != 'NL1c' else {})}
        poll['parameters'] = [parameter('id'), parameter('message_id')]
        response = {'message_id': {'type': 'string'},
                    'status': {'type': 'string', 'enum': ['PENDING', 'COMPLETED', 'FAILED']},
                    'result': {'type': 'string'}}
        if case == 'NL1b': response['id'] = {'type': 'string'}
        poll['responses']['200']['content']['application/json']['schema']['properties'] = response
        doc['paths'] = {'/agents/{id}/sessions': {'post': submit},
                        '/sessions/{id}/messages/{message_id}': {'get': poll}}
    return doc


@pytest.mark.parametrize('case,parent', [
    ('HP1', 'agent_id'), ('HP1b', 'agent_id'), ('HP2', 'AgentId'), ('HP3', 'project'),
    ('NL1c', 'id'),
])
def test_nested_poll_without_exact_response_parent_requires_explicit_mapping(tmp_path, case, parent):
    result, out = run(tmp_path, spelled_parent_document(case))
    assert result.exit_code == 3, result.output
    spec, report, _ = artifacts(out)
    assert spec is None
    gap = next(gap for gap in report['gaps'] if gap['code'] == 'poll_id_binding_missing')
    assert '{' + parent + '}' in gap['why']
    assert 'explicit' in gap['why'] and 'mapping' in gap['why']
    assert 'No submit response field maps uniquely' not in gap['why']


def test_nested_heuristic_stays_blocked_with_explicit_parent_mapping(tmp_path):
    doc = spelled_parent_document('HP1')
    binding = {'poll': {'operation': 'get_run', 'parameters': {'agent_id': 'agent_id'}}}
    result, out = run(tmp_path, doc, binding)
    spec, report, _ = artifacts(out)
    assert result.exit_code == 3, result.output
    assert spec is None
    gap = next(gap for gap in report['gaps'] if gap['code'] == 'poll_id_binding_missing')
    assert '{id}' in gap['why'] and 'response ID' in gap['why']


def test_same_named_response_parents_fill_nested_poll_without_carries(tmp_path):
    doc = document(resource=False)
    doc['paths'][SUBMIT]['post']['responses']['202']['content']['application/json']['schema']['properties'].update({
        name: {'type': 'string'} for name in ('o', 'w', 'a')})
    result, out = run(tmp_path, doc)
    spec, report, _ = artifacts(out)
    assert result.exit_code == 3, result.output
    assert spec is not None and codes(report, True) == []
    assert set(spec['transport']['delivery']['ids']) == {'o', 'w', 'a', 'r'}
    assert spec['transport']['delivery']['request']['url'].endswith('/orgs/{o}/ws/{w}/autos/{a}/runs/{r}')


def test_explicit_nested_mappings_verify_local_with_response_run_id(tmp_path):
    binding = {'poll': {'operation': 'get_run', 'parameters': {
        name: name for name in ('o', 'w', 'a')}}}
    path = tmp_path / 'explicit-scenario.json'
    path.write_text(json.dumps(scenario()))
    result, out = run(tmp_path, None, binding, '--verify-local', '--scenario', str(path))
    assert result.exit_code == 3, result.output
    spec, report, provenance = artifacts(out)
    assert spec is not None and codes(report, True) == []
    assert list(spec['transport']['delivery']['ids']) == ['r']
    assert all(provenance['fields']['/transport/delivery/request/url/' + name]['basis'] == 'user_selection'
               for name in ('o', 'w', 'a'))
    local = provenance['validation']['local']
    assert local['status'] == 'verified' and local['semantic_success'] is True
    assert local['execution']['requests']['poll'] == 1


@pytest.mark.parametrize('change', ['missing_source', 'missing_inputs', 'response_parent'])
def test_compiler_rejects_implicit_nested_parent_ownership(tmp_path, change):
    from dataclasses import replace
    from argus.drafting.bindings import read_bindings
    from argus.drafting.draft import IdBinding, choose_without_model, compile_draft
    from test_draft_async import catalog_for
    doc = document(resource=False)
    doc['paths'][SUBMIT]['post']['responses']['202']['content']['application/json']['schema']['properties']['parent_id'] = {'type': 'string'}
    catalog = catalog_for(tmp_path, doc)
    binding = tmp_path / 'explicit.json'
    binding.write_text(json.dumps({'version': 1, 'poll': {'operation': 'get_run', 'parameters': {
        name: name for name in ('o', 'w', 'a')}}}))
    choices = choose_without_model(catalog, operation='invoke', poll_operation='get_run', inputs=read_bindings(binding))
    delivery = choices.delivery
    if change == 'missing_source':
        delivery = replace(delivery, carried=(replace(delivery.carried[0], source=None), *delivery.carried[1:]))
    elif change == 'missing_inputs':
        choices = replace(choices, inputs=None)
    else:
        run = delivery.ids[0]
        parent = replace(run.submit, path=('parent_id',), pointer=run.submit.pointer.rsplit('/', 1)[0] + '/parent_id')
        delivery = replace(delivery, ids=(*delivery.ids, IdBinding('parent_id', parent, 'o')),
                           carried=tuple(item for item in delivery.carried if item.parameter != 'o'))
    with pytest.raises(ValueError, match='explicit'):
        compile_draft(catalog, replace(choices, delivery=delivery))


def explicit_run_field_document():
    doc = document(resource=False)
    submit = doc['paths'][SUBMIT]['post']
    submit['responses']['202']['content']['application/json']['schema']['properties'] = {'resource': {'type': 'string'}}
    poll = doc['paths'].pop(POLL)['get']
    poll['parameters'][-1]['name'] = 'id'
    poll['responses']['200']['content']['application/json']['schema']['properties']['resource'] = poll_fields(document(resource=False))['r']
    del poll['responses']['200']['content']['application/json']['schema']['properties']['r']
    doc['paths'][POLL.replace('{r}', '{id}')] = {'get': poll}
    return doc


def test_nested_non_id_named_response_field_can_be_selected_explicitly(tmp_path):
    binding = {'poll': {'operation': 'get_run', 'parameters': {name: name for name in ('o', 'w', 'a')}},
               'ids': {'resource': {'last_segment': False, 'origin': 'gold_derived'}}}
    result, out = run(tmp_path, explicit_run_field_document(), binding)
    assert result.exit_code == 3, result.output
    spec, report, provenance = artifacts(out)
    assert spec is not None and codes(report, True) == []
    assert spec['transport']['delivery']['ids'] == {'resource': {'path': '$.resource'}}
    assert spec['transport']['delivery']['request']['url'].endswith('/runs/{resource}')
    source = provenance['fields']['/transport/delivery/ids/resource']
    assert source['basis'] == 'user_selection'
    assert {'file': 'bindings.json', 'pointer': '/ids/resource'} in source['source']
    gap = next(gap for gap in report['gaps'] if gap['field'] == '/transport/delivery/ids/resource')
    assert 'bindings file' in gap['why'] and 'by name' not in gap['why']


def test_multiple_explicit_run_fields_are_ambiguous(tmp_path):
    doc = explicit_run_field_document()
    doc['paths'][SUBMIT]['post']['responses']['202']['content']['application/json']['schema']['properties']['other'] = {'type': 'string'}
    binding = {'poll': {'operation': 'get_run', 'parameters': {name: name for name in ('o', 'w', 'a')}},
               'ids': {'resource': {'last_segment': False}, 'other': {'last_segment': False}}}
    result, out = run(tmp_path, doc, binding)
    spec, report, _ = artifacts(out)
    assert result.exit_code == 3, result.output
    assert spec is None and 'poll_id_binding_missing' in codes(report, True)


def test_explicit_parent_mappings_allow_more_than_four_total_placeholders(tmp_path):
    result, out = run_with_explicit_parents(tmp_path, document(extra=True))
    spec, report, _ = artifacts(out)
    assert result.exit_code == 3, result.output
    assert spec is not None and codes(report, True) == []
    assert list(spec['transport']['delivery']['ids']) == ['r']
    assert '{input_region}' in spec['transport']['delivery']['request']['url']


def test_single_placeholder_keeps_the_id_named_heuristic_and_accurate_text(tmp_path):
    doc = single_id_document()
    submit = doc['paths']['/runs']['post']
    submit['responses']['202']['content']['application/json']['schema']['properties'] = {'job_id': {'type': 'string'}}
    poll = doc['paths'].pop('/runs/{r}')['get']
    poll['parameters'] = [parameter('id')]
    fields = poll['responses']['200']['content']['application/json']['schema']['properties']
    fields['job_id'] = fields.pop('r')
    doc['paths']['/runs/{id}'] = {'get': poll}
    result, out = run(tmp_path, doc)
    spec, report, _ = artifacts(out)
    assert result.exit_code == 3, result.output
    assert spec is not None and codes(report, True) == []
    why = next(gap['why'] for gap in report['gaps'] if gap['code'] == 'poll_id_binding_proposed')
    assert 'proposed' in why and 'by name' not in why


def test_compiler_rejects_a_nested_heuristic_run_selector_without_explicit_selection(tmp_path):
    from dataclasses import replace
    from argus.drafting.draft import compile_draft
    doc = document(resource=False)
    doc['paths'][SUBMIT]['post']['responses']['202']['content']['application/json']['schema']['properties']['resource'] = {'type': 'string'}
    catalog, choices = explicit_choices(tmp_path, doc)
    run = choices.delivery.ids[0]
    response = replace(run.submit, path=('resource',), pointer=run.submit.pointer.rsplit('/', 1)[0] + '/resource')
    delivery = replace(choices.delivery, ids=(replace(run, name='resource', submit=response),))
    with pytest.raises(ValueError, match='explicit'):
        compile_draft(catalog, replace(choices, delivery=delivery))


@pytest.mark.parametrize('case', ['NL1', 'NL1b'])
async def test_response_parent_ownership_does_not_reuse_submit_path_input(tmp_path, case):
    result, out = run(tmp_path, spelled_parent_document(case))
    spec, report, _ = artifacts(out)
    assert result.exit_code == 3, result.output
    assert spec is not None and codes(report, True) == []
    assert spec['transport']['delivery']['ids']['id'] == {'path': '$.id'}
    seen = []
    app = RecordingApp()
    async def submitted(request):
        seen.append(('POST', request.raw_path))
        return web.json_response({'id': '12', 'message_id': '1'}, status=202)
    async def polled(request):
        seen.append(('GET', request.raw_path))
        return web.json_response({'message_id': '1', 'status': 'COMPLETED', 'result': 'own session reply'})
    app.route('POST', '/{tail:.*}', submitted)
    app.route('GET', '/{tail:.*}', polled)
    async with serve(app) as origin:
        parsed = TransportSpecV2.from_dict(with_origin(spec['transport'], origin))
        runtime = V2Run(parsed, policy=ExecutionPolicy.local(parsed), environ={'TARGET_INPUT_ID': '7'})
        try:
            response = await runtime.attempt(TransportContext(prompt='ping'))
        finally:
            await runtime.close()
    assert response.outcome == 'succeeded' and response.response_text == 'own session reply'
    assert seen == [('POST', '/agents/7/sessions'), ('GET', '/sessions/12/messages/1')]


def test_parent_response_and_explicit_carries_can_be_mixed(tmp_path):
    doc = document(resource=False)
    doc['paths'][SUBMIT]['post']['responses']['202']['content']['application/json']['schema']['properties']['o'] = {'type': 'string'}
    binding = {'poll': {'operation': 'get_run', 'parameters': {'w': 'w', 'a': 'a'}}}
    result, out = run(tmp_path, doc, binding)
    spec, report, _ = artifacts(out)
    assert result.exit_code == 3, result.output
    assert spec is not None and codes(report, True) == []
    assert spec['transport']['delivery']['ids']['o'] == {'path': '$.o'}
    assert spec['transport']['delivery']['request']['url'].endswith('/orgs/{o}/ws/{input_w}/autos/{input_a}/runs/{r}')


@pytest.mark.parametrize('schema', [{'type': 'integer'}, {'type': 'string', 'writeOnly': True}])
def test_incompatible_response_parent_reports_named_missing_binding(tmp_path, schema):
    doc = document(resource=False)
    fields = doc['paths'][SUBMIT]['post']['responses']['202']['content']['application/json']['schema']['properties']
    fields.update({name: {'type': 'string'} for name in ('o', 'w', 'a')})
    fields['o'] = schema
    result, out = run(tmp_path, doc)
    spec, report, _ = artifacts(out)
    assert result.exit_code == 3, result.output
    assert spec is None
    gap = next(gap for gap in report['gaps'] if gap['code'] == 'poll_id_binding_missing')
    assert '{o}' in gap['why'] and '{w}' not in gap['why'] and '{a}' not in gap['why']


def test_explicit_run_selector_does_not_select_parent_alias(tmp_path):
    result, out = run(tmp_path, explicit_run_field_document(), {'ids': {'resource': {'last_segment': False}}})
    spec, report, _ = artifacts(out)
    assert result.exit_code == 3, result.output
    assert spec is None
    gap = next(gap for gap in report['gaps'] if gap['code'] == 'poll_id_binding_missing')
    assert all('{' + name + '}' in gap['why'] for name in ('o', 'w', 'a'))
