import json
from dataclasses import replace
from urllib.parse import parse_qs, urlsplit

import pytest
from aiohttp import web

from argus.drafting.bindings import read_bindings
from argus.drafting.draft import choose_without_model, compile_draft
from argus_transport import ExecutionPolicy, TransportContext, TransportSpecV2, V2Run, with_origin
from test_draft_async import async_document, catalog_for, poll_schema
from test_transport_v2_poll import poll_spec
from transport_v2_fakes import RecordingApp, serve


def identity_document(*, required=True, formatted=False):
    doc = async_document(result={'type': 'string'})
    schema = poll_schema(doc)
    if formatted:
        schema['properties']['name'] = {'type': 'string', 'description': 'Format: organizations/{organization}/jobs/{job}'}
        submit = doc['paths'].pop('/jobs')['post']
        parent = {'name': 'organization', 'in': 'path', 'required': True, 'schema': {'type': 'string'}}
        submit['parameters'] = [parent]
        poll = doc['paths'].pop('/jobs/{id}')['get']
        poll['parameters'].insert(0, dict(parent))
        doc['paths']['/organizations/{organization}/jobs'] = {'post': submit}
        doc['paths']['/organizations/{organization}/jobs/{id}'] = {'get': poll}
        field = 'name'
    else:
        schema['properties']['job_id'] = {'type': 'string'}
        field = 'job_id'
    if required:
        schema['required'].append(field)
    return doc


def query_document(*, query_name='run_id', query_required=False, query_only=False):
    doc = async_document(result={'type': 'string'})
    submit = doc['paths']['/jobs']['post']
    submit['responses']['202']['content']['application/json']['schema'] = {
        'type': 'object', 'required': ['agent_id', query_name],
        'properties': {'agent_id': {'type': 'string'}, query_name: {'type': 'string'}}}
    poll = doc['paths'].pop('/jobs/{id}')['get']
    poll['parameters'] = ([] if query_only else [
        {'name': 'agent_id', 'in': 'path', 'required': True, 'schema': {'type': 'string'}}]) + [
        {'name': query_name, 'in': 'query', 'required': query_required, 'schema': {'type': 'string'}}]
    doc['paths']['/runs' if query_only else '/agents/{agent_id}/status'] = {'get': poll}
    return doc


def chosen(tmp_path, doc):
    catalog = catalog_for(tmp_path, doc)
    inputs = None
    if '/organizations/{organization}/jobs' in doc['paths']:
        path = tmp_path / 'bindings.json'
        path.write_text(json.dumps({'version': 1, 'poll': {'operation': 'get_job',
                                                       'parameters': {'organization': 'organization'}},
                                   'ids': {'job_id': {'last_segment': True}}}))
        inputs = read_bindings(path)
    return catalog, choose_without_model(catalog, operation='submit_job', poll_operation='get_job', inputs=inputs)


def compiled(tmp_path, doc):
    catalog, choices = chosen(tmp_path, doc)
    return compile_draft(catalog, choices)


async def execute(spec, submit, poll, *, submit_status=202):
    app = RecordingApp()
    async def submitted(request):
        return web.json_response(submit, status=submit_status)
    async def polled(request):
        return web.json_response(poll)
    app.route('POST', '/{tail:.*}', submitted)
    app.route('GET', '/{tail:.*}', polled)
    async with serve(app) as origin:
        parsed = TransportSpecV2.from_dict(with_origin(spec['transport'], origin))
        runtime = V2Run(parsed, policy=ExecutionPolicy.local(parsed), environ={'TARGET_INPUT_ORGANIZATION': 'org-1', 'TARGET_INPUT_AGENT_ID': 'agent-1'})
        try:
            result = await runtime.attempt(TransportContext(prompt='ping', run_id='context-run'))
        finally:
            await runtime.close()
    return result, app.calls


async def test_required_ordinary_omission_fails_before_accepting_reply(tmp_path):
    report = compiled(tmp_path, identity_document())
    assert report.spec is not None
    result, calls = await execute(report.spec, {'job_id': 'job-1'},
                                  {'status': 'COMPLETED', 'result': 'foreign reply'})
    assert result.outcome == 'target_error'
    assert result.reason_code == 'poll_identity_changed'
    assert len(calls) == 2
    assert report.spec['transport']['delivery']['ids']['job_id'] == {
        'path': '$.job_id', 'poll': {'path': '$.job_id'}}


async def test_required_ordinary_matching_identity_succeeds(tmp_path):
    report = compiled(tmp_path, identity_document())
    assert report.spec is not None
    result, _ = await execute(report.spec, {'job_id': 'job-1'},
                               {'job_id': 'job-1', 'status': 'COMPLETED', 'result': 'own reply'})
    assert result.outcome == 'succeeded' and result.response_text == 'own reply'


async def test_optional_ordinary_omission_succeeds_with_truthful_gap(tmp_path):
    report = compiled(tmp_path, identity_document(required=False))
    assert report.spec is not None
    result, _ = await execute(report.spec, {'job_id': 'job-1'},
                               {'status': 'COMPLETED', 'result': 'reply'})
    assert result.outcome == 'succeeded'
    omission_gaps = [gap for gap in report.gaps if gap.code == 'poll_identity_unchecked']
    assert omission_gaps
    gap = omission_gaps[0]
    assert not gap.blocking and 'omit' in gap.why.lower()
    assert 'job_id' in gap.why and len(gap.source) >= 2
    assert report.spec['transport']['delivery']['ids']['job_id'] == {'path': '$.job_id'}


@pytest.mark.parametrize('value', ['job-2', None, 1])
async def test_optional_ordinary_present_bad_identity_fails(tmp_path, value):
    report = compiled(tmp_path, identity_document(required=False))
    assert report.spec is not None
    result, _ = await execute(report.spec, {'job_id': 'job-1'},
                               {'job_id': value, 'status': 'COMPLETED', 'result': 'foreign'})
    assert result.reason_code == 'poll_identity_changed'


@pytest.mark.parametrize('present,value,want', [
    (False, None, 'target_error'), (True, 'organizations/org-1/jobs/job-1', 'succeeded'),
    (True, None, 'target_error'), (True, 'other/job-1', 'target_error'),
    (True, 'organizations/org-1/jobs/job-2', 'target_error'), (True, 1, 'target_error'),
])
async def test_optional_formatted_identity_retains_strict_presence(tmp_path, present, value, want):
    report = compiled(tmp_path, identity_document(required=False, formatted=True))
    assert report.spec is not None
    body = {'status': 'COMPLETED', 'result': 'reply'}
    if present:
        body['name'] = value
    result, _ = await execute(report.spec, {'job_id': 'organizations/org-1/jobs/job-1'}, body)
    assert result.outcome == want
    if want == 'target_error':
        assert result.reason_code == 'poll_identity_changed'
    selector = report.spec['transport']['delivery']['ids']['job_id'].get('poll', {})
    assert selector.get('required', True) is True and selector['last_segment'] is True
    assert not any(gap.code == 'poll_identity_unchecked' for gap in report.gaps)


@pytest.mark.parametrize('mutation', ['drop', 'foreign_field'])
def test_compiler_rejects_forged_required_identity(tmp_path, mutation):
    catalog, choices = chosen(tmp_path, identity_document())
    item = choices.delivery.ids[0]
    if mutation == 'drop':
        item = replace(item, identity=None, fallback=None)
    else:
        foreign = replace(item.submit, pointer=item.submit.pointer)
        item = replace(item, fallback=foreign, identity=None)
    with pytest.raises(ValueError):
        compile_draft(catalog, replace(choices, delivery=replace(choices.delivery, ids=(item,))))


@pytest.mark.parametrize('query_required,query_only', [(False, False), (True, False), (False, True)])
def test_documented_run_query_is_directly_captured_and_sent(tmp_path, query_required, query_only):
    report = compiled(tmp_path, query_document(query_required=query_required, query_only=query_only))
    assert report.spec is not None, [gap.to_dict() for gap in report.gaps]
    delivery = report.spec['transport']['delivery']
    assert delivery['ids']['run_id'] == {'path': '$.run_id'}
    assert delivery['request']['query']['run_id'] == {'var': 'run_id'}
    if not query_only:
        assert delivery['ids']['agent_id'] == {'path': '$.agent_id'}
        assert delivery['request']['url'].endswith('/agents/{agent_id}/status')


async def test_r5c_poll_uses_own_query_run_instead_of_foreign_latest_reply(tmp_path):
    report = compiled(tmp_path, query_document())
    assert report.spec is not None
    app = RecordingApp()
    async def submitted(request):
        return web.json_response({'agent_id': 'agent-1', 'run_id': 'run-1'}, status=202)
    async def polled(request):
        return web.json_response({'status': 'COMPLETED', 'result':
                                 'own reply' if request.query.get('run_id') == 'run-1' else 'foreign latest reply'})
    app.route('POST', '/jobs', submitted)
    app.route('GET', '/agents/{agent_id}/status', polled)
    async with serve(app) as origin:
        parsed = TransportSpecV2.from_dict(with_origin(report.spec['transport'], origin))
        runtime = V2Run(parsed, policy=ExecutionPolicy.local(parsed), environ={'TARGET_INPUT_ORGANIZATION': 'org-1'})
        try:
            result = await runtime.attempt(TransportContext(prompt='ping', run_id='context-run'))
        finally:
            await runtime.close()
    assert result.response_text == 'own reply'
    assert app.calls[1][1] == '/agents/agent-1/status?run_id=run-1'


async def test_query_capture_missing_submit_id_sends_no_poll(tmp_path):
    report = compiled(tmp_path, query_document())
    assert report.spec is not None
    result, calls = await execute(report.spec, {'agent_id': 'agent-1'},
                                  {'status': 'COMPLETED', 'result': 'foreign'})
    assert result.reason_code == 'missing_id'
    assert len(calls) == 1


@pytest.mark.parametrize('kind', ['missing', 'wrong_type', 'write_only'])
def test_unfillable_optional_run_query_blocks_with_named_gap(tmp_path, kind):
    doc = query_document()
    fields = doc['paths']['/jobs']['post']['responses']['202']['content']['application/json']['schema']['properties']
    if kind == 'missing':
        del fields['run_id']
        doc['paths']['/jobs']['post']['responses']['202']['content']['application/json']['schema']['required'].remove('run_id')
    elif kind == 'wrong_type':
        fields['run_id'] = {'type': 'integer'}
    else:
        fields['run_id']['writeOnly'] = True
    report = compiled(tmp_path, doc)
    assert report.spec is None
    assert any(gap.blocking and gap.code == 'poll_id_binding_missing' and 'run_id' in gap.why
               for gap in report.gaps)


@pytest.mark.parametrize('query_name', ['id', 'session_id', 'agentId'])
def test_identity_query_with_unresolved_role_blocks(tmp_path, query_name):
    doc = query_document(query_name=query_name, query_only=True)
    schema = doc['paths']['/jobs']['post']['responses']['202']['content']['application/json']['schema']
    del schema['properties'][query_name]
    schema['required'].remove(query_name)
    report = compiled(tmp_path, doc)
    assert report.spec is None
    assert any(gap.blocking and gap.code == 'poll_parameter_role_ambiguous' for gap in report.gaps)


def test_query_run_role_rejects_submit_path_echo(tmp_path):
    doc = query_document()
    submit = doc['paths'].pop('/jobs')['post']
    submit['parameters'] = [{'name': 'run_id', 'in': 'path', 'required': True, 'schema': {'type': 'string'}}]
    doc['paths']['/runs/{run_id}:invoke'] = {'post': submit}
    report = compiled(tmp_path, doc)
    assert report.spec is None
    assert any(gap.blocking and gap.code == 'poll_id_binding_missing' for gap in report.gaps)


@pytest.mark.parametrize('query_patch', [
    {'style': 'deepObject'}, {'allowReserved': True}, {'explode': 1},
    {'schema': {'type': 'array', 'items': {'type': 'string'}}},
])
def test_optional_run_query_unsupported_serialization_blocks(tmp_path, query_patch):
    doc = query_document()
    doc['paths']['/agents/{agent_id}/status']['get']['parameters'][-1].update(query_patch)
    report = compiled(tmp_path, doc)
    assert report.spec is None
    assert any(gap.blocking and gap.code == 'poll_parameter_unsupported' for gap in report.gaps)


async def test_query_identity_hostile_characters_are_encoded_once(tmp_path):
    report = compiled(tmp_path, query_document())
    assert report.spec is not None
    value = 'own/&run_id=foreign?x=# +%'
    result, calls = await execute(report.spec, {'agent_id': 'agent-1', 'run_id': value},
                                  {'status': 'COMPLETED', 'result': 'reply'})
    assert result.outcome == 'succeeded'
    assert parse_qs(urlsplit(calls[1][1]).query) == {'run_id': [value]}


@pytest.mark.parametrize('mutation', ['missing_query', 'path_instead', 'capture_parent'])
def test_compiler_rejects_forged_query_destination_or_capture(tmp_path, mutation):
    catalog, choices = chosen(tmp_path, query_document())
    assert choices.delivery is not None
    assert any(item.name == 'run_id' for item in choices.delivery.ids)
    if mutation == 'missing_query':
        delivery = replace(choices.delivery, ids=tuple(item for item in choices.delivery.ids if item.name != 'run_id'))
    else:
        item = next(item for item in choices.delivery.ids if item.name == 'run_id')
        if mutation == 'path_instead':
            item = replace(item, location='path')
        else:
            parent = next(item for item in choices.delivery.ids if item.name == 'agent_id')
            item = replace(item, name=parent.name, submit=parent.submit)
        delivery = replace(choices.delivery, ids=tuple(item if old.name == 'run_id' else old for old in choices.delivery.ids))
    with pytest.raises(ValueError):
        compile_draft(catalog, replace(choices, delivery=delivery))


def query_transport():
    data = poll_spec('http://127.0.0.1/run')
    data['auth'] = {'kind': 'none'}
    data['delivery']['request']['url'] = 'http://127.0.0.1/runs'
    data['delivery']['request']['query'] = {'run_id': {'var': 'run_id'}}
    data['delivery']['request']['headers'] = {}
    return data


def test_transport_accepts_one_direct_query_id_destination_and_roundtrips():
    data = query_transport()
    parsed = TransportSpecV2.from_dict(data)
    assert parsed.to_dict()['delivery'] == data['delivery']
    assert TransportSpecV2.from_dict(parsed.to_dict()) == parsed


@pytest.mark.parametrize('mutation', ['absent', 'duplicate_query', 'path_and_query', 'wrapped_query', 'hidden_duplicate'])
def test_transport_rejects_absent_duplicate_or_hidden_id_destination(mutation):
    data = query_transport()
    request = data['delivery']['request']
    if mutation == 'absent':
        request['query'] = {}
    elif mutation == 'duplicate_query':
        request['query']['other'] = {'var': 'run_id'}
    elif mutation == 'path_and_query':
        request['url'] += '/{run_id}'
    elif mutation == 'hidden_duplicate':
        request['query']['other'] = {'concat': [{'literal': 'prefix'}, {'var': 'run_id'}]}
    else:
        request['query']['run_id'] = {'concat': [{'literal': 'prefix'}, {'var': 'run_id'}]}
    with pytest.raises(ValueError):
        TransportSpecV2.from_dict(data)


@pytest.mark.parametrize('required', [False, True])
def test_poll_presence_policy_roundtrips(required):
    data = poll_spec('http://127.0.0.1/run')
    data['delivery']['ids']['run_id']['poll'] = {'path': '$.run_id', 'required': required}
    parsed = TransportSpecV2.from_dict(data)
    assert parsed.to_dict()['delivery']['ids'] == data['delivery']['ids']
    assert TransportSpecV2.from_dict(parsed.to_dict()) == parsed


@pytest.mark.parametrize('required', [None, 0, 1, 'false'])
def test_poll_presence_policy_requires_boolean(required):
    data = poll_spec('http://127.0.0.1/run')
    data['delivery']['ids']['run_id']['poll'] = {'path': '$.run_id', 'required': required}
    with pytest.raises(ValueError):
        TransportSpecV2.from_dict(data)


async def test_handwritten_poll_selector_defaults_to_strict_presence():
    data = poll_spec('http://127.0.0.1/run')
    data['auth'] = {'kind': 'none'}
    data['delivery']['ids']['run_id']['poll'] = {'path': '$.run_id'}
    result, _ = await execute({'transport': data}, {'run_id': 'job-1'},
                               {'status': 'COMPLETED', 'result': 'foreign'})
    assert result.outcome == 'target_error' and result.reason_code == 'poll_identity_changed'


def test_documented_run_role_phrase_binds_exactly_named_query(tmp_path):
    doc = query_document(query_name='execution')
    query = doc['paths']['/agents/{agent_id}/status']['get']['parameters'][-1]
    query['description'] = 'ID of the run to retrieve.'
    report = compiled(tmp_path, doc)
    assert report.spec is not None
    assert report.spec['transport']['delivery']['request']['query']['execution'] == {'var': 'execution'}


@pytest.mark.parametrize('case', ['two_run_queries', 'duplicate_query', 'identity_header'])
def test_optional_identity_declarations_cannot_disappear(tmp_path, case):
    doc = query_document()
    parameters = doc['paths']['/agents/{agent_id}/status']['get']['parameters']
    if case == 'two_run_queries':
        parameters.append({'name': 'runId', 'in': 'query', 'schema': {'type': 'string'}})
    elif case == 'duplicate_query':
        parameters.append(dict(parameters[-1]))
    else:
        parameters[-1]['in'] = 'header'
    report = compiled(tmp_path, doc)
    assert report.spec is None
    assert any(gap.blocking and gap.code in {'poll_parameter_role_ambiguous', 'poll_parameter_unsupported'}
               for gap in report.gaps)


def test_optional_nonidentity_filter_can_be_omitted_with_review(tmp_path):
    doc = query_document()
    doc['paths']['/agents/{agent_id}/status']['get']['parameters'].append(
        {'name': 'verbose', 'in': 'query', 'schema': {'type': 'boolean'}})
    report = compiled(tmp_path, doc)
    assert report.spec is not None
    assert report.spec['transport']['delivery']['request']['query'] == {'run_id': {'var': 'run_id'}}
    assert any(not gap.blocking and gap.code == 'optional_inputs_unbound' and 'verbose' in gap.why
               for gap in report.gaps)


def test_required_business_query_blocks_without_becoming_identity(tmp_path):
    doc = query_document()
    doc['paths']['/agents/{agent_id}/status']['get']['parameters'].append(
        {'name': 'mode', 'in': 'query', 'required': True, 'schema': {'type': 'string'}})
    report = compiled(tmp_path, doc)
    assert report.spec is None
    assert any(gap.blocking and gap.code == 'poll_parameter_unsupported' for gap in report.gaps)


@pytest.mark.parametrize('formatted', [False, True])
def test_compiler_rejects_forged_required_presence_relaxation(tmp_path, formatted):
    catalog, choices = chosen(tmp_path, identity_document(formatted=formatted))
    item = choices.delivery.ids[0]
    assert item.identity is not None
    relaxed = replace(item, identity=replace(item.identity, required=False))
    with pytest.raises(ValueError):
        compile_draft(catalog, replace(choices, delivery=replace(choices.delivery, ids=(relaxed,))))


@pytest.mark.parametrize('formatted', [False, True])
def test_compiler_rejects_different_valid_documented_identity_field(tmp_path, formatted):
    doc = identity_document(formatted=formatted)
    poll = next(path['get'] for path in doc['paths'].values() if 'get' in path)
    schema = poll['responses']['200']['content']['application/json']['schema']
    schema['properties']['other_id'] = {'type': 'string'}
    catalog, choices = chosen(tmp_path, doc)
    item = choices.delivery.ids[0]
    assert item.identity is not None
    other = replace(item.identity.field, path=('other_id',),
                    pointer=item.identity.field.pointer.rsplit('/', 1)[0] + '/other_id')
    forged = replace(item, identity=replace(item.identity, field=other))
    wire = compile_draft(catalog, choices).spec['transport']
    wire['delivery']['ids']['job_id']['poll']['path'] = '$.other_id'
    TransportSpecV2.from_dict(wire)
    with pytest.raises(ValueError):
        compile_draft(catalog, replace(choices, delivery=replace(choices.delivery, ids=(forged,))))


def test_run_id_reference_requires_visibility_and_declarations_stay_forbidden():
    from argus_transport.spec_v2 import value_expr_v2
    with pytest.raises(ValueError):
        value_expr_v2({'var': 'run_id'}, visible=frozenset())
    assert value_expr_v2({'context': 'run_id'}, visible=frozenset()) == {'context': 'run_id'}
    assert value_expr_v2({'var': 'run_id'}, visible=frozenset({'run_id'})) == {'var': 'run_id'}
    data = query_transport()
    data['let'] = {'run': {'run_id': {'literal': 'foreign'}}}
    with pytest.raises(ValueError):
        TransportSpecV2.from_dict(data)


async def test_query_var_run_id_is_captured_while_context_run_id_is_attempt_context(tmp_path):
    report = compiled(tmp_path, query_document())
    assert report.spec is not None
    report.spec['transport']['delivery']['request']['query']['context_id'] = {'context': 'run_id'}
    result, calls = await execute(report.spec, {'agent_id': 'agent-1', 'run_id': 'captured-run'},
                                  {'status': 'COMPLETED', 'result': 'reply'})
    assert result.outcome == 'succeeded'
    query = parse_qs(urlsplit(calls[1][1]).query)
    assert query['run_id'] == ['captured-run']
    assert query['context_id'] == ['context-run']


@pytest.mark.parametrize('failure', ['missing', 'unsupported'])
async def test_related_run_query_keeps_sync_reply(tmp_path, failure):
    doc = query_document()
    submit = doc['paths']['/jobs']['post']
    response = submit['responses'].pop('202')
    submit['responses']['200'] = response
    schema = response['content']['application/json']['schema']
    schema['properties']['result'] = {'type': 'string'}
    if failure == 'missing':
        del schema['properties']['run_id']
        schema['required'].remove('run_id')
    else:
        doc['paths']['/agents/{agent_id}/status']['get']['parameters'][-1]['style'] = 'deepObject'
    catalog = catalog_for(tmp_path, doc)
    report = compile_draft(catalog, choose_without_model(catalog, operation='submit_job'))
    assert report.spec is not None
    assert report.spec['transport']['delivery'] == {'kind': 'sync'}
    assert not any(gap.blocking for gap in report.gaps)
    result, calls = await execute(report.spec, {'result': 'sync answer', 'agent_id': 'agent-1', 'run_id': 'run-1'}, {}, submit_status=200)
    assert result.outcome == 'succeeded' and result.response_text == 'sync answer'
    assert len(calls) == 1


def test_unrelated_run_query_does_not_block_synchronous_reply(tmp_path):
    doc = query_document(query_only=True)
    submit = doc['paths']['/jobs']['post']
    response = submit['responses'].pop('202')
    submit['responses']['200'] = response
    response['content']['application/json']['schema'] = {
        'type': 'object', 'required': ['result'], 'properties': {'result': {'type': 'string'}}}
    doc['paths']['/runs']['get']['parameters'][0]['style'] = 'deepObject'
    catalog = catalog_for(tmp_path, doc)
    report = compile_draft(catalog, choose_without_model(catalog, operation='submit_job'))
    assert report.spec is not None
    assert report.spec['transport']['delivery'] == {'kind': 'sync'}


@pytest.mark.parametrize('name', ['createdAt', 'start_at'])
def test_optional_timestamp_poll_filters_remain_omitted_with_review(tmp_path, name):
    doc = query_document()
    doc['paths']['/agents/{agent_id}/status']['get']['parameters'].append(
        {'name': name, 'in': 'query', 'schema': {'type': 'string', 'format': 'date-time'}})
    report = compiled(tmp_path, doc)
    assert report.spec is not None
    assert report.spec['transport']['delivery']['request']['query'] == {'run_id': {'var': 'run_id'}}
    assert any(not gap.blocking and gap.code == 'optional_inputs_unbound' and name in gap.why for gap in report.gaps)


@pytest.mark.parametrize('location', [['query'], {'kind': 'query'}])
def test_malformed_poll_parameter_location_has_named_gap(tmp_path, location):
    doc = query_document()
    doc['paths']['/agents/{agent_id}/status']['get']['parameters'][-1]['in'] = location
    report = compiled(tmp_path, doc)
    assert report.spec is None
    assert any(gap.blocking and gap.code == 'poll_parameter_unsupported' for gap in report.gaps)


def test_multiple_run_queries_do_not_change_sync_draft(tmp_path):
    doc = query_document()
    submit = doc['paths']['/jobs']['post']
    response = submit['responses'].pop('202')
    submit['responses']['200'] = response
    response['content']['application/json']['schema']['properties']['result'] = {'type': 'string'}
    doc['paths']['/agents/{agent_id}/status']['get']['parameters'].append(
        {'name': 'runId', 'in': 'query', 'schema': {'type': 'string'}})
    catalog = catalog_for(tmp_path, doc)
    report = compile_draft(catalog, choose_without_model(catalog, operation='submit_job'))
    assert report.spec is not None
    assert report.spec['transport']['delivery'] == {'kind': 'sync'}
    assert not any(gap.blocking for gap in report.gaps)


@pytest.mark.parametrize('required', [['job_id', 'job_id'], 'job_id', ['job_id', 1]])
def test_identity_presence_retains_existing_required_list_review_policy(tmp_path, required):
    doc = identity_document()
    poll_schema(doc)['required'] = required
    report = compiled(tmp_path, doc)
    assert report.spec is not None
    selector = report.spec['transport']['delivery']['ids']['job_id']
    if isinstance(required, list) and all(isinstance(name, str) for name in required):
        assert selector['poll'] == {'path': '$.job_id'}
    else:
        assert selector == {'path': '$.job_id'}
        assert any(gap.code == 'success_conditions_minimal' and not gap.blocking for gap in report.gaps)
        assert any(gap.code == 'poll_identity_unchecked' and not gap.blocking for gap in report.gaps)


@pytest.mark.parametrize('case', ['S1b', 'S7'])
async def test_sync_submit_ignores_related_status_and_list_queries(tmp_path, case):
    doc = query_document()
    submit = doc['paths']['/jobs']['post']
    response = submit['responses'].pop('202')
    submit['responses']['200'] = response
    response['content']['application/json']['schema']['properties']['result'] = {'type': 'string'}
    poll = doc['paths']['/agents/{agent_id}/status']['get']
    if case == 'S1b':
        del poll['responses']['200']['content']['application/json']['schema']['properties']['result']
    else:
        del response['content']['application/json']['schema']['properties']['run_id']
        response['content']['application/json']['schema']['required'].remove('run_id')
        submit['parameters'] = [{'name': 'agent_id', 'in': 'path', 'required': True, 'schema': {'type': 'string'}}]
        doc['paths']['/agents/{agent_id}/messages'] = {'post': doc['paths'].pop('/jobs')['post']}
        doc['paths']['/agents/{agent_id}/runs'] = {'get': doc['paths'].pop('/agents/{agent_id}/status')['get']}
        poll['responses']['200']['content']['application/json']['schema'] = {
            'type': 'object', 'properties': {'items': {'type': 'array', 'items': {'type': 'object'}}}}
    catalog = catalog_for(tmp_path, doc)
    report = compile_draft(catalog, choose_without_model(catalog, operation='submit_job'))
    assert report.spec is not None, [gap.to_dict() for gap in report.gaps]
    assert report.spec['transport']['delivery'] == {'kind': 'sync'}
    result, calls = await execute(report.spec, {'result': 'sync answer', 'agent_id': 'agent-1', 'run_id': 'run-1'}, {}, submit_status=200)
    assert result.outcome == 'succeeded' and result.response_text == 'sync answer'
    assert len(calls) == 1 and calls[0][0] == 'POST'


@pytest.mark.parametrize('query_name', ['run', 'job', 'execution'])
@pytest.mark.parametrize('source_format', [None, 'uuid'])
async def test_exact_name_run_query_reads_own_reply(tmp_path, query_name, source_format):
    doc = query_document(query_name=query_name)
    if source_format:
        doc['paths']['/jobs']['post']['responses']['202']['content']['application/json']['schema']['properties'][query_name]['format'] = source_format
    parameter = doc['paths']['/agents/{agent_id}/status']['get']['parameters'][-1]
    parameter['description'] = {'run': 'The run to fetch.', 'job': 'The job to read.', 'execution': 'Execution to read.'}[query_name]
    report = compiled(tmp_path, doc)
    assert report.spec is not None
    app = RecordingApp()
    async def submitted(request):
        return web.json_response({'agent_id': 'agent-1', query_name: 'own-1'}, status=202)
    async def polled(request):
        return web.json_response({'status': 'COMPLETED', 'result':
                                 'own reply' if request.query.get(query_name) == 'own-1' else 'foreign latest'})
    app.route('POST', '/jobs', submitted)
    app.route('GET', '/agents/{agent_id}/status', polled)
    async with serve(app) as origin:
        parsed = TransportSpecV2.from_dict(with_origin(report.spec['transport'], origin))
        runtime = V2Run(parsed, policy=ExecutionPolicy.local(parsed))
        try:
            result = await runtime.attempt(TransportContext(prompt='ping'))
        finally:
            await runtime.close()
    assert result.outcome == 'succeeded' and result.response_text == 'own reply'
    assert app.calls[1][1] == '/agents/agent-1/status?' + query_name + '=own-1'
    assert report.spec['transport']['delivery']['request']['query'][query_name] == {'var': query_name}


@pytest.mark.parametrize('kind', ['write_only', 'wrong_type'])
def test_unusable_exact_name_query_source_blocks_instead_of_omission(tmp_path, kind):
    doc = query_document(query_name='job')
    field = doc['paths']['/jobs']['post']['responses']['202']['content']['application/json']['schema']['properties']['job']
    if kind == 'write_only':
        field['writeOnly'] = True
    else:
        field['type'] = 'integer'
    report = compiled(tmp_path, doc)
    assert report.spec is None
    assert any(gap.blocking and gap.code == 'poll_id_binding_missing' for gap in report.gaps)


@pytest.mark.parametrize('name,schema', [
    ('verbose', {'type': 'boolean'}),
    ('createdAt', {'type': 'string'}),
    ('updated_at', {'type': 'string'}),
    ('last_seen', {'type': 'string', 'format': 'date-time'}),
])
async def test_matching_nonidentity_filters_do_not_replace_run_query(tmp_path, name, schema):
    doc = query_document()
    submit = doc['paths']['/jobs']['post']['responses']['202']['content']['application/json']['schema']
    submit['properties'][name] = schema
    poll = doc['paths']['/agents/{agent_id}/status']['get']
    poll['parameters'].append({'name': name, 'in': 'query', 'schema': schema})
    report = compiled(tmp_path, doc)
    assert report.spec is not None, [gap.to_dict() for gap in report.gaps]
    assert report.spec['transport']['delivery']['request']['query'] == {'run_id': {'var': 'run_id'}}
    result, calls = await execute(report.spec, {'agent_id': 'agent-1', 'run_id': 'own-1'},
                                  {'status': 'COMPLETED', 'result': 'own reply'})
    assert result.outcome == 'succeeded' and result.response_text == 'own reply'
    assert calls[1][1] == '/agents/agent-1/status?run_id=own-1'


def test_multiple_exact_name_query_captures_are_ambiguous(tmp_path):
    doc = query_document(query_name='job')
    doc['paths']['/jobs']['post']['responses']['202']['content']['application/json']['schema']['properties']['execution'] = {'type': 'string'}
    doc['paths']['/agents/{agent_id}/status']['get']['parameters'].append(
        {'name': 'execution', 'in': 'query', 'schema': {'type': 'string'}})
    report = compiled(tmp_path, doc)
    assert report.spec is None
    assert any(gap.blocking and gap.code == 'poll_parameter_role_ambiguous' for gap in report.gaps)
