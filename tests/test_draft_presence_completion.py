import copy
import hashlib
import json

import pytest

from argus.drafting.bindings import read_bindings
from argus.drafting.draft import choose_without_model, compile_draft
from argus.drafting.scenario import parse_scenario, document_cases
from test_draft_async import async_document, blocking, catalog_for, gaps, poll_schema, run, scenario
from test_draft_verify_local import verify


def presence_document(names=('pending', 'executing', 'stopping', 'awaiting_guidance', 'completed', 'failed', 'stopped', 'mystery')):
    doc = async_document(result={'type': 'string'})
    fields = poll_schema(doc)['properties']
    fields.pop('status')
    fields['state'] = {'type': 'object', 'properties': {name: {'type': 'object', 'properties': {}} for name in names}}
    fields['state']['properties']['update_time'] = {'type': 'string', 'format': 'date-time'}
    poll_schema(doc)['required'] = ['state']
    return doc


def completion(style='presence', **changes):
    return {'path': '/state' if style == 'presence' else '/status', 'style': style,
            'succeeded': 'completed' if style == 'presence' else 'COMPLETED',
            'pending': ['pending', 'executing', 'stopping', 'awaiting_guidance'] if style == 'presence' else ['PENDING', 'RUNNING'],
            'failed': ['failed', 'stopped'] if style == 'presence' else ['FAILED'], 'origin': 'doc_prose', **changes}


def bindings(tmp_path, entry):
    path = tmp_path / 'bindings.json'
    path.write_text(json.dumps({'version': 1, 'completion': entry}))
    return path


def compiled(tmp_path, doc=None, entry=None):
    catalog = catalog_for(tmp_path, doc or presence_document())
    inputs = read_bindings(bindings(tmp_path, entry)) if entry else None
    artifacts = compile_draft(catalog, choose_without_model(catalog, inputs=inputs))
    assert artifacts.spec is not None, [g.to_dict() for g in artifacts.gaps]
    return catalog, artifacts


def presence_scenario(tmp_path, states, outcome='succeeded', reply='pong'):
    raw = json.loads(scenario(tmp_path).read_text())
    raw['operations'][1]['calls'] = {'min': len(states), 'max': len(states)}
    raw['operations'][1]['replies'] = [{'status': 200, 'body': {'state': state, 'result': 'pong'}, 'effects': []} for state in states]
    raw['expect'].update(outcome=outcome, reply=reply)
    return raw


async def test_presence_pending_executing_then_completed(tmp_path):
    catalog, artifact = compiled(tmp_path)
    result = await verify(artifact.spec, presence_scenario(tmp_path, [{'pending': {}}, {'executing': {}}, {'completed': {}}]))
    execution = result.as_dict()['execution']
    assert execution['outcome'] == 'succeeded', result.as_dict()
    assert execution['requests']['poll'] == 3
    assert execution['reply'] == 'pong'
    unknown = [g for g in artifact.gaps if g.code == 'poll_status_unclassified']
    assert len(unknown) == 1 and not unknown[0].blocking and 'mystery' in unknown[0].why
    assert 'update_time' not in unknown[0].why
    provenance = artifact.provenance['fields']
    rules = artifact.spec['transport']['outcome']['rules']
    at = next(i for i, r in enumerate(rules) if r['id'] == 'completed')
    assert any(s['pointer'].endswith('/properties/completed') for s in provenance[f'/transport/outcome/rules/{at}']['source'])


@pytest.mark.parametrize('state', [{'completed': None}, {}, {'completed': {}, 'failed': {}}, {'completed': {}, 'stopped': {}}, {'stopped': {}}, {'mystery': {}}])
async def test_inactive_failure_and_unknown_states_never_succeed(tmp_path, state):
    _, artifact = compiled(tmp_path)
    result = await verify(artifact.spec, presence_scenario(tmp_path, [state], 'target_error', None))
    assert result.as_dict()['execution']['outcome'] == 'target_error', result.as_dict()
    assert result.as_dict()['execution']['requests']['poll'] == 1


async def test_awaiting_guidance_exhausts_bounded_polls(tmp_path):
    _, artifact = compiled(tmp_path)
    artifact.spec['transport']['delivery']['max_polls'] = 3
    result = await verify(artifact.spec, presence_scenario(tmp_path, [{'awaiting_guidance': {}}] * 3, 'target_error', None))
    execution = result.as_dict()['execution']
    assert execution['reason'] == 'poll_limit', result.as_dict()
    assert execution['requests']['poll'] == 3


async def test_stopping_can_progress_to_completed(tmp_path):
    _, artifact = compiled(tmp_path)
    result = await verify(artifact.spec, presence_scenario(tmp_path, [{'stopping': {}}, {'completed': {}}]))
    assert result.as_dict()['execution']['outcome'] == 'succeeded', result.as_dict()
    assert result.as_dict()['execution']['requests']['poll'] == 2


@pytest.mark.parametrize('valid', [True, False])
def test_named_state_owns_inference_beside_unrelated_enum(tmp_path, valid):
    doc = presence_document()
    poll_schema(doc)['properties']['stage'] = {'type': 'string', 'enum': ['PENDING', 'COMPLETED', 'FAILED']}
    if not valid:
        poll_schema(doc)['properties']['state'] = {'type': 'string'}
    result, out = run(tmp_path, doc)
    assert result.exit_code == 3, result.output
    assert out.exists() is valid
    if valid:
        assert 'state' in json.dumps(json.loads(out.read_text())['transport']['delivery']['pending'])
    else:
        assert 'async_shape_unsupported' in blocking(out)


@pytest.mark.parametrize('style', ['presence', 'enum'])
def test_reviewed_completion_is_sourced_and_hashed(tmp_path, style):
    doc = presence_document() if style == 'presence' else async_document(result={'type': 'string'})
    entry = completion(style)
    path = bindings(tmp_path, entry)
    result, out = run(tmp_path, doc, '--bindings', str(path))
    assert out.exists(), result.output
    provenance = json.loads(out.with_suffix('.provenance.json').read_text())
    rules = json.loads(out.read_text())['transport']['outcome']['rules']
    at = next(i for i, rule in enumerate(rules) if rule['id'] == 'completed')
    record = provenance['fields'][f'/transport/outcome/rules/{at}']
    assert record['basis'] == 'user_selection' and record['origin'] == 'doc_prose'
    assert {'file': 'bindings.json', 'pointer': '/completion'} in record['source']
    assert {'file': 'bindings.json', 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()} in provenance['inputs']
    assert not any(g['code'] == 'poll_status_proposed' for g in gaps(out)['gaps'])


@pytest.mark.parametrize('change', [
    {'style': 'other'}, {'succeeded': ''}, {'pending': []}, {'pending': ['pending', 'pending']},
    {'failed': ['completed']}, {'origin': 1}, {'path': 'state'}, {'pending': 'pending'},
    {'pending': list(map(str, range(33)))}, {'extra': True}, {'failed': None},
])
def test_completion_structure_is_usage_error_without_artifacts(tmp_path, change):
    result, out = run(tmp_path, presence_document(), '--bindings', str(bindings(tmp_path, completion(**change))))
    assert result.exit_code == 2, result.output
    assert not out.with_suffix('.gaps.json').exists()


@pytest.mark.parametrize('change', [
    {'succeeded': 'stopped', 'failed': ['failed']}, {'succeeded': 'awaiting_guidance', 'pending': ['pending', 'executing', 'stopping']},
    {'pending': ['pending']}, {'failed': ['failed']}, {'pending': ['pending', 'executing', 'stopping'], 'failed': ['failed', 'stopped', 'awaiting_guidance']},
    {'succeeded': 'absent'}, {'path': '/missing'}, {'style': 'enum'},
])
def test_incompatible_override_writes_blocking_sourced_artifacts(tmp_path, change):
    result, out = run(tmp_path, presence_document(), '--bindings', str(bindings(tmp_path, completion(**change))))
    assert result.exit_code == 3, result.output
    assert not out.exists()
    rows = [g for g in gaps(out)['gaps'] if g['code'] == 'binding_unresolved']
    assert rows and all(g['blocking'] for g in rows)
    assert any({'file': 'bindings.json', 'pointer': '/completion'} in g['source'] for g in rows)


@pytest.mark.parametrize('shape', ['scalar', 'write_only', 'ambiguous', 'map_only', 'bad_path'])
def test_presence_document_incompatibility_blocks(tmp_path, shape):
    doc = presence_document()
    state = poll_schema(doc)['properties']['state']
    if shape == 'scalar': state['properties']['completed'] = {'type': 'string'}
    elif shape == 'write_only': state['properties']['completed']['writeOnly'] = True
    elif shape == 'ambiguous': state['properties']['completed'] = {'oneOf': [{'type': 'object'}, {'type': 'object'}]}
    elif shape == 'map_only': state.pop('properties'); state['additionalProperties'] = {'type': 'object'}
    else: state['properties']["bad'path"] = state['properties'].pop('completed')
    entry = completion(succeeded="bad'path") if shape == 'bad_path' else completion()
    result, out = run(tmp_path, doc, '--bindings', str(bindings(tmp_path, entry)))
    assert result.exit_code == 3, result.output
    assert not out.exists() and 'binding_unresolved' in blocking(out)


@pytest.mark.parametrize('wrap', ['type', 'anyOf', 'oneOf'])
def test_nullable_presence_container_and_literal_child_names(tmp_path, wrap):
    doc = presence_document(('pending', 'completed.done', 'failed'))
    state = poll_schema(doc)['properties']['state']
    if wrap == 'type': state['type'] = ['object', 'null']
    else: poll_schema(doc)['properties']['state'] = {wrap: [state, {'type': 'null'}]}
    entry = completion(succeeded='completed.done', pending=['pending'], failed=['failed'])
    _, artifact = compiled(tmp_path, doc, entry)
    assert "$['state']['completed.done']" in json.dumps(artifact.spec)
    at = next(i for i, r in enumerate(artifact.spec['transport']['outcome']['rules']) if r['id'] == 'completed')
    sources = artifact.provenance['fields'][f'/transport/outcome/rules/{at}']['source']
    assert any(s['pointer'].endswith('/properties/completed.done') for s in sources)


async def test_compound_success_retains_required_outer_fields(tmp_path):
    doc = presence_document()
    poll_schema(doc)['properties']['receipt'] = {'type': 'string'}
    poll_schema(doc)['required'].append('receipt')
    _, artifact = compiled(tmp_path, doc)
    raw = presence_scenario(tmp_path, [{'completed': {}}], 'target_error', None)
    result = await verify(artifact.spec, raw)
    assert result.as_dict()['execution']['outcome'] == 'target_error', result.as_dict()
    raw['operations'][1]['replies'][0]['body']['receipt'] = 'documented-receipt'
    raw['expect'].update(outcome='succeeded', reply='pong')
    result = await verify(artifact.spec, raw)
    assert result.as_dict()['execution']['outcome'] == 'succeeded', result.as_dict()


def test_derived_presence_cases_clear_siblings_preserve_metadata_and_ids(tmp_path):
    doc = presence_document()
    poll_schema(doc)['properties']['state']['properties']['stopping']['required'] = ['reason']
    poll_schema(doc)['properties']['state']['properties']['stopping']['properties'] = {'reason': {'type': 'string'}}
    catalog, _ = compiled(tmp_path, doc)
    raw = presence_scenario(tmp_path, [{'completed': {}, 'update_time': '2026-01-01T00:00:00Z'}])
    raw['operations'][1]['replies'][0]['body']['job_id'] = 'job-7'
    cases = document_cases(parse_scenario(raw), catalog)
    assert cases is not None
    by_name = {c.status: c for c in cases}
    assert by_name['mystery'].scenario is None
    assert by_name['stopping'].scenario is None
    assert 'update_time' not in by_name
    for value, kind in [('pending', 'pending'), ('executing', 'pending'), ('failed', 'failed'), ('stopped', 'failed')]:
        case = by_name[value]
        assert case.status_class == kind and case.scenario is not None
        body = case.scenario.operations[1].replies[0].body
        assert body['job_id'] == 'job-7'
        assert body['state'] == {value: {}, 'update_time': '2026-01-01T00:00:00Z'}
        assert case.scenario.outcome == ('succeeded' if kind == 'pending' else 'target_error')


@pytest.mark.parametrize('style', ['enum', 'presence'])
def test_override_selects_unknown_success_and_preserves_canonical_classes(tmp_path, style):
    doc = presence_document() if style == 'presence' else async_document(result={'type': 'string'})
    if style == 'presence':
        entry = completion(succeeded='mystery')
    else:
        poll_schema(doc)['properties']['status']['enum'].extend(['FINISHED_OK', 'awaiting_guidance', 'stopped'])
        entry = completion('enum', succeeded='FINISHED_OK', pending=['PENDING', 'RUNNING', 'awaiting_guidance'], failed=['FAILED', 'stopped'])
    _, artifact = compiled(tmp_path, doc, entry)
    assert any(g.code == 'poll_status_unclassified' and ('completed' if style == 'presence' else 'COMPLETED') in g.why for g in artifact.gaps)


@pytest.mark.parametrize('word', ['awaiting_guidance', 'stopped'])
def test_enum_override_cannot_promote_unsafe_words(tmp_path, word):
    doc = async_document(result={'type': 'string'})
    poll_schema(doc)['properties']['status']['enum'].append(word)
    result, out = run(tmp_path, doc, '--bindings', str(bindings(tmp_path, completion('enum', succeeded=word))))
    assert result.exit_code == 3, result.output
    assert not out.exists() and 'binding_unresolved' in blocking(out)


@pytest.mark.parametrize('alter', ['duplicate_success', 'missing_failed', 'missing_style', 'invalid_origin', 'enum_limit', 'presence_failure_limit'])
def test_additional_completion_structure_errors(tmp_path, alter):
    entry = completion()
    if alter == 'duplicate_success': entry['pending'].append('completed')
    elif alter == 'missing_failed': del entry['failed']
    elif alter == 'missing_style': del entry['style']
    elif alter == 'invalid_origin': entry['origin'] = None
    elif alter == 'enum_limit': entry = completion('enum', pending=list(map(str, range(129))))
    else: entry['failed'] = list(map(str, range(33)))
    result, out = run(tmp_path, presence_document(), '--bindings', str(bindings(tmp_path, entry)))
    assert result.exit_code == 2, result.output
    assert not out.with_suffix('.gaps.json').exists()


@pytest.mark.parametrize('names', [('completed', 'pending'), ('completed', 'succeeded', 'pending')])
def test_success_ambiguity_requires_reviewed_selection(tmp_path, names):
    doc = presence_document(names)
    if len(names) == 3:
        result, out = run(tmp_path, doc)
        assert not out.exists() and 'completion_missing' in blocking(out), result.output
    _, artifact = compiled(tmp_path, doc, completion(pending=['pending'], failed=[]))
    assert artifact.spec is not None


async def test_immediate_submit_presence_failure_and_202_semantics(tmp_path):
    doc = presence_document()
    submit = doc['paths']['/jobs']['post']['responses']
    response = {'description': 'Accepted or terminal run', 'content': {'application/json': {'schema': copy.deepcopy(poll_schema(doc))}}}
    response['content']['application/json']['schema']['properties']['job_id'] = {'type': 'string'}
    response['content']['application/json']['schema']['required'].append('job_id')
    submit['200'] = copy.deepcopy(response)
    submit['202'] = copy.deepcopy(response)
    _, artifact = compiled(tmp_path, doc)
    for status, state, outcome, polls in [(200, {'completed': {}, 'failed': {}}, 'target_error', 0),
                                          (200, {'completed': {}}, 'succeeded', 0),
                                          (202, {'completed': {}}, 'succeeded', 1)]:
        raw = presence_scenario(tmp_path, [{'completed': {}}], outcome, 'pong' if outcome == 'succeeded' else None)
        raw['operations'][0]['replies'] = [{'status': status, 'body': {'job_id': 'job-7', 'state': state, 'result': 'pong'}, 'effects': []}]
        raw['operations'][1]['calls'] = {'min': polls, 'max': max(1, polls)}
        result = await verify(artifact.spec, raw)
        execution = result.as_dict()['execution']
        assert execution['outcome'] == outcome, result.as_dict()
        assert execution['requests']['poll'] == polls


@pytest.mark.parametrize('alter', ['missing_owned_id', 'two_named_states', 'write_only_container', 'enum_beside_state_override'])
def test_completion_does_not_bypass_ownership_or_named_state(tmp_path, alter):
    doc = presence_document()
    entry = completion()
    if alter == 'missing_owned_id':
        doc['paths']['/jobs']['post']['responses']['202']['content']['application/json']['schema']['properties'] = {}
    elif alter == 'two_named_states':
        poll_schema(doc)['properties']['status'] = copy.deepcopy(poll_schema(doc)['properties']['state'])
    elif alter == 'write_only_container': poll_schema(doc)['properties']['state']['writeOnly'] = True
    else:
        poll_schema(doc)['properties']['stage'] = {'type': 'string', 'enum': ['PENDING', 'COMPLETED', 'FAILED']}
        entry = completion('enum', path='/stage')
    result, out = run(tmp_path, doc, '--bindings', str(bindings(tmp_path, entry)))
    assert result.exit_code == 3, result.output
    assert not out.exists()
    assert blocking(out) & {'poll_id_binding_missing', 'binding_unresolved'}


def test_compound_success_keeps_31_required_checks_and_reports_overflow(tmp_path):
    doc = presence_document()
    schema = poll_schema(doc)
    schema['properties'].update({f'field_{i}': {'type': 'string'} for i in range(33)})
    schema['required'] = ['state', *(f'field_{i}' for i in range(33))]
    _, artifact = compiled(tmp_path, doc)
    rule = next(r for r in artifact.spec['transport']['outcome']['rules'] if r['id'] == 'completed')
    assert len(rule['when']['all']) == 32
    assert len(rule['when']['all'][0]['all']) == 2
    row = next(g for g in artifact.gaps if g.code == 'required_fields_unchecked')
    assert 'field_31' in row.why and 'field_32' in row.why
