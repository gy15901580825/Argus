import copy
import json

import pytest

from argus.drafting.scenario import document_cases, parse_scenario
from argus_transport.engine import matches_predicate
from argus_transport.models import predicate
from test_draft_async import async_document, blocking, catalog_for, gaps, poll_schema, run
from test_draft_presence_completion import (
    bindings, compiled, completion, presence_document, presence_scenario,
)
from test_draft_verify_local import verify


@pytest.mark.parametrize('kind,value', [
    ('object', {}), ('array', []), ('string', ''), ('number', 0),
    ('number', 1.5), ('boolean', False), ('null', None),
])
def test_type_predicate_matches_only_the_json_type(kind, value):
    rule = predicate({'path': '$.value', 'type': kind})
    assert matches_predicate({'value': value}, rule)
    assert not matches_predicate({}, rule)
    for other in [{}, [], '', 0, 1.5, False, None]:
        expected = (type(other) is type(value)) or (kind == 'number' and type(other) in {int, float})
        assert matches_predicate({'value': other}, rule) is expected


@pytest.mark.parametrize('kind', ['integer', '', 'Object', None, False, 0, [], {}])
def test_type_predicate_rejects_unknown_or_nonstring_types(kind):
    with pytest.raises(ValueError, match='type'):
        predicate({'path': '$.value', 'type': kind})


def test_type_predicate_cannot_be_combined_with_another_operator():
    with pytest.raises(ValueError):
        predicate({'path': '$.value', 'type': 'object', 'exists': True})


def test_named_state_rejects_override_inside_executing(tmp_path):
    doc = presence_document()
    poll_schema(doc)['properties']['state']['properties']['executing']['properties'] = {
        'completed': {'type': 'object'}, 'pending': {'type': 'object'},
    }
    entry = completion(path='/state/executing', pending=['pending'], failed=[])
    result, out = run(tmp_path, doc, '--bindings', str(bindings(tmp_path, entry)))
    assert result.exit_code == 3 and not out.exists(), result.output
    assert 'binding_unresolved' in blocking(out)


@pytest.mark.parametrize('override', [False, True])
@pytest.mark.parametrize('value', [False, 0, '', [], 'false'])
async def test_malformed_completed_value_never_succeeds(tmp_path, override, value):
    _, artifact = compiled(tmp_path, entry=completion() if override else None)
    result = await verify(artifact.spec, presence_scenario(tmp_path, [{'completed': value}], 'target_error', None))
    assert result.as_dict()['execution']['outcome'] == 'target_error'


@pytest.mark.parametrize('override', [False, True])
@pytest.mark.parametrize('value', [False, {}])
@pytest.mark.parametrize('pending', ['executing', 'pending', 'awaiting_guidance', 'stopping'])
async def test_completed_with_pending_keeps_polling_to_bound(tmp_path, override, value, pending):
    _, artifact = compiled(tmp_path, entry=completion() if override else None)
    artifact.spec['transport']['delivery']['max_polls'] = 2
    artifact.spec['transport']['delivery']['interval_s'] = 0.001
    state = {'completed': value, pending: {}}
    result = await verify(artifact.spec, presence_scenario(tmp_path, [state] * 2, 'target_error', None))
    execution = result.as_dict()['execution']
    assert execution['outcome'] == 'target_error'
    assert execution['reason'] == 'poll_limit'
    assert execution['requests']['poll'] == 2


@pytest.mark.parametrize('override', [False, True])
async def test_completed_with_unknown_ends_target_error(tmp_path, override):
    _, artifact = compiled(tmp_path, entry=completion() if override else None)
    result = await verify(artifact.spec, presence_scenario(tmp_path, [{'completed': {}, 'mystery': {}}], 'target_error', None))
    assert result.as_dict()['execution']['outcome'] == 'target_error'
    row = next(g for g in artifact.gaps if g.code == 'poll_status_unclassified')
    assert 'prevent success' in row.why and 'mystery' in row.why


@pytest.mark.parametrize('override', [False, True])
async def test_null_pending_and_unknown_allow_completed(tmp_path, override):
    _, artifact = compiled(tmp_path, entry=completion() if override else None)
    result = await verify(artifact.spec, presence_scenario(tmp_path, [{'completed': {}, 'executing': None, 'mystery': None}]))
    assert result.as_dict()['execution']['outcome'] == 'succeeded'


@pytest.mark.parametrize('override', [False, True])
def test_submit_completion_uses_same_type_and_exclusion_rules(tmp_path, override):
    doc = presence_document()
    submit = doc['paths']['/jobs']['post']['responses']['202']['content']['application/json']['schema']
    submit['properties'].update(copy.deepcopy(poll_schema(doc)['properties']))
    doc['paths']['/jobs']['post']['responses']['200'] = copy.deepcopy(doc['paths']['/jobs']['post']['responses']['202'])
    _, artifact = compiled(tmp_path, doc, completion() if override else None)
    rule = next(r for r in artifact.spec['transport']['delivery']['submit_outcome']['rules'] if r['id'] == 'completed')
    assert matches_predicate({'job_id': 'job-7', 'state': {'completed': {}}, 'result': 'pong'}, rule['when'])
    for state in [{'completed': False}, {'completed': {}, 'executing': {}}, {'completed': {}, 'mystery': {}}]:
        assert not matches_predicate({'job_id': 'job-7', 'state': state, 'result': 'partial'}, rule['when'])


@pytest.mark.parametrize('sibling', [{'type': 'string'}, {'type': 'object', 'properties': {'a': {'type': 'object'}, 'b': {'type': 'object'}}}])
def test_enum_beside_inert_named_sibling_retains_enum_spec(tmp_path, sibling):
    doc = async_document(result={'type': 'string'})
    _, original = compiled(tmp_path, doc)
    poll_schema(doc)['properties']['state'] = sibling
    _, restored = compiled(tmp_path, doc)
    assert restored.spec == original.spec


def test_empty_enum_value_is_drafted_and_listed_as_unknown(tmp_path):
    doc = async_document(result={'type': 'string'})
    _, original = compiled(tmp_path, doc)
    poll_schema(doc)['properties']['status']['enum'].append('')
    _, restored = compiled(tmp_path, doc)
    assert restored.spec == original.spec
    row = next(g for g in restored.gaps if g.code == 'poll_status_unclassified')
    assert '""' in row.why


@pytest.mark.parametrize('word', ['executing', 'completed', 'failed'])
def test_enum_beside_named_object_with_class_word_stays_blocked(tmp_path, word):
    doc = async_document(result={'type': 'string'})
    poll_schema(doc)['properties']['state'] = {'type': 'object', 'properties': {word: {'type': 'object'}}}
    result, out = run(tmp_path, doc)
    assert result.exit_code == 3 and not out.exists(), result.output
    row = next(g for g in gaps(out)['gaps'] if g['code'] == 'completion_missing')
    assert 'status' in row['why'] and 'state' in row['why'] and 'disagree' in row['why']


@pytest.mark.parametrize('name,schema', [('update_time', {'type': 'string', 'format': 'date-time'}), ('failed_at', {'type': 'object'}), ('failed', {'type': 'string', 'format': 'date-time'})])
def test_metadata_presence_child_has_named_review_row(tmp_path, name, schema):
    doc = presence_document()
    poll_schema(doc)['properties']['state']['properties'][name] = schema
    _, artifact = compiled(tmp_path, doc)
    rows = [g for g in artifact.gaps if g.code == 'poll_status_metadata_omitted']
    assert rows and all(not g.blocking for g in rows)
    row = next(g for g in rows if name in g.why)
    assert any(s.pointer.endswith('/properties/' + name) for s in row.source)


@pytest.mark.parametrize('value', [False, 0, '', [], 'false'])
def test_derived_presence_cases_reject_malformed_success_seed(tmp_path, value):
    catalog = catalog_for(tmp_path, presence_document())
    raw = presence_scenario(tmp_path, [{'completed': value}])
    assert document_cases(parse_scenario(raw), catalog) is None


def test_success_excludes_all_unknown_children_with_bounded_fan_in(tmp_path):
    names = ('pending', 'completed', *(f'unknown_{i}' for i in range(70)))
    _, artifact = compiled(tmp_path, presence_document(names))
    rule = next(r for r in artifact.spec['transport']['outcome']['rules'] if r['id'] == 'completed')
    assert matches_predicate({'state': {'completed': {}}}, rule['when'])
    for name in names[2:]:
        assert not matches_predicate({'state': {'completed': {}, name: {}}}, rule['when'])
    predicate(rule['when'])


def test_enum_beside_inert_state_does_not_ignore_another_enum(tmp_path):
    doc = async_document(result={'type': 'string'})
    poll_schema(doc)['properties']['state'] = {'type': 'string'}
    poll_schema(doc)['properties']['stage'] = {'type': 'string', 'enum': ['PENDING', 'COMPLETED']}
    result, out = run(tmp_path, doc)
    assert result.exit_code == 3 and not out.exists(), result.output


@pytest.mark.parametrize('kind', ['boolean', 'number', 'array'])
def test_enum_restoration_does_not_add_other_sibling_kinds(tmp_path, kind):
    doc = async_document(result={'type': 'string'})
    poll_schema(doc)['properties']['state'] = {'type': kind}
    result, out = run(tmp_path, doc)
    assert result.exit_code == 3 and not out.exists(), result.output


@pytest.mark.parametrize('schema', [
    {'type': 'string', 'format': 'date-time'},
    {'type': 'object', 'writeOnly': True},
    {'type': 'string'},
])
def test_enum_conflict_uses_all_raw_child_class_words(tmp_path, schema):
    doc = async_document(result={'type': 'string'})
    poll_schema(doc)['properties']['state'] = {'type': 'object', 'properties': {'failed': schema}}
    result, out = run(tmp_path, doc)
    assert result.exit_code == 3 and not out.exists(), result.output


def test_unwritable_unknown_presence_child_blocks_instead_of_disappearing(tmp_path):
    doc = presence_document()
    poll_schema(doc)['properties']['state']['properties']["unknown'child"] = {'type': 'object'}
    result, out = run(tmp_path, doc)
    assert result.exit_code == 3 and not out.exists(), result.output
