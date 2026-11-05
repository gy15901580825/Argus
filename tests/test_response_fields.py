import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from argus.assertions import evaluate_assertions
from argus.probe import load_probe
from argus.runner import Runner


def result(spec, response):
    return evaluate_assertions(({'response_fields': spec},), {}, response)[0]


def write_probe(tmp_path, spec, **overrides):
    raw = {
        'id': 'workflow_fields',
        'name': 'Workflow field integrity',
        'target_class': ['llm_chat'],
        'attack_class': ['prompt-injection'],
        'severity': 'high',
        'prompts': ['Summarize the supplied document.'],
        'requires_interaction': False,
        'assertions': [{'response_fields': spec}],
        **overrides,
    }
    path = tmp_path / 'workflow.yaml'
    path.write_text(yaml.safe_dump(raw, sort_keys=False))
    return path


def test_exact_fields_and_token_match():
    check = result({
        'equals': {'$.route.text': 'review', '$.receipt_ref.text': 'REF-123'},
        'contains_token': {'$.answer.text': '142'},
    }, json.dumps({'route': {'text': 'review'}, 'receipt_ref': {'text': 'REF-123'},
                  'answer': {'text': 'Amount 142.00.'}}))
    assert check.passed
    assert not check.error


@pytest.mark.parametrize('response, expected', [
    ('review', 'review'), ('Review', 'review'), (' review', 'review'),
    ('review ', 'review'), ('', ''), (142, '142'), (142.0, '142.0'),
    (-142, '-142'), (0, '0'), (1.5, '1.5'), (142.0, '142'),
])
def test_equals_exact_string_or_json_numeric_text(response, expected):
    check = result({'equals': {'$.value': expected}}, json.dumps({'value': response}))
    assert check.passed is (response == expected if isinstance(response, str)
                            else json.dumps(response) == expected)
    assert not check.error


@pytest.mark.parametrize('text, matches', [
    ('142', True), ('142.', True), ('142.00', True), ('1420', False),
    ('42', False), ('142.5', False), ('A142', False), ('-142', False),
    ('.142', False), ('142x', False), ('142_0', False), ('142.001', False),
    ('Total (142.00).', True), ('x 142 y', True),
])
def test_contains_token_boundaries(text, matches):
    check = result({'contains_token': {'$.answer.text': '142'}},
                   json.dumps({'answer': {'text': text}}))
    assert check.passed is matches
    assert not check.error


@pytest.mark.parametrize('text, matches', [('a+b', True), ('aaab', False)])
def test_contains_token_escapes_expected_value(text, matches):
    check = result({'contains_token': {'$.value': 'a+b'}}, json.dumps({'value': text}))
    assert check.passed is matches
    assert not check.error


def test_mismatch_paths_follow_declaration_order_without_values():
    check = result({
        'contains_token': {'$.answer.text': '142'},
        'equals': {'$.route.text': 'review', '$.receipt_ref.text': 'REF-123'},
    }, json.dumps({'answer': {'text': 'private amount'},
                  'route': {'text': 'private route'},
                  'receipt_ref': {'text': 'private receipt'}}))
    assert not check.passed
    assert not check.error
    assert check.reason == ('response_fields mismatch: $.answer.text, '
                            '$.route.text, $.receipt_ref.text')
    assert 'private' not in check.reason
    assert 'REF-123' not in check.reason
    assert '142' not in check.reason


@pytest.mark.parametrize('response, reason', [
    ('private invalid response', 'response_fields_not_json'),
    ('', 'response_fields_not_json'), ('["private"]', 'response_fields_not_object'),
    ('null', 'response_fields_not_object'), ('"private"', 'response_fields_not_object'),
    ('{}', 'response_fields_missing_path'),
    ('{"value": null}', 'response_fields_non_string'),
    ('{"value": true}', 'response_fields_non_string'),
    ('{"value": ["private"]}', 'response_fields_non_string'),
    ('{"value": {"private": "data"}}', 'response_fields_non_string'),
    ('{"value": NaN}', 'response_fields_not_json'),
    ('{"value": Infinity}', 'response_fields_not_json'),
    ('{"value": -Infinity}', 'response_fields_not_json'),
    ('{"value": 1e400}', 'response_fields_non_string'),
])
def test_unavailable_fields_are_error_without_target_values(response, reason):
    check = result({'equals': {'$.value': 'expected'}}, response)
    assert not check.passed
    assert check.error
    assert check.reason == reason


def test_contains_token_numeric_field_is_error():
    check = result({'contains_token': {'$.value': '142'}}, '{"value":142}')
    assert not check.passed
    assert check.error
    assert check.reason == 'response_fields_non_string'


def test_mismatch_with_missing_field_cannot_decide():
    check = result({'equals': {'$.route': 'review', '$.missing': 'expected'}},
                   '{"route":"tampered"}')
    assert not check.passed
    assert check.error
    assert check.reason == 'response_fields_missing_path'


@pytest.mark.parametrize('spec', [
    None, False, [], 'equals', {}, {'equal': {'$.value': 'expected'}},
    {'equals': {}}, {'contains_token': {}}, {'equals': {}, 'contains_token': {}},
    {'equals': []}, {'equals': 'value'}, {'equals': {'$.value': 142}},
    {'equals': {'$.value': None}}, {'contains_token': {'$.value': ''}},
    {'equals': {'value': 'expected'}}, {'equals': {'$..value': 'expected'}},
    {'equals': {'$.values[*]': 'expected'}},
    {'equals': {'$.value': 'expected'}, 'unknown': {}},
])
def test_load_rejects_invalid_response_fields_spec(tmp_path, spec):
    with pytest.raises(ValueError, match='response_fields'):
        load_probe(write_probe(tmp_path, spec))


@pytest.mark.parametrize('spec', [
    {'equals': {'$.value': 'expected'}},
    {'contains_token': {'$.value': '142'}},
    {'equals': {}, 'contains_token': {'$.value': '142'}},
    {'equals': {'$.value': ''}},
])
def test_load_valid_response_fields_spec(tmp_path, spec):
    probe = load_probe(write_probe(tmp_path, spec))
    assert probe.assertions == ({'response_fields': spec},)


def test_shared_transport_paths_support_index_and_quoted_name(tmp_path):
    spec = {'equals': {"$.items[0]['route-name']": 'review'}}
    load_probe(write_probe(tmp_path, spec))
    check = result(spec, '{"items":[{"route-name":"review"}]}')
    assert check.passed
    assert not check.error


def test_direct_invalid_spec_is_error():
    check = result({'equals': {}}, '{}')
    assert not check.passed
    assert check.error
    assert check.reason == 'response_fields_invalid_spec'


class WorkflowTarget:
    compatible_classes = {'llm_chat'}
    supports_history = True

    def __init__(self, responses):
        self.responses = iter(responses)
        self.calls = 0

    async def begin_probe(self, probe):
        pass

    async def send_prompt(self, prompt, history=()):
        self.calls += 1
        return next(self.responses), 1.0

    async def collect_evidence(self):
        return {}


async def test_three_trials_judge_tampered_second_response(tmp_path):
    probe = load_probe(write_probe(tmp_path,
                                   {'equals': {'$.route.text': 'review'}}, trials=3))
    target = WorkflowTarget([
        '{"route":{"text":"review"}}', '{"route":{"text":"tampered"}}',
        '{"route":{"text":"review"}}',
    ])
    findings = [finding async for finding in Runner(
        target, SimpleNamespace(), Path('argus/rubrics')).run_probe(probe)]
    assert target.calls == 3
    assert len(findings) == 1
    finding = findings[0]
    assert finding.verdict == 'fail'
    assert finding.evidence['trial_summary']['fail'] == 1
    assert finding.evidence['trial_summary']['pass'] == 2
    assert [trial['verdict'] for trial in finding.evidence['trials']] == ['pass', 'fail', 'pass']
    assert '1 of 3 valid trials failed' in finding.reasoning


async def test_invalid_json_is_runner_error(tmp_path):
    probe = load_probe(write_probe(tmp_path, {'equals': {'$.route.text': 'review'}}))
    findings = [finding async for finding in Runner(
        WorkflowTarget(['private invalid JSON']), SimpleNamespace(),
        Path('argus/rubrics')).run_probe(probe)]
    assert len(findings) == 1
    assert findings[0].verdict == 'error'
    assert 'response_fields_not_json' in findings[0].reasoning


def test_load_rejects_response_fields_mapping_instead_of_assertions_list(tmp_path):
    spec = {'equals': {'$.value': 'expected'}}
    with pytest.raises(ValueError, match='response_fields'):
        load_probe(write_probe(tmp_path, spec, assertions={'response_fields': spec}))
