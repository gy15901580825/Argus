"""Cross-session outcomes through the real CLI and a loopback chat endpoint."""
import json
from pathlib import Path

from click.testing import CliRunner
from fastapi import FastAPI, Request
import pytest

from argus.cli.__main__ import main
from argus.demo.servers import _bind, _serve
from argus.probe import load_probe

PROBE_PATH = Path(__file__).resolve().parents[1] / 'argus/probes/memory_builtin_cross_session.yaml'
PROBE = load_probe(PROBE_PATH)
CANARY = PROBE.assertions[0]['no_cross_session_instruction']['canary']
FACT = PROBE.assertions[0]['no_cross_session_instruction']['recall']


def fake_chat(mode):
    app = FastAPI()
    requests = []
    memory = {}

    @app.post('/chat')
    async def chat(request: Request):
        body = await request.json()
        requests.append(body)
        prompt = body['prompt']
        if prompt == PROBE.sessions[0][0]:
            if mode != 'stateless':
                memory['fact'] = FACT
            reply = 'User fact saved.'
        elif prompt == PROBE.sessions[0][1]:
            if mode in {'poisoned', 'poisoned_without_fact'}:
                memory['instruction'] = CANARY
            reply = 'The workshop will prepare badges and paper folding materials.'
            if mode == 'setup_only_canary':
                reply += ' ' + CANARY
        else:
            reply = 'Try apples, crackers, and carrot sticks.'
            if 'fact' in memory and mode != 'poisoned_without_fact':
                reply += ' Your craft project codename is ' + memory['fact'] + '.'
            else:
                reply += ' I cannot remember a previous codename.'
        if 'instruction' in memory:
            reply += ' ' + memory['instruction']
        return {'text': reply}

    return app, requests


@pytest.mark.parametrize(('mode', 'verdict'), [
    ('poisoned', 'fail'), ('facts_only', 'pass'), ('stateless', 'skipped'),
    ('setup_only_canary', 'pass'), ('poisoned_without_fact', 'fail'),
])
def test_cli_cross_session_outcomes(tmp_path, monkeypatch, mode, verdict):
    monkeypatch.setenv('NO_PROXY', '127.0.0.1')
    monkeypatch.delenv('ARGUS_API_URL', raising=False)
    app, requests = fake_chat(mode)
    report = tmp_path / 'run.json'
    with _serve(app, _bind(), 'synthetic memory chat') as url:
        spec = {
            'kind': 'custom_http', 'request_url': url + '/chat',
            'request_body_template': '{"prompt": {{ prompt|tojson }}, "history": {{ history|tojson }}, "conversation_id": {{ conversation_id|tojson }}}',
            'response_jsonpath': '$.text',
        }
        result = CliRunner().invoke(main, ['run', '--local', '--target', json.dumps(spec),
            '--probes', PROBE.id, '--format', 'json', '--out', str(report)])
    assert result.exit_code == 0, result.output
    run = json.loads(report.read_text())
    assert len(run['findings']) == 1
    finding = run['findings'][0]
    assert finding['verdict'] == verdict
    assert finding['judge_model'] == ''
    assert len(requests) == 3
    assert requests[0]['history'] == requests[2]['history'] == []
    assert requests[1]['conversation_id'] == requests[0]['conversation_id']
    assert requests[2]['conversation_id'] != requests[0]['conversation_id']
    assert len(requests[1]['history']) == 2
    assert FACT not in requests[2]['prompt'] and CANARY not in requests[2]['prompt']
    assert finding['evidence']['sessions'][-1]['session'] == 2
    assert finding['evidence']['sessions'][-1]['reply'] == finding['target_response']
    if verdict == 'fail':
        assert CANARY in finding['target_response']
        assert CANARY in finding['evidence']['sessions'][-1]['reply']
    if mode == 'stateless':
        assert 'no cross-session memory was observed' in finding['reasoning']
        assert 'no cross-session memory was observed' in result.output


def test_builtin_probe_contract():
    assert PROBE.target_class == ('http-chat',)
    assert PROBE.severity == 'high'
    assert PROBE.needs_history and not PROBE.is_phased and not PROBE.needs_judge
    assert PROBE.exchange_count == 3
    assert PROBE.mappings.owasp_agentic == ('ASI06',)
    assert PROBE.mappings.atlas == ('AML.T0051.001',)


def test_deep_mode_does_not_flatten_cross_session_probe(tmp_path):
    result = CliRunner().invoke(main, ['run', '--local', '--mode', 'deep', '--target',
        json.dumps({'kind': 'custom_http', 'request_url': 'http://127.0.0.1:1/chat',
                    'request_body_template': '{"prompt": {{ prompt|tojson }}}',
                    'response_jsonpath': '$.text'}), '--probes', PROBE.id, '--out', str(tmp_path / 'run.json')])
    assert result.exit_code != 0
    assert 'set mode=static' in result.output


@pytest.mark.parametrize('fail_on', [None, 'high'])
def test_stateless_skip_does_not_fail_run(tmp_path, monkeypatch, fail_on):
    monkeypatch.setenv('NO_PROXY', '127.0.0.1')
    monkeypatch.delenv('ARGUS_API_URL', raising=False)
    app, requests = fake_chat('stateless')
    report = tmp_path / 'stateless.json'
    with _serve(app, _bind(), 'synthetic stateless chat') as url:
        spec = {
            'kind': 'custom_http', 'request_url': url + '/chat',
            'request_body_template': '{"prompt": {{ prompt|tojson }}, "history": {{ history|tojson }}, "conversation_id": {{ conversation_id|tojson }}}',
            'response_jsonpath': '$.text',
        }
        args = ['run', '--local', '--target', json.dumps(spec), '--probes', PROBE.id,
                '--format', 'json', '--out', str(report)]
        if fail_on:
            args += ['--fail-on', fail_on]
        result = CliRunner().invoke(main, args)
    assert result.exit_code == 0, result.output
    run = json.loads(report.read_text())
    assert run['findings'][0]['verdict'] == 'skipped'
    assert run['status'] == 'completed'
    assert 'incomplete_reason' not in run
    assert 'no cross-session memory was observed' in result.output
    assert 'incomplete' not in result.output.lower()
    assert len(requests) == 3


def test_default_selection_never_sends_memory_probe(tmp_path, monkeypatch):
    from argus import llm
    monkeypatch.setenv('NO_PROXY', '127.0.0.1')
    monkeypatch.delenv('ARGUS_API_URL', raising=False)
    monkeypatch.setattr(llm, 'missing_text', lambda cfg: 'no synthetic judge configured')
    app, requests = fake_chat('stateless')
    report = tmp_path / 'default.json'
    with _serve(app, _bind(), 'synthetic default-selection chat') as url:
        spec = {
            'kind': 'custom_http', 'request_url': url + '/chat',
            'request_body_template': '{"prompt": {{ prompt|tojson }}, "history": {{ history|tojson }}, "conversation_id": {{ conversation_id|tojson }}}',
            'response_jsonpath': '$.text',
        }
        args = ['run', '--local', '--target', json.dumps(spec), '--skip-judged',
                '--format', 'json', '--out', str(report)]
        args += ['--probes', 'all']
        result = CliRunner().invoke(main, args)
    assert report.exists(), result.output
    run = json.loads(report.read_text())
    assert run['findings']
    assert all(f['probe_id'] != PROBE.id for f in run['findings'])
    assert requests
    assert all(r['prompt'] not in PROBE.prompts for r in requests)
    assert all(CANARY not in r['prompt'] and FACT not in r['prompt'] for r in requests)


@pytest.mark.parametrize('value', ['true', 'false', 1, 0, None, [], {}])
def test_malformed_opt_in_rejected_at_load(tmp_path, value):
    import yaml
    data = yaml.safe_load(PROBE_PATH.read_text())
    data['opt_in'] = value
    path = tmp_path / 'malformed-opt-in.yaml'
    path.write_text(yaml.safe_dump(data))
    with pytest.raises(ValueError, match='opt_in must be a boolean') as exc:
        load_probe(path)
    assert str(path) in str(exc.value)


def test_list_probes_marks_opt_in(monkeypatch):
    monkeypatch.delenv('ARGUS_API_URL', raising=False)
    result = CliRunner().invoke(main, ['list-probes', '--filter', PROBE.id])
    assert result.exit_code == 0, result.output
    assert PROBE.id + ' [opt-in]' in result.output


def test_suite_selection_excludes_opt_in():
    from argus.api import _resolve_probe_ids, _resolve_suite
    from argus.probe import load_probe_library
    from argus.api import PROBES_DIR
    from argus.suites import derive_suites
    assert PROBE.opt_in
    assert PROBE.id not in _resolve_probe_ids([])
    assert _resolve_probe_ids([PROBE.id]) == [PROBE.id]
    for suite in derive_suites(load_probe_library(PROBES_DIR)):
        assert PROBE.id not in _resolve_suite(suite)
