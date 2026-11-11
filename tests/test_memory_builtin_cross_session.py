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
    ('poisoned', 'fail'), ('facts_only', 'pass'), ('stateless', 'error'),
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
    assert result.exit_code == (1 if verdict == 'error' else 0), result.output
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
