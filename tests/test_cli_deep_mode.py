from dataclasses import replace
import importlib
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from click.testing import CliRunner
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError

from argus import api, llm, local
from argus.cli import api_client, run_json
from argus.cli.__main__ import main
from argus.cost_meter import CostExceededError, CostMeter
from argus.judge import Verdict
from argus.probe import IndirectItem, Probe, ProbeMappings
from argus.targets._base import Turn
from argus.targets.http_upload import HTTPUploadSpec, HTTPUploadTarget

SPEC = {
    'kind': 'custom_http', 'request_url': 'http://127.0.0.1/run',
    'request_body_template': '{"prompt": {{ prompt|tojson }}}', 'response_jsonpath': '$.text',
}


class Target:
    compatible_classes = {'llm_chat'}
    supports_history = True
    material_channel = False

    def __init__(self):
        self.calls = []

    async def send_prompt(self, prompt, history=(), material=None):
        self.calls.append((prompt, tuple(history), material))
        return 'benign reply', 1.0


@pytest.fixture
def engine(monkeypatch):
    probe = Probe('deep_fixture', 'Benign adaptation fixture', ('llm_chat',), ('prompt-injection',),
                  'medium', ('benign task',), ProbeMappings(), 'fixture', 'rubrics/default.md')
    target = Target()
    cfg = llm.LLMConfig('test', 'fixture', 'fixture', False, None)
    judge = SimpleNamespace(judge=AsyncMock(return_value=Verdict('pass', 'info', 1.0, 'benign', 'fixture', None)))
    completion = AsyncMock(return_value=llm.Completion('benign turn', 0, 0, 'fixture'))
    monkeypatch.setattr(api, 'load_probe_library', lambda *_: [probe])
    monkeypatch.setattr(local, 'load_probe_library', lambda *_: [probe])
    monkeypatch.setattr(api, 'build_target', lambda *a, **k: target)
    monkeypatch.setattr(local, 'build_target', lambda *a, **k: target)
    monkeypatch.setattr(api, 'Judge', lambda **_: judge)
    monkeypatch.setattr(llm, 'resolve_config', lambda *_: cfg)
    monkeypatch.setattr(llm, 'complete', completion)
    monkeypatch.setitem(importlib.import_module('argus.cost_meter')._PRICES_PER_M_TOKENS,
                        'fixture', {'input': 0.01, 'output': 0.01})
    monkeypatch.setattr(api, '_COST_METER', CostMeter(daily_cap_usd=1000, deep_per_run_cap_usd=1000))
    judge._cost_meter = api._COST_METER
    return SimpleNamespace(probe=probe, target=target, cfg=cfg, judge=judge, completion=completion)


def arguments(tmp_path, *, local_run=True, extra=()):
    args = ['run', '--target', json.dumps(SPEC), '--probes', 'deep_fixture', '--format',
            'json' if local_run else 'html', '--out', str(tmp_path / 'run.json')]
    args += ['--local'] if local_run else ['--api-url', 'http://127.0.0.1:1', '--token', 'fixture-token']
    return args + list(extra)


@pytest.mark.parametrize('rounds', [1, 20])
def test_request_accepts_round_limit_and_seed(rounds):
    request = api.RunRequest(target=SPEC, mode='deep', max_rounds=rounds, seed='repeat')
    assert request.max_rounds == rounds and request.seed == 'repeat'


@pytest.mark.parametrize('rounds', [0, 21, True, 1.5, '2'])
def test_request_rejects_invalid_round_limit(rounds):
    with pytest.raises(ValidationError, match='max_rounds'):
        api.RunRequest(target=SPEC, max_rounds=rounds)


def test_request_rejects_nontext_seed():
    with pytest.raises(ValidationError, match='seed'):
        api.RunRequest(target=SPEC, seed=2)


def test_estimate_uses_requested_rounds_and_pairings():
    req = api.RunRequest(target=SPEC, mode='deep', deep_pairs=2, max_rounds=3)
    assert api._estimate_exchanges(req, ['one', 'two']) == 12


def test_local_cli_runs_deep_flags_and_records_run_metadata(tmp_path, engine):
    result = CliRunner().invoke(main, arguments(tmp_path, extra=['--mode', 'deep', '--deep-pairs', '2',
                                                               '--max-rounds', '3', '--seed', 'repeat']))
    assert result.exit_code == 0, result.output
    record = json.loads((tmp_path / 'run.json').read_text())
    assert record['schema_version'] == 'argus.run/1'
    assert record['deep']['seed'] == 'repeat'
    assert record['deep']['deep_pairs'] == 2 and record['deep']['max_rounds'] == 3
    assert len(record['deep']['threads']) == 2
    assert all(t['base_probe_id'] == 'deep_fixture' and t['thread_id'] ==
               f"deep_fixture::{t['persona']}::{t['strategy']}" for t in record['deep']['threads'])
    assert len(record['findings']) == 6
    assert record['summary']['total'] == 6
    assert 'Estimated' in result.output
    assert result.output.index('Estimated') < result.output.index('pass')


def test_server_cli_forwards_all_deep_options_without_local_admission(tmp_path, engine, monkeypatch):
    seen = {}
    monkeypatch.setattr(api_client, 'post_run', lambda *a, body: seen.update(body) or {'run_id': 'run-1'})
    monkeypatch.setattr(api_client, 'poll_until_complete', lambda *a, **k: {'status': 'completed', 'findings': []})
    monkeypatch.setattr(api_client, 'get_report', lambda *a, **k: 'report')
    result = CliRunner().invoke(main, arguments(tmp_path, local_run=False, extra=[
        '--mode', 'deep', '--deep-pairs', '2', '--max-rounds', '8', '--seed', 'repeat', '--per-run-cap', '0']))
    assert result.exit_code == 0, result.output
    assert {key: seen[key] for key in ('mode', 'deep_pairs', 'max_rounds', 'seed')} == {
        'mode': 'deep', 'deep_pairs': 2, 'max_rounds': 8, 'seed': 'repeat'}
    assert 'client-side' in result.output and 'estimate' in result.output.lower()


@pytest.mark.parametrize('extra, fix', [
    (['--trials', '2'], '--trials 1'),
    (['--probes', 'all'], '--probes'),
])
def test_deep_cli_refusals_are_usage_errors(tmp_path, engine, extra, fix):
    result = CliRunner().invoke(main, arguments(tmp_path, extra=['--mode', 'deep', *extra]))
    assert result.exit_code == 2, result.output
    assert fix in result.output
    assert not (tmp_path / 'run.json').exists() and not engine.target.calls


def test_phased_deep_refusal_names_static_fix(tmp_path, engine, monkeypatch):
    probe = replace(engine.probe, scenario_control='honest')
    monkeypatch.setattr(api, 'load_probe_library', lambda *_: [probe])
    monkeypatch.setattr(local, 'load_probe_library', lambda *_: [probe])
    result = CliRunner().invoke(main, arguments(tmp_path, extra=['--mode', 'deep']))
    assert result.exit_code == 2, result.output
    assert '--mode static' in result.output and not engine.target.calls


def test_deep_without_text_model_is_usage_error(tmp_path, engine, monkeypatch):
    cfg = replace(engine.cfg, provider=llm.PROVIDER_JEV)
    monkeypatch.setattr(llm, 'resolve_config', lambda *_: cfg)
    result = CliRunner().invoke(main, arguments(tmp_path, extra=['--mode', 'deep']))
    assert result.exit_code == 2, result.output
    assert '--judge-explain-model' in result.output


async def collect_deep(seed, engine):
    return [event async for event in local.run_local(SPEC, [engine.probe.id], mode='deep',
                                                    deep_pairs=3, max_rounds=1, seed=seed)]


@pytest.mark.asyncio
async def test_seed_pairings_replay_and_omitted_seed_is_recorded(engine):
    same = [await collect_deep('repeat', engine), await collect_deep('repeat', engine)]
    changed = await collect_deep('different', engine)
    missing = [await collect_deep(None, engine), await collect_deep(None, engine)]
    metadata = lambda events: next(event['deep'] for event in events if event.get('type') == 'deep_run')
    assert metadata(same[0])['threads'] == metadata(same[1])['threads']
    assert metadata(same[0])['threads'] != metadata(changed)['threads']
    assert metadata(missing[0])['seed'] and metadata(missing[0])['seed'] != metadata(missing[1])['seed']
    assert metadata(await collect_deep('', engine))['seed'] == ''


@pytest.mark.asyncio
async def test_check_run_accepts_same_deep_options(engine):
    local.check_run(SPEC, [engine.probe.id], mode='deep', deep_pairs=2, max_rounds=1, seed='repeat')


def test_server_deep_metadata_is_not_a_finding(engine):
    app = FastAPI()
    app.include_router(api.router)
    response = TestClient(app).post('/redteam/run', json={'target': SPEC, 'probe_ids': [engine.probe.id],
                                    'mode': 'deep', 'deep_pairs': 2, 'max_rounds': 1, 'seed': 'repeat'})
    assert response.status_code == 200
    events = [json.loads(line[6:]) for line in response.text.splitlines() if line.startswith('data: ')][:-1]
    metadata = next(event['deep'] for event in events if event.get('type') == 'deep_run')
    assert metadata['seed'] == 'repeat' and len(metadata['threads']) == 2
    coverage = next(event for event in events if event.get('type') == 'coverage')
    assert coverage['summary']['total'] == 2


def test_server_deep_without_text_model_returns_422_with_fix(engine, monkeypatch):
    monkeypatch.setattr(llm, 'resolve_config', lambda *_: replace(engine.cfg, provider=llm.PROVIDER_JEV))
    monkeypatch.setattr(llm, 'credential_error', lambda *_: None)
    app = FastAPI()
    app.include_router(api.router)
    response = TestClient(app).post('/redteam/run', json={'target': SPEC, 'probe_ids': [engine.probe.id], 'mode': 'deep'})
    assert response.status_code == 422 and '--judge-explain-model' in response.text


def test_static_json_does_not_gain_deep_metadata():
    record = json.loads(run_json.render_json({'target_spec': SPEC, 'findings': []}))
    assert 'deep' not in record


@pytest.mark.asyncio
async def test_deep_records_existing_static_material_fallback(engine, monkeypatch):
    probe = replace(engine.probe, indirect=(IndirectItem('benign task', 'material'),), prompts=())
    engine.target.material_channel = True
    monkeypatch.setattr(api, 'load_probe_library', lambda *_: [probe])
    monkeypatch.setattr(local, 'load_probe_library', lambda *_: [probe])
    events = [event async for event in local.run_local(SPEC, [probe.id], mode='deep',
                                                      deep_pairs=2, max_rounds=1, seed='repeat')]
    metadata = next(event['deep'] for event in events if event.get('type') == 'deep_run')
    assert metadata['threads'] == [] and metadata['static_material_probe_ids'] == [probe.id]
    assert engine.completion.await_count == 0 and len(engine.target.calls) == 1


@pytest.mark.asyncio
async def test_attacker_spend_still_hits_run_cap(engine):
    engine.completion.return_value = llm.Completion('benign turn', 0, 200_000_000, 'fixture')
    req = api.RunRequest(target=SPEC, probe_ids=[engine.probe.id], mode='deep', max_rounds=1, deep_pairs=1,
                         seed='repeat', per_run_cap_usd=1)
    events = []
    with api._COST_METER.run_scope('fixture', deep=True, per_run_cap_usd=1):
        with pytest.raises(CostExceededError):
            async for event in api._run_probes(req, None, trusted_code=True):
                events.append(event)
        assert api._COST_METER.spent_in_current_run() > 1
    assert any(event.get('verdict') == 'aborted_cost' for event in events)
    assert not engine.target.calls


@pytest.mark.asyncio
async def test_http_upload_accepts_cold_history_without_sending_it(monkeypatch):
    requests = []
    async def respond(request):
        requests.append(request)
        return httpx.Response(200, json={'url': '/render'}) if request.url.path == '/upload' else httpx.Response(200, text='benign')
    real_client = httpx.AsyncClient
    monkeypatch.setattr('argus.targets.http_upload.httpx.AsyncClient',
                        lambda **kwargs: real_client(transport=httpx.MockTransport(respond), **kwargs))
    target = HTTPUploadTarget(HTTPUploadSpec(upload_url='http://127.0.0.1/upload', render_url_jsonpath='$.url'))
    for prompt in ('first', 'second'):
        reply, _ = await target.send_prompt(prompt, history=(Turn('user', 'old text'),))
        assert reply == 'benign'
    assert not target.supports_history
    assert len(requests) == 4
    assert b'old text' not in requests[0].content and b'old text' not in requests[2].content
    assert b'first' in requests[0].content and b'second' in requests[2].content
