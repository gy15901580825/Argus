import copy
import json
import re
from dataclasses import replace
from datetime import date
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from click.testing import CliRunner
from pydantic import ValidationError

from argus import api, local, llm
from argus.cli import api_client
from argus.cli.__main__ import main
from argus.probe import load_probe, load_probe_library
from argus.runner import Runner
from argus.trials import pass_wording
from argus_transport import local_transport_mode
from test_runner_phased import StubWorldTarget, probe as paired_probe
from test_transport_lifecycle import deletes, lifecycle_dict, recording_lifecycle
from transport_v2_fakes import serve_in_thread


class FakeTarget:
    compatible_classes = {'llm_chat', 'payment_agent'}
    supports_history = True

    def __init__(self, alternating=False):
        self.alternating = alternating
        self.calls = []
        self.begun = []
        self.evidence = {}

    async def begin_probe(self, probe):
        self.begun.append(probe.id)
        self.evidence.clear()

    async def send_prompt(self, prompt, history=()):
        self.calls.append((prompt, tuple(history)))
        amount = '2000' if self.alternating and len(self.calls) % 2 == 0 else '1'
        self.evidence.update(authorizations=[{'amount': amount, 'asset': 'USDC', 'payee': 'local'}], interaction_count=1)
        return 'completed', 1.0

    async def collect_evidence(self):
        return self.evidence

    def rendered_prompt(self, prompt):
        return prompt.replace('{merchant_url}', 'http://127.0.0.1/merchant')


@pytest.fixture
def library(monkeypatch):
    base = next(p for p in load_probe_library(api.PROBES_DIR) if p.id == 'pay_approval_forged')
    p = replace(base, id='static_trial_fixture', target_class=('llm_chat',), prompts=('normal',), scenario_kind=None, scenario_payload='')
    def install(probe=p, target=None):
        monkeypatch.setattr(api, 'load_probe_library', lambda *_: [probe])
        monkeypatch.setattr(local, 'load_probe_library', lambda *_: [probe])
        monkeypatch.setattr(api, 'Judge', lambda **_: SimpleNamespace())
        monkeypatch.setattr(llm, 'resolve_config', lambda *_: llm.LLMConfig('test', 'unused', 'unused', False, None))
        if target is not None:
            monkeypatch.setattr(api, 'build_target', lambda *a, **k: target)
            monkeypatch.setattr(local, 'build_target', lambda *a, **k: target)
        return probe
    install()
    return p, base, install


def invoke(tmp_path, probe, *, trials=None):
    out = tmp_path / 'run.json'
    args = ['run', '--local', '--target', json.dumps({'kind': 'custom_http', 'request_url': 'http://127.0.0.1/run', 'request_body_template': '{"prompt": {{ prompt|tojson }}}', 'response_jsonpath': '$.text'}), '--probes', probe.id, '--format', 'json', '--out', str(out), '--fail-on', 'info']
    if trials is not None:
        args += ['--trials', str(trials)]
    result = CliRunner().invoke(main, args)
    return result, out


def normalized(text):
    text = re.sub(r'("(?:id|run_id)"\s*:\s*")[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}(")', lambda m: m.group(1) + '<id>' + m.group(2), text)
    text = re.sub(r'("argus_version"\s*:\s*")[^"\n]*(")', r'\1<version>\2', text)
    return re.sub(r'("(?:started_at|finished_at|probed_at|created_at)"\s*:\s*")[^"\n]*(")', r'\1<timestamp>\2', text)


def test_cli_alternate_four_trials(tmp_path, library):
    p, _, install = library
    target = FakeTarget(alternating=True)
    install(p, target)
    result, out = invoke(tmp_path, p, trials=4)
    assert result.exit_code == 3, result.output
    record = json.loads(out.read_text())
    assert len(target.calls) == 4 and len(target.begun) == 4
    assert len(record['findings']) == 1
    finding = record['findings'][0]
    assert finding['verdict'] == 'fail'
    summary = finding['evidence']['trial_summary']
    assert summary['attempted'] == summary['valid'] == 4
    assert summary['pass'] == summary['fail'] == 2
    assert '2 of 4 valid trials failed' in finding['reasoning']
    assert [trial['verdict'] for trial in finding['evidence']['trials']] == ['pass', 'fail', 'pass', 'fail']
    assert all(set(t) == {'trial', 'verdict', 'reason_code', 'reason', 'clean', 'attack'} and t['clean'] is None for t in finding['evidence']['trials'])


def test_cli_all_pass_wording(tmp_path, library):
    p, _, install = library
    install(p, FakeTarget())
    result, out = invoke(tmp_path, p, trials=4)
    assert result.exit_code == 0, result.output
    finding = json.loads(out.read_text())['findings'][0]
    assert finding['verdict'] == 'pass'
    assert pass_wording(4, date.fromisoformat(finding['probed_at'][:10])) in finding['reasoning']


@pytest.mark.parametrize("trials", [None, 1])
def test_single_trial_existing_probe_golden(tmp_path, library, trials):
    _, existing, install = library
    install(existing, FakeTarget())
    result, out = invoke(tmp_path, existing, trials=trials)
    assert result.exit_code == 0, result.output
    assert normalized(out.read_bytes().decode()).encode() == (Path(__file__).parent / 'fixtures/static-trials-one-run.json').read_bytes()
    assert 'trial_summary' not in json.loads(out.read_text())['findings'][0]['evidence']


async def test_whole_multi_prompt_trial_and_snapshot_isolation(library):
    p, _, _ = library
    p = replace(p, prompts=('first', 'second'), trials=3)
    target = FakeTarget(alternating=True)
    findings = [f async for f in Runner(target, SimpleNamespace(), api.RUBRICS_DIR).run_probe(p)]
    assert len(findings) == 1
    assert [c[0] for c in target.calls] == ['first', 'second'] * 3
    assert len(target.begun) == 3
    f = findings[0]
    assert f.evidence['trial_summary']['fail'] == 3
    saved = copy.deepcopy(f.evidence)
    target.evidence.clear()
    assert f.evidence == saved
    json.dumps(f.evidence)


@pytest.mark.parametrize('value', [0, 21, 1.5, '4', True])
def test_api_trials_strict_range(value):
    with pytest.raises(ValidationError, match='trials'):
        api.RunRequest(target={}, trials=value)


@pytest.mark.parametrize('value', [0, 21, 1.5, True])
def test_yaml_trials_strict_range(tmp_path, value):
    raw = yaml.safe_load(next(api.PROBES_DIR.rglob('pay_approval_forged.yaml')).read_text())
    raw['trials'] = value
    path = tmp_path / 'probe.yaml'
    path.write_text(yaml.safe_dump(raw))
    with pytest.raises(ValueError, match='trials must be an integer from 1 to 20'):
        load_probe(path)


def test_yaml_static_trials_valid(tmp_path):
    raw = yaml.safe_load(next(api.PROBES_DIR.rglob('pay_approval_forged.yaml')).read_text())
    raw['trials'] = 4
    path = tmp_path / 'probe.yaml'
    path.write_text(yaml.safe_dump(raw))
    assert load_probe(path).trials == 4


@pytest.mark.parametrize('value', ['0', '21', '1.5'])
def test_cli_trials_invalid(tmp_path, value):
    result = CliRunner().invoke(main, ['run', '--local', '--target', '{}', '--trials', value])
    assert result.exit_code == 2
    assert 'Invalid value' in result.output and '--trials' in result.output


def test_local_override_replaces_probe_estimate(library, monkeypatch):
    p, _, install = library
    p = replace(p, trials=2, judge_when_assertions_pass=True)
    install(p, FakeTarget())
    monkeypatch.setattr(llm, 'missing_text', lambda *_: None)
    seen = []
    monkeypatch.setattr(api._COST_METER, 'check_or_abort_pre_run', lambda **kw: seen.append(kw))
    local.check_run({'kind': 'custom_http'}, [p.id], env={}, trials=4)
    assert seen[0]['total_exchanges'] == 4


def test_remote_override_payload(tmp_path, monkeypatch):
    seen = {}
    monkeypatch.setattr(api_client, 'post_run', lambda url, token, body: seen.update(body) or {'run_id': 'local-run'})
    monkeypatch.setattr(api_client, 'poll_until_complete', lambda *a, **k: {'status': 'completed', 'findings': []})
    monkeypatch.setattr(api_client, 'get_report', lambda *a, **k: '<html/>')
    monkeypatch.setattr('argus.cli.cmd_run.git_context.detect', lambda: {})
    result = CliRunner().invoke(main, ['run', '--target', json.dumps({'kind': 'custom_http', 'request_url': 'http://127.0.0.1/run', 'request_body_template': '{"prompt": {{ prompt|tojson }}}', 'response_jsonpath': '$.text'}), '--probes', 'p', '--trials', '4', '--api-url', 'http://127.0.0.1', '--token', 'offline-test-value', '--out', str(tmp_path / 'report.html')])
    assert result.exit_code == 0, result.output
    assert seen['trials'] == 4


async def test_run_override_preserves_phased_pairs(library):
    _, _, install = library
    p = paired_probe(trials=2)
    target = StubWorldTarget()
    install(p, target)
    req = api.RunRequest(target={'kind': 'custom_http'}, probe_ids=[p.id], trials=3)
    rows = [r async for r in api._run_probes(req, None)]
    assert target.begun == [('clean', 1), ('attack', 1), ('clean', 2), ('attack', 2), ('clean', 3), ('attack', 3)]
    assert rows[0]['evidence']['trial_summary']['attempted'] == 3


@pytest.mark.parametrize('max_requests', [None, 3])
@pytest.mark.parametrize('indirect', [False, True])
def test_transport_trials_lifecycle_shared_budget(tmp_path, library, max_requests, indirect):
    from argus.probe import IndirectItem
    p, _, install = library
    if indirect:
        p = replace(p, indirect=(IndirectItem('normal task', 'offline material'),))
    install(replace(p, requires_interaction=False))
    app = recording_lifecycle()
    with serve_in_thread(app) as origin:
        spec = lifecycle_dict(origin)
        if indirect:
            spec['lifecycle']['attempt'][0]['request']['body'] = {'text': {'context': 'material'}}
        if max_requests is not None:
            spec['budget'] = {'max_requests': max_requests}
        target = tmp_path / 'target.json'
        target.write_text(json.dumps({'kind': 'custom_http', 'transport': spec}))
        out = tmp_path / 'run.json'
        result = CliRunner().invoke(main, ['run', '--local', '--target', str(target), '--probes', p.id, '--trials', '4', '--format', 'json', '--out', str(out)])
        assert result.exit_code == (0 if max_requests is None else 1), result.output
        record = json.loads(out.read_text())
    n = 4 if max_requests is None else 1
    assert sum(call[0] == 'POST' and call[1] == '/run' for call in app.calls) == n
    assert sum(path.startswith('/v1/messages?') for path in deletes(app)) == n
    assert deletes(app).count('/v1/sources/source-one') == 1
    if indirect:
        ingests = [call[3].decode() for call in app.calls if call[0] == 'POST' and call[1] == '/v1/messages']
        assert ingests == ['offline material'] * n
    assert record['target_cleanup']['complete'] is True
    assert record['status'] == ('completed' if max_requests is None else 'incomplete')
    if max_requests is not None:
        assert record['target_cleanup']['stop_reason'] == 'request_budget'


async def test_transport_budget_stop_propagates_with_cleanup(library):
    from argus_transport.runtime_v2 import TargetRunStopped
    p, _, install = library
    install(replace(p, trials=4, requires_interaction=False))
    app = recording_lifecycle()
    rows = []
    with serve_in_thread(app) as origin:
        spec = lifecycle_dict(origin)
        spec['budget'] = {'max_requests': 3}
        req = api.RunRequest(target={'kind': 'custom_http', 'transport': spec}, probe_ids=[p.id])
        with local_transport_mode():
            with pytest.raises(TargetRunStopped) as caught:
                async for row in api._run_probes(req, None, trusted_code=True):
                    rows.append(row)
    assert caught.value.reason == 'request_budget'
    assert caught.value.target_cleanup['complete'] is True
    assert caught.value.target_cleanup['stop_reason'] == 'request_budget'
    assert sum(call[0] == 'POST' and call[1] == '/run' for call in app.calls) == 1
    assert not any(row.get('verdict') == 'pass' for row in rows)


@pytest.mark.parametrize('value', ['4', True, 1.0])
def test_yaml_exact_integer(tmp_path, value):
    raw = yaml.safe_load(next(api.PROBES_DIR.rglob('pay_approval_forged.yaml')).read_text())
    raw['trials'] = value
    path = tmp_path / 'probe.yaml'
    path.write_text(yaml.safe_dump(raw))
    with pytest.raises(ValueError, match='trials must be an integer'):
        load_probe(path)


async def test_cost_stop_retains_only_started_trials(library):
    from argus.cost_meter import CostExceededError
    p, _, _ = library
    stop = CostExceededError('offline cap')
    class Target(FakeTarget):
        async def send_prompt(self, prompt, history=()):
            if self.calls:
                raise stop
            return await super().send_prompt(prompt, history)
    target = Target()
    rows = []
    with pytest.raises(CostExceededError) as caught:
        async for f in Runner(target, SimpleNamespace(), api.RUBRICS_DIR).run_probe(replace(p, trials=4)):
            rows.append(f)
    assert caught.value is stop
    assert len(rows) == 1 and rows[0].verdict == 'aborted_cost'
    summary = rows[0].evidence['trial_summary']
    assert summary['attempted'] == 2 and summary['valid'] == 1
    assert len(rows[0].evidence['trials']) == 2
    assert rows[0].evidence['trials'][1]['attack']['observations'] == []


async def test_logical_breaker_once_per_repeated_probe(library):
    import httpx
    from argus.runner import TargetUnreachableError, UNREACHABLE_AFTER
    p, _, _ = library
    class Target(FakeTarget):
        async def send_prompt(self, prompt, history=()):
            self.calls.append((prompt, history))
            raise httpx.ConnectError('offline unreachable')
    target = Target()
    runner = Runner(target, SimpleNamespace(), api.RUBRICS_DIR)
    for _ in range(UNREACHABLE_AFTER - 1):
        rows = [f async for f in runner.run_probe(replace(p, trials=4))]
        assert len(rows) == 1 and rows[0].verdict == 'error'
    with pytest.raises(TargetUnreachableError):
        async for _ in runner.run_probe(replace(p, trials=4)):
            pass
    assert len(target.calls) == 4 * UNREACHABLE_AFTER


async def test_trial_conversations_restart(library):
    p, _, _ = library
    target = FakeTarget()
    rows = [f async for f in Runner(target, SimpleNamespace(), api.RUBRICS_DIR).run_probe(replace(p, trials=3, conversation=True, prompts=('setup', 'decide')))]
    assert len(rows) == 1
    assert [len(history) for _, history in target.calls] == [0, 2] * 3
    assert rows[0].evidence['trial_summary']['valid'] == 3


async def test_never_reached_gate_finalizes_each_trial(library):
    p, _, _ = library
    class Target(FakeTarget):
        async def collect_evidence(self):
            return {'authorizations': [], 'interaction_count': 0}
    rows = [f async for f in Runner(Target(), SimpleNamespace(), api.RUBRICS_DIR).run_probe(replace(p, trials=3))]
    assert len(rows) == 1 and rows[0].verdict == 'error'
    assert rows[0].evidence['trial_summary']['error'] == 3
    assert all(t['attack']['observations'][0]['verdict'] == 'error' for t in rows[0].evidence['trials'])


async def test_mapped_refusal_exposure_finalizes_each_trial(library):
    from argus.targets._base import TargetBlockedError
    p, _, _ = library
    class Target(FakeTarget):
        async def send_prompt(self, prompt, history=()):
            raise TargetBlockedError('offline refusal', transport_metadata={'http_status': 200, 'exposure': 'unknown', 'origin': 'mapped_body_rule', 'outcome': 'blocked', 'matched_rule_id': 'offline-rule'})
    rows = [f async for f in Runner(Target(), SimpleNamespace(), api.RUBRICS_DIR).run_probe(replace(p, trials=2))]
    assert len(rows) == 1 and rows[0].verdict == 'blocked_by_target'
    for trial in rows[0].evidence['trials']:
        observation = trial['attack']['observations'][0]
        assert observation['evidence']['transport']['exposure'] == 'not_exercised'
        assert '_mapped_body_refusal' not in observation['evidence']


@pytest.mark.parametrize('second', ['error', 'skipped', 'all_error'])
async def test_mixed_trial_outcomes_never_pass(library, second):
    from argus.targets._base import ProbeNotApplicable, TargetTransportError
    p, _, _ = library
    class Target(FakeTarget):
        async def begin_probe(self, probe):
            await super().begin_probe(probe)
            if second == 'skipped' and len(self.begun) == 2:
                raise ProbeNotApplicable('offline unavailable')
        async def send_prompt(self, prompt, history=()):
            if second == 'all_error' or second == 'error' and len(self.begun) == 2:
                raise TargetTransportError('offline broken reply')
            return await super().send_prompt(prompt, history)
    rows = [f async for f in Runner(Target(), SimpleNamespace(), api.RUBRICS_DIR).run_probe(replace(p, trials=2))]
    assert len(rows) == 1 and rows[0].verdict == 'error'
    assert rows[0].evidence['trial_summary']['attempted'] == 2
    assert rows[0].evidence['trial_summary']['valid'] == (0 if second == 'all_error' else 1)


def test_override_one_replaces_yaml_count(tmp_path, library):
    p, _, install = library
    target = FakeTarget()
    install(replace(p, trials=4), target)
    result, out = invoke(tmp_path, p, trials=1)
    assert result.exit_code == 0, result.output
    assert len(target.calls) == 1
    record = json.loads(out.read_text())
    assert len(record['findings']) == 1
    assert 'trial_summary' not in record['findings'][0]['evidence']


async def test_mid_prompt_budget_stop_preserves_observed_prompt(library):
    from argus_transport.runtime_v2 import TargetRunStopped
    p, _, _ = library
    stop = TargetRunStopped('request_budget', 'offline budget')
    class Target(FakeTarget):
        async def send_prompt(self, prompt, history=()):
            if len(self.calls) == 3:
                raise stop
            return await super().send_prompt(prompt, history)
    rows = []
    with pytest.raises(TargetRunStopped) as caught:
        async for f in Runner(Target(), SimpleNamespace(), api.RUBRICS_DIR).run_probe(replace(p, trials=4, prompts=('first', 'second'))):
            rows.append(f)
    assert caught.value is stop
    assert len(rows) == 1 and rows[0].verdict == 'error'
    trials = rows[0].evidence['trials']
    assert len(trials) == 2
    assert [len(t['attack']['observations']) for t in trials] == [2, 1]
    assert trials[1]['attack']['observations'][0]['attack_prompt'] == 'first'


async def test_staging_transport_failures_count_one_logical_probe(library):
    import httpx
    from argus.runner import UNREACHABLE_AFTER, TargetUnreachableError
    p, _, _ = library
    class Target(FakeTarget):
        async def begin_probe(self, probe):
            self.begun.append(probe.id)
            raise httpx.ConnectError('offline staging unavailable')
    target = Target()
    runner = Runner(target, SimpleNamespace(), api.RUBRICS_DIR)
    for _ in range(UNREACHABLE_AFTER - 1):
        rows = [f async for f in runner.run_probe(replace(p, trials=3))]
        assert len(rows) == 1 and rows[0].evidence['trial_summary']['error'] == 3
    with pytest.raises(TargetUnreachableError):
        async for _ in runner.run_probe(replace(p, trials=3)):
            pass
    assert len(target.begun) == UNREACHABLE_AFTER * 3


@pytest.mark.parametrize('guard', ['compat', 'history', 'rubric'])
async def test_preexecution_guards_do_not_invent_trials(library, tmp_path, guard):
    p, _, _ = library
    target = FakeTarget()
    if guard == 'compat':
        p = replace(p, target_class=('mcp_agent',))
    elif guard == 'history':
        p = replace(p, conversation=True)
        target.supports_history = False
    else:
        p = replace(p, assertions=(), judge_rubric_path='missing.md')
    rows = [f async for f in Runner(target, SimpleNamespace(), tmp_path).run_probe(replace(p, trials=4))]
    assert len(rows) == 1
    assert rows[0].verdict == ('error' if guard == 'rubric' else 'skipped')
    assert 'trial_summary' not in (rows[0].evidence or {})
    assert target.calls == target.begun == []


def test_server_preflight_402_accounts_for_override(library, monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from argus import cost_meter
    from argus.cost_meter import CostMeter
    from argus.judge import Verdict
    p, _, install = library
    target = FakeTarget()
    install(replace(p, judge_when_assertions_pass=True), target)
    monkeypatch.setattr(llm, 'credential_error', lambda *_: None)
    monkeypatch.setattr(cost_meter, '_price_for', lambda *_: {'input': 1.0, 'output': 1.0})
    monkeypatch.setattr(api, '_COST_METER', CostMeter(daily_cap_usd=100, per_run_cap_usd=0.01))
    class Judge:
        async def judge(self, **kwargs):
            return Verdict('pass', 'info', 1.0, 'offline safe reply', 'test')
    monkeypatch.setattr(api, 'Judge', lambda **_: Judge())
    app = FastAPI()
    app.include_router(api.router)
    with TestClient(app) as client:
        body = {'target': {'kind': 'custom_http'}, 'probe_ids': [p.id], 'trials': 1}
        single = client.post('/redteam/run', json=body)
        assert single.status_code == 200 and 'event: error' not in single.text
        assert len(target.calls) == 1
        multiple = client.post('/redteam/run', json={**body, 'trials': 4})
        assert multiple.status_code == 402
        assert 'estimated cost' in multiple.json()['detail']
        assert len(target.calls) == 1


@pytest.mark.parametrize('count', [2, 20])
def test_iterative_yaml_rejects_repeated_trials(tmp_path, count):
    raw = yaml.safe_load(next(api.PROBES_DIR.rglob('pay_approval_forged.yaml')).read_text())
    raw.update(iterative=True, trials=count)
    path = tmp_path / 'probe.yaml'
    path.write_text(yaml.safe_dump(raw))
    with pytest.raises(ValueError, match='iterative'):
        load_probe(path)


@pytest.mark.parametrize('count', [None, 1, 4])
def test_deep_exchange_estimate_is_unchanged(library, count):
    p, _, install = library
    install(replace(p, trials=3))
    req = api.RunRequest(target={}, probe_ids=[p.id], mode='deep', trials=count)
    ceiling = api.DEFAULT_DEEP_PAIRS * api.DEFAULT_MAX_ROUNDS
    assert api._estimate_exchanges(req, [p.id]) == ceiling
    assert api._judged_exchanges(req, [p.id]) == ceiling


async def test_static_override_does_not_repeat_iterative_probe(library):
    from unittest.mock import AsyncMock
    p, _, install = library
    probe = SimpleNamespace(id=p.id, name=p.name, iterative=True, target_class=p.target_class,
                            prompts=p.prompts, conversation=False, judge_rubric_path=p.judge_rubric_path,
                            assertions=(), mappings=p.mappings, next_prompt=AsyncMock(return_value=None),
                            should_halt=lambda _: False)
    target = FakeTarget()
    install(probe, target)
    req = api.RunRequest(target={}, probe_ids=[p.id], trials=4)
    assert [row async for row in api._run_probes(req, None)] == []
    assert probe.next_prompt.await_count == 1
    assert len(target.begun) == 1 and target.calls == []
    assert not hasattr(probe, 'trials')


async def test_deep_trials_rejected_after_server_configuration(library, monkeypatch):
    from fastapi import HTTPException
    from argus.probe import IndirectItem
    p, _, install = library
    target = FakeTarget()
    target.material_channel = True
    install(replace(p, indirect=(IndirectItem('task', 'material'),)), target)
    monkeypatch.setattr(llm, 'credential_error', lambda *_: None)
    req = api.RunRequest(target={}, probe_ids=[p.id], mode='deep', trials=4)
    with pytest.raises(HTTPException) as caught:
        await api.run(req)
    assert caught.value.status_code == 422 and 'trials' in caught.value.detail
    monkeypatch.setattr(llm, 'resolve_config', lambda *_: llm.LLMConfig(llm.PROVIDER_JEV, 'test', 'test', False, None))
    monkeypatch.setattr(llm, 'explain_config', lambda *_: None)
    with pytest.raises(HTTPException) as caught:
        await api.run(req)
    assert caught.value.status_code == 422 and '--judge-explain-model' in caught.value.detail
    assert '--mode static' in caught.value.detail


def test_deep_trials_rejected_after_local_configuration(library, monkeypatch):
    from argus.probe import IndirectItem
    p, _, install = library
    target = FakeTarget()
    target.material_channel = True
    install(replace(p, indirect=(IndirectItem('task', 'material'),)), target)
    monkeypatch.setattr(llm, 'missing_text', lambda *_: None)
    with pytest.raises(local.LocalRunError, match='trials'):
        local.check_run({}, [p.id], mode='deep', trials=4, env={})
    monkeypatch.setattr(llm, 'resolve_config', lambda *_: llm.LLMConfig(llm.PROVIDER_JEV, 'test', 'test', False, None))
    monkeypatch.setattr(llm, 'explain_config', lambda *_: None)
    with pytest.raises(local.LocalRunError, match='--judge-explain-model'):
        local.check_run({}, [p.id], mode='deep', trials=4, env={})


@pytest.mark.parametrize('override', [None, 1, 4])
@pytest.mark.parametrize('phased', [False, True])
def test_effective_trials_exchange_count_is_used_once(library, override, phased):
    p, _, install = library
    p = paired_probe(trials=3) if phased else replace(p, trials=3, prompts=('first', 'second'), judge_when_assertions_pass=True)
    install(p)
    req = api.RunRequest(target={}, probe_ids=[p.id], trials=override)
    expected = (3 if override is None else override) * len(p.prompts) * (2 if phased else 1)
    assert api._estimate_exchanges(req, [p.id]) == expected
    assert api._judged_exchanges(req, [p.id]) == (0 if phased else expected)


@pytest.mark.parametrize('verdict', ['fail', 'warn'])
@pytest.mark.parametrize('stop_kind', ['request_budget', 'cost_cap'])
async def test_interrupted_trial_preserves_finalized_fail_or_warn(library, verdict, stop_kind):
    from argus.cost_meter import CostExceededError
    from argus.judge import Verdict
    from argus_transport.runtime_v2 import TargetRunStopped
    p, _, _ = library
    stop = CostExceededError('offline cap') if stop_kind == 'cost_cap' else TargetRunStopped('request_budget', 'offline budget')
    class Target(FakeTarget):
        async def send_prompt(self, prompt, history=()):
            if self.calls:
                raise stop
            return await super().send_prompt(prompt, history)
    class Judge:
        async def judge(self, **kwargs):
            return Verdict(verdict, 'high', 1.0, 'offline observed result', 'test')
    rows = []
    target = Target()
    with pytest.raises(type(stop)) as caught:
        async for row in Runner(target, Judge(), api.RUBRICS_DIR).run_probe(replace(p, trials=4, prompts=('first', 'second'), assertions=())):
            rows.append(row)
    assert caught.value is stop
    assert len(rows) == 1 and rows[0].verdict == verdict
    trials = rows[0].evidence['trials']
    assert len(trials) == 1 and trials[0]['verdict'] == verdict
    assert trials[0]['reason_code'] == stop_kind
    assert trials[0]['attack']['observations'][0]['verdict'] == verdict
    assert rows[0].evidence['trial_summary'][verdict] == 1
    assert rows[0].evidence['trial_summary']['valid'] == 1
    assert len(target.calls) == 1
