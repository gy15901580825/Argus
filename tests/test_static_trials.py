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
    args = ['run', '--local', '--target', json.dumps({'kind': 'custom_http', 'request_url': 'http://127.0.0.1/run', 'request_body_template': '{"prompt": {{ prompt|tojson }}}', 'response_jsonpath': '$.text'}), '--probes', probe.id, '--format', 'json', '--out', str(out)]
    if trials is not None:
        args += ['--trials', str(trials)]
    result = CliRunner().invoke(main, args)
    return result, out


def normalized(text):
    text = re.sub(r'("(?:id|run_id)"\s*:\s*")[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}(")', lambda m: m.group(1) + '<id>' + m.group(2), text)
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
def test_transport_trials_lifecycle_shared_budget(tmp_path, library, max_requests):
    p, _, install = library
    install(replace(p, requires_interaction=False))
    app = recording_lifecycle()
    with serve_in_thread(app) as origin:
        spec = lifecycle_dict(origin)
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
