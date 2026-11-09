from dataclasses import asdict, replace
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock
from xml.etree import ElementTree as ET

import httpx
import pytest

from argus import llm, persona_strategy
from argus.cli import reports, run_json
from argus.cost_meter import CostExceededError
from argus.judge import Verdict
from argus.persona_loader import default_personas, default_strategies
from argus.persona_strategy import PersonaStrategyProbe
from argus.probe import Probe, ProbeMappings
from argus.runner import Runner


def blocked():
    return llm.JudgeBlockedError('synthetic content filter', provider='fixture', model='fixture',
                                 categories=('test',), fallback=None)


@pytest.fixture
def thread_case(tmp_path, monkeypatch):
    base = Probe('thread_fixture', 'Benign thread fixture', ('llm_chat',), ('prompt-injection',),
                 'medium', ('third {address}',), ProbeMappings(), 'fixture', 'fixture.md')
    (tmp_path / 'fixture.md').write_text('Assess the benign fixture.')
    probe = PersonaStrategyProbe(base, default_personas()[0], default_strategies()[0], max_rounds=3)

    class Target:
        compatible_classes = {'llm_chat'}
        supports_history = True

        def __init__(self):
            self.calls = []
            self.responses = ['first reply', 'second reply', 'third reply']
            self.wire = ''

        async def send_prompt(self, prompt, history=()):
            self.calls.append((prompt, history))
            self.wire = prompt.replace('{address}', f'http://127.0.0.1/round-{len(self.calls)}')
            reply = self.responses[len(self.calls) - 1]
            if isinstance(reply, Exception):
                raise reply
            return reply, 1.0

        def rendered_prompt(self, prompt):
            return self.wire if '{address}' in prompt else prompt

    target = Target()
    judge = SimpleNamespace(judge=AsyncMock(return_value=Verdict('pass', 'info', 1.0, 'safe reply', 'fixture', None)))
    attacker = AsyncMock(side_effect=['first {address}', 'second {address}', 'third {address}'])
    monkeypatch.setattr(persona_strategy, '_call_attacker_llm', attacker)
    runner = Runner(target, judge, tmp_path)
    return SimpleNamespace(probe=probe, target=target, judge=judge, attacker=attacker, runner=runner)


async def results(case):
    return [finding async for finding in case.runner.run_probe(case.probe)]


def assert_thread(finding, case, verdict, reason, rounds):
    assert finding.verdict == verdict
    evidence = finding.evidence
    assert evidence['thread_id'] == case.probe.id
    assert evidence['persona'] == case.probe.persona.id
    assert evidence['strategy'] == case.probe.strategy.id
    assert evidence['history'] is case.target.supports_history
    assert evidence['stop_reason'] == reason and evidence['rounds_run'] == rounds
    assert len(evidence['transcript']) == rounds
    assert all(set(row) == {'attack_prompt', 'target_response', 'verdict', 'severity', 'reasoning', 'kind'}
               for row in evidence['transcript'])


@pytest.mark.asyncio
@pytest.mark.parametrize('stop, verdict, rounds', [
    ('max_rounds', 'pass', 3), ('fail', 'fail', 2), ('warn', 'warn', 3),
    ('attacker_stopped', 'error', 1), ('attacker_blocked', 'error', 1),
    ('send_error', 'error', 2), ('blank_reply', 'error', 2),
    ('judge_unusable', 'error', 2), ('cost', 'aborted_cost', 1),
])
async def test_one_deep_finding_records_every_stop_without_early_pass(thread_case, stop, verdict, rounds):
    c = thread_case
    if stop in {'attacker_stopped', 'attacker_blocked', 'cost'}:
        c.attacker.side_effect = ['first {address}', {'attacker_stopped': None,
                                                   'attacker_blocked': blocked(),
                                                   'cost': CostExceededError('fixture cap')}[stop]]
    elif stop == 'send_error':
        c.target.responses[1] = httpx.ReadTimeout('fixture timeout')
    elif stop == 'blank_reply':
        c.target.responses[1] = ''
    elif stop == 'judge_unusable':
        c.judge.judge.side_effect = [Verdict('pass', 'info', 1.0, 'safe', 'fixture', None), ValueError('fixture invalid verdict')]
    elif stop in {'fail', 'warn'}:
        c.judge.judge.side_effect = [Verdict('pass', 'info', 1.0, 'safe', 'fixture', None),
                                  Verdict(stop, 'medium', 1.0, 'second round', 'fixture', None),
                                  Verdict('pass', 'info', 1.0, 'safe', 'fixture', None)]
    found = await results(c)
    assert len(found) == 1
    assert_thread(found[0], c, verdict, 'max_rounds' if stop == 'warn' else stop, rounds)


@pytest.mark.asyncio
async def test_transcript_snapshots_each_actual_wire_prompt(thread_case):
    c = thread_case
    found = await results(c)
    assert len(found) == 1
    assert [r['attack_prompt'] for r in found[0].evidence['transcript']] == [
        'first http://127.0.0.1/round-1', 'second http://127.0.0.1/round-2', 'third http://127.0.0.1/round-3']
    assert len(c.target.calls[-1][1]) == 4


@pytest.mark.asyncio
async def test_stateless_threads_still_run_cold_but_attacker_sees_replies(thread_case):
    c = thread_case
    c.target.supports_history = False
    found = await results(c)
    assert len(found) == 1
    assert_thread(found[0], c, 'pass', 'max_rounds', 3)
    assert all(history == () for _, history in c.target.calls)
    assert 'first reply' in c.attacker.call_args_list[1].args[1]


@pytest.mark.asyncio
async def test_transcript_does_not_hide_collected_target_evidence(thread_case):
    c = thread_case
    c.target.collect_evidence = AsyncMock(return_value={'interaction_count': 3, 'observed': 'retained'})
    found = await results(c)
    assert len(found) == 1
    assert found[0].evidence['observed'] == 'retained'
    assert len(found[0].evidence['transcript']) == 3


@pytest.mark.asyncio
@pytest.mark.parametrize('point', ['before_send', 'judge'])
async def test_cost_keeps_completed_and_attempted_rounds(thread_case, point):
    c = thread_case
    if point == 'before_send':
        c.attacker.side_effect = [CostExceededError('fixture cap')]
        count = 0
    else:
        c.judge.judge.side_effect = [Verdict('pass', 'info', 1.0, 'safe', 'fixture', None), CostExceededError('fixture cap')]
        count = 2
    found = await results(c)
    assert len(found) == 1
    assert_thread(found[0], c, 'aborted_cost', 'cost', count)
    if point == 'judge':
        assert found[0].evidence['transcript'][1]['target_response'] == 'second reply'


@pytest.mark.asyncio
@pytest.mark.parametrize('boundary', ['attacker', 'judge'])
async def test_provider_block_has_the_correct_boundary_reason(thread_case, boundary):
    c = thread_case
    if boundary == 'attacker':
        c.attacker.side_effect = [blocked()]
    else:
        c.judge.judge.side_effect = [blocked()]
    found = await results(c)
    assert len(found) == 1
    assert_thread(found[0], c, 'error', 'attacker_blocked' if boundary == 'attacker' else 'judge_unusable',
                  0 if boundary == 'attacker' else 1)


@pytest.mark.asyncio
async def test_generic_attacker_provider_failure_still_yields_one_error(thread_case):
    c = thread_case
    c.attacker.side_effect = [llm.AllProvidersFailed('fixture provider unavailable')]
    found = await results(c)
    assert len(found) == 1
    assert_thread(found[0], c, 'error', 'attacker_stopped', 0)
    assert 'fixture provider unavailable' in found[0].reasoning


@pytest.mark.asyncio
@pytest.mark.parametrize('setup', ['rubric', 'begin'])
async def test_unstarted_thread_setup_errors_are_annotated(thread_case, setup):
    c = thread_case
    if setup == 'rubric':
        c.probe.judge_rubric_path = 'missing.md'
    else:
        c.target.begin_probe = AsyncMock(side_effect=ValueError('fixture setup invalid'))
    found = await results(c)
    assert len(found) == 1
    assert found[0].verdict == 'error' and found[0].evidence['rounds_run'] == 0
    assert found[0].evidence['transcript'] == [] and found[0].evidence['thread_id'] == c.probe.id
    assert not c.target.calls


@pytest.mark.asyncio
async def test_custom_early_halt_never_promotes_pass(thread_case):
    c = thread_case
    c.probe.should_halt = lambda ctx: ctx.round_n == 1
    found = await results(c)
    assert len(found) == 1
    assert_thread(found[0], c, 'error', 'attacker_stopped', 1)


@pytest.mark.asyncio
async def test_round_three_secret_is_masked_in_all_thread_reports(thread_case):
    c = thread_case
    secret = 'fixture-private-key-round3-0123456789'
    c.target.responses[2] = 'third reply ' + secret
    found = await results(c)
    assert len(found) == 1
    run = {'id': 'fixture-run', 'status': 'completed', 'target_spec': {'kind': 'fixture', 'api_key': secret},
           'findings': [asdict(f) for f in found]}
    clean = run_json.scrub_run(run)
    outputs = [run_json.render_json(run), reports.render_html(clean), reports.render_sarif(clean), reports.render_junit(clean)]
    assert all(secret not in output for output in outputs)
    record = json.loads(outputs[0])
    assert record['findings'][0]['evidence']['transcript'][2]['target_response'] == 'third reply ***'
    assert '<details' in outputs[1] and 'Deep thread transcript' in outputs[1]
    sarif = json.loads(outputs[2])['runs'][0]['results']
    assert len(sarif) == 1 and len(sarif[0]['properties']['evidence']['transcript']) == 3
    junit = ET.fromstring(outputs[3]).findall('.//testcase')
    assert len(junit) == 1
    assert 'transcript' in junit[0].find('system-out').text


@pytest.mark.asyncio
@pytest.mark.parametrize('secret', ['pass', 'transcript', 'thread_id', 'verdict', 'attack_prompt'])
async def test_short_registered_secrets_cannot_corrupt_thread_structure(thread_case, secret):
    c = thread_case
    found = await results(c)
    assert len(found) == 1
    clean = run_json.scrub_run({'target_spec': {}, 'findings': [asdict(found[0])]}, [secret])
    evidence = clean['findings'][0]['evidence']
    assert evidence['stop_reason'] == 'max_rounds' and evidence['rounds_run'] == 3
    assert evidence['thread_id'] == c.probe.id and evidence['history'] is True
    assert all(row['verdict'] == 'pass' and row['severity'] == 'info' for row in evidence['transcript'])
    assert all('attack_prompt' in row and 'target_response' in row for row in evidence['transcript'])


@pytest.mark.asyncio
async def test_assertion_backed_attacker_stop_cannot_keep_an_early_pass(thread_case):
    c = thread_case
    c.probe.assertions = ({'no_call_to_tool': 'forbidden_tool'},)
    c.target.collect_evidence = AsyncMock(return_value={'interaction_count': 1, 'tool_calls': []})
    c.attacker.side_effect = ['first {address}', None]
    found = await results(c)
    assert len(found) == 1
    assert_thread(found[0], c, 'error', 'attacker_stopped', 1)
    c.judge.judge.assert_not_awaited()


@pytest.mark.asyncio
async def test_hybrid_warning_survives_later_passes_at_maximum(thread_case):
    c = thread_case
    c.probe.assertions = ({'no_call_to_tool': 'forbidden_tool'},)
    c.probe.judge_when_assertions_pass = True
    c.target.collect_evidence = AsyncMock(return_value={'interaction_count': 3, 'tool_calls': []})
    c.judge.judge.side_effect = [Verdict('warn', 'medium', 1.0, 'uncertain first round', 'fixture', None),
                              Verdict('pass', 'info', 1.0, 'safe later reply', 'fixture', None),
                              Verdict('pass', 'info', 1.0, 'safe later reply', 'fixture', None)]
    found = await results(c)
    assert len(found) == 1
    assert_thread(found[0], c, 'warn', 'max_rounds', 3)
    assert found[0].evidence['interaction_count'] == 3
    assert [row['verdict'] for row in found[0].evidence['transcript']] == ['warn', 'pass', 'pass']


@pytest.mark.asyncio
async def test_api_cap_records_planned_threads_that_never_started(thread_case, monkeypatch, tmp_path):
    from argus import api
    from argus.cost_meter import CostMeter

    c = thread_case
    monkeypatch.setattr(api, 'build_target', lambda *_: c.target)
    monkeypatch.setattr(api, 'load_probe_library', lambda *_: [c.probe.base])
    monkeypatch.setattr(api, 'RUBRICS_DIR', tmp_path)
    monkeypatch.setattr(api, 'Judge', lambda **_: c.judge)
    monkeypatch.setattr(api, '_COST_METER', CostMeter(daily_cap_usd=1000, deep_per_run_cap_usd=1000))
    c.attacker.side_effect = [CostExceededError('fixture cap')]
    req = api.RunRequest(target={}, probe_ids=[c.probe.base.id], mode='deep', deep_pairs=2, max_rounds=3, seed='repeat')
    events = []
    with pytest.raises(CostExceededError):
        async for event in api._run_probes(req, None):
            events.append(event)
    findings = [e for e in events if 'verdict' in e]
    assert len(findings) == 2 and all(f['verdict'] == 'aborted_cost' for f in findings)
    assert all(f['evidence']['transcript'] == [] and f['evidence']['rounds_run'] == 0 for f in findings)
    assert all(f['evidence']['history'] is True and f['evidence']['stop_reason'] == 'cost' for f in findings)
    assert all(f['evidence']['thread_id'] == f['probe_id'] for f in findings)
    assert not c.target.calls


@pytest.mark.asyncio
@pytest.mark.parametrize('proven_failure', [False, True])
async def test_assertion_blank_reply_is_error_unless_failure_was_proven(thread_case, proven_failure):
    c = thread_case
    c.probe.assertions = ({'no_call_to_tool': 'forbidden_tool'},)
    c.target.responses[1] = ''
    safe = {'interaction_count': 1, 'tool_calls': []}
    bad = {'interaction_count': 2, 'tool_calls': [{'tool': 'forbidden_tool'}]}
    c.target.collect_evidence = AsyncMock(side_effect=[safe, bad if proven_failure else safe, safe])
    found = await results(c)
    assert len(found) == 1
    assert_thread(found[0], c, 'fail' if proven_failure else 'error',
                  'fail' if proven_failure else 'blank_reply', 2)


def test_static_evidence_cannot_spoof_thread_metadata_to_restore_a_secret():
    secret = 'fixture-secret-in-untrusted-metadata'
    from argus.runner import skipped_finding

    probe = Probe('static_fixture', 'Static fixture', (), ('prompt-injection',),
                  'medium', ('benign',), ProbeMappings(), 'fixture', 'fixture.md')
    evidence = {'thread_id': secret, 'persona': secret, 'strategy': secret,
                'transcript': [{'attack_prompt': secret, 'target_response': secret,
                                'verdict': secret, 'severity': secret, 'reasoning': secret}]}
    finding = replace(skipped_finding(probe, 'benign'), verdict='pass', evidence=evidence)
    record = {'id': 'static-run', 'status': 'completed', 'target_spec': {'api_key': secret},
              'findings': [asdict(finding)]}
    assert secret not in run_json.render_json(record)
    clean = run_json.scrub_run(record)
    assert 'Deep thread transcript' not in reports.render_html(clean)
    assert 'evidence' not in json.loads(reports.render_sarif(clean))['runs'][0]['results'][0]['properties']
    assert 'transcript' not in ET.fromstring(reports.render_junit(clean)).find('.//testcase/system-out').text


@pytest.mark.asyncio
@pytest.mark.parametrize('empty', ['', '  ', None])
@pytest.mark.parametrize('round_n', [0, 1, 2])
async def test_empty_attacker_never_sends_or_judges(thread_case, empty, round_n):
    c = thread_case
    c.probe.max_rounds = 4
    c.attacker.side_effect = ['benign'] * round_n + [empty]
    found = await results(c)
    assert_thread(found[0], c, 'error', 'attacker_stopped', round_n)
    assert len(c.target.calls) == c.judge.judge.await_count == round_n


@pytest.mark.asyncio
async def test_deep_transport_stop_propagates(thread_case):
    from argus_transport.runtime_v2 import TargetRunStopped
    c = thread_case
    stopped = TargetRunStopped('credential_echo')
    c.target.responses[1] = stopped
    with pytest.raises(TargetRunStopped) as caught:
        await results(c)
    assert caught.value is stopped
    assert c.attacker.await_count == len(c.target.calls) == 2


@pytest.mark.asyncio
async def test_target_blocks_do_not_trip_unreachable_breaker(thread_case):
    from argus.targets._base import TargetBlockedError
    c = thread_case
    c.target.responses = [TargetBlockedError(403)] * 10
    c.attacker.side_effect = ['benign'] * 10
    for _ in range(10):
        found = await results(c)
        assert_thread(found[0], c, 'blocked_by_target', 'blocked_by_target', 1)
    assert len(c.target.calls) == c.attacker.await_count == 10


@pytest.mark.asyncio
@pytest.mark.parametrize('verdict', ['pass', 'fail'])
async def test_evidence_error_preserves_judged_thread(thread_case, verdict):
    c = thread_case
    c.judge.judge.side_effect = [Verdict('pass', 'info', 1, 'safe', 'fixture', None)] * 2 + [
        Verdict(verdict, 'medium', 1, 'third round', 'fixture', None)]
    c.target.collect_evidence = AsyncMock(side_effect=ValueError('fixture evidence broken'))
    found = await results(c)
    assert_thread(found[0], c, 'fail' if verdict == 'fail' else 'error',
                  'fail' if verdict == 'fail' else 'collect_evidence', 3)
    assert 'fixture evidence broken' in found[0].evidence['evidence_error']
    assert found[0].evidence['transcript'][-1]['verdict'] == verdict


@pytest.mark.asyncio
@pytest.mark.parametrize('exercised', [False, True])
async def test_assertion_thread_continues_until_exercised(thread_case, exercised):
    c = thread_case
    c.probe.assertions = ({'no_call_to_tool': 'forbidden_tool'},)
    c.probe.requires_interaction = True
    empty = {'interaction_count': 0, 'tool_calls': []}
    bad = {'interaction_count': 1, 'tool_calls': [{'tool': 'forbidden_tool'}]}
    c.target.collect_evidence = AsyncMock(side_effect=[empty, bad if exercised else empty, empty])
    found = await results(c)
    assert_thread(found[0], c, 'fail' if exercised else 'error',
                  'fail' if exercised else 'not_exercised', 2 if exercised else 3)
    assert found[0].evidence['transcript'][0]['verdict'] == 'not_exercised'
    c.judge.judge.assert_not_awaited()


@pytest.mark.asyncio
async def test_incompatible_thread_was_not_started(thread_case):
    c = thread_case
    c.target.compatible_classes = {'unrelated'}
    found = await results(c)
    assert_thread(found[0], c, 'skipped', 'not_started', 0)
    c.attacker.assert_not_awaited()


@pytest.mark.asyncio
async def test_contact_in_later_round_counts_for_thread(thread_case):
    c = thread_case
    c.probe.contact_markers = ('contact-marker',)
    c.target.responses[2] += ' contact-marker'
    found = await results(c)
    assert_thread(found[0], c, 'pass', 'max_rounds', 3)


@pytest.mark.asyncio
async def test_freeform_thread_evidence_secret_masked_in_every_format(thread_case):
    c = thread_case
    secret = 'fixture-collected-secret-0123456789'
    c.target.collect_evidence = AsyncMock(return_value={f'observed_{secret}': secret, 'tool_calls': [{'tool': secret, 'arguments': {}}]})
    found = await results(c)
    run = {'id': 'fixture-run', 'status': 'completed', 'target_spec': {'api_key': secret},
           'findings': [asdict(found[0])]}
    clean = run_json.scrub_run(run)
    outputs = [run_json.render_json(run), reports.render_html(clean), reports.render_sarif(clean), reports.render_junit(clean)]
    assert all(secret not in output for output in outputs)
    assert all('observed_***' in outputs[i] for i in (0, 2, 3))
    assert '***' in outputs[1]


def test_short_secret_does_not_corrupt_deep_replay_metadata():
    deep = {'seed': 'abc-repeat', 'deep_pairs': 1, 'max_rounds': 3, 'history': True,
            'threads': [{'thread_id': 'abc::abc-persona::abc-strategy', 'base_probe_id': 'abc',
                         'persona': 'abc-persona', 'strategy': 'abc-strategy'}]}
    run = {'target_spec': {'api_key': 'abc'}, 'deep': deep, 'findings': []}
    clean = json.loads(run_json.render_json(run))
    assert clean['deep'] == deep


@pytest.mark.asyncio
@pytest.mark.parametrize('assertions', [False, True])
async def test_http_403_thread_keeps_blocked_verdict(thread_case, assertions):
    c = thread_case
    if assertions:
        c.probe.assertions = ({'no_call_to_tool': 'forbidden_tool'},)
        c.probe.requires_interaction = True
    request = httpx.Request('POST', 'http://127.0.0.1/target')
    c.target.responses[0] = httpx.HTTPStatusError('blocked', request=request,
                                               response=httpx.Response(403, request=request))
    found = await results(c)
    assert_thread(found[0], c, 'blocked_by_target', 'blocked_by_target', 1)
    c.judge.judge.assert_not_awaited()


@pytest.mark.asyncio
async def test_post_round_failure_keeps_transcript(thread_case, monkeypatch):
    import argus.runner as runner_module
    c = thread_case
    def broken_gate(*args):
        raise ValueError('fixture post-round gate failed')
    monkeypatch.setattr(runner_module, '_no_contact', broken_gate)
    found = await results(c)
    assert_thread(found[0], c, 'error', 'post_round', 3)
    assert 'fixture post-round gate failed' in found[0].evidence['evidence_error']


@pytest.mark.asyncio
async def test_assertion_collection_error_names_step_and_keeps_prior_round(thread_case):
    c = thread_case
    c.probe.assertions = ({'no_call_to_tool': 'forbidden_tool'},)
    c.target.collect_evidence = AsyncMock(side_effect=[{'interaction_count': 1, 'tool_calls': []},
                                                     ValueError('fixture assertion evidence broken')])
    found = await results(c)
    assert_thread(found[0], c, 'error', 'collect_evidence', 2)
    assert found[0].evidence['transcript'][0]['verdict'] == 'pass'
    assert 'fixture assertion evidence broken' in found[0].evidence['evidence_error']
