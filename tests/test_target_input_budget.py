"""Target input limits preserve fixed probes and the complete audit transcript."""

from dataclasses import asdict, replace
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from click.testing import CliRunner

from argus import persona_strategy
from argus.cli.__main__ import main
from argus.cli.run_json import scrub_run
from argus.cli.target_loader import TargetLoadError, check_target_spec
from argus.judge import Verdict
from argus.persona_loader import Persona, Strategy
from argus.persona_strategy import build_deep_probes
from argus.probe import Probe, ProbeMappings
from argus.runner import Runner
from argus.targets import build_target
from argus.targets._base import Turn

SPEC = {'kind': 'openai_compat', 'endpoint_url': 'https://example.invalid/chat', 'model': 'fixture'}
BASE = Probe('budget_fixture', 'Direct ask', ('llm_chat',), ('prompt-injection',),
             'medium', ('fixed direct ask ' * 10,), ProbeMappings(), 'fixture', 'fixture.md')
PERSONA = Persona('fixture', 'Fixture', 'voice', 'traits', 'any', 'body')
STRATEGY = Strategy('fixture', 'Fixture', 'mechanics', 'any', 'steps', 'body')


@pytest.fixture
def case(tmp_path, monkeypatch):
    (tmp_path / 'fixture.md').write_text('Assess the fixture.')
    target = build_target(SPEC)
    calls = []
    replies = []

    async def send(prompt, history=(), *, material=None):
        calls.append((prompt, history))
        reply = replies.pop(0) if replies else 'safe'
        if isinstance(reply, Exception):
            raise reply
        return reply, 1.0

    monkeypatch.setattr(target, 'send_prompt', send)
    attacker = AsyncMock(side_effect=['one', 'two', 'three'])
    monkeypatch.setattr(persona_strategy, '_call_attacker_llm', attacker)
    judge = SimpleNamespace(judge=AsyncMock(return_value=Verdict('pass', 'info', 1.0, 'safe', 'fixture', None)))
    return SimpleNamespace(target=target, calls=calls, replies=replies, attacker=attacker,
                           judge=judge, runner=Runner(target, judge, tmp_path))


def limits(case, **values):
    case.target.input_limits = build_target({**SPEC, 'input_limits': values}).input_limits
    # Build a fresh runner so it reads the built target's public budget.
    case.runner = Runner(case.target, case.judge, case.runner._rubrics_dir)


def thread(rounds=3):
    return build_deep_probes(BASE, (PERSONA,), (STRATEGY,), deep_pairs=1,
                             max_rounds=rounds, seed='budget-replay')[0]


async def run(case, probe=None):
    found = [f async for f in case.runner.run_probe(probe or thread())]
    assert len(found) == 1
    return found[0]


async def test_unset_limits_preserve_seeded_wire_prompts_and_histories(case):
    finding = await run(case)
    assert case.calls == [('one', ()), ('two', (Turn('user', 'one'), Turn('assistant', 'safe'))),
                          (BASE.prompts[0], (Turn('user', 'one'), Turn('assistant', 'safe'),
                                             Turn('user', 'two'), Turn('assistant', 'safe')))]
    assert case.attacker.await_count == 2
    assert all(set(row) == {'attack_prompt', 'target_response', 'verdict', 'severity', 'reasoning', 'kind'}
               for row in finding.evidence['transcript'])


async def test_empty_limits_preserve_unset_wire_and_attacker_inputs(case):
    await run(case)
    original_calls = list(case.calls)
    original_attacker = list(case.attacker.call_args_list)
    limits(case)
    case.calls.clear()
    case.attacker.reset_mock(side_effect=True)
    case.attacker.side_effect = ['one', 'two']
    await run(case)
    assert case.calls == original_calls
    assert case.attacker.call_args_list == original_attacker


@pytest.mark.parametrize('second, sent, cut', [('b' * 80, 'b' * 80, False), ('b' * 250, 'b' * 100, True)])
async def test_oversized_attacker_retries_once_then_obeys_exact_limit(case, second, sent, cut):
    limits(case, max_message_chars=100)
    case.attacker.side_effect = ['a' * 300, second]
    finding = await run(case, thread(1))
    assert case.calls == [(sent, ())]
    assert case.attacker.await_count == 2
    system, note = case.attacker.call_args_list[1].args
    assert '100 characters' in system
    assert '300' in note and '100' in note
    row = finding.evidence['transcript'][0]
    assert row['message_regenerated'] is True
    assert row.get('message_cut', False) is cut
    clean = scrub_run({'target_spec': {}, 'findings': [asdict(finding)]}, secret_values=('message_regenerated',))
    assert clean['findings'][0]['evidence']['transcript'][0]['message_regenerated'] is True


async def test_short_message_includes_limit_in_attacker_prompt_without_retry(case):
    limits(case, max_message_chars=100)
    await run(case, thread(1))
    assert case.calls == [('one', ())]
    assert case.attacker.await_count == 1
    assert '100 characters' in case.attacker.call_args.args[0]


async def test_closing_and_static_prompts_over_limit_are_sent_verbatim(case):
    limits(case, max_message_chars=100)
    finding = await run(case)
    assert case.calls[-1][0] == BASE.prompts[0]
    assert len(case.calls[-1][0]) > 100
    assert not finding.evidence['transcript'][-1].get('message_cut', False)
    case.calls.clear()
    await run(case, BASE)
    assert case.calls == [(BASE.prompts[0], ())]


async def test_history_keeps_newest_whole_pairs_and_full_run_json(case):
    limits(case, max_history_chars=8)
    case.attacker.side_effect = ['oldest', 'new', 'last']
    finding = await run(case, thread(4))
    assert case.calls == [('oldest', ()), ('new', ()),
                          ('last', (Turn('user', 'new'), Turn('assistant', 'safe'))),
                          (BASE.prompts[0], (Turn('user', 'last'), Turn('assistant', 'safe')))]
    rows = finding.evidence['transcript']
    assert [row.get('history_turns_dropped', 0) for row in rows] == [0, 2, 2, 4]
    # Both the attacker and the serializable report retain the oldest exchange.
    assert 'oldest' in case.attacker.call_args_list[2].args[1]
    report = json.loads(json.dumps(asdict(finding), default=str))
    assert [row['attack_prompt'] for row in report['evidence']['transcript']] == ['oldest', 'new', 'last', BASE.prompts[0]]
    assert [row['target_response'] for row in rows] == ['safe'] * 4


async def test_single_oversized_pair_leaves_empty_history_but_sends_message(case):
    limits(case, max_history_chars=1)
    finding = await run(case)
    assert all(history == () for _, history in case.calls)
    assert [row.get('history_turns_dropped', 0) for row in finding.evidence['transcript']] == [0, 2, 4]


async def test_static_conversation_trims_oldest_pairs_with_same_rule(case):
    limits(case, max_history_chars=8)
    probe = replace(BASE, prompts=('oldest', 'new', 'last', 'fixed'), conversation=True)
    findings = [f async for f in case.runner.run_probe(probe)]
    assert len(findings) == 4
    assert case.calls == [('oldest', ()), ('new', ()),
                          ('last', (Turn('user', 'new'), Turn('assistant', 'safe'))),
                          ('fixed', (Turn('user', 'last'), Turn('assistant', 'safe')))]


async def test_limit_actions_survive_target_error(case):
    limits(case, max_message_chars=100, max_history_chars=1)
    case.attacker.side_effect = ['one', 'a' * 300, 'b' * 250]
    case.replies[:] = ['safe', httpx.ReadTimeout('fixture')]
    finding = await run(case)
    row = finding.evidence['transcript'][1]
    assert finding.verdict == 'error'
    assert row['message_regenerated'] and row['message_cut']
    assert row['history_turns_dropped'] == 2


@pytest.mark.parametrize('field', ['max_message_chars', 'max_history_chars'])
@pytest.mark.parametrize('value', [0, -1, '4000', True, 1.5, None])
def test_spec_rejects_nonpositive_or_noninteger_limit(field, value, tmp_path):
    spec = {**SPEC, 'input_limits': {field: value}}
    with pytest.raises(TargetLoadError, match=rf'input_limits\.{field}.*positive integer'):
        check_target_spec(spec)
    with pytest.raises(ValueError, match=rf'input_limits\.{field}.*positive integer'):
        build_target(spec)
    path = tmp_path / 'target.json'
    path.write_text(json.dumps(spec))
    result = CliRunner().invoke(main, ['validate-target', '--target', str(path)])
    assert result.exit_code == 1
    assert f'input_limits.{field}' in result.output
    assert 'positive integer' in result.output


@pytest.mark.parametrize('value, message', [({'max_tokens': 100}, 'unknown'), (None, 'object'), ([], 'object'), (100, 'object')])
def test_spec_rejects_unknown_subkeys_and_nonobjects(value, message):
    with pytest.raises(TargetLoadError, match=rf'input_limits.*{message}'):
        check_target_spec({**SPEC, 'input_limits': value})


def test_factory_budget_is_frozen_and_does_not_modify_caller_spec():
    from dataclasses import FrozenInstanceError
    spec = {**SPEC, 'input_limits': {'max_message_chars': 100, 'max_history_chars': 800}}
    target = build_target(spec)
    assert target.input_limits.max_message_chars == 100
    assert target.input_limits.max_history_chars == 800
    assert spec['input_limits'] == {'max_message_chars': 100, 'max_history_chars': 800}
    with pytest.raises(FrozenInstanceError):
        target.input_limits.max_message_chars = 101


def test_shared_factory_strips_budget_before_builtin_and_plugin_spec_construction(monkeypatch):
    from dataclasses import dataclass
    from argus import targets
    from argus.targets._base import Target

    @dataclass
    class Spec:
        kind: str

    class Adapter(Target):
        def __init__(self, spec):
            self.spec = spec

        async def send_prompt(self, prompt, history=(), *, material=None):
            return 'safe', 1.0

    original_kinds = tuple(targets._BUILDERS)
    monkeypatch.setattr(targets, '_BUILDERS', {kind: (Spec, Adapter) for kind in original_kinds})
    monkeypatch.setattr(targets, '_plugin_builders', lambda: {'fixture_plugin': (Spec, Adapter)})
    for kind in (*original_kinds, 'fixture_plugin'):
        spec = {'kind': kind, 'input_limits': {'max_message_chars': 100}}
        built = build_target(spec, trusted_code=True)
        assert built.input_limits.max_message_chars == 100
        assert built.input_limits.max_history_chars is None
        assert built.spec.kind == kind
