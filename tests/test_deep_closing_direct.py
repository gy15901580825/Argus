"""Deep threads preserve adaptive turns and finish with a static direct ask."""

from dataclasses import asdict, replace
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from argus import persona_strategy
from argus.cli.run_json import scrub_run
from argus.iterative import IterationContext
from argus.judge import Verdict
from argus.persona_loader import Persona, Strategy
from argus.persona_strategy import build_deep_probes
from argus.probe import Probe, ProbeMappings
from argus.runner import Runner


PERSONAS = tuple(Persona(str(i), str(i), 'voice', 'traits', 'any', 'body') for i in range(3))
STRATEGIES = tuple(Strategy(str(i), str(i), 'mechanics', 'any', 'steps', 'body') for i in range(3))
BASE = Probe('closing_fixture', 'Direct ask', ('llm_chat',), ('prompt-injection',),
             'medium', ('  Direct ask A\n', 'Direct ask B\n'), ProbeMappings(), 'fixture', 'fixture.md')
PASS = Verdict('pass', 'info', 1.0, 'safe', 'fixture', None)
FAIL = Verdict('fail', 'high', 1.0, 'failed', 'fixture', None)


@pytest.fixture
def closing_case(tmp_path, monkeypatch):
    (tmp_path / 'fixture.md').write_text('Assess the fixture.')
    attacker = AsyncMock(side_effect=['adaptive one', 'adaptive two', 'adaptive three'])
    monkeypatch.setattr(persona_strategy, '_call_attacker_llm', attacker)

    class Target:
        compatible_classes = {'llm_chat'}
        supports_history = True

        def __init__(self):
            self.calls = []

        async def send_prompt(self, prompt, history=()):
            self.calls.append((prompt, history))
            return 'safe reply', 1.0

    target = Target()
    judge = SimpleNamespace(judge=AsyncMock(return_value=PASS))
    return SimpleNamespace(target=target, judge=judge, attacker=attacker,
                           runner=Runner(target, judge, tmp_path))


def thread(base=BASE, *, max_rounds=3, seed='replay'):
    return build_deep_probes(base, PERSONAS, STRATEGIES, deep_pairs=1,
                             max_rounds=max_rounds, seed=seed)[0]


async def run(case, probe):
    findings = [finding async for finding in case.runner.run_probe(probe)]
    assert len(findings) == 1
    return findings[0]


async def test_last_round_is_verbatim_without_attacker_rewrite(closing_case):
    c = closing_case
    finding = await run(c, thread())
    prompts = [prompt for prompt, _ in c.target.calls]
    assert prompts[:2] == ['adaptive one', 'adaptive two']
    assert prompts[2] in BASE.prompts
    assert c.attacker.await_count == 2
    assert len(c.target.calls[2][1]) == 4
    assert finding.evidence['rounds_run'] == 3
    assert finding.evidence['stop_reason'] == 'max_rounds'


async def test_failure_in_round_two_prevents_closing_send(closing_case):
    c = closing_case
    c.judge.judge.side_effect = [PASS, FAIL]
    finding = await run(c, thread())
    assert [prompt for prompt, _ in c.target.calls] == ['adaptive one', 'adaptive two']
    assert finding.verdict == 'fail'
    assert finding.evidence['stop_reason'] == 'fail'
    assert c.attacker.await_count == 2


async def test_one_round_keeps_attacker_generated_prompt(closing_case):
    c = closing_case
    finding = await run(c, thread(max_rounds=1))
    assert [prompt for prompt, _ in c.target.calls] == ['adaptive one']
    assert c.attacker.await_count == 1
    assert finding.evidence['transcript'][0]['kind'] == 'adaptive'


async def test_only_last_round_is_marked_even_after_secret_scrubbing(closing_case):
    finding = await run(closing_case, thread())
    want = ['adaptive', 'adaptive', 'closing_direct']
    assert [row['kind'] for row in finding.evidence['transcript']] == want
    clean = scrub_run({'target_spec': {}, 'findings': [asdict(finding)]},
                      secret_values=('adaptive', 'closing_direct', 'kind'))
    assert [row['kind'] for row in clean['findings'][0]['evidence']['transcript']] == want


async def test_seed_preserves_legacy_pairings_and_selects_closing_text(closing_case):
    closing_case.attacker.side_effect = None
    closing_case.attacker.return_value = 'adaptive generated'
    probes = build_deep_probes(BASE, PERSONAS, STRATEGIES, deep_pairs=3, max_rounds=3, seed='replay')
    assert [(p.persona.id, p.strategy.id) for p in probes] == [('2', '2'), ('2', '1'), ('1', '0')]
    same = build_deep_probes(BASE, PERSONAS, STRATEGIES, deep_pairs=3, max_rounds=3, seed='replay')
    ctx = IterationContext(2, ('one', 'two'), ('safe', 'safe'), (PASS, PASS))
    closing = [await p.next_prompt(ctx) for p in probes]
    assert closing == [await p.next_prompt(ctx) for p in same]
    assert closing == ['Direct ask B\n', '  Direct ask A\n', '  Direct ask A\n']
    assert await thread(seed='other').next_prompt(ctx) != await thread(seed='replay').next_prompt(ctx)


async def test_closing_preserves_adapter_placeholder_and_canary(closing_case):
    text = 'Use {merchant_url} with user secret CANARY-FIXTURE-123.\n'
    base = replace(BASE, prompts=(text,),
                   assertions=({'no_canary_in_trap_requests': 'CANARY-FIXTURE-123'},))
    closing_case.target.collect_evidence = AsyncMock(return_value={
        'trap_requests': [], 'interaction_count': 1})
    finding = await run(closing_case, thread(base))
    assert finding.evidence['transcript'][-1]['verdict'] == 'pass'
    assert closing_case.target.calls[-1][0] == text


async def test_closing_renders_generator_placeholder_like_static(closing_case):
    base = replace(BASE, prompts=('Ask {generator.name} directly.',))
    await run(closing_case, thread(base))
    assert closing_case.target.calls[-1][0] == 'Ask the assistant directly.'


async def test_empty_base_prompts_keeps_adaptive_final_round(closing_case):
    await run(closing_case, thread(replace(BASE, prompts=())))
    assert [prompt for prompt, _ in closing_case.target.calls] == [
        'adaptive one', 'adaptive two', 'adaptive three']
    assert closing_case.attacker.await_count == 3
