"""Deterministic verdict records for every shipped phased probe."""
import asyncio
import copy
import json
from pathlib import Path
from argus.probe import load_all_probes
from argus.runner import Runner
from argus import phases
from argus.phases import PhaseRun, judge_trial
from test_runner_phased import make_world_evidence, probe as sample_probe
from a2a_evidence import linked_chain

SOURCE = Path(__file__).resolve().parents[1]
probes = [p for p in load_all_probes(SOURCE / 'argus' / 'probes') if p.is_phased]
assert len(probes) == 25

class ForbiddenJudge:
    _cost_meter = None
    async def judge(self, **kwargs):
        raise AssertionError('model call forbidden')

class Target:
    supports_phases = supports_history = True
    compatible_classes = frozenset(c for p in probes for c in p.target_class)
    def __init__(self, evidence, failures):
        self.evidence, self.failures = evidence, failures
        self.begun = []
    async def begin_phase(self, probe, side, trial):
        self.side, self.trial = side, trial
        self.begun.append((side, trial))
    async def begin_conversation(self, index):
        pass
    async def send_prompt(self, prompt, history=()):
        return 'Completed.', 0.0
    async def end_phase(self):
        return copy.deepcopy(self.evidence[self.side])

def evidence(p, side, fixture):
    if fixture == 'bare':
        return {'interaction_count': 1}
    if p.scenario_kind == 'a2a_world':
        ev = linked_chain(phase=side, session_id=f'{side}-1', capabilities=list(p.requires_capabilities))
        if fixture == 'benign':
            ev['claims'] = [{**c, 'kind': 'legit', 'truth': c['value']} for c in ev['claims']]
        return ev
    count = len(p.session_prompts)
    ev = make_world_evidence(side, interaction_count_by_session={str(i): {'tool_calls': 1} for i in range(1, count+1)})
    # Complete world envelope; individual probe requirements may still error.
    if fixture == 'violating':
        ev['tool_calls'][0]['arguments'] = {'pay_to': 'ACCT-TEST'}
        ev['executions'] = [{'tool': 'pay_invoice', 'state_changing': True, 'linked_decision': 'none', 'seq': 3, 'conversation': 1, 'params': {}, 'target': 'record-A', 'outcome': 'ok'}]
    return ev

async def runner_row(p, clean, attack):
    target = Target({'clean': clean, 'attack': attack}, {})
    findings = [f async for f in Runner(target, ForbiddenJudge(), SOURCE / 'argus' / 'rubrics').run_probe(p)]
    assert len(findings) == 1
    f = findings[0]
    # Strip dated pass wording by comparing the complete deterministic trial rows.
    return {'verdict': f.verdict, 'trials': f.evidence['trials'], 'begun': target.begun}

def generate():
    rows = []
    for p in sorted(probes, key=lambda p:p.id):
        for fixture in ('bare', 'benign', 'violating'):
            clean, attack = (evidence(p, s, fixture) for s in ('clean', 'attack'))
            for side, ev in (('clean', clean), ('attack', attack)):
                try:
                    out = phases._assertions(p, ev, '', phase=side)
                except Exception as exc:
                    out = [('crash', type(exc).__name__, str(exc))]
                rows.append({'probe': p.id, 'fixture': fixture, 'path': 'assertions-'+side, 'out': out})
            variants = {'normal': (clean, attack, None), 'clean_unsealed': ({**clean, 'sealed': False}, attack, None), 'attack_wrong_side': (clean, {**attack, 'phase': 'clean'}, None), 'shared_world': (clean, {**attack, 'session_id':clean.get('session_id')}, None), 'attack_failed': (clean, attack, ('error', 'fixture send failed'))}
            for name, (c, a, failure) in variants.items():
                c_run = PhaseRun('clean', 1, None, c, None, ('task',), ('done',))
                a_run = PhaseRun('attack', 1, failure, a, None, ('task',), ('done',))
                r = judge_trial(p, c_run, a_run)
                rows.append({'probe': p.id, 'fixture': fixture, 'path': name, 'out': [r.verdict, r.reason_code, r.reason]})
            rows.append({'probe':p.id, 'fixture': fixture, 'path':'runner', 'out':asyncio.run(runner_row(p, clean, attack))})
    return b''.join((json.dumps(r, sort_keys=True, separators=(',', ':'))+'\n').encode() for r in rows), rows


if __name__ == "__main__":
    import sys
    data, _ = generate()
    sys.stdout.buffer.write(data)
