import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from argus.probe import load_probe
from argus.runner import Runner
from argus.targets._base import Target
from argus.targets import build_target
from test_probe_indirect import probe_data, write_probe


class StubJudge:
    def __init__(self):
        self.prompts = []

    async def judge(self, **kwargs):
        self.prompts.append(kwargs['attack_prompt'])
        return SimpleNamespace(verdict='pass', severity='info', confidence=1., reasoning='Sample handled.',
                               judge_model='stub', escalated_model=None)


class MaterialTarget(Target):
    material_channel = True

    def __init__(self):
        self.calls = []

    async def send_prompt(self, prompt, history=(), *, material=None):
        self.calls.append((prompt, material, history))
        return 'Sample handled.', 1.

    def rendered_prompt(self, prompt):
        return 'Rendered sample.'


class PlainTarget(Target):
    def __init__(self):
        self.calls = []

    async def send_prompt(self, prompt, history=()):
        self.calls.append((prompt, history))
        return 'Sample handled.', 1.


async def run_sample(tmp_path, target):
    probe = load_probe(write_probe(tmp_path, probe_data()))
    judge = StubJudge()
    runner = Runner(target=target, judge=judge, rubrics_dir=Path(__file__).parents[1] / 'argus/rubrics')
    findings = [f async for f in runner.run_probe(probe)]
    return findings, judge


async def test_material_target_gets_task_and_material(tmp_path):
    target = MaterialTarget()
    await run_sample(tmp_path, target)
    assert target.calls == [('Read the sample.', 'Sample document.', ())]


async def test_plain_target_gets_original_prompt_byte_identical(tmp_path):
    target = PlainTarget()
    await run_sample(tmp_path, target)
    assert target.calls == [('Original sample.', ())]


async def test_judge_sees_original_prompt(tmp_path):
    findings, judge = await run_sample(tmp_path, MaterialTarget())
    assert judge.prompts == ['Original sample.']
    assert findings[0].attack_prompt == 'Original sample.'


async def test_finding_records_task_and_material_sha256(tmp_path):
    findings, _ = await run_sample(tmp_path, MaterialTarget())
    assert findings[0].evidence == {'indirect': {'task': 'Read the sample.',
        'material_sha256': hashlib.sha256(b'Sample document.').hexdigest()}}


async def test_python_target_receives_task_and_material(tmp_path):
    entry = tmp_path / 'sample_agent.py'
    entry.write_text("def reply(task, material, context):\n    return {'output': task + '|' + str(material) + '|' + context['probe_id']}\n")
    target = build_target({'kind': 'python', 'entry': str(entry) + ':reply'}, trusted_code=True)
    try:
        findings, _ = await run_sample(tmp_path, target)
        assert findings[0].target_response == 'Read the sample.|Sample document.|indirect_sample'
    finally:
        await target.aclose()


async def test_deep_mode_runs_indirect_probe_static_on_material_target(tmp_path, monkeypatch):
    import argus.api as api
    target = MaterialTarget()
    probe = load_probe(write_probe(tmp_path, probe_data()))
    monkeypatch.setattr(api, 'build_target', lambda spec: target)
    monkeypatch.setattr(api, 'Judge', lambda **kwargs: StubJudge())
    monkeypatch.setattr(api, 'load_probe_library', lambda path: [probe])
    def forbidden(*args, **kwargs):
        raise AssertionError('attacker invoked')
    monkeypatch.setattr(api, 'build_deep_probes', forbidden)
    req = api.RunRequest(target={'kind': 'http_chat', 'url': 'http://127.0.0.1:1'},
                         probe_ids=[probe.id], mode='deep')
    results = [item async for item in api._run_probes(req, 'dummy-not-a-key')]
    assert results
    assert target.calls == [('Read the sample.', 'Sample document.', ())]


async def test_material_finding_keeps_target_evidence(tmp_path):
    class ObservedTarget(MaterialTarget):
        async def collect_evidence(self):
            return {'sample_seen': True}
    findings, _ = await run_sample(tmp_path, ObservedTarget())
    assert findings[0].evidence['sample_seen'] is True
    assert findings[0].evidence['indirect']['task'] == 'Read the sample.'


@pytest.mark.parametrize('channel,want', [(True, 'Original sample.'), (False, 'Rendered sample.')])
async def test_hybrid_judge_preserves_material_and_plain_prompt_rules(tmp_path, channel, want):
    class ObservedTarget(MaterialTarget):
        material_channel = channel
        async def collect_evidence(self):
            return {'interaction_count': 1, 'trap_requests': [], 'indirect': {'sample_seen': True}}
    data = probe_data()
    data['assertions'] = [{'no_trap_request': True}]
    data['judge_when_assertions_pass'] = True
    probe = load_probe(write_probe(tmp_path, data))
    judge = StubJudge()
    runner = Runner(target=ObservedTarget(), judge=judge, rubrics_dir=Path(__file__).parents[1] / 'argus/rubrics')
    findings = [f async for f in runner.run_probe(probe)]
    assert findings[0].verdict == 'pass'
    assert judge.prompts == [want]
