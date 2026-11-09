import json

import httpx
import pytest

from argus import api, persona_strategy
from argus.cli import run_json
from test_public_run_stop_cleanup import (
    SECRET, SPEC, Plugin, cleanup, engine, frames, server, stop,
)


class SecretPlugin(Plugin):
    def __init__(self, mode='normal'):
        super().__init__(mode)
        self.primary = stop('quota', f'plugin limit {SECRET}')
        self.secondary = stop('close_limit', f'close limit {SECRET}')

    async def send_prompt(self, prompt, history=()):
        await super().send_prompt(prompt, history)
        return f'Target reply {SECRET}', 0.0

    def cleanup_report(self):
        report = super().cleanup_report()
        abort = {'scope': 'attempt', 'step': 'delivery.abort', 'status': 'failed',
                 'method': 'DELETE', 'url': f'http://127.0.0.1/abort/{SECRET}',
                 'http_status': 500, 'attempt': 1, 'failure_reason': f'abort failed {SECRET}'}
        return report | {'open': [*report['open'], abort], 'aborts': [abort]}


def shape(value):
    if isinstance(value, dict):
        return {key: shape(item) for key, item in value.items()}
    if isinstance(value, list):
        return [shape(item) for item in value]
    return type(value).__name__


@pytest.mark.parametrize('mode', ['static', 'trials', 'deep', 'quota', 'close_stop'])
def test_every_real_http_payload_masks_secrets_and_keeps_main_frame_shapes(
        engine, server, monkeypatch, mode):
    raw = []
    original = api._run_probes
    original_coverage = api.build_coverage

    async def proposed(*args, **kwargs):
        return f'Attacker prompt {SECRET}'

    async def recorded(*args, **kwargs):
        async for item in original(*args, **kwargs):
            raw.append(item)
            yield item

    def coverage(*args, **kwargs):
        # Coverage is also free to carry a diagnostic from a future producer.
        return original_coverage(*args, **kwargs) | {'diagnostic': f'coverage {SECRET}'}

    monkeypatch.setattr(persona_strategy, '_call_attacker_llm', proposed)
    monkeypatch.setattr(api, '_run_probes', recorded)
    monkeypatch.setattr(api, 'build_coverage', coverage)
    engine.target = SecretPlugin(mode if mode in ('quota', 'close_stop') else 'normal')
    request = {'target': SPEC, 'probe_ids': [p.id for p in engine.probes]}
    if mode == 'trials':
        request['trials'] = 3
    if mode == 'deep':
        request.update(mode='deep', deep_pairs=2, max_rounds=2, seed=SECRET)
    response = httpx.post(server + '/redteam/run', json=request, timeout=20)
    stream = frames(response)

    emitted = [item for item in raw if item.get('type') != 'target_cleanup']
    findings = [item for item in emitted if item.get('type') != 'deep_run']
    if mode in ('quota', 'close_stop'):
        error = engine.target.primary if mode == 'quota' else engine.target.secondary
        expected = [(None, item) for item in emitted] + [('error', {
            'detail': str(error), 'type': type(error).__name__,
            'cost': {'spent_usd': 0.0, 'per_run_cap_usd': 0.5},
            'target_cleanup': error.target_cleanup})]
    else:
        expected = [(None, item) for item in emitted] + [(None, {
            'type': 'coverage', 'coverage': coverage(api.load_probe_library(api.PROBES_DIR), findings),
            'summary': api.build_summary(findings),
            'cost': {'spent_usd': 0.0, 'per_run_cap_usd': 5.0 if mode == 'deep' else 0.5},
            'target_cleanup': raw[-1]['target_cleanup']}), ('end', {})]
    # The expected objects follow main's frame construction, before masking.
    assert [(event, payload.get('type')) for event, payload in stream] == [
        (event, payload.get('type')) for event, payload in expected]
    assert [shape(payload) for _, payload in stream] == [shape(payload) for _, payload in expected]
    assert len(findings) == (1 if mode == 'quota' else 10 if mode == 'deep' else 5)
    assert SECRET in json.dumps(expected)
    assert SECRET not in response.text
    secrets = run_json.run_secrets(SPEC)
    assert stream == [(event, run_json._scrub(payload, secrets)) for event, payload in expected]
    # run.json still uses the same mask and leaves the source objects intact.
    record = json.loads(run_json.render_json({
        'target_spec': SPEC, 'findings': findings,
        'target_cleanup': expected[-1 if mode in ('quota', 'close_stop') else -2][1]['target_cleanup']}))
    assert SECRET not in json.dumps(record)
    assert record['target_cleanup'] == stream[-1 if mode in ('quota', 'close_stop') else -2][1]['target_cleanup']
    assert record['findings'] == [payload for _, payload in stream if 'probe_id' in payload]
    assert SECRET in json.dumps(findings)
    if mode == 'deep':
        assert all(SECRET in row['target_response']
                   for finding in findings for row in finding['evidence']['transcript'])


@pytest.mark.parametrize('payload', ['detail', 'deep_run', 'coverage', 'cleanup'])
def test_nonfinding_payloads_mask_at_stream_boundary(engine, server, monkeypatch, payload):
    engine.target = Plugin('normal')

    async def events(*args, **kwargs):
        if payload == 'detail':
            raise stop('quota', SECRET)
        if payload == 'deep_run':
            yield {'type': 'deep_run', 'deep': {'seed': SECRET}}
        if payload == 'cleanup':
            yield {'type': 'target_cleanup', 'target_cleanup': cleanup(opened=True)}
        if False:
            yield {}

    monkeypatch.setattr(api, '_run_probes', events)
    if payload == 'coverage':
        monkeypatch.setattr(api, 'build_coverage', lambda *a: {'diagnostic': SECRET})
    response = httpx.post(server + '/redteam/run', json={
        'target': SPEC, 'probe_ids': [engine.probes[0].id]}, timeout=10)
    stream = frames(response)
    assert SECRET not in response.text
    assert run_json.MASK in response.text
    if payload == 'detail':
        assert stream == [('error', {'detail': f'quota: {run_json.MASK}', 'type': 'TargetRunStopped',
                                     'cost': {'spent_usd': 0.0, 'per_run_cap_usd': 0.5}})]
