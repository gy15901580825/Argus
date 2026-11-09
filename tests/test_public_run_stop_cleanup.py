import asyncio
import copy
import json
import socket
import threading
import time
from dataclasses import replace
from types import SimpleNamespace

import httpx
import pytest
import uvicorn
from click.testing import CliRunner
from fastapi import FastAPI

from argus import api, cost_meter, llm, local
from argus.cli import run_json
from argus.cli.__main__ import main
from argus.probe import Probe, ProbeMappings
from argus_transport.runtime_v2 import TargetRunStopped

SECRET = 'synthetic-cleanup-secret'
SPEC = {'kind': 'custom_http', 'request_url': 'http://127.0.0.1/run',
        'request_body_template': '{"prompt": {{ prompt|tojson }}}',
        'response_jsonpath': '$.text', 'access_token': SECRET}


def stop(reason='quota', detail=''):
    import argus.targets
    return getattr(argus.targets, 'RunStopped', TargetRunStopped)(reason, detail)


def cleanup(reason=None, *, opened=False):
    records = [{'scope': 'run', 'step': 'resource', 'status': 'failed', 'method': 'DELETE',
                'url': f'http://127.0.0.1/resource/{SECRET}', 'http_status': 500}] if opened else []
    return {'complete': not records, 'done': 0, 'open': records, 'stop_reason': reason, 'leftover': []}


class Plugin:
    compatible_classes = frozenset()
    supports_history = False
    material_channel = False

    def __init__(self, mode='normal'):
        self.mode, self.calls, self.closes, self.reads = mode, 0, 0, 0
        self.primary = stop('quota', 'plugin limit')
        self.primary.checklist = ('retain original task',)
        self.secondary = stop('close_limit', 'secondary')
        self.stale = cleanup('earlier')
        if mode in ('invalid_stale', 'none_stale', 'getter_stale'):
            self.primary.set_cleanup(self.stale)

    async def send_prompt(self, prompt, history=()):
        self.calls += 1
        if self.mode not in ('normal', 'none', 'invalid', 'getter_error', 'close_stop') and self.calls == 2:
            raise self.primary
        return 'Benign task complete.', 0.0

    async def aclose(self):
        self.closes += 1
        if self.mode in ('close_stop', 'primary_secondary'):
            raise self.secondary

    def cleanup_report(self):
        self.reads += 1
        assert self.closes == 1
        if self.mode in ('getter_error', 'getter_stale'):
            raise RuntimeError('private cleanup source details')
        if self.mode in ('none', 'none_stale'):
            return None
        if self.mode in ('invalid', 'invalid_stale'):
            return cleanup(opened=True) | {'complete': True}
        reason = 'close_limit' if self.mode in ('close_stop', 'primary_secondary') else (
            'quota' if self.mode != 'normal' else None)
        return cleanup(reason, opened=True)


@pytest.fixture
def engine(monkeypatch, tmp_path):
    rubric = tmp_path / 'rubrics'
    rubric.mkdir()
    (rubric / 'unused.md').write_text('Assess the generic response.\n')
    probes = [Probe(id=f'fixture_{i}', name='Generic stop fixture', target_class=('llm_chat',),
        attack_class=('prompt-injection',), severity='info', prompts=('Complete a benign task.',),
        mappings=ProbeMappings(), judge_model='unused', judge_rubric_path='unused.md',
        assertions=({'no_secret_in_response': 'synthetic-response-marker'},), requires_interaction=False)
        for i in range(5)]
    model_calls = []

    async def forbidden(*args, **kwargs):
        model_calls.append(1)
        raise AssertionError('model calls forbidden')

    class Judge:
        _cost_meter = None
        def __init__(self, **kwargs):
            pass
        judge = forbidden

    monkeypatch.setattr(api, 'RUBRICS_DIR', rubric)
    monkeypatch.setattr(api, 'Judge', Judge)
    monkeypatch.setattr(api, 'load_probe_library', lambda *_: probes)
    monkeypatch.setattr(local, 'load_probe_library', lambda *_: probes)
    monkeypatch.setattr(llm, 'resolve_config', lambda *a, **k: llm.LLMConfig('test', 'unused', 'unused', False, None))
    monkeypatch.setattr(llm, 'credential_error', lambda _: None)
    monkeypatch.setattr(llm, 'complete', forbidden)
    monkeypatch.setattr(llm, '_acompletion', forbidden)
    monkeypatch.setitem(cost_meter._PRICES_PER_M_TOKENS, 'unused', {'input': 0.0, 'output': 0.0})
    state = SimpleNamespace(target=None, probes=probes, model_calls=model_calls)
    monkeypatch.setattr(api, 'build_target', lambda *a, **k: state.target)
    monkeypatch.setattr(local, 'build_target', lambda *a, **k: state.target)
    yield state
    assert model_calls == []


@pytest.fixture
def server(engine):
    app = FastAPI()
    app.include_router(api.router)
    sock = socket.socket()
    sock.bind(('127.0.0.1', 0))
    origin = f'http://127.0.0.1:{sock.getsockname()[1]}'
    server = uvicorn.Server(uvicorn.Config(app, log_level='error'))
    thread = threading.Thread(target=lambda: server.run(sockets=[sock]), daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    try:
        while not server.started:
            assert time.monotonic() < deadline, 'loopback server failed to start'
            time.sleep(.01)
        yield origin
    finally:
        server.should_exit = True
        thread.join(10)
        sock.close()
        assert not thread.is_alive()


def frames(response):
    assert response.status_code == 200, response.text
    result = []
    for block in response.text.strip().split('\n\n'):
        lines = block.splitlines()
        event = next((line[7:] for line in lines if line.startswith('event: ')), None)
        data = json.loads(next(line[6:] for line in lines if line.startswith('data: ')))
        result.append((event, data))
    return result


def request(engine, server, mode):
    engine.target = Plugin(mode)
    response = httpx.post(server + '/redteam/run', json={
        'target': SPEC, 'probe_ids': [p.id for p in engine.probes]}, timeout=10)
    return response, frames(response)


@pytest.mark.parametrize('mode', ['normal', 'quota', 'close_stop'])
def test_real_http_cleanup_in_existing_payloads_and_secret_bytes(engine, server, mode):
    response, stream = request(engine, server, mode)
    target = engine.target
    assert target.calls == (2 if mode == 'quota' else 5)
    assert (target.closes, target.reads) == (1, 1)
    if mode == 'normal':
        assert [(event, payload.get('type', 'finding')) for event, payload in stream] == [
            *[(None, 'finding')] * 5, (None, 'coverage'), ('end', 'finding')]
        payload = stream[-2][1]
        assert payload['summary']['total'] == 5
    else:
        count = 1 if mode == 'quota' else 5
        assert [event for event, _ in stream] == [None] * count + ['error']
        payload = stream[-1][1]
        assert payload['type'] == 'TargetRunStopped'
        assert ('quota' if mode == 'quota' else 'close_limit') in payload['detail']
    assert 'target_cleanup' in payload
    assert payload['target_cleanup'] == run_json._scrub(cleanup(None if mode == 'normal' else ('quota' if mode == 'quota' else 'close_limit'), opened=True), run_json.run_secrets(SPEC))
    assert SECRET not in response.text
    assert all('target_cleanup' not in p for _, p in stream[:-2] if p.get('probe_id'))
    assert all(p['verdict'] == 'pass' for _, p in stream if p.get('probe_id'))


@pytest.mark.parametrize('mode', ['none', 'none_stale'])
def test_real_http_none_omits_cleanup_without_unknown(engine, server, mode):
    response, stream = request(engine, server, mode)
    assert all('target_cleanup' not in payload for _, payload in stream)
    assert 'cleanup state unknown' not in response.text
    assert (engine.target.closes, engine.target.reads) == (1, 1)
    if mode == 'none_stale':
        assert engine.target.primary.target_cleanup is None
        assert engine.target.stale == {}


@pytest.mark.parametrize('mode', ['invalid', 'invalid_stale', 'getter_error', 'getter_stale'])
def test_real_http_invalid_cleanup_never_looks_complete(engine, server, mode):
    response, stream = request(engine, server, mode)
    assert stream[-1][0] == 'error'
    assert 'cleanup state unknown' in stream[-1][1]['detail']
    assert 'target_cleanup' not in stream[-1][1]
    assert 'private cleanup source details' not in response.text
    assert (engine.target.closes, engine.target.reads) == (1, 1)
    if mode.endswith('stale'):
        assert 'quota' in stream[-1][1]['detail']
        assert engine.target.primary.target_cleanup is None
        assert engine.target.stale == {}


@pytest.mark.parametrize('mode', ['quota', 'normal', 'close_stop', 'invalid', 'none', 'none_stale'])
def test_parsed_run_json_uses_final_cleanup(engine, tmp_path, mode):
    engine.target = Plugin(mode)
    output = tmp_path / 'run.json'
    result = CliRunner().invoke(main, ['run', '--local', '--target', json.dumps(SPEC),
        '--probes', ','.join(p.id for p in engine.probes), '--format', 'json', '--out', str(output)])
    assert output.is_file(), result.output
    record = json.loads(output.read_text())
    assert (engine.target.closes, engine.target.reads) == (1, 1)
    assert len(record['findings']) == (1 if mode in ('quota', 'none_stale') else 5)
    if mode in ('none', 'none_stale', 'invalid'):
        assert 'target_cleanup' not in record
    else:
        assert record['target_cleanup']['complete'] is False
        assert SECRET not in output.read_text()
    if mode == 'invalid':
        assert 'cleanup state unknown' in record['incomplete_reason']
    if mode == 'quota':
        assert engine.target.calls == 2
        assert 'quota' in record['incomplete_reason']


@pytest.mark.asyncio
async def test_primary_stop_survives_secondary_close_stop(engine):
    engine.target = Plugin('primary_secondary')
    target = engine.target
    req = api.RunRequest(target=SPEC, probe_ids=[p.id for p in engine.probes])
    with pytest.raises(TargetRunStopped) as caught:
        async for _ in api._run_probes(req, ''):
            pass
    assert caught.value is target.primary
    assert caught.value.reason == 'quota' and caught.value.detail == 'plugin limit'
    assert caught.value.checklist == ('retain original task',)
    assert caught.value.target_cleanup['stop_reason'] == 'close_limit'
    assert (target.calls, target.closes, target.reads) == (2, 1, 1)


@pytest.mark.asyncio
async def test_early_generator_close_finalizes_once(engine):
    target = engine.target = Plugin('normal')
    req = api.RunRequest(target=SPEC, probe_ids=[p.id for p in engine.probes])
    generator = api._run_probes(req, '')
    assert (await generator.__anext__())['verdict'] == 'pass'
    await generator.aclose()
    await generator.aclose()
    assert (target.calls, target.closes, target.reads) == (1, 1, 1)


@pytest.mark.asyncio
async def test_cancelled_run_finalizes_once(engine):
    target = engine.target = Plugin('normal')
    entered = asyncio.Event()
    async def waiting(*args, **kwargs):
        entered.set()
        await asyncio.Event().wait()
    target.send_prompt = waiting
    req = api.RunRequest(target=SPEC, probe_ids=[p.id for p in engine.probes])
    generator = api._run_probes(req, '')
    task = asyncio.create_task(generator.__anext__())
    await entered.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await generator.aclose()
    assert (target.closes, target.reads) == (1, 1)


@pytest.mark.asyncio
@pytest.mark.parametrize('close_report', [False, True])
async def test_missing_getter_preserves_detached_exception_report(engine, close_report):
    class Legacy:
        compatible_classes = frozenset()
        supports_history = False
        calls = 0
        closes = 0
        primary = stop('quota')
        secondary = stop('close_limit')
        async def send_prompt(self, *args, **kwargs):
            self.calls += 1
            self.primary.set_cleanup(cleanup('primary'))
            raise self.primary
        async def aclose(self):
            self.closes += 1
            if close_report:
                self.secondary.set_cleanup(cleanup('secondary'))
                raise self.secondary
    target = engine.target = Legacy()
    req = api.RunRequest(target=SPEC, probe_ids=[p.id for p in engine.probes])
    with pytest.raises(TargetRunStopped) as caught:
        async for _ in api._run_probes(req, ''):
            pass
    assert caught.value is target.primary
    assert caught.value.target_cleanup == cleanup('secondary' if close_report else 'primary')
    assert target.closes == 1


@pytest.mark.asyncio
@pytest.mark.parametrize('async_callback', [False, True])
async def test_python_callback_stop_ends_whole_run_at_second_send(engine, async_callback):
    from argus.targets.python_target import PythonSpec, PythonTarget
    count = []
    primary = stop('quota')
    primary.set_cleanup(cleanup('quota'))
    def callback(prompt, material, context):
        count.append(prompt)
        if len(count) == 2:
            raise primary
        return {'output': 'Benign task complete.'}
    async def async_fn(*args):
        return callback(*args)
    target = engine.target = PythonTarget(PythonSpec(entry='generic_module:call'))
    target._fn = async_fn if async_callback else callback
    req = api.RunRequest(target=SPEC, probe_ids=[p.id for p in engine.probes])
    found = []
    with pytest.raises(TargetRunStopped) as caught:
        async for finding in api._run_probes(req, '', trusted_code=True):
            found.append(finding)
    assert caught.value is primary
    assert len(count) == 2 and len(found) == 1
    assert caught.value.target_cleanup == cleanup('quota')


@pytest.mark.asyncio
async def test_repeated_trials_stop_all_remaining_probes(engine):
    target = engine.target = Plugin('quota')
    req = api.RunRequest(target=SPEC, probe_ids=[p.id for p in engine.probes], trials=5)
    found = []
    with pytest.raises(TargetRunStopped) as caught:
        async for item in api._run_probes(req, ''):
            found.append(item)
    assert caught.value is target.primary
    assert (target.calls, target.closes, target.reads) == (2, 1, 1)
    assert len(found) == 1
    assert found[0]['evidence']['trial_summary']['attempted'] == 2


@pytest.mark.asyncio
async def test_deep_stop_ends_all_threads_without_model_calls(engine, monkeypatch):
    from argus import persona_strategy
    async def proposed(*args, **kwargs):
        return 'Complete a benign task.'
    monkeypatch.setattr(persona_strategy, '_call_attacker_llm', proposed)
    target = engine.target = Plugin('quota')
    req = api.RunRequest(target=SPEC, probe_ids=[p.id for p in engine.probes], mode='deep',
                         deep_pairs=2, max_rounds=3, seed='fixed')
    found = []
    with pytest.raises(TargetRunStopped) as caught:
        async for item in api._run_probes(req, ''):
            found.append(item)
    assert caught.value is target.primary
    assert (target.calls, target.closes, target.reads) == (2, 1, 1)
    assert found[0]['type'] == 'deep_run'


@pytest.mark.asyncio
async def test_close_after_final_cleanup_yield_does_not_read_again(engine):
    target = engine.target = Plugin('normal')
    req = api.RunRequest(target=SPEC, probe_ids=[p.id for p in engine.probes])
    generator = api._run_probes(req, '')
    for _ in range(5):
        assert (await generator.__anext__())['verdict'] == 'pass'
    assert (await generator.__anext__())['type'] == 'target_cleanup'
    await generator.aclose()
    await generator.aclose()
    assert (target.closes, target.reads) == (1, 1)


@pytest.mark.asyncio
@pytest.mark.parametrize('kind', ['cost', 'unreachable'])
async def test_local_error_translation_preserves_unknown_diagnostic(engine, kind):
    from argus.cost_meter import CostExceededError
    from argus.runner import TargetUnreachableError
    error = CostExceededError('generic cap') if kind == 'cost' else TargetUnreachableError('generic outage')
    target = engine.target = Plugin('invalid')
    async def failed(*args, **kwargs):
        raise error
    target.send_prompt = failed
    with pytest.raises(local.LocalRunError, match='cleanup state unknown'):
        async for _ in local.run_local(SPEC, [p.id for p in engine.probes]):
            pass
    assert (target.closes, target.reads) == (1, 1)


@pytest.mark.asyncio
async def test_noncallable_getter_invalidates_stale_complete(engine):
    target = engine.target = Plugin('quota')
    target.primary.set_cleanup(target.stale)
    target.cleanup_report = 'not callable'
    req = api.RunRequest(target=SPEC, probe_ids=[p.id for p in engine.probes])
    with pytest.raises(TargetRunStopped) as caught:
        async for _ in api._run_probes(req, ''):
            pass
    assert caught.value is target.primary
    assert caught.value.target_cleanup is None and target.stale == {}
    assert target.closes == 1


@pytest.mark.asyncio
async def test_absent_getter_invalid_secondary_attachment_is_not_fallback(engine):
    class Legacy:
        compatible_classes = frozenset()
        supports_history = False
        primary = stop('quota')
        secondary = stop('close_limit')
        async def send_prompt(self, *args, **kwargs):
            self.primary.set_cleanup(cleanup('earlier'))
            raise self.primary
        async def aclose(self):
            self.secondary.set_cleanup(cleanup(opened=True) | {'complete': True})
            raise self.secondary
    target = engine.target = Legacy()
    req = api.RunRequest(target=SPEC, probe_ids=[p.id for p in engine.probes])
    with pytest.raises(TargetRunStopped) as caught:
        async for _ in api._run_probes(req, ''):
            pass
    assert caught.value is target.primary
    assert caught.value.target_cleanup is None
