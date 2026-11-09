import asyncio
import json
from dataclasses import replace
from unittest.mock import patch

import pytest
from click.testing import CliRunner
from fastapi import FastAPI
from fastapi.testclient import TestClient

from argus import api, local
from argus.cli.__main__ import main
from argus.probe import load_probe_library
from argus.runner import skipped_finding
from test_transport_lifecycle import deletes, lifecycle_dict, recording_lifecycle
from transport_v2_fakes import serve_in_thread


@pytest.fixture
def local_library(monkeypatch):
    base = load_probe_library(api.PROBES_DIR)[0]
    probe = replace(base, id='local_lifecycle', target_class=('llm_chat',), prompts=('normal',),
                    assertions=({'type': 'tool_not_called', 'tool': 'unused'},),
                    judge_when_assertions_pass=False, conversation=False, requires_interaction=False)
    monkeypatch.setattr(api, 'load_probe_library', lambda *_: [probe])
    monkeypatch.setattr(local, 'load_probe_library', lambda *_: [probe])
    monkeypatch.setattr(api, 'Judge', lambda **_: None)
    monkeypatch.setenv('ANTHROPIC_API_KEY', 'dummy-not-a-key')
    return probe


async def test_run_undo_reaches_loopback_when_consumer_stops_early(local_library):
    app = recording_lifecycle()
    with serve_in_thread(app) as origin:
        gen = local.run_local({'kind': 'custom_http', 'transport': lifecycle_dict(origin)}, [local_library.id])
        event = await gen.__anext__()
        assert event['probe_id'] == local_library.id
        await gen.aclose()
        assert deletes(app)[-1] == '/v1/sources/source-one'


@pytest.mark.parametrize('undo_status, expected_status, code', [(204, 'completed', 0), (500, 'incomplete', 1)])
def test_run_json_records_target_cleanup_and_marks_incomplete_when_open(tmp_path, local_library, undo_status, expected_status, code):
    app = recording_lifecycle(undo_status=undo_status)
    with serve_in_thread(app) as origin:
        target = tmp_path / 'target.json'
        target.write_text(json.dumps({'kind': 'custom_http', 'transport': lifecycle_dict(origin)}))
        out = tmp_path / 'run.json'
        result = CliRunner().invoke(main, ['run', '--local', '--target', str(target), '--probes', local_library.id, '--format', 'json', '--out', str(out)])
        assert result.exit_code == code, result.output
        record = json.loads(out.read_text())
        assert record['status'] == expected_status
        assert record['target_cleanup']['complete'] is (undo_status == 204)
        assert len(record['findings']) == 1
        assert record['summary']['total'] == 1
        if undo_status == 500:
            assert 'Target cleanup incomplete:' in result.stderr
            assert '/v1/sources/source-one' in result.stderr


def test_server_stream_keeps_cleanup_in_coverage_without_extra_frame(local_library, monkeypatch):
    async def events(*args, **kwargs):
        yield api.finding_dict(replace(skipped_finding(local_library, 'ok'), verdict='pass'), local_library)
        yield {'type': 'target_cleanup', 'target_cleanup': {'complete': True, 'done': 1, 'open': [], 'stop_reason': None}}
    monkeypatch.setattr(api, '_run_probes', events)
    app = FastAPI()
    app.include_router(api.router)
    with TestClient(app) as client:
        response = client.post('/redteam/run', json={'target': {'kind': 'openai_compat', 'endpoint_url': 'http://127.0.0.1:1', 'model': 'dummy'}, 'probe_ids': [local_library.id]})
    assert response.status_code == 200, response.text
    data = [json.loads(line[6:]) for line in response.text.splitlines() if line.startswith('data: ')]
    assert not any(event.get('type') == 'target_cleanup' for event in data)
    coverage = next(event for event in data if event.get('type') == 'coverage')
    assert coverage['summary']['total'] == 1
    assert coverage['target_cleanup']['complete'] is True
    assert len(data) == 3


@pytest.mark.parametrize('probe_error', [None, RuntimeError('probe failed')])
async def test_close_exception_is_propagated_without_retry(local_library, probe_error):
    class Target:
        compatible_classes = frozenset({'llm_chat'})
        closed = 0
        async def aclose(self):
            self.closed += 1
            raise ValueError('close failed')
    target = Target()
    class Runner:
        def __init__(self, **kwargs):
            pass
        async def run_probe(self, probe):
            if probe_error:
                raise probe_error
            yield skipped_finding(probe, 'ok')
    with patch.object(api, 'build_target', lambda *_: target), patch.object(api, 'Runner', Runner):
        with pytest.raises(RuntimeError if probe_error is not None else ValueError,
                           match='probe failed' if probe_error is not None else 'close failed') as caught:
            async for _ in api._run_probes(api.RunRequest(target={'kind': 'openai_compat'}, probe_ids=[local_library.id]), 'dummy'):
                pass
        if probe_error is not None:
            assert caught.value is probe_error
    assert target.closed == 1


@pytest.mark.parametrize('error_type', [local.CostExceededError, local.TargetUnreachableError])
async def test_local_error_translation_keeps_cleanup(local_library, monkeypatch, error_type):
    report = {'complete': False, 'done': 0, 'open': [], 'stop_reason': None}
    async def events(*args, **kwargs):
        exc = error_type('failed')
        exc.target_cleanup = report
        raise exc
        yield
    monkeypatch.setattr(api, '_run_probes', events)
    with pytest.raises(local.LocalRunError) as caught:
        async for _ in local.run_local({'kind': 'custom_http', 'transport': lifecycle_dict('http://127.0.0.1:1')}, [local_library.id]):
            pass
    assert caught.value.target_cleanup == report


async def test_budget_stop_keeps_stable_cleanup_aliases_after_run_close(local_library, monkeypatch):
    probe = replace(local_library, prompts=('first', 'second'))
    monkeypatch.setattr(api, 'load_probe_library', lambda *_: [probe])
    monkeypatch.setattr(local, 'load_probe_library', lambda *_: [probe])
    app = recording_lifecycle()
    with serve_in_thread(app) as origin:
        data = lifecycle_dict(origin)
        data['budget'] = {'max_requests': 3}
        events = []
        with pytest.raises(Exception) as caught:
            async for event in local.run_local({'kind': 'custom_http', 'transport': data}, [probe.id]):
                events.append(event)
        exc = caught.value
        assert exc.reason == 'request_budget'
        assert exc.cleanup is exc.target_cleanup
        assert exc.transport_diagnostics['cleanup'] is exc.target_cleanup
        assert exc.target_cleanup == {'complete': True, 'done': 2, 'open': [], 'stop_reason': 'request_budget', 'leftover': []}
        assert len(events) == 1
        assert deletes(app) == ['/v1/messages?remoteId=local-ref&sourceId=source-one', '/v1/sources/source-one']
