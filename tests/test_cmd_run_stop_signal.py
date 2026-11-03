import asyncio
import json
import os
import signal
import subprocess
import sys
import threading

import pytest
from aiohttp import web
from click.testing import CliRunner

from argus import api
from argus.cli.__main__ import main
from argus.runner import skipped_finding
from test_transport_lifecycle import deletes, lifecycle_dict, recording_lifecycle
from test_transport_lifecycle_local import local_library
from transport_v2_fakes import serve_in_thread


@pytest.mark.parametrize('signum, code, message', [(signal.SIGINT, 130, 'Interrupted'), (signal.SIGTERM, 143, 'Terminated'), (None, 1, None)])
def test_close_exception_preserves_local_stop_signal(tmp_path, local_library, monkeypatch, signum, code, message):
    initial_cleanup = {'complete': False, 'done': 0, 'open': [], 'stop_reason': None}
    final_cleanup = {
        'complete': False,
        'done': 1,
        'open': [{'method': 'DELETE', 'url': 'http://127.0.0.1:1/resources/remaining', 'step': 'source', 'status': 'failed'}],
        'stop_reason': None,
    }
    class Target:
        compatible_classes = frozenset({'llm_chat'})
        closed = 0
        report = initial_cleanup
        async def aclose(self):
            self.closed += 1
            self.report = final_cleanup
            raise RuntimeError('close failed')
        def cleanup_report(self):
            return self.report
    target = Target()
    class Runner:
        def __init__(self, **kwargs):
            pass
        async def run_probe(self, probe):
            if signum is not None:
                os.kill(os.getpid(), signum)
                await asyncio.sleep(10)
            yield skipped_finding(probe, 'ok')
    monkeypatch.setattr(api, 'build_target', lambda *args, **kwargs: target)
    monkeypatch.setattr(api, 'Runner', Runner)
    escaped = []
    old = {sig: signal.signal(sig, lambda sig, frame: escaped.append(sig)) for sig in (signal.SIGINT, signal.SIGTERM)}
    installed = {sig: signal.getsignal(sig) for sig in old}
    try:
        target_file = tmp_path / 'target.json'
        target_file.write_text(json.dumps({'kind': 'custom_http', 'transport': lifecycle_dict('http://127.0.0.1:1')}))
        out = tmp_path / 'run.json'
        result = CliRunner().invoke(main, ['run', '--local', '--target', str(target_file), '--probes', local_library.id, '--format', 'json', '--out', str(out)])
        assert result.exit_code == code, result.output
        assert target.closed == 1
        assert escaped == []
        assert {sig: signal.getsignal(sig) for sig in old} == installed
        assert 'Target cleanup incomplete: 1 item(s)' in result.stderr
        assert 'http://127.0.0.1:1/resources/remaining (step source, failed)' in result.stderr
        if signum is not None:
            assert f'{message}: the run was stopped before it finished; no report was written.' in result.stderr
            assert not out.exists()
        else:
            record = json.loads(out.read_text())
            assert record['status'] == 'incomplete'
            assert record['target_cleanup'] == final_cleanup
            assert 'RuntimeError: close failed' in record['incomplete_reason']
    finally:
        for sig, handler in old.items():
            signal.signal(sig, handler)


@pytest.mark.parametrize('signum, code, message', [(signal.SIGINT, 130, 'Interrupted'), (signal.SIGTERM, 143, 'Terminated')])
@pytest.mark.parametrize('second_signal', [False, True])
def test_stop_signal_during_local_run_runs_undos_and_exits(tmp_path, local_library, signum, code, message, second_signal):
    escaped = []
    old = {sig: signal.signal(sig, lambda sig, frame: escaped.append(sig)) for sig in (signal.SIGINT, signal.SIGTERM)}
    installed = {sig: signal.getsignal(sig) for sig in old}
    source_deleted = threading.Event()
    async def source_undo(request):
        source_deleted.set()
        if second_signal:
            os.kill(os.getpid(), signal.SIGTERM if signum == signal.SIGINT else signal.SIGINT)
            await asyncio.sleep(10)
        return web.Response(status=204)
    app = recording_lifecycle()
    app.route('DELETE', '/second-signal/{ident}', source_undo)
    async def blocked(request):
        os.kill(os.getpid(), signum)
        for _ in range(1000):
            if source_deleted.is_set() or '/v1/sources/source-one' in deletes(app):
                break
            await asyncio.sleep(0.01)
        return web.json_response({})
    app.route('POST', '/submit', blocked)
    try:
        with serve_in_thread(app) as origin:
            data = lifecycle_dict(origin)
            data['request']['url'] = origin + '/submit'
            if second_signal:
                data['lifecycle']['run'][0]['undo']['request']['url'] = origin + '/second-signal/{source_id}'
            target = tmp_path / 'target.json'
            target.write_text(json.dumps({'kind': 'custom_http', 'transport': data}))
            out = tmp_path / 'run.json'
            result = CliRunner().invoke(main, ['run', '--local', '--target', str(target), '--probes', local_library.id, '--format', 'json', '--out', str(out)])
            assert result.exit_code == code, result.output
            assert f'{message}: the run was stopped before it finished; no report was written.' in result.stderr
            assert not out.exists()
            assert '/v1/messages?remoteId=local-ref&sourceId=source-one' in deletes(app)
            if second_signal:
                assert deletes(app).count('/second-signal/source-one') == 1
                assert 'Target cleanup incomplete: 1 item(s)' in result.stderr
                assert '/second-signal/source-one (step source, failed)' in result.stderr
            else:
                assert '/v1/sources/source-one' in deletes(app)
            assert escaped == []
            assert {sig: signal.getsignal(sig) for sig in old} == installed
    finally:
        for sig, handler in old.items():
            signal.signal(sig, handler)


def test_sigterm_subprocess_sends_undo_delete_to_loopback_fake(tmp_path):
    submitted = threading.Event()
    async def blocked(request):
        submitted.set()
        await asyncio.sleep(30)
        return web.json_response({})
    app = recording_lifecycle()
    app.route('POST', '/submit', blocked)
    with serve_in_thread(app) as origin:
        data = lifecycle_dict(origin)
        data['request']['url'] = origin + '/submit'
        target = tmp_path / 'target.json'
        target.write_text(json.dumps({'kind': 'custom_http', 'transport': data}))
        out = tmp_path / 'run.json'
        proc = subprocess.Popen([sys.executable, '-m', 'argus.cli', 'run', '--local', '--target', str(target), '--probes', 'owasp_01_prompt_injection_basic', '--format', 'json', '--out', str(out)], env={'PYTHON_DOTENV_DISABLED': '1', 'ANTHROPIC_API_KEY': 'dummy-not-a-key', 'VENDOR_A_API_KEY': 'dummy-not-a-key'}, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            assert submitted.wait(10), 'local CLI did not reach submit'
            proc.send_signal(signal.SIGTERM)
            stdout, stderr = proc.communicate(timeout=30)
            assert proc.returncode == 143, stderr
            assert 'Terminated: the run was stopped before it finished; no report was written.' in stderr
            assert '/v1/sources/source-one' in deletes(app)
            assert '/v1/messages?remoteId=local-ref&sourceId=source-one' in deletes(app)
            assert not out.exists()
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate(timeout=5)


def test_signal_preserves_exit_code_when_attempt_cleanup_times_out(tmp_path, local_library):
    app = recording_lifecycle()
    async def blocked(request):
        os.kill(os.getpid(), signal.SIGTERM)
        await asyncio.sleep(10)
        return web.json_response({})
    async def undo_blocked(request):
        await asyncio.sleep(10)
        return web.Response(status=204)
    app.route('POST', '/submit', blocked)
    app.route('DELETE', '/slow-undo', undo_blocked)
    with serve_in_thread(app) as origin:
        data = lifecycle_dict(origin)
        data['request']['url'] = origin + '/submit'
        data['lifecycle']['attempt'][0]['undo']['request']['url'] = origin + '/slow-undo'
        data['timeout']['cleanup_s'] = 0.05
        target = tmp_path / 'target.json'
        target.write_text(json.dumps({'kind': 'custom_http', 'transport': data}))
        out = tmp_path / 'run.json'
        result = CliRunner().invoke(main, ['run', '--local', '--target', str(target), '--probes', local_library.id, '--format', 'json', '--out', str(out)])
        assert result.exit_code == 143, result.output
        assert not out.exists()
        assert 'Terminated: the run was stopped before it finished; no report was written.' in result.stderr
        assert '(step ingest, failed)' in result.stderr
        assert '(step source, blocked_by_inner)' in result.stderr
