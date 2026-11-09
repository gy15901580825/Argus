import asyncio
import json
import textwrap

import pytest

from argus.api import _finalize_target
from argus.targets import RunStopped
from argus.targets._base import TargetTransportError
from argus.targets.python_target import PythonSpec, PythonTarget
from argus_transport.cleanup import CleanupStateUnknown


REPORT = {'complete': True, 'done': 1, 'open': [], 'stop_reason': None, 'leftover': []}


def test_required_entry_is_not_optional():
    with pytest.raises(ValueError, match='entry must be'):
        PythonSpec(entry=None)
    assert PythonSpec(entry='fixture_module:call', cleanup=None, close=None).entry == 'fixture_module:call'


def make_target(tmp_path, extra='', **options):
    path = tmp_path / 'agent.py'
    path.write_text(textwrap.dedent('''
        calls = []
        def call(prompt, material, context):
            calls.append('entry')
            return {'output': 'Done'}
    ''') + '\n' + textwrap.dedent(extra))
    return PythonTarget(PythonSpec(entry=f'{path}:call', cleanup=f'{path}:cleanup', close=f'{path}:close', **options))


@pytest.mark.parametrize('async_cleanup,async_close', [(False, False), (False, True), (True, False), (True, True)])
async def test_hooks_share_file_state_and_cache_once(tmp_path, async_cleanup, async_close):
    target = make_target(tmp_path, f'''
        {'async ' if async_cleanup else ''}def cleanup(context):
            assert calls == ['entry']
            assert context['probe_id'] == 'fixture-probe'
            calls.append('cleanup')
            return {REPORT!r}
        {'async ' if async_close else ''}def close(context):
            assert calls == ['entry', 'cleanup']
            calls.append('close')
    ''')
    await target.begin_probe(type('P', (), {'id': 'fixture-probe', 'assertions': ()})())
    await target.send_prompt('Task')
    await asyncio.gather(target.aclose(), target.aclose())
    await target.aclose()
    report = target.cleanup_report()
    assert report == REPORT
    report['leftover'].append('changed')
    assert target.cleanup_report() == REPORT
    with pytest.raises(TargetTransportError, match='closed'):
        await target.send_prompt('later')


async def test_file_module_state_is_per_target(tmp_path):
    target = make_target(tmp_path, f'''
        def cleanup(context):
            assert calls == ['entry']
            return {REPORT!r}
        def close(context):
            calls.append('close')
    ''')
    second = PythonTarget(target.spec)
    await target.send_prompt('first')
    await second.send_prompt('second')
    await target.aclose()
    await second.aclose()
    assert target.cleanup_report() == second.cleanup_report() == REPORT


@pytest.mark.parametrize('failure', ['return {}', "raise RuntimeError('private detail')"])
async def test_cleanup_unknown_still_calls_close_and_is_cached(tmp_path, failure):
    target = make_target(tmp_path, f'''
        def cleanup(context):
            calls.append('cleanup')
            {failure}
        def close(context):
            assert calls == ['entry', 'cleanup']
            calls.append('close')
    ''')
    await target.send_prompt('Task')
    final = await _finalize_target(target, None)
    assert isinstance(final.cleanup_error, CleanupStateUnknown)
    assert final.report is None
    with pytest.raises(CleanupStateUnknown):
        target.cleanup_report()
    try:
        await target.aclose()
    except TargetTransportError:
        pass


async def test_successful_cleanup_survives_close_failure(tmp_path):
    target = make_target(tmp_path, f'''
        def cleanup(context):
            return {REPORT!r}
        def close(context):
            raise RuntimeError('private detail')
    ''')
    final = await _finalize_target(target, None)
    assert final.report == REPORT
    assert isinstance(final.close_error, TargetTransportError)
    assert 'private detail' not in str(final.close_error)


async def test_entry_stop_attached_report_survives_new_getter(tmp_path):
    target = PythonTarget(PythonSpec(entry='fixture_module:call'))
    stopped = RunStopped('quota', 'original detail')
    stopped.set_cleanup(REPORT)
    def call(*args):
        raise stopped
    target._fn = call
    with pytest.raises(RunStopped) as exc:
        await target.send_prompt('Task')
    assert exc.value is stopped
    final = await _finalize_target(target, stopped)
    assert final.report == REPORT
    assert stopped.reason == 'quota'
    assert stopped.target_cleanup == REPORT


async def test_hook_stop_keeps_original_run_stop_and_closes(tmp_path):
    target = make_target(tmp_path, f'''
        from argus.targets import RunStopped
        def cleanup(context):
            stopped = RunStopped('cleanup stop')
            stopped.set_cleanup({REPORT!r})
            calls.append('cleanup')
            raise stopped
        def close(context):
            assert calls == ['cleanup']
    ''')
    primary = RunStopped('entry stop')
    final = await _finalize_target(target, primary)
    assert isinstance(final.close_error, RunStopped)
    assert primary.reason == 'entry stop'
    assert final.report == REPORT
    assert primary.target_cleanup == REPORT


async def test_caller_cancellation_does_not_repeat_or_cancel_finalization(tmp_path):
    target = make_target(tmp_path, f'''
        import asyncio
        started = asyncio.Event()
        released = asyncio.Event()
        async def cleanup(context):
            calls.append('cleanup')
            started.set()
            await released.wait()
            return {REPORT!r}
        def close(context):
            assert calls == ['entry', 'cleanup']
            calls.append('close')
    ''')
    await target.send_prompt('Task')
    controls = target._fn.__globals__
    waiter = asyncio.create_task(target.aclose())
    await controls['started'].wait()
    waiter.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiter
    controls['released'].set()
    await target.aclose()
    assert controls['calls'] == ['entry', 'cleanup', 'close']
    assert target.cleanup_report() == REPORT


def test_all_hook_paths_anchor_like_entry(tmp_path, monkeypatch):
    from argus.cli.target_loader import load_target_spec
    folder = tmp_path / 'config'
    folder.mkdir()
    (folder / 'agent.py').write_text('def call(*args): return {"output": "Done"}\n')
    path = folder / 'target.json'
    path.write_text(json.dumps({'kind': 'python', 'entry': 'agent.py:call', 'cleanup': 'agent.py:cleanup', 'close': 'agent.py:close'}))
    monkeypatch.chdir(tmp_path)
    spec = load_target_spec(str(path))
    assert spec['entry'] == f'{folder / "agent.py"}:call'
    assert spec['cleanup'] == f'{folder / "agent.py"}:cleanup'
    assert spec['close'] == f'{folder / "agent.py"}:close'


@pytest.mark.parametrize('name', ['cleanup', 'close'])
def test_optional_hook_entry_is_validated(name):
    with pytest.raises(ValueError):
        PythonSpec(entry='fixture:call', **{name: 'not-an-entry'})


@pytest.mark.parametrize('async_cleanup', [False, True])
async def test_cleanup_timeout_still_closes_without_retry(tmp_path, async_cleanup, monkeypatch):
    if async_cleanup:
        body = '''
            import asyncio
            import threading
            started = threading.Event()
            async def cleanup(context):
                calls.append('cleanup')
                started.set()
                await asyncio.Event().wait()
            def close(context):
                calls.append('close')
        '''
    else:
        body = '''
            import threading
            started = threading.Event()
            released = threading.Event()
            def cleanup(context):
                calls.append('cleanup')
                started.set()
                released.wait()
            def close(context):
                calls.append('close')
                released.set()
        '''
    target = make_target(tmp_path, body)
    await target.send_prompt('Task')
    wait_for = asyncio.wait_for
    first = True

    async def expire_cleanup(awaitable, timeout):
        nonlocal first
        if not first:
            return await wait_for(awaitable, timeout)
        first = False
        running = asyncio.create_task(awaitable)
        await asyncio.to_thread(target._fn.__globals__['started'].wait)
        running.cancel()
        with pytest.raises(asyncio.CancelledError):
            await running
        raise asyncio.TimeoutError

    monkeypatch.setattr(asyncio, 'wait_for', expire_cleanup)
    final = await _finalize_target(target, None)
    assert isinstance(final.cleanup_error, CleanupStateUnknown)
    assert isinstance(final.close_error, TargetTransportError)
    assert target._fn.__globals__['calls'] == ['entry', 'cleanup', 'close']
    with pytest.raises(TargetTransportError):
        await target.aclose()
    assert target._fn.__globals__['calls'] == ['entry', 'cleanup', 'close']


async def test_closed_hook_non_none_result_is_mapping_error(tmp_path):
    target = make_target(tmp_path, f'''
        def cleanup(context):
            return {REPORT!r}
        def close(context):
            return 'not a close result'
    ''')
    with pytest.raises(TargetTransportError, match='mapping_error: python target close must return None'):
        await target.aclose()
    assert target.cleanup_report() == REPORT
