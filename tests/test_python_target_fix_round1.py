import asyncio
import json
import multiprocessing
import time
from dataclasses import replace

import pytest
from click.testing import CliRunner

from argus.cli.__main__ import main
from argus.targets._base import TargetTransportError
from argus.targets.python_evidence import validate_python_evidence
from argus.targets.python_target import PythonSpec, PythonTarget
from argus_transport.cleanup import CleanupStateUnknown
from test_python_target_evidence import probe, run, target_with


@pytest.mark.parametrize('forbidden,want', [(True, 'fail'), (False, 'pass')])
async def test_three_turn_conversation_retains_first_turn_actions(tmp_path, forbidden, want):
    target = PythonTarget(PythonSpec(entry='fixture:call'))
    def call(prompt, material, context):
        calls = [{'tool': 'exfil_notes'}] if forbidden and not context['history'] else []
        return {'output': 'Done', 'evidence': {'tool_calls': calls, 'interaction_count': 1}}
    target._fn = call
    p = replace(probe('no_call_to_tool', 'exfil_notes'), prompts=('connect', 'read', 'summarize'), conversation=True)
    finding = await run(target, p, tmp_path)
    assert finding.verdict == want
    assert finding.evidence['tool_calls'] == ([{'tool': 'exfil_notes'}] if forbidden else [])


async def test_begin_probe_clears_evidence_before_any_send(tmp_path):
    target = target_with(tmp_path, {'tool_calls': [{'tool': 'exfil_notes'}], 'interaction_count': 1})
    await target.send_prompt('first')
    await target.begin_probe(probe('max_tool_calls', 0))
    with pytest.raises(TargetTransportError, match='tool_calls'):
        await target.collect_evidence()
    target._fn = lambda *args: {'output': 'Done', 'evidence': {'tool_calls': [], 'interaction_count': 1}}
    await target.send_prompt('second')
    assert (await target.collect_evidence())['tool_calls'] == []


@pytest.mark.parametrize('first,second', [(1, 2), ({'a': 1}, {'a': 2}), (1, True), ([], {})])
async def test_conflicting_evidence_is_atomic(tmp_path, first, second):
    target = target_with(tmp_path)
    target._fn = lambda *args: {'output': 'Done', 'evidence': {'report': first, 'tool_calls': [{'tool': 'first'}]}}
    await target.send_prompt('first')
    target._fn = lambda *args: {'output': 'Done', 'evidence': {'report': second, 'tool_calls': [{'tool': 'second'}]}}
    with pytest.raises(TargetTransportError, match='evidence_conflict'):
        await target.send_prompt('second')
    assert await target.collect_evidence() == {'report': first, 'tool_calls': [{'tool': 'first'}]}


@pytest.mark.parametrize('result', [{'error': 'unavailable'}, {'output': 5}, {'output': 'Done', 'evidence': {'unknown': 1}}])
async def test_failed_call_keeps_prior_evidence(tmp_path, result):
    target = target_with(tmp_path, {'tool_calls': [{'tool': 'first'}]})
    await target.send_prompt('first')
    target._fn = lambda *args: result
    with pytest.raises(TargetTransportError):
        await target.send_prompt('second')
    assert await target.collect_evidence() == {'tool_calls': [{'tool': 'first'}]}


async def test_list_evidence_accumulates_in_call_order(tmp_path):
    target = target_with(tmp_path)
    for tool in ('first', 'second', 'third'):
        target._fn = lambda *args: {'output': 'Done', 'evidence': {'tool_calls': [{'tool': tool}], 'report': {'actions': []}}}
        await target.send_prompt(tool)
    assert await target.collect_evidence() == {'tool_calls': [{'tool': 'first'}, {'tool': 'second'}, {'tool': 'third'}], 'report': {'actions': []}}


@pytest.mark.parametrize('methods', [5, [['tools/call']], [1, 'a']])
async def test_canary_rpc_methods_are_typed(tmp_path, methods):
    target = target_with(tmp_path, {'canary': 'fixture-marker', 'canary_hits': [{'rpc_methods': methods}], 'interaction_count': 1})
    finding = await run(target, probe('no_canary_in_mcp_requests', True), tmp_path)
    assert finding.verdict == 'error'
    assert 'rpc_methods' in finding.reasoning


@pytest.mark.parametrize('approval_id', [['a1'], {}, 7])
async def test_execution_approval_id_is_typed(tmp_path, approval_id):
    target = target_with(tmp_path, {'approvals': [{'approval_id': 'a1', 'decision': 'denied', 'action': 'send_email', 'seq': 1}],
                                 'executions': [{'tool': 'send_email', 'seq': 2, 'approval_id': approval_id}], 'interaction_count': 1})
    finding = await run(target, probe('no_action_after_denial', True), tmp_path)
    assert finding.verdict == 'error'
    assert 'approval_id' in finding.reasoning


@pytest.mark.parametrize('exception', [TypeError, KeyError, ValueError])
async def test_assertion_boundary_contains_undeclared_field_errors(tmp_path, monkeypatch, exception):
    from argus.assertions import _CHECKS
    def synthetic(value, evidence, response):
        raise exception('synthetic nested field')
    monkeypatch.setitem(_CHECKS, 'response_fields', synthetic)
    finding = await run(target_with(tmp_path, {'interaction_count': 1}), probe('response_fields', {}), tmp_path)
    assert finding.verdict == 'error'
    assert 'response_fields' in finding.reasoning
    assert 'evidence_assertion_error' in finding.reasoning
    assert exception.__name__ in finding.reasoning
    assert 'synthetic nested field' not in finding.reasoning


def _validate_dag(connection):
    import argus.targets.python_evidence as boundary
    def forbidden_dump(*args, **kwargs):
        raise AssertionError('json.dumps reached')
    boundary.json.dumps = forbidden_dump
    value = ['a']
    for _ in range(8):
        value = [value] * 10
    import tracemalloc
    tracemalloc.start()
    try:
        boundary.validate_python_evidence({'tool_calls': value})
    except Exception as exc:
        connection.send((str(exc), tracemalloc.get_traced_memory()[1]))
    finally:
        connection.close()


def test_shared_dag_is_bounded_before_json_dump():
    context = multiprocessing.get_context('fork')
    parent, child = context.Pipe(duplex=False)
    process = context.Process(target=_validate_dag, args=(child,))
    started = time.monotonic()
    process.start()
    process.join(0.75)
    finished = not process.is_alive()
    if not finished:
        process.terminate()
        process.join()
    assert finished, 'shared DAG validation exceeded 0.75 seconds'
    assert time.monotonic() - started < 1
    assert parent.poll()
    reason, peak = parent.recv()
    assert reason in ('mapping_error: evidence_too_large', 'mapping_error: evidence_work_limit')
    assert peak < 2 * 1024 * 1024
    parent.close()
    child.close()


def test_every_shared_reference_counts_against_work_budget():
    shared = []
    with pytest.raises(TargetTransportError, match='evidence_work_limit'):
        validate_python_evidence({'tool_calls': [shared] * 65536})


def test_utf8_byte_budget_stops_before_serialization(monkeypatch):
    import argus.targets.python_evidence as boundary
    def forbidden_dump(*args, **kwargs):
        raise AssertionError('oversized evidence reached json.dumps')
    monkeypatch.setattr(boundary.json, 'dumps', forbidden_dump)
    with pytest.raises(TargetTransportError, match='evidence_too_large'):
        validate_python_evidence({'report': 'é' * 131072})


async def test_accumulated_ledger_size_limit_is_atomic(tmp_path):
    target = target_with(tmp_path, {'tool_calls': ['x' * 70000, 'y' * 70000]})
    await target.send_prompt('first')
    saved = await target.collect_evidence()
    with pytest.raises(TargetTransportError, match='evidence_too_large'):
        await target.send_prompt('second')
    assert await target.collect_evidence() == saved


async def test_cleanup_report_is_unknown_before_finalization(tmp_path):
    target = PythonTarget(PythonSpec(entry='fixture:call', cleanup='fixture:cleanup'))
    with pytest.raises(CleanupStateUnknown):
        target.cleanup_report()


@pytest.mark.parametrize('hook', ['cleanup', 'close'])
def test_missing_hook_file_names_entry(tmp_path, hook):
    with pytest.raises(ValueError, match=f'{hook} file not found'):
        PythonSpec(entry='fixture:call', **{hook: f'{tmp_path / "missing.py"}:hook'})


@pytest.mark.parametrize('report', [
    {'complete': True, 'done': 0, 'open': [], 'stop_reason': None, 'leftover': ['fixture-resource']},
    {'complete': False, 'done': 0, 'open': [{'scope': 'run', 'step': 'undo', 'status': 'pending', 'method': 'DELETE', 'url': None, 'http_status': None}], 'stop_reason': None, 'leftover': []},
])
def test_validate_execute_reports_unfinished_cleanup(tmp_path, report):
    path = tmp_path / 'agent.py'
    path.write_text(f'def call(*args):\n    return {{"output": "pong"}}\ndef cleanup(context):\n    return {report!r}\n')
    config = tmp_path / 'target.json'
    config.write_text(json.dumps({'kind': 'python', 'entry': f'{path}:call', 'cleanup': f'{path}:cleanup'}))
    result = CliRunner().invoke(main, ['validate-target', '--target', str(config), '--execute'])
    assert result.exit_code == 1
    assert 'OK' not in result.output
    assert 'cleanup' in result.output


async def test_python_evidence_error_names_target(tmp_path):
    finding = await run(target_with(tmp_path, {'interaction_count': 1}), probe('max_tool_calls', 0), tmp_path)
    assert finding.verdict == 'error'
    assert 'from the target' in finding.reasoning
    assert 'testbed' not in finding.reasoning
