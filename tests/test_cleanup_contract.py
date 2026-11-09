import importlib
import shutil
import subprocess
import sys
from pathlib import Path
from typing import get_args

import pytest


def report(**changes):
    value = {'complete': True, 'done': 1, 'open': [], 'stop_reason': None, 'leftover': []}
    value.update(changes)
    return value


def record(**changes):
    value = {'scope': 'run', 'step': 'resource', 'status': 'failed', 'method': 'DELETE',
             'url': 'http://127.0.0.1/resource', 'http_status': None}
    value.update(changes)
    return value


def validator():
    return importlib.import_module('argus_transport.cleanup').validate_cleanup_report


def test_public_stop_is_exact_legacy_class_with_mutable_cleanup():
    from argus.targets import RunStopped
    from argus_transport import RunStopped as TransportStop
    from argus_transport.runtime_v2 import TargetRunStopped
    assert RunStopped is TransportStop is TargetRunStopped
    stopped = RunStopped('quota', 'limit reached')
    assert isinstance(stopped, TargetRunStopped)
    assert stopped.args == ('quota: limit reached',)
    assert stopped.reason == 'quota' and stopped.detail == 'limit reached'
    assert stopped.checklist == () and stopped.cleanup is None
    assert stopped.target_cleanup is None and stopped.transport_diagnostics == {}
    first, second = report(), report(done=2)
    stopped.set_cleanup(first)
    stopped.set_cleanup(second)
    assert stopped.cleanup is first is stopped.target_cleanup
    assert first == second and stopped.transport_diagnostics['cleanup'] is first
    stopped.set_cleanup(None)
    assert stopped.cleanup is first
    try:
        raise stopped
    except TargetRunStopped as caught:
        assert caught is stopped
    try:
        raise TargetRunStopped('quota')
    except RunStopped as caught:
        assert caught.reason == 'quota'


def test_client_image_layout_public_stop_has_no_engine_dependency(tmp_path):
    root = Path(__file__).resolve().parents[1]
    for package in ('argus_transport', 'client_agent'):
        shutil.copytree(root / package, tmp_path / package, ignore=shutil.ignore_patterns('__pycache__'))
    program = """
import importlib.abc, sys
sys.path.insert(0, sys.argv[1])
class DenyEngine(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'argus' or fullname.startswith('argus.'):
            raise AssertionError('engine import in client image')
sys.meta_path.insert(0, DenyEngine())
from argus_transport import RunStopped
from argus_transport.runtime_v2 import TargetRunStopped
assert RunStopped is TargetRunStopped
assert not any(n == 'argus' or n.startswith('argus.') for n in sys.modules)
"""
    result = subprocess.run([sys.executable, '-I', '-c', program, str(tmp_path)],
                            cwd=tmp_path, text=True, capture_output=True)
    assert result.returncode == 0, result.stderr


def test_none_and_detached_valid_report():
    validate = validator()
    assert validate(None) is None
    original = report(leftover=['informational-resource'], aborts=[])
    result = validate(original)
    assert type(result) is dict and result == original and result is not original
    result['leftover'].append('another')
    assert original['leftover'] == ['informational-resource']


@pytest.mark.parametrize('status', ['pending', 'done', 'failed', 'skipped_stopped', 'blocked_by_inner', 'unbound', 'unconfirmed'])
def test_undo_statuses_preserved(status):
    value = report(complete=False, open=[record(status=status)])
    assert validator()(value) == value


@pytest.mark.parametrize('status', ['not_needed', 'armed', 'done', 'failed', 'unconfirmed', 'skipped_stopped', 'interrupted'])
def test_abort_records_allowed_in_open_and_aborts(status):
    abort = record(scope='attempt', status=status, attempt=2, failure_reason='not confirmed')
    value = report(complete=False, open=[abort], aborts=[abort])
    result = validator()(value)
    assert result == value and result['open'][0] is not abort


@pytest.mark.parametrize('field,value', [('complete', 1), ('done', True), ('open', ()),
    ('stop_reason', 3), ('leftover', [2]), ('aborts', ()), ('unknown', 'extra')])
def test_invalid_top_level_fields_rejected(field, value):
    with pytest.raises(ValueError, match='cleanup state unknown'):
        validator()(report(**{field: value}))


@pytest.mark.parametrize('field', ['complete', 'done', 'open', 'stop_reason', 'leftover'])
def test_missing_required_fields_rejected(field):
    value = report()
    del value[field]
    with pytest.raises(ValueError, match='cleanup state unknown'):
        validator()(value)


@pytest.mark.parametrize('changes', [{'scope': 'other'}, {'status': 'unknown'}, {'step': 1},
    {'method': False}, {'url': 2}, {'http_status': True}, {'extra': 1},
    {'attempt': True, 'scope': 'attempt'}, {'attempt': 1, 'scope': 'run'},
    {'attempt': 1, 'scope': 'attempt', 'failure_reason': 2}])
def test_invalid_records_rejected(changes):
    with pytest.raises(ValueError, match='cleanup state unknown'):
        validator()(report(complete=False, open=[record(**changes)]))


@pytest.mark.parametrize('value', [report(complete=False), report(open=[record()])])
def test_complete_exactly_matches_empty_open(value):
    with pytest.raises(ValueError, match='cleanup state unknown'):
        validator()(value)


def test_validator_does_not_invent_count_or_http_ranges():
    value = report(complete=False, done=-1, open=[record(http_status=-1)])
    assert validator()(value) == value


def test_status_aliases_are_shared_with_runtime():
    cleanup = importlib.import_module('argus_transport.cleanup')
    runtime = importlib.import_module('argus_transport.runtime_v2')
    assert runtime.UndoStatus is cleanup.UndoStatus
    assert set(get_args(cleanup.AbortStatus)) == {'not_needed', 'armed', 'done', 'failed', 'unconfirmed', 'skipped_stopped', 'interrupted'}


@pytest.mark.parametrize('status', ['armed', 'failed', 'unconfirmed', 'skipped_stopped', 'interrupted'])
def test_unfinished_abort_only_in_aborts_cannot_claim_complete(status):
    abort = record(scope='attempt', status=status, attempt=1)
    with pytest.raises(ValueError, match='cleanup state unknown'):
        validator()(report(aborts=[abort]))


@pytest.mark.parametrize('status', ['done', 'not_needed'])
def test_finished_abort_only_in_aborts_keeps_complete(status):
    value = report(aborts=[record(scope='attempt', status=status, attempt=1)])
    assert validator()(value) == value


@pytest.mark.parametrize('status', ['armed', 'failed', 'unconfirmed', 'skipped_stopped', 'interrupted'])
def test_unfinished_abort_only_in_aborts_accepts_incomplete_report(status):
    value = report(complete=False, aborts=[record(scope='attempt', status=status, attempt=1)])
    assert validator()(value) == value
