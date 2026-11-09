from __future__ import annotations

from typing import Literal, NotRequired, TypedDict, get_args

UndoStatus = Literal['pending', 'done', 'failed', 'skipped_stopped', 'blocked_by_inner', 'unbound', 'unconfirmed']
AbortStatus = Literal['not_needed', 'armed', 'done', 'failed', 'unconfirmed', 'skipped_stopped', 'interrupted']


class CleanupRecord(TypedDict):
    scope: Literal['run', 'attempt']
    step: str
    status: UndoStatus
    method: str
    url: str | None
    http_status: int | None


class AbortRecord(TypedDict):
    scope: Literal['attempt']
    step: str
    status: AbortStatus
    method: str
    url: str | None
    http_status: int | None
    attempt: int
    failure_reason: NotRequired[str]


class CleanupReport(TypedDict):
    complete: bool
    done: int
    open: list[CleanupRecord | AbortRecord]
    stop_reason: str | None
    leftover: list[str]
    aborts: NotRequired[list[AbortRecord]]


class CleanupStateUnknown(ValueError):
    def __init__(self):
        super().__init__('cleanup state unknown')


def run_error_detail(error: BaseException) -> str:
    text = str(error)
    if getattr(error, 'cleanup_diagnostic', None) == 'cleanup state unknown':
        return f'{text}; cleanup state unknown' if text else 'cleanup state unknown'
    return text


def _record(value: object, *, abort: bool = False) -> dict:
    if type(value) is not dict:
        raise CleanupStateUnknown()
    required = {'scope', 'step', 'status', 'method', 'url', 'http_status'}
    abort = abort or 'attempt' in value
    if abort:
        required.add('attempt')
    optional = {'failure_reason'} if abort else set()
    if not required <= value.keys() or value.keys() - required - optional:
        raise CleanupStateUnknown()
    if (type(value['scope']) is not str or type(value['status']) is not str
            or value['scope'] not in (('attempt',) if abort else ('run', 'attempt'))
            or value['status'] not in get_args(AbortStatus if abort else UndoStatus)
            or type(value['step']) is not str or type(value['method']) is not str
            or (value['url'] is not None and type(value['url']) is not str)
            or (value['http_status'] is not None and type(value['http_status']) is not int)
            or (abort and type(value['attempt']) is not int)
            or ('failure_reason' in value and type(value['failure_reason']) is not str)):
        raise CleanupStateUnknown()
    return dict(value)


def validate_cleanup_report(value: object) -> CleanupReport | None:
    if value is None:
        return None
    required = {'complete', 'done', 'open', 'stop_reason', 'leftover'}
    if type(value) is not dict or not required <= value.keys() or value.keys() - required - {'aborts'}:
        raise CleanupStateUnknown()
    if (type(value['complete']) is not bool or type(value['done']) is not int
            or type(value['open']) is not list or type(value['leftover']) is not list
            or any(type(name) is not str for name in value['leftover'])
            or (value['stop_reason'] is not None and type(value['stop_reason']) is not str)
            or ('aborts' in value and type(value['aborts']) is not list)):
        raise CleanupStateUnknown()
    result = dict(value, open=[_record(item) for item in value['open']], leftover=list(value['leftover']))
    if 'aborts' in value:
        result['aborts'] = [_record(item, abort=True) for item in value['aborts']]
    complete = not result['open'] and all(
        item['status'] in {'done', 'not_needed'} for item in result.get('aborts', [])
    )
    if result['complete'] != complete:
        raise CleanupStateUnknown()
    return result
