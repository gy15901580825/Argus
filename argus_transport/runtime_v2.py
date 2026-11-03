from __future__ import annotations

import asyncio
import os
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Literal

import httpx

from .engine import _OMIT
from .engine_v2 import TransportEngineV2, bind_v2
from .models import SafeReasonCode, SyncSpec, TransportContext, TransportResult
from .security import ExecutionPolicy, Redactor
from .spec_v2 import PollSpecV2, RequestSpecV2, TransportSpecV2, UndoSpec, _iter_expressions


class TargetRunStopped(Exception):
    def __init__(self, reason: str, detail: str = ''):
        super().__init__(f'{reason}: {detail}' if detail else reason)
        self.reason = reason
        self.detail = detail
        self.checklist: tuple[str, ...] = ()
        self.cleanup: dict | None = None
        self.target_cleanup: dict | None = None
        self.transport_diagnostics: dict = {}

    def set_cleanup(self, report: dict | None) -> None:
        if report is not None:
            if self.cleanup is None:
                self.cleanup = report
            else:
                self.cleanup.clear()
                self.cleanup.update(report)
            self.target_cleanup = self.cleanup
            self.transport_diagnostics['cleanup'] = self.cleanup


UndoStatus = Literal['pending', 'done', 'failed', 'skipped_stopped', 'blocked_by_inner', 'unbound']


@dataclass
class UndoIntent:
    scope: Literal['run', 'attempt']
    step_id: str
    spec: UndoSpec
    needs: frozenset[str]
    provides: frozenset[str]
    status: UndoStatus = 'pending'
    http_status: int | None = None
    url: str | None = None
    _request: RequestSpecV2 | None = field(default=None, repr=False)
    _content: bytes | None = field(default=None, repr=False)
    _headers: dict[str, str] = field(default_factory=dict, repr=False)
    _bindings: Mapping[str, str | int] = field(default_factory=dict, repr=False)


class RequestLedger:
    def __init__(self, max_requests: int | None, cleanup_reserve: int):
        self.max_requests = max_requests
        self.cleanup_reserve = cleanup_reserve
        self.counts = dict.fromkeys(('provision', 'setup', 'submit', 'poll', 'cleanup'), 0)
        self._reserved = 0

    def _check_request(self) -> None:
        if self.max_requests is not None and sum(
            count for phase, count in self.counts.items() if phase != 'cleanup'
        ) >= self.max_requests:
            raise TargetRunStopped('request_budget')

    def charge(self, phase: str) -> None:
        self._check_request()
        self.counts[phase] += 1

    def reserve_cleanup(self) -> None:
        if self._reserved >= self.cleanup_reserve:
            raise TargetRunStopped('cleanup_reserve')
        self._reserved += 1

    def spend_cleanup(self) -> None:
        if self.counts['cleanup'] >= self._reserved:
            raise TargetRunStopped('cleanup_reserve')
        self.counts['cleanup'] += 1


class UndoStack:
    def __init__(self, ledger: RequestLedger):
        self.ledger = ledger
        self.intents: list[UndoIntent] = []

    def register(self, intent: UndoIntent) -> None:
        self.ledger.reserve_cleanup()
        self.intents.append(intent)

    async def unwind(self, send: Callable[[UndoIntent], Awaitable[None]], *, timeout_s: float) -> None:
        async def unwind_all():
            for intent in reversed(self.intents):
                if intent.status == 'pending':
                    await send(intent)
        try:
            await asyncio.wait_for(unwind_all(), timeout_s)
        except (TimeoutError, asyncio.CancelledError):
            for intent in self.intents:
                if intent.status == 'pending':
                    intent.status = 'failed'
            raise

    def report(self, stop_reason: str | None = None) -> dict:
        return cleanup_summary(self.intents, stop_reason)


def cleanup_summary(intents, stop_reason=None):
    opened = [
        {'scope': item.scope, 'step': item.step_id, 'status': item.status,
         'method': item.spec.request.method, 'url': item.url, 'http_status': item.http_status}
        for item in intents if item.status != 'done'
    ]
    return {'complete': not opened, 'done': sum(item.status == 'done' for item in intents),
            'open': opened, 'stop_reason': stop_reason}


class V2Run:
    def __init__(
        self,
        spec: TransportSpecV2,
        *,
        policy: ExecutionPolicy,
        environ: Mapping[str, str] | None = None,
        client: httpx.AsyncClient | None = None,
    ):
        self.spec = spec
        self.policy = policy
        self.redactor = Redactor()
        self.env: Mapping[str, str] = MappingProxyType({})
        self.run_vars: Mapping[str, str | int] = MappingProxyType({})
        self.client = client
        self._environ = os.environ if environ is None else environ
        self._started = False
        self._start_failed = False
        self._startup_error: BaseException | None = None
        self._stop_error: TargetRunStopped | None = None
        self._closed = False
        self.ledger = RequestLedger(spec.budget.max_requests, spec.budget.cleanup_reserve)
        self.run_undos = UndoStack(self.ledger)
        self.attempt_undos: list[UndoStack] = []
        self._has_undo = any(step.undo for step in (*spec.lifecycle.run, *spec.lifecycle.attempt))

    def _start(self, context: TransportContext):
        requirements: dict[str, bool] = {}

        def collect(expression, required_owner):
            if 'env' in expression:
                name = expression['env']
                requirements[name] = requirements.get(name, False) or (
                    required_owner and expression.get('missing') != 'omit'
                )
            elif 'base64' in expression:
                collect(expression['base64'], required_owner)
            elif 'object' in expression:
                for item in expression['object'].values():
                    collect(item, required_owner)
            elif 'array' in expression or 'concat' in expression:
                for item in expression.get('array', expression.get('concat', ())):
                    collect(item, required_owner)

        for item in _iter_expressions(self.spec):
            collect(item.expression, item.owner in {'let', 'submit', 'poll'})
        allowed = self.policy.allowed_env_names
        if allowed is not None and any(name not in allowed for name in requirements):
            raise ValueError('Environment reference denied')
        snapshot = {}
        for name, required in requirements.items():
            item = self._environ.get(name)
            if item is None:
                if required:
                    raise ValueError('Environment value missing')
            else:
                if not isinstance(item, str) or len(item.encode('utf-8')) > 1024:
                    raise ValueError('Environment value exceeds byte limit')
                snapshot[name] = item
        self.env = MappingProxyType(snapshot)
        scope = {}
        for name, expression in self.spec.let.run.items():
            item = bind_v2(expression, context, scope, self.env)
            if item is not _OMIT:
                if type(item) not in {str, int}:
                    raise ValueError('Variable requires a string or integer')
                scope[name] = item
        self.run_vars = MappingProxyType(scope)

    async def attempt(self, context: TransportContext) -> TransportResult:
        start = time.monotonic()
        engine = TransportEngineV2(self.spec, run=self, client=self.client)
        if not isinstance(self.spec.delivery, (SyncSpec, PollSpecV2)):
            return await engine.run(context)
        if self._closed:
            raise TargetRunStopped('run_closed')
        if not self._started:
            self._started = True
            try:
                self._start(context)
            except (ValueError, TypeError, AttributeError, OverflowError, RecursionError):
                self._start_failed = True
            if not self._start_failed:
                try:
                    await engine.startup(context)
                except BaseException as exc:
                    self._startup_error = exc
        if self._startup_error is not None:
            if isinstance(self._startup_error, TargetRunStopped):
                self._stop_error = self._startup_error
                self._stop_error.set_cleanup(self.cleanup_report())
            raise self._startup_error
        if self._start_failed:
            return engine.failure(SafeReasonCode.BINDING_ERROR, start)
        try:
            return await engine.run(context)
        except TargetRunStopped as exc:
            self._stop_error = exc
            exc.set_cleanup(self.cleanup_report())
            raise

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            for intent in self.run_undos.intents:
                if intent.status == 'pending' and any(
                    intent.provides & inner.needs
                    for stack in self.attempt_undos for inner in stack.intents
                    if inner.status != 'done'
                ):
                    intent.status = 'blocked_by_inner'
            engine = TransportEngineV2(self.spec, run=self, client=self.client)
            await engine.cleanup(self.run_undos)
        finally:
            if self._stop_error is not None:
                self._stop_error.set_cleanup(self.cleanup_report())

    def cleanup_report(self) -> dict | None:
        if not self._has_undo:
            return None
        intents = [*self.run_undos.intents,
                   *(item for stack in self.attempt_undos for item in stack.intents)]
        return cleanup_summary(intents, self._stop_error.reason if self._stop_error else None)
