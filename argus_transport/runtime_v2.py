from __future__ import annotations

import os
import time
from collections.abc import Mapping
from types import MappingProxyType

import httpx

from .engine import _OMIT
from .engine_v2 import TransportEngineV2, bind_v2
from .models import SafeReasonCode, SyncSpec, TransportContext, TransportResult
from .security import ExecutionPolicy, Redactor
from .spec_v2 import PollSpecV2, TransportSpecV2, iter_requests


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

    def _start(self, context: TransportContext):
        names = set()

        def collect(expression):
            if "env" in expression:
                names.add(expression["env"])
            elif "base64" in expression:
                collect(expression["base64"])
            elif "object" in expression:
                for item in expression["object"].values():
                    collect(item)
            elif "array" in expression or "concat" in expression:
                for item in expression.get("array", expression.get("concat", ())):
                    collect(item)

        for declarations in (self.spec.let.run, self.spec.let.attempt):
            for expression in declarations.values():
                collect(expression)
        for _, request in iter_requests(self.spec):
            for expression in request.query.values():
                collect(expression)
            if "json" in request.body:
                for expression in request.body["json"].values():
                    collect(expression)
            elif "text" in request.body:
                collect(request.body["text"])
        snapshot = {}
        for name in names:
            item = self._environ.get(name)
            if item is not None:
                if not isinstance(item, str) or len(item.encode("utf-8")) > 1024:
                    raise ValueError("Environment value exceeds byte limit")
                snapshot[name] = item
        self.env = MappingProxyType(snapshot)
        scope = {}
        for name, expression in self.spec.let.run.items():
            item = bind_v2(expression, context, scope, self.env)
            if item is not _OMIT:
                if type(item) not in {str, int}:
                    raise ValueError("Variable requires a string or integer")
                scope[name] = item
        self.run_vars = MappingProxyType(scope)

    async def attempt(self, context: TransportContext) -> TransportResult:
        start = time.monotonic()
        engine = TransportEngineV2(self.spec, run=self, client=self.client)
        if not isinstance(self.spec.delivery, (SyncSpec, PollSpecV2)):
            return await engine.run(context)
        if not self._started:
            self._started = True
            try:
                self._start(context)
            except (
                ValueError,
                TypeError,
                AttributeError,
                OverflowError,
                RecursionError,
            ):
                self._start_failed = True
        if self._start_failed:
            return engine.failure(SafeReasonCode.BINDING_ERROR, start)
        return await engine.run(context)
