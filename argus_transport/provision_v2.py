from __future__ import annotations

from collections.abc import Callable

import httpx

from .engine import _OMIT, matches_predicate
from .engine_v2 import (
    _CaptureAmbiguous,
    _CaptureNotFound,
    _CapturePrefixError,
    bind_v2,
    capture_value,
)
from .models import TransportResult
from .runtime_v2 import TargetRunStopped, V2Run
from .spec_v2 import provision_checklist


async def run_provision(run: V2Run, exchange: Callable) -> dict[str, str | int]:
    provision = run.spec.lifecycle.provision
    scope = dict(run.run_vars)
    if provision is None:
        return scope
    context = run._provision_context

    async def execute(step, *, find):
        try:
            if find and step.given:
                given = {name: bind_v2(expr, context, scope, run.env)
                         for name, expr in step.given.items()}
                if all(item is not _OMIT and item is not None and item != '' for item in given.values()):
                    selected = {name: capture_value(step.capture[name], item, context, scope, run.env, given=True)
                                for name, item in given.items()}
                    scope.update(selected)
                    return
            response = await exchange(step.request, scope)
            if isinstance(response, TransportResult) or response.status not in step.expect.http_status or (
                step.expect.when is not None and not matches_predicate(response.body, step.expect.when)
            ):
                raise TargetRunStopped('setup_failed_run', f"{'find ' if find else ''}step '{step.id}'")
            selected = {name: capture_value(selector, response.body, context, scope, run.env)
                        for name, selector in step.capture.items()}
            scope.update(selected)
        except _CapturePrefixError:
            raise TargetRunStopped('id_prefix_mismatch', f"{'find ' if find else ''}step '{step.id}'") from None
        except _CaptureAmbiguous as exc:
            raise TargetRunStopped('ambiguous', f"{'find ' if find else ''}step '{step.id}' matched {exc.count} items; narrow its where") from None
        except _CaptureNotFound:
            if find:
                raise
            raise TargetRunStopped('setup_failed_run', f"step '{step.id}'") from None
        except (ValueError, TypeError, AttributeError, OverflowError, RecursionError, OSError, httpx.HTTPError):
            raise TargetRunStopped('setup_failed_run', f"{'find ' if find else ''}step '{step.id}'") from None

    for retry in (False, True):
        missing = None
        for index, step in enumerate(provision.find):
            try:
                await execute(step, find=True)
            except _CaptureNotFound:
                missing = step
                break
        if missing is None:
            return scope
        if retry or index != len(provision.find) - 1 or not provision.create:
            stopped = TargetRunStopped('not_provisioned', f"find step '{missing.id}' matched no item (0 business requests sent)")
            stopped.checklist = tuple(provision_checklist(run.spec, step_id=missing.id, hint=missing.hint))
            raise stopped
        for step in provision.create:
            await execute(step, find=False)
        for step in provision.find:
            for name in step.capture:
                scope.pop(name, None)
    raise AssertionError('Provision lookup did not resolve')
