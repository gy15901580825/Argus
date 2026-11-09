"""Python target: a function in the caller's own code answers for the agent.

It runs arbitrary local code, so `build_target` builds it only for callers that
pass `trusted_code=True` (the local run path).
"""
from __future__ import annotations

import asyncio
import copy
import hashlib
import importlib
import importlib.util
import inspect
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from types import ModuleType

from argus_transport.stops import RunStopped
from argus_transport.cleanup import CleanupReport, CleanupStateUnknown, validate_cleanup_report

from argus.targets._base import Target, TargetTransportError, Turn
from argus.targets.custom_http import CustomHTTPTarget, run_log_from_metadata
from argus.targets.python_evidence import accumulate_python_evidence, validate_python_evidence, validate_python_observations

_RESULT_KEYS = frozenset({"output", "error", "run_log", "evidence"})


def split_entry(entry: str) -> tuple[str, str]:
    target, sep, func = entry.rpartition(":")
    if not sep or not target or not func.isidentifier():
        raise ValueError("entry must be 'module:func' or 'path/to/file.py:func'")
    return target, func


def is_path_entry(target: str) -> bool:
    return "/" in target or target.endswith(".py")


@dataclass(frozen=True)
class PythonSpec:
    kind: str = "python"
    entry: str = ""
    history: bool = True
    timeout_s: float = 300
    material: bool = False
    cleanup: str | None = None
    close: str | None = None

    def __post_init__(self) -> None:
        if self.kind != "python":
            raise ValueError(f"kind must be 'python', got {self.kind!r}")
        entries = (("entry", self.entry), ("cleanup", self.cleanup), ("close", self.close))
        for name, entry in entries:
            if name != "entry" and entry is None:
                continue
            if not isinstance(entry, str):
                raise ValueError("entry must be 'module:func' or 'path/to/file.py:func'")
            target, _ = split_entry(entry)
            if is_path_entry(target):
                if not target.endswith(".py"):
                    raise ValueError("a file entry must end in .py")
                if Path(target).is_absolute() and not Path(target).is_file():
                    raise ValueError(f"{name} file not found: {target}")
        if not isinstance(self.timeout_s, (int, float)) or self.timeout_s <= 0:
            raise ValueError("timeout_s must be positive")
        if not isinstance(self.material, bool):
            raise ValueError("material must be true or false")


def load_entry(entry: str, *, modules: dict[str, ModuleType] | None = None) -> Callable:
    target, func = split_entry(entry)
    key = str(Path(target).resolve()) if is_path_entry(target) else target
    module = modules.get(key) if modules is not None else None
    if module is None:
        if is_path_entry(target):
            name = "argus_python_target_" + hashlib.sha256(key.encode()).hexdigest()[:12]
            spec = importlib.util.spec_from_file_location(name, key)
            if spec is None or spec.loader is None:
                raise ValueError(f"cannot load {target}")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        else:
            module = importlib.import_module(target)
        if modules is not None:
            modules[key] = module
    fn = getattr(module, func, None)
    if not callable(fn):
        raise ValueError(f"{entry} is not a callable")
    return fn


class PythonTarget(Target):
    compatible_classes = CustomHTTPTarget.compatible_classes

    def __init__(self, spec: PythonSpec) -> None:
        self.spec = spec
        self.supports_history = spec.history
        self.material_channel = spec.material
        self._fn: Callable | None = None
        self._conversation_id = str(uuid.uuid4())
        self._probe_id = ""
        self._last_run_log = None
        self._evidence = {}
        self._assertions = ()
        self._modules: dict[str, ModuleType] = {}
        self._hook_functions: dict[str, Callable] = {}
        self._context = {"history": [], "conversation_id": self._conversation_id, "probe_id": ""}
        self._entry_stop: RunStopped | None = None
        self._close_task: asyncio.Task | None = None
        self._cleanup_result: CleanupReport | CleanupStateUnknown | None = None

    async def begin_probe(self, probe) -> None:
        self._evidence = {}
        self._last_run_log = None
        self._assertions = tuple(getattr(probe, "assertions", ()))
        self._probe_id = probe.id
        self._conversation_id = str(uuid.uuid4())
        self._context = {"history": [], "conversation_id": self._conversation_id, "probe_id": self._probe_id}

    def last_run_log(self):
        return self._last_run_log

    async def send_prompt(
        self, prompt: str, history: tuple[Turn, ...] = (), *, material: str | None = None
    ) -> tuple[str, float]:
        self._last_run_log = None
        if self._close_task is not None:
            raise TargetTransportError("python target is closed")
        if self._fn is None:
            try:
                self._fn = await asyncio.to_thread(load_entry, self.spec.entry, modules=self._modules)
            except RunStopped as exc:
                self._entry_stop = exc
                raise
            except Exception as exc:
                raise TargetTransportError(
                    f"python_target_error: cannot load entry: {type(exc).__name__}"
                ) from None
        context = {
            "history": [{"role": t.role, "content": t.content} for t in history],
            "conversation_id": self._conversation_id,
            "probe_id": self._probe_id,
        }
        self._context = copy.deepcopy(context)
        started = time.monotonic()
        try:
            if inspect.iscoroutinefunction(self._fn):
                call = self._fn(prompt, material, context)
            else:
                call = asyncio.to_thread(self._fn, prompt, material, context)
            result = await asyncio.wait_for(call, self.spec.timeout_s)
        except asyncio.TimeoutError:
            raise TimeoutError("timeout: python target exceeded timeout_s") from None
        except RunStopped as exc:
            self._entry_stop = exc
            raise
        except Exception as exc:
            raise TargetTransportError(
                f"python_target_error: {type(exc).__name__}"
            ) from None
        latency_ms = (time.monotonic() - started) * 1000
        return self._output(result), latency_ms

    def _output(self, result) -> str:
        if not isinstance(result, dict):
            raise TargetTransportError("mapping_error: python target must return a dict")
        if not set(result) <= _RESULT_KEYS:
            raise TargetTransportError(
                "mapping_error: python target returned unknown keys"
            )
        if "error" in result:
            raise TargetTransportError("python_target_error")
        output = result.get("output")
        if not isinstance(output, str):
            raise TargetTransportError("mapping_error: python target output must be a string")
        run_log = None
        if "run_log" in result:
            try:
                run_log = run_log_from_metadata({"run_log": result["run_log"]})
            except ValueError:
                raise TargetTransportError(
                    "mapping_error: python target run_log is invalid"
                ) from None
        evidence = validate_python_evidence(result["evidence"]) if "evidence" in result else {}
        evidence = accumulate_python_evidence(self._evidence, evidence)
        self._last_run_log = run_log
        self._evidence = evidence
        return output

    async def collect_evidence(self) -> dict:
        validate_python_observations(self._assertions, self._evidence)
        return copy.deepcopy(self._evidence)

    async def _call_hook(self, name: str):
        async def invoke():
            if name not in self._hook_functions:
                self._hook_functions[name] = await asyncio.to_thread(
                    load_entry, getattr(self.spec, name), modules=self._modules
                )
            fn = self._hook_functions[name]
            context = copy.deepcopy(self._context)
            if inspect.iscoroutinefunction(fn):
                return await fn(context)
            return await asyncio.to_thread(fn, context)
        return await asyncio.wait_for(invoke(), self.spec.timeout_s)

    def _cache_cleanup(self, candidate) -> None:
        try:
            self._cleanup_result = validate_cleanup_report(candidate)
        except CleanupStateUnknown as exc:
            self._cleanup_result = exc

    async def _finish_close(self) -> None:
        cleanup_error = None
        close_error = None
        attached = getattr(self._entry_stop, "target_cleanup", None)
        self._cache_cleanup(attached)
        if self.spec.cleanup is not None:
            try:
                candidate = await self._call_hook("cleanup")
                self._cache_cleanup(candidate if candidate is not None else attached)
            except RunStopped as exc:
                cleanup_error = exc
                candidate = exc.target_cleanup if exc.target_cleanup is not None else attached
                if candidate is None:
                    self._cleanup_result = CleanupStateUnknown()
                else:
                    self._cache_cleanup(candidate)
            except BaseException as exc:
                self._cleanup_result = CleanupStateUnknown()
                cleanup_error = exc if isinstance(exc, asyncio.CancelledError) else TargetTransportError(
                    f"python_target_cleanup_error: {type(exc).__name__}"
                )
        if self.spec.close is not None:
            try:
                result = await self._call_hook("close")
            except RunStopped as exc:
                close_error = exc
                if self._cleanup_result is None and exc.target_cleanup is not None:
                    self._cache_cleanup(exc.target_cleanup)
            except BaseException as exc:
                close_error = exc if isinstance(exc, asyncio.CancelledError) else TargetTransportError(
                    f"python_target_close_error: {type(exc).__name__}"
                )
            else:
                if result is not None:
                    close_error = TargetTransportError("mapping_error: python target close must return None")
        if isinstance(cleanup_error, RunStopped):
            error = cleanup_error
        elif isinstance(close_error, RunStopped):
            error = close_error
        else:
            error = cleanup_error or close_error
        if error is not None:
            raise error

    async def aclose(self) -> None:
        if self._close_task is None:
            self._close_task = asyncio.create_task(self._finish_close())
        await asyncio.shield(self._close_task)

    def cleanup_report(self) -> CleanupReport | None:
        if self.spec.cleanup is not None and self._close_task is None:
            raise CleanupStateUnknown()
        if self._close_task is not None and not self._close_task.done():
            raise CleanupStateUnknown()
        if isinstance(self._cleanup_result, CleanupStateUnknown):
            raise self._cleanup_result
        return copy.deepcopy(self._cleanup_result)
