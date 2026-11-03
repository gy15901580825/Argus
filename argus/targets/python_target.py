"""Python target: a function in the caller's own code answers for the agent.

It runs arbitrary local code, so `build_target` builds it only for callers that
pass `trusted_code=True` (the local run path).
"""
from __future__ import annotations

import asyncio
import hashlib
import importlib
import importlib.util
import inspect
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, ClassVar

from argus.targets._base import Target, TargetTransportError, Turn
from argus.targets.custom_http import CustomHTTPTarget, run_log_from_metadata

_RESULT_KEYS = frozenset({"output", "error", "run_log"})


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

    def __post_init__(self) -> None:
        if self.kind != "python":
            raise ValueError(f"kind must be 'python', got {self.kind!r}")
        target, _ = split_entry(self.entry)
        if is_path_entry(target):
            if not target.endswith(".py"):
                raise ValueError("a file entry must end in .py")
            if Path(target).is_absolute() and not Path(target).is_file():
                raise ValueError(f"entry file not found: {target}")
        if not isinstance(self.timeout_s, (int, float)) or self.timeout_s <= 0:
            raise ValueError("timeout_s must be positive")


def load_entry(entry: str) -> Callable:
    target, func = split_entry(entry)
    if is_path_entry(target):
        path = str(Path(target).resolve())
        name = "argus_python_target_" + hashlib.sha256(path.encode()).hexdigest()[:12]
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None or spec.loader is None:
            raise ValueError(f"cannot load {target}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    else:
        module = importlib.import_module(target)
    fn = getattr(module, func, None)
    if not callable(fn):
        raise ValueError(f"{entry} is not a callable")
    return fn


class PythonTarget(Target):
    material_channel: ClassVar[bool] = True
    compatible_classes = CustomHTTPTarget.compatible_classes

    def __init__(self, spec: PythonSpec) -> None:
        self.spec = spec
        self.supports_history = spec.history
        self._fn: Callable | None = None
        self._conversation_id = str(uuid.uuid4())
        self._probe_id = ""
        self._last_run_log = None

    async def begin_probe(self, probe) -> None:
        self._probe_id = probe.id
        self._conversation_id = str(uuid.uuid4())
        self._last_run_log = None

    def last_run_log(self):
        return self._last_run_log

    async def send_prompt(
        self, prompt: str, history: tuple[Turn, ...] = (), *, material: str | None = None
    ) -> tuple[str, float]:
        if self._fn is None:
            try:
                self._fn = await asyncio.to_thread(load_entry, self.spec.entry)
            except Exception as exc:
                raise TargetTransportError(
                    f"python_target_error: cannot load entry: {type(exc).__name__}"
                ) from None
        context = {
            "history": [{"role": t.role, "content": t.content} for t in history],
            "conversation_id": self._conversation_id,
            "probe_id": self._probe_id,
        }
        self._last_run_log = None
        started = time.monotonic()
        try:
            if inspect.iscoroutinefunction(self._fn):
                call = self._fn(prompt, material, context)
            else:
                call = asyncio.to_thread(self._fn, prompt, material, context)
            result = await asyncio.wait_for(call, self.spec.timeout_s)
        except asyncio.TimeoutError:
            raise TimeoutError("timeout: python target exceeded timeout_s") from None
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
        if "run_log" in result:
            try:
                self._last_run_log = run_log_from_metadata({"run_log": result["run_log"]})
            except ValueError:
                raise TargetTransportError(
                    "mapping_error: python target run_log is invalid"
                ) from None
        return output
