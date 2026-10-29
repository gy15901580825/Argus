"""In-process entry point for `argus-probe run --local`.

Wraps the generator and validators that already power POST /redteam/run so
the CLI can run probes without api_service, Postgres or an HTTP hop. api.py
is deliberately left untouched: its tests patch `api._run_probes`, and this
module reaches every api function through the module object so those
patches keep applying.
"""
from __future__ import annotations

import math
import os
from typing import AsyncIterator, Mapping

from fastapi import HTTPException

from argus import api, llm
from argus.cost_meter import CostExceededError
from argus.coverage import build_coverage
from argus.probe import load_probe_library
from argus.runner import NO_JUDGE_KEY, TargetUnreachableError, skipped_finding
from argus.targets import build_target
from argus.targets.browser_use import local_browser_mode


class LocalRunError(Exception):
    """A run could not start or had to stop.

    `code` is "config", "input", "usage" (unknown probe ids), "cost" or "unreachable".
    """

    def __init__(self, message: str, code: str) -> None:
        super().__init__(message)
        self.code = code


async def run_local(
    target: dict,
    probe_ids: list[str],
    *,
    mode: str = "static",
    per_run_cap_usd: float | None = None,
    env: Mapping[str, str] | None = None,
) -> AsyncIterator[dict]:
    """Yield finding dicts, then one {"type": "coverage", "coverage": dict} event."""
    env = os.environ if env is None else env

    # Same credential rule as POST /redteam/run: the configured provider decides
    # which key is mandatory.
    try:
        cfg = llm.resolve_config(env)
    except ValueError as e:
        raise LocalRunError(str(e), code="config") from e
    anthropic_api_key = env.get("ANTHROPIC_API_KEY")

    if not isinstance(target, dict):
        raise LocalRunError("target must be a JSON object", code="input")
    try:
        target_obj = build_target(target)
    except (ValueError, TypeError) as e:
        # TypeError: SpecClass(**spec) rejects unexpected or missing fields.
        raise LocalRunError(str(e), code="input") from e

    try:
        req = api.RunRequest(
            target=target, probe_ids=probe_ids, mode=mode, per_run_cap_usd=per_run_cap_usd
        )
    except ValueError as e:  # pydantic ValidationError is a ValueError subclass
        raise LocalRunError(str(e), code="input") from e
    try:
        # "all" narrows to the probes this target can run, before any key or cost check.
        requested = api._resolve_request_probe_ids(req, target_obj)
    except HTTPException as e:
        raise LocalRunError(str(e.detail), code="input") from e
    if (unknown := api.unknown_probe_ids(requested)):
        raise LocalRunError(unknown, code="usage")

    # Assertion-backed probes are decided from evidence and never call the judge.
    # Without a judge key the judged ones are reported as skipped and the rest run.
    by_id = {p.id: p for p in load_probe_library(api.PROBES_DIR)}
    judged = requested if mode == "deep" else [pid for pid in requested if not by_id[pid].assertions]
    skipped: list[dict] = []
    err = llm.credential_error(cfg) if judged else None
    if err:
        runnable = [pid for pid in requested if pid not in set(judged)]
        # Deep mode needs the attacker LLM for every probe; an all-skipped run would exit 0 untested.
        if mode == "deep" or not runnable:
            n = len(requested)
            head = "the selected probe needs" if n == 1 else f"all {n} selected probes need"
            raise LocalRunError(f"{head} an LLM judge: {err}", code="config")
        reason = f"{NO_JUDGE_KEY}: {cfg.missing_credential()} is not set; this probe needs an LLM judge"
        skipped = [api.finding_dict(skipped_finding(by_id[pid], reason)) for pid in judged]
        requested, judged = runnable, []
    req = req.model_copy(update={"probe_ids": requested})

    try:
        api._COST_METER.check_or_abort_pre_run(
            probe_ids=requested,
            target_kind=api._resolve_target_kind(target),
            total_exchanges=api._judged_exchanges(req, requested),
            deep=mode == "deep",
            per_run_cap_override=per_run_cap_usd,
        )
    except CostExceededError as e:
        raise LocalRunError(_cost_message(e), code="cost") from e

    if judged and cfg.provider == llm.PROVIDER_LITELLM:
        yield {
            "type": "warning",
            "message": (
                f"Judge model {cfg.fast_model} is not one Argus ships with. Small models miss "
                "many jailbreaks (in JailbreakBench, a 7B judge missed 61%), so a clean report "
                "from this judge is weak evidence."
            ),
        }

    emitted: list[dict] = []
    for finding in skipped:
        emitted.append(finding)
        yield finding
    probes = api._run_probes(req, anthropic_api_key)
    try:
        while True:
            # browser_use targets serve their trap page from this process. The flag is
            # set per step so it never stays set in the caller across our yield.
            with local_browser_mode():
                try:
                    finding = await probes.__anext__()
                except StopAsyncIteration:
                    break
            emitted.append(finding)
            yield finding
    except CostExceededError as e:
        # Raised by cost_meter.record() once the run is underway. Other mid-run
        # exceptions propagate unchanged for the CLI to report.
        raise LocalRunError(str(e), code="cost") from e
    except TargetUnreachableError as e:
        raise LocalRunError(str(e), code="unreachable") from e
    finally:
        await probes.aclose()
    yield {
        "type": "coverage",
        "coverage": build_coverage(load_probe_library(api.PROBES_DIR), emitted),
    }


def _cost_message(e: CostExceededError) -> str:
    """The meter's reason, plus the --per-run-cap value that would let the run start."""
    estimate = getattr(e, "estimated_usd", None)
    if estimate is None:
        return str(e)
    fit = math.ceil(estimate * 100) / 100  # next cent up, so the suggested cap is never short
    return f"{e}; rerun with --per-run-cap {fit:.2f} or select fewer probes"
