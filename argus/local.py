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
from typing import AsyncIterator, Mapping, NamedTuple

from fastapi import HTTPException

from argus import api, decider, llm
from argus.cost_meter import CostExceededError
from argus.coverage import build_coverage, build_summary
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


class _Plan(NamedTuple):
    req: api.RunRequest
    cfg: llm.LLMConfig
    anthropic_api_key: str | None
    skipped: list[dict]
    warnings: list[str]
    judged: list[str]


def check_run(
    target: dict,
    probe_ids: list[str],
    *,
    mode: str = "static",
    per_run_cap_usd: float | None = None,
    env: Mapping[str, str] | None = None,
    skip_judged: bool = False,
) -> None:
    """Raise LocalRunError when run_local would refuse to start (target, probe ids, key, cost).

    Calls nothing over the network, so a caller can run it before starting anything for the run."""
    _prepare(target, probe_ids, mode=mode, per_run_cap_usd=per_run_cap_usd, env=env, skip_judged=skip_judged)


def _prepare(target, probe_ids, *, mode, per_run_cap_usd, env, skip_judged) -> _Plan:
    env = os.environ if env is None else env

    # Same credential rule as POST /redteam/run: the configured provider decides
    # which key is mandatory.
    try:
        cfg = llm.resolve_config(env)
    except ValueError as e:
        raise LocalRunError(str(e), code="config") from e
    if mode == "deep" and llm.explain_config(cfg) is None and cfg.provider == llm.PROVIDER_JEV:
        # The attacker writes prompts; Jev cannot, and nothing may quietly stand in for it.
        raise LocalRunError(llm.NEEDS_TEXT_MODEL, code="config")
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

    # Assertion-backed probes are decided from evidence and never call the judge (hybrid
    # ones do: needs_judge), and a probe the target cannot run is skipped by the runner,
    # so neither needs a key.
    by_id = {p.id: p for p in load_probe_library(api.PROBES_DIR)}
    fits = set(api.compatible_probe_ids(target_obj))
    runs = requested if mode == "deep" else [pid for pid in requested if pid in fits]
    judged = runs if mode == "deep" else [pid for pid in runs if by_id[pid].needs_judge]
    skipped: list[dict] = []
    warnings: list[str] = []
    missing = llm.missing_text(cfg) if judged else None
    if missing:
        n, m = len(judged), len(runs)
        # Without --skip-judged a missing key refuses the run: skipping silently would let
        # a CI gate pass on a fraction of the probes. Deep mode needs the attacker LLM too.
        if mode == "deep" or not skip_judged or n == m:
            if mode != "deep" and n < m:
                hint = (f"Set a key, or pass --skip-judged to run only the {m - n} "
                        f"probe{'' if m - n == 1 else 's'} decided by deterministic checks.")
            elif skip_judged and mode != "deep":
                hint = "Set a key; --skip-judged would leave nothing to run."
            else:
                hint = "Set a key."
            raise LocalRunError(f"{n} of {m} selected probes need an LLM judge: {missing}. "
                                f"{hint} {_KEY_HELP}", code="config")
        reason = f"{NO_JUDGE_KEY}: {missing}; skipped by --skip-judged"
        skipped = [api.finding_dict(skipped_finding(by_id[pid], reason), by_id[pid]) for pid in judged]
        requested = [pid for pid in requested if pid not in set(judged)]
        judged = []
    elif skip_judged and cfg.missing_credential() is None:
        warnings.append("--skip-judged has no effect: a judge key is set, so every probe runs.")
    req = req.model_copy(update={"probe_ids": requested})

    try:
        api._COST_METER.check_or_abort_pre_run(
            probe_ids=requested,
            target_kind=api._resolve_target_kind(target),
            # A probe the runner will skip for this target sends nothing and calls no judge.
            total_exchanges=api._judged_exchanges(
                req, requested if mode == "deep" else [pid for pid in requested if pid in fits]),
            deep=mode == "deep",
            per_run_cap_override=per_run_cap_usd,
        )
    except CostExceededError as e:
        raise LocalRunError(_cost_message(e), code="cost") from e

    return _Plan(req, cfg, anthropic_api_key, skipped, warnings, judged)


async def run_local(
    target: dict,
    probe_ids: list[str],
    *,
    mode: str = "static",
    per_run_cap_usd: float | None = None,
    env: Mapping[str, str] | None = None,
    skip_judged: bool = False,
) -> AsyncIterator[dict]:
    """Yield events and finding dicts, then one {"type": "coverage", "coverage": dict, "summary": dict} event.

    Before any finding: {"type": "judge", "judge": llm.describe(cfg), "record": llm.judge_record(cfg),
    "disclosure": llm.disclosure(cfg)} when a probe will be judged, then {"type": "warning", "message": str} events.

    skip_judged: without a judge key, report the probes that need the judge as
    skipped and run the rest, instead of refusing the run.
    """
    req, cfg, anthropic_api_key, skipped, warnings, judged = _prepare(
        target, probe_ids, mode=mode, per_run_cap_usd=per_run_cap_usd, env=env, skip_judged=skip_judged)

    if judged:
        yield {"type": "judge", "judge": llm.describe(cfg), "record": llm.judge_record(cfg),
               "disclosure": llm.disclosure(cfg, decider=decider.from_env() is not None)}
    for message in warnings:
        yield {"type": "warning", "message": message}
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
    spent, started = 0.0, False
    try:
        while True:
            # browser_use targets serve their trap page from this process, and the per-run
            # cap holds during the run (issue #15). Both are entered per step, so neither
            # stays set in the caller across our yield, even if the caller stops iterating.
            with local_browser_mode(), api._COST_METER.run_scope(
                "local", deep=mode == "deep", per_run_cap_usd=per_run_cap_usd, spent_usd=spent, resume=started,
            ):
                started = True
                try:
                    finding = await probes.__anext__()
                except StopAsyncIteration:
                    break
                finally:
                    spent = api._COST_METER.spent_in_current_run()
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
        "summary": build_summary(emitted),
    }


_KEY_HELP = ("Judge keys: ANTHROPIC_API_KEY or OPENAI_API_KEY, or choose another judge with "
             "--judge-provider (azure, litellm or jev) and --judge-model (see the README).")


def _cost_message(e: CostExceededError) -> str:
    """The meter's reason, plus a --per-run-cap at or above the estimate."""
    estimate = getattr(e, "estimated_usd", None)
    if estimate is None:
        return str(e)
    fit = math.ceil(estimate * 100) / 100  # next cent up, so the suggested cap is never short
    return f"{e}; rerun with --per-run-cap {fit:.2f} or select fewer probes"
