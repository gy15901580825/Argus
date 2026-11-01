"""FastAPI sub-router for redteam runs (called by a server implementing the
/api/v1/redteam API).

Auth: the router itself does not authenticate callers. argus.server adds a
bearer-token check (ARGUS_SERVER_TOKEN) when it mounts the router; any other
server that mounts it must authenticate callers itself.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
from dataclasses import asdict
from pathlib import Path
from typing import Any, AsyncIterator

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from argus import llm, remediation
from argus.coverage import build_coverage, build_summary
from argus.cost_meter import CostExceededError, CostMeter
from argus.judge import Judge
from argus.probe import load_probe_library
from argus.persona_strategy import (
    DEFAULT_DEEP_PAIRS,
    DEFAULT_MAX_ROUNDS,
    build_deep_probes,
)
from argus.persona_loader import default_personas, default_strategies
from argus.runner import NOT_STARTED_AT_CAP, VERDICT_ABORTED, Runner, aborted_finding
from argus.suites import derive_suites
from argus.targets import build_target

router = APIRouter(prefix="/redteam", tags=["redteam"])

PROBES_DIR = Path(__file__).parent / "probes"

_VALID_MODES = frozenset({"static", "deep"})
RUBRICS_DIR = Path(__file__).parent / "rubrics"
DAILY_CAP_USD = float(os.environ.get("REDTEAM_DAILY_CAP_USD", "13.50"))  # ~$400/month
# Process-level meter — single tenant for v0; per-customer meters arrive in M3+.
_COST_METER = CostMeter(daily_cap_usd=DAILY_CAP_USD)


class RunRequest(BaseModel):
    # Raw dict — build_target() factory validates and constructs the right spec/target.
    # Accepts all 5 adapter kinds: openai_compat, anthropic_native, custom_http, grpc, browser_use.
    target: dict[str, Any]
    probe_ids: list[str] = []
    # Auto-derived suite id (see suites.py / GET /redteam/suites). Mutually
    # exclusive with a non-empty probe_ids — supplying both is a 422.
    suite: str | None = None
    # "static" (default) runs each probe's fixed prompts. "deep" wraps each selected
    # probe in persona x strategy multi-turn threads — far more expensive, so it
    # requires an explicit probe selection (see _resolve_request_probe_ids).
    mode: str = "static"
    deep_pairs: int = DEFAULT_DEEP_PAIRS
    # Caller-supplied per-run cost cap (overrides singleton default when present).
    per_run_cap_usd: float | None = None


def _resolve_target_kind(target: Any) -> str:
    """Extract 'kind' from target dict, defaulting to 'openai_compat'."""
    if isinstance(target, dict):
        return target.get("kind", "openai_compat")
    return "openai_compat"


def compatible_probe_ids(target_obj: Any) -> list[str]:
    """Library probes this built target can run; the runner would skip the rest.

    Same two skip rules as Runner.run_probe: the target class (no declared classes
    on either side means compatible) and conversation history. Reads the instance,
    because testbed_agent sets its classes per spec and its history per inner target.
    """
    classes = getattr(target_obj, "compatible_classes", frozenset())
    history = getattr(target_obj, "supports_history", False)
    return [
        p.id
        for p in load_probe_library(PROBES_DIR)
        if (not classes or not p.target_class or set(p.target_class) & classes)
        and (
            history
            or not getattr(p, "needs_history", getattr(p, "conversation", False))
        )
    ]


def _resolve_probe_ids(probe_ids: list[str], target_obj: Any = None) -> list[str]:
    """Empty probe_ids list means 'run every probe in the library'.

    The CLI sends [] when the user passes --probes all, by historical
    convention. Without this resolution every loaded probe would be
    filtered out by the `not in requested` check below, causing the run
    to silently complete with zero findings. With the built target, "all"
    means every probe that target can run.
    """
    if probe_ids:
        return probe_ids
    if target_obj is not None:
        return compatible_probe_ids(target_obj)
    return [p.id for p in load_probe_library(PROBES_DIR)]


def unknown_probe_ids(probe_ids: list[str]) -> str | None:
    """The error message for ids the library does not have, or None.

    `_run_probes` drops ids it cannot find, so a typo would run nothing and
    still report a completed, clean run.
    """
    known = {p.id for p in load_probe_library(PROBES_DIR)}
    unknown = [pid for pid in dict.fromkeys(probe_ids) if pid not in known]
    if not unknown:
        return None
    return f"unknown probe id(s): {', '.join(unknown)}; run `argus-probe list-probes` to see the valid ids"


def _resolve_suite(suite: str) -> list[str]:
    """Suite id → its probe ids. Raises 422 on an unknown id, listing the valid ones."""
    suites = derive_suites(load_probe_library(PROBES_DIR))
    if suite not in suites:
        raise HTTPException(
            status_code=422,
            detail=f"unknown suite {suite!r}; valid suites: {sorted(suites)}",
        )
    return suites[suite]


def _resolve_request_probe_ids(req: RunRequest, target_obj: Any = None) -> list[str]:
    """Resolve `suite` / `probe_ids` to a concrete probe id list.

    The two are mutually exclusive: an empty probe_ids means "the whole
    library" (CLI convention), so a suite request must not carry one.
    `target_obj` narrows "the whole library" to the probes that target can run.
    """
    if req.mode not in _VALID_MODES:
        raise HTTPException(
            status_code=422,
            detail=f"unknown mode {req.mode!r}; valid modes: {sorted(_VALID_MODES)}",
        )
    # Deep mode must never run the whole library. At ~$0.39/probe worst case it
    # would cost roughly $65 across 167 probes and abort partway, leaving a partial
    # report. Failing up front reads as a budget constraint; a mid-run abort reads
    # as a broken product.
    if req.mode == "deep" and req.suite is None and not req.probe_ids:
        raise HTTPException(
            status_code=422,
            detail=(
                "mode=deep requires an explicit probe selection (probe_ids or suite). "
                "Deep mode runs multi-turn persona x strategy threads per probe and "
                "cannot be run across the whole library within the per-run cost cap."
            ),
        )
    if req.suite is not None:
        if req.probe_ids:
            raise HTTPException(
                status_code=422,
                detail="probe_ids and suite are mutually exclusive — supply exactly one",
            )
        ids = _resolve_suite(req.suite)
    else:
        ids = _resolve_probe_ids(req.probe_ids, target_obj)
    if not ids:
        # Never hand [] on: it means "all" again downstream.
        raise HTTPException(
            status_code=422,
            detail=f"no probe in the library fits target kind {_resolve_target_kind(req.target)}",
        )
    if req.mode == "deep":
        phased = [
            p.id
            for p in load_probe_library(PROBES_DIR)
            if p.id in ids and getattr(p, "is_phased", False)
        ]
        if phased:
            raise HTTPException(
                422,
                "deep mode cannot run paired-run probes (sessions/control/trials): "
                + ", ".join(phased),
            )
    return ids


def _estimate_exchanges(req: RunRequest, probe_ids: list[str]) -> int:
    """Worst-case attack exchanges (one prompt sent + judged) the run will make.

    A probe is not an exchange. `_run_static` sends every prompt the probe
    declares, and deep mode expands each probe into `deep_pairs` threads of up to
    DEFAULT_MAX_ROUNDS rounds. Estimating one exchange per probe understated a
    deep run by ~60x, so the pre-run gate — the component whose only job is to
    refuse a run before money is spent — waved it through.

    Deep threads stop on the first `fail` verdict, so the deep number is a
    ceiling. That is the right side to err on for a gate.
    """
    if req.mode == "deep":
        return len(probe_ids) * max(1, req.deep_pairs) * DEFAULT_MAX_ROUNDS
    by_id = {p.id: p for p in load_probe_library(PROBES_DIR)}
    # An id the library doesn't know runs nothing, but counting it as one
    # exchange keeps the estimate conservative rather than optimistic.
    return sum(
        (
            getattr(by_id[pid], "exchange_count", len(by_id[pid].prompts))
            if pid in by_id
            else 1
        )
        for pid in probe_ids
    )


def _judged_exchanges(req: RunRequest, probe_ids: list[str]) -> int:
    """Of those exchanges, how many actually call the judge.

    An assertion-backed probe is decided from evidence and never reaches the
    judge, so billing it for a judge call would over-estimate the run and reject
    scans that cost nothing to judge. A hybrid probe judges when its evidence is clean.
    """
    if req.mode == "deep":
        return _estimate_exchanges(req, probe_ids)
    by_id = {p.id: p for p in load_probe_library(PROBES_DIR)}
    return sum(
        (
            getattr(by_id[pid], "exchange_count", len(by_id[pid].prompts))
            if pid in by_id
            else 1
        )
        for pid in probe_ids
        if pid not in by_id or by_id[pid].needs_judge
    )


async def _run_probes(req: RunRequest, anthropic_api_key: str) -> AsyncIterator[dict]:
    # build_target() validates the dict and selects the right adapter — C1 fix.
    target = await asyncio.to_thread(build_target, req.target)
    # Released however the run ends: normally, on a raise, or when the consumer
    # closes this generator early (run_local's probes.aclose()). Plugin targets
    # need not subclass Target, so aclose is optional like the runner's hooks.
    try:
        judge = Judge(api_key=anthropic_api_key, cost_meter=_COST_METER)
        runner = Runner(target=target, judge=judge, rubrics_dir=RUBRICS_DIR)

        requested = set(_resolve_request_probe_ids(req, target))
        selected = [p for p in load_probe_library(PROBES_DIR) if p.id in requested]

        if req.mode == "deep":
            personas, strategies = default_personas(), default_strategies()
            to_run = [
                dp
                for base in selected
                for dp in build_deep_probes(
                    base, personas, strategies, deep_pairs=req.deep_pairs
                )
            ]
        else:
            to_run = selected

        # Once a cap is hit, no further probe or deep thread starts: each remaining one is
        # reported as aborted_cost without another paid call, then the caller sees why.
        cap_hit: CostExceededError | None = None
        for probe in to_run:
            if cap_hit is not None:
                yield finding_dict(
                    aborted_finding(
                        probe,
                        f"{NOT_STARTED_AT_CAP}: the run had stopped at the cost cap ({cap_hit})",
                    ),
                    probe,
                )
                continue
            emitted_for_probe = False
            try:
                async for finding in runner.run_probe(probe):
                    emitted_for_probe = True
                    yield finding_dict(finding, probe)
                    # An iterative thread reports the cap as aborted_cost instead of raising.
                    if finding.verdict == VERDICT_ABORTED and cap_hit is None:
                        m = re.match(
                            r"cost cap hit at round \d+: (.*)", finding.reasoning, re.S
                        )
                        cap_hit = CostExceededError(
                            m.group(1) if m else finding.reasoning
                        )
            except CostExceededError as e:
                if not emitted_for_probe:
                    yield finding_dict(
                        aborted_finding(probe, f"cost cap reached: {e}"), probe
                    )
                cap_hit = e
        if cap_hit is not None:
            raise cap_hit
    finally:
        close = getattr(target, "aclose", None)
        if close is not None:
            await close()


def finding_dict(finding, probe) -> dict:
    """A Finding as the JSON-ready dict every run path emits, with the probe's remediation."""
    # asdict() recurses dataclasses but does NOT convert UUIDs/datetimes.
    # When adding Finding fields, ensure they're JSON-serializable here.
    d = asdict(finding)
    d["remediation"] = remediation.for_probe(probe)
    d["id"] = str(finding.id)
    d["probed_at"] = finding.probed_at.isoformat()
    d["created_at"] = finding.created_at.isoformat()
    return d


@router.post("/run/preflight", status_code=200)
async def preflight(req: RunRequest):
    """Lightweight cost-cap check — no probe execution.

    The calling server runs this before it records the run, so it can
    surface a 402 to its caller.  Returns 200 {} on pass, 402 on cost exceeded.
    """
    if not isinstance(req.target, dict):
        raise HTTPException(status_code=422, detail="target must be a JSON object")
    try:
        # Validate target dict is buildable before we run cost math — C1 fix.
        # Off the event loop: building renders the spec's templates once.
        target_obj = await asyncio.to_thread(build_target, req.target)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    # 422s on suite/probe_ids conflict or unknown suite id, before any cost math.
    requested = _resolve_request_probe_ids(req, target_obj)
    if unknown := unknown_probe_ids(requested):
        raise HTTPException(status_code=422, detail=unknown)

    try:
        from argus.cost_meter import CostExceededError

        kind = _resolve_target_kind(req.target)
        # Honor caller-supplied cap when present — C2 fix; I2 fix (kind from dict).
        # Resolve [] → full library so cost estimate reflects real run scope.
        _COST_METER.check_or_abort_pre_run(
            probe_ids=requested,
            target_kind=kind,
            total_exchanges=_judged_exchanges(req, requested),
            deep=req.mode == "deep",
            per_run_cap_override=req.per_run_cap_usd,
        )
    except CostExceededError as e:
        raise HTTPException(status_code=402, detail=str(e))
    return {}


@router.post("/run")
async def run(req: RunRequest):
    # Credential requirements follow the configured provider — an Azure-primary
    # deployment must not be blocked for lacking an Anthropic key. Fallback being
    # enabled makes the *other* provider's credential desirable but not mandatory;
    # llm.complete() surfaces a missing one as AllProvidersFailed at call time.
    anthropic_api_key = os.environ.get("ANTHROPIC_API_KEY")
    # Input errors first: a typo'd probe id must be named even on a server with no key.
    if unknown := unknown_probe_ids(req.probe_ids):
        raise HTTPException(status_code=422, detail=unknown)
    try:
        cfg = llm.resolve_config()
    except ValueError as e:
        raise HTTPException(status_code=500, detail=str(e))
    err = llm.credential_error(cfg)
    if err:
        raise HTTPException(status_code=500, detail=err)
    if (
        req.mode == "deep"
        and cfg.provider == llm.PROVIDER_JEV
        and llm.explain_config(cfg) is None
    ):
        raise HTTPException(status_code=500, detail=llm.NEEDS_TEXT_MODEL)

    if not isinstance(req.target, dict):
        raise HTTPException(status_code=422, detail="target must be a JSON object")
    try:
        # Validate early, off the event loop (building renders the spec's templates once);
        # the actual target is rebuilt inside _run_probes.
        target_obj = await asyncio.to_thread(build_target, req.target)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    # 422s on suite/probe_ids conflict or unknown suite id, before SSE streaming starts.
    requested = _resolve_request_probe_ids(req, target_obj)

    # Pre-run cost check (Plan 4 T7) — happens before SSE streaming starts.
    try:
        from argus.cost_meter import CostExceededError

        kind = _resolve_target_kind(req.target)
        # Resolve [] → full library so cost estimate reflects real run scope.
        _COST_METER.check_or_abort_pre_run(
            probe_ids=requested,
            target_kind=kind,
            total_exchanges=_judged_exchanges(req, requested),
            deep=req.mode == "deep",
            per_run_cap_override=req.per_run_cap_usd,
        )
    except CostExceededError as e:
        raise HTTPException(status_code=402, detail=str(e))

    async def _sse() -> AsyncIterator[bytes]:
        emitted: list[dict] = []
        try:
            async for finding_dict in _run_probes(req, anthropic_api_key):
                emitted.append(finding_dict)
                yield f"data: {json.dumps(finding_dict)}\n\n".encode()
            coverage_event = {
                "type": "coverage",
                "coverage": build_coverage(load_probe_library(PROBES_DIR), emitted),
                "summary": build_summary(emitted),
            }
            yield f"data: {json.dumps(coverage_event)}\n\n".encode()
            yield b"event: end\ndata: {}\n\n"
        except Exception as exc:
            payload = json.dumps({"detail": str(exc), "type": type(exc).__name__})
            yield f"event: error\ndata: {payload}\n\n".encode()

    return StreamingResponse(_sse(), media_type="text/event-stream")


@router.get("/probes")
async def list_probes() -> dict:
    """Returns list of probe ids the orchestrator currently has loaded."""
    probes = load_probe_library(PROBES_DIR)
    return {"probe_ids": [p.id for p in probes]}


@router.get("/suites")
async def list_suites() -> dict:
    """Returns the suites derived from the loaded probes' standards mappings.

    Suites with no probes are omitted, so every key here is runnable via
    RunRequest.suite.
    """
    return {"suites": derive_suites(load_probe_library(PROBES_DIR))}


@router.get("/coverage")
async def coverage() -> dict:
    """What the probe library can and cannot speak to, per standard.

    Deliberately findings-free and free of charge: a prospect must be able to
    ask what we cover before paying for a scan.
    """
    return {"coverage": build_coverage(load_probe_library(PROBES_DIR))}
