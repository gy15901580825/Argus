"""FastAPI sub-router for redteam runs (called by api_service).

Auth: this endpoint has no authentication. api_service is the only v0 caller
and lives on the same cluster network; per-tenant isolation arrives in M3+.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict
from pathlib import Path
from typing import Any, AsyncIterator

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from orchestrator.redteam import llm
from orchestrator.redteam.coverage import build_coverage
from orchestrator.redteam.cost_meter import CostMeter
from orchestrator.redteam.judge import Judge
from orchestrator.redteam.probe import load_all_probes
from orchestrator.redteam.persona_strategy import (
    DEFAULT_DEEP_PAIRS,
    DEFAULT_MAX_ROUNDS,
    build_deep_probes,
)
from orchestrator.redteam.persona_loader import default_personas, default_strategies
from orchestrator.redteam.runner import Runner
from orchestrator.redteam.suites import derive_suites
from orchestrator.redteam.targets import build_target


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


def _resolve_probe_ids(probe_ids: list[str]) -> list[str]:
    """Empty probe_ids list means 'run every probe in the library'.

    The CLI sends [] when the user passes --probes all, by historical
    convention. Without this resolution every loaded probe would be
    filtered out by the `not in requested` check below, causing the run
    to silently complete with zero findings.
    """
    if probe_ids:
        return probe_ids
    return [p.id for p in load_all_probes(PROBES_DIR)]


def _resolve_suite(suite: str) -> list[str]:
    """Suite id → its probe ids. Raises 422 on an unknown id, listing the valid ones."""
    suites = derive_suites(load_all_probes(PROBES_DIR))
    if suite not in suites:
        raise HTTPException(
            status_code=422,
            detail=f"unknown suite {suite!r}; valid suites: {sorted(suites)}",
        )
    return suites[suite]


def _resolve_request_probe_ids(req: RunRequest) -> list[str]:
    """Resolve `suite` / `probe_ids` to a concrete probe id list.

    The two are mutually exclusive: an empty probe_ids means "the whole
    library" (CLI convention), so a suite request must not carry one.
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
        return _resolve_suite(req.suite)
    return _resolve_probe_ids(req.probe_ids)


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
    by_id = {p.id: p for p in load_all_probes(PROBES_DIR)}
    # An id the library doesn't know runs nothing, but counting it as one
    # exchange keeps the estimate conservative rather than optimistic.
    return sum(len(by_id[pid].prompts) if pid in by_id else 1 for pid in probe_ids)


def _judged_exchanges(req: RunRequest, probe_ids: list[str]) -> int:
    """Of those exchanges, how many actually call the judge.

    An assertion-backed probe is decided from evidence and never reaches the
    judge, so billing it for a judge call would over-estimate the run and reject
    scans that cost nothing to judge.
    """
    if req.mode == "deep":
        return _estimate_exchanges(req, probe_ids)
    by_id = {p.id: p for p in load_all_probes(PROBES_DIR)}
    return sum(
        len(by_id[pid].prompts) if pid in by_id else 1
        for pid in probe_ids
        if not (pid in by_id and by_id[pid].assertions)
    )


async def _run_probes(req: RunRequest, anthropic_api_key: str) -> AsyncIterator[dict]:
    # build_target() validates the dict and selects the right adapter — C1 fix.
    target = build_target(req.target)
    judge = Judge(api_key=anthropic_api_key, cost_meter=_COST_METER)
    runner = Runner(target=target, judge=judge, rubrics_dir=RUBRICS_DIR)

    requested = set(_resolve_request_probe_ids(req))
    selected = [p for p in load_all_probes(PROBES_DIR) if p.id in requested]

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

    for probe in to_run:
        async for finding in runner.run_probe(probe):
            # asdict() recurses dataclasses but does NOT convert UUIDs/datetimes.
            # When adding Finding fields, ensure they're JSON-serializable here.
            d = asdict(finding)
            d["id"] = str(finding.id)
            d["probed_at"] = finding.probed_at.isoformat()
            d["created_at"] = finding.created_at.isoformat()
            yield d


@router.post("/run/preflight", status_code=200)
async def preflight(req: RunRequest):
    """Lightweight cost-cap check — no probe execution.

    api_service calls this synchronously before creating the DB row so it can
    surface a 402 to the caller.  Returns 200 {} on pass, 402 on cost exceeded.
    """
    if not isinstance(req.target, dict):
        raise HTTPException(status_code=422, detail="target must be a JSON object")
    try:
        # Validate target dict is buildable before we run cost math — C1 fix.
        build_target(req.target)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    # 422s on suite/probe_ids conflict or unknown suite id, before any cost math.
    requested = _resolve_request_probe_ids(req)

    try:
        from orchestrator.redteam.cost_meter import CostExceededError
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
    try:
        cfg = llm.resolve_config()
    except ValueError as e:
        raise HTTPException(status_code=500, detail=str(e))
    if cfg.provider == llm.PROVIDER_ANTHROPIC and not anthropic_api_key:
        raise HTTPException(
            status_code=500,
            detail="ANTHROPIC_API_KEY not set in orchestrator env "
                   "(REDTEAM_MODEL_PROVIDER=anthropic). Set the key, or set "
                   "REDTEAM_MODEL_PROVIDER=azure to run the judge on Azure OpenAI.",
        )

    if not isinstance(req.target, dict):
        raise HTTPException(status_code=422, detail="target must be a JSON object")
    try:
        build_target(req.target)  # validate early; actual target rebuilt inside _run_probes
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    # 422s on suite/probe_ids conflict or unknown suite id, before SSE streaming starts.
    requested = _resolve_request_probe_ids(req)

    # Pre-run cost check (Plan 4 T7) — happens before SSE streaming starts.
    try:
        from orchestrator.redteam.cost_meter import CostExceededError
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
                "coverage": build_coverage(load_all_probes(PROBES_DIR), emitted),
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
    from orchestrator.redteam.probe import load_all_probes
    probes = list(load_all_probes(PROBES_DIR))
    return {"probe_ids": [p.id for p in probes]}


@router.get("/suites")
async def list_suites() -> dict:
    """Returns the suites derived from the loaded probes' standards mappings.

    Suites with no probes are omitted, so every key here is runnable via
    RunRequest.suite.
    """
    return {"suites": derive_suites(load_all_probes(PROBES_DIR))}


@router.get("/coverage")
async def coverage() -> dict:
    """What the probe library can and cannot speak to, per standard.

    Deliberately findings-free and free of charge: a prospect must be able to
    ask what we cover before paying for a scan.
    """
    return {"coverage": build_coverage(load_all_probes(PROBES_DIR))}
