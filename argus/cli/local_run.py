"""Run probes in this process (`argus-probe run --local`) and render the report."""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from typing import Iterable

import click

from argus.cli import reports, run_json

def run_local_and_render(
    spec: dict, probe_ids: list[str], per_run_cap: float | None, report_format: str,
    secret_values: Iterable[str] = (),
) -> tuple[str, list[dict]]:
    """Run the probes, print one line per finding, return (report_text, findings).

    Re-raises argus.local.LocalRunError when the run cannot start and lets any
    mid-run exception propagate. `secret_values` are masked in every format.
    """
    from argus.local import run_local

    started_at = datetime.now(timezone.utc)
    findings: list[dict] = []
    coverage: dict | None = None

    async def _consume() -> None:
        nonlocal coverage
        async for event in run_local(spec, probe_ids, per_run_cap_usd=per_run_cap):
            if event.get("type") == "coverage":
                coverage = event.get("coverage")
                continue
            if event.get("type") == "warning":
                click.echo(f"Warning: {event['message']}", err=True)
                continue
            findings.append(event)
            click.echo(f"  {event.get('verdict', '?'):<18} {event.get('severity', '?'):<9} {event.get('probe_id', '?')}")

    asyncio.run(_consume())

    run = {
        "id": str(uuid.uuid4()),
        "status": "completed",
        "started_at": started_at.isoformat(),
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "target_spec": spec,
        "coverage": coverage,
        "findings": findings,
    }
    if report_format == "json":
        return run_json.render_json(run, secret_values), findings
    # Same scrub as run.json, so no format can leak what another one masks.
    render = {"html": reports.render_html, "sarif": reports.render_sarif, "junit": reports.render_junit}[report_format]
    return render(run_json.scrub_run(run, secret_values)), findings
