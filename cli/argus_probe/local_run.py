"""Run probes in this process (`argus-probe run --local`) and render the report."""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone

import click

from argus_probe import reports

_INSTALL_HINT = (
    "local mode needs the argus-orchestrator package: "
    'pip install "argus-probe[local]", or with pipx: pipx install --force "argus-probe[local]"'
)


class LocalUnavailable(RuntimeError):
    """The orchestrator package is not importable."""


def run_local_and_render(
    spec: dict, probe_ids: list[str], per_run_cap: float | None, report_format: str
) -> tuple[str, list[dict]]:
    """Run the probes, print one line per finding, return (report_text, findings).

    Raises LocalUnavailable when the orchestrator package is missing, re-raises
    orchestrator.redteam.local.LocalRunError when the run cannot start, and
    lets any mid-run exception propagate.
    """
    try:
        from orchestrator.redteam.local import run_local
    except ModuleNotFoundError as e:
        if e.name == "orchestrator" or (e.name or "").startswith("orchestrator."):
            raise LocalUnavailable(_INSTALL_HINT) from e
        raise

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
    render = {"html": reports.render_html, "sarif": reports.render_sarif, "junit": reports.render_junit}[report_format]
    return render(run), findings
