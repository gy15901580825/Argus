"""Run probes in this process (`argus-probe run --local`) and render the report."""
from __future__ import annotations

import asyncio
import uuid
from contextlib import nullcontext
from datetime import datetime, timezone
from typing import Iterable, NamedTuple

import click

from argus.cli import reports, run_json
from argus.cli.severity import blocked_warning, incomplete_lines, judge_skip_line, run_exit_code


class LocalRunResult(NamedTuple):
    report: str
    findings: list[dict]
    # The exception that ended the run before every probe ran, and its text for the operator.
    stopped_by: Exception | None = None
    stop_reason: str | None = None
    exit_code: int = 0


def run_local_and_render(
    spec: dict, probe_ids: list[str], per_run_cap: float | None, report_format: str,
    secret_values: Iterable[str] = (), fail_on: str | None = None, skip_judged: bool = False,
) -> LocalRunResult:
    """Run the probes, print one line per finding, return the rendered report and findings.

    Re-raises argus.local.LocalRunError when the run cannot start. A failure after
    findings exist still renders them, with status "incomplete" and `stopped_by` set.
    `secret_values` are masked in every format. A spec with `testbed_url: "local"` runs against
    the bundled testbed, started on 127.0.0.1 for this call only.
    """
    if isinstance(spec, dict) and spec.get("testbed_url") == "local":
        from argus.demo import servers
        from argus.local import check_run

        # A run the engine would refuse (bad spec, no key, over the cap) must not start a testbed.
        check_run(spec, probe_ids, per_run_cap_usd=per_run_cap, skip_judged=skip_judged)
        env, testbed = servers.local_environment(spec), servers.local_testbed(spec)
    else:
        # Nothing to start, so the demo servers stay unimported.
        env, testbed = None, nullcontext(spec)
    with testbed as resolved:
        if env:
            click.echo(f"Started the bundled {servers.LABELS[env]} testbed on {resolved['testbed_url']} for this "
                       "run. The agent under test must be able to reach that address.")
        return _run_and_render(resolved, probe_ids, per_run_cap, report_format, secret_values, fail_on, skip_judged)


def _run_and_render(
    spec: dict, probe_ids: list[str], per_run_cap: float | None, report_format: str,
    secret_values: Iterable[str], fail_on: str | None, skip_judged: bool,
) -> LocalRunResult:
    from argus.local import LocalRunError, run_local

    started_at = datetime.now(timezone.utc)
    findings: list[dict] = []
    coverage: dict | None = None
    judge: str | None = None

    async def _consume() -> None:
        nonlocal coverage, judge
        async for event in run_local(spec, probe_ids, per_run_cap_usd=per_run_cap, skip_judged=skip_judged):
            if event.get("type") == "coverage":
                coverage = event.get("coverage")
                continue
            if event.get("type") == "judge":
                judge = event["judge"]
                click.echo(f"Judge: {judge}")
                continue
            if event.get("type") == "warning":
                click.echo(f"Warning: {event['message']}", err=True)
                continue
            findings.append(event)
            click.echo(f"  {event.get('verdict', '?'):<18} {event.get('severity', '?'):<9} {event.get('probe_id', '?')}")

    stopped_by: Exception | None = None
    stop_reason: str | None = None
    try:
        asyncio.run(_consume())
    except Exception as e:
        # A run that never started (no key, bad spec, over the cap) has nothing to report.
        if isinstance(e, LocalRunError) and not findings:
            raise
        stopped_by = e
        # LocalRunError text is written for the operator; anything else needs its class name.
        if isinstance(e, LocalRunError):
            stop_reason = str(e)
        else:
            stop_reason = f"{type(e).__name__}: {e}" if str(e) else type(e).__name__
        if coverage is None:
            # The engine emits coverage only at the end; build it from what did run.
            from argus.api import PROBES_DIR
            from argus.coverage import build_coverage
            from argus.probe import load_probe_library

            coverage = build_coverage(load_probe_library(PROBES_DIR), findings)

    incomplete = [line.strip() for line in incomplete_lines(findings, stop_reason)]
    notes = list(incomplete)
    if warning := blocked_warning(findings):
        notes.append(warning)
    if skip_note := judge_skip_line(findings):
        notes.append(skip_note)
    if judge:
        notes.append(f"Judged by {judge}")
    run = {
        "id": str(uuid.uuid4()),
        "status": "incomplete" if incomplete else "completed",
        "started_at": started_at.isoformat(),
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "target_spec": spec,
        "coverage": coverage,
        "findings": findings,
    }
    exit_code = run_exit_code(findings, stopped_by, fail_on)
    # SARIF's exitCode; render_json leaves it out of run.json.
    run["exit_code"] = exit_code
    if incomplete:
        run["incomplete_reason"] = "; ".join(incomplete)
    if notes:
        run["notes"] = notes
    if report_format == "json":
        return LocalRunResult(run_json.render_json(run, secret_values, include_notes=True), findings, stopped_by,
                              stop_reason, exit_code)
    # Same scrub as run.json, so no format can leak what another one masks.
    render = {"html": reports.render_html, "sarif": reports.render_sarif, "junit": reports.render_junit}[report_format]
    return LocalRunResult(render(run_json.scrub_run(run, secret_values)), findings, stopped_by, stop_reason,
                          exit_code)
