"""Run probes in this process (`argus-probe run --local`) and render the report."""

from __future__ import annotations

import asyncio
import uuid
from contextlib import nullcontext
from datetime import datetime, timezone
from typing import Iterable, NamedTuple

import click

from argus_transport.cleanup import run_error_detail

from argus.cli import reports, run_json
from argus.cli.baseline_key import baseline_key
from argus.cli.local_baseline import compare_baseline, new_failure_findings
from argus.cli.severity import (
    blocked_warning,
    incomplete_lines,
    judge_skip_line,
    run_exit_code,
)


class StopSignalReceived(Exception):
    def __init__(self, signum: int, target_cleanup: dict | None = None, cleanup_diagnostic: str | None = None):
        super().__init__(signum)
        self.signum = signum
        self.target_cleanup = target_cleanup
        self.cleanup_diagnostic = cleanup_diagnostic


class TargetCleanupIncomplete(Exception):
    pass


def cleanup_lines(report: dict) -> list[str]:
    lines = []
    if not report["complete"]:
        opened = report["open"]
        lines.extend([
            f"Target cleanup incomplete: {len(opened)} item(s) left on the target. Remove them by hand:",
            *(f"[ ] {item['method']} {item['url']} (step {item['step']}, {item['status']})" for item in opened),
        ])
    if leftover := report.get("leftover"):
        lines.extend([
            f"Target resources left on the target: {len(leftover)} item(s). Review them for manual cleanup:",
            *(f"[ ] {name}" for name in leftover),
        ])
    return lines


class LocalRunResult(NamedTuple):
    report: str
    findings: list[dict]
    # The exception that ended the run before every probe ran, and its text for the operator.
    stopped_by: Exception | None = None
    stop_reason: str | None = None
    exit_code: int = 0
    target_cleanup: dict | None = None
    baseline: dict | None = None


def run_local_and_render(
    spec: dict,
    probe_ids: list[str],
    per_run_cap: float | None,
    report_format: str,
    secret_values: Iterable[str] = (),
    fail_on: str | None = None,
    skip_judged: bool = False,
    trials: int | None = None,
    mode: str = "static",
    deep_pairs: int = 3,
    max_rounds: int = 20,
    seed: str | None = None,
    baseline_run: dict | None = None,
) -> LocalRunResult:
    """Run the probes, print one line per finding, return the rendered report and findings.

    Re-raises argus.local.LocalRunError when the run cannot start. A failure after
    findings exist still renders them, with status "incomplete" and `stopped_by` set.
    `secret_values` are masked in every format. A spec with `testbed_url: "local"` runs against
    the bundled testbed, started on 127.0.0.1 for this call only.
    """
    options = run_options(mode, deep_pairs, max_rounds, seed)
    if isinstance(spec, dict) and spec.get("testbed_url") == "local":
        from argus.demo import servers
        from argus.local import check_run

        # A run the engine would refuse (bad spec, no key, over the cap) must not start a testbed.
        check_run(spec, probe_ids, per_run_cap_usd=per_run_cap, skip_judged=skip_judged,
                  **options, **({"trials": trials} if trials is not None else {}))
        env, testbed = servers.local_environment(spec), servers.local_testbed(spec)
    else:
        # Nothing to start, so the demo servers stay unimported.
        env, testbed = None, nullcontext(spec)
    with testbed as resolved:
        if env == "a2a":
            click.echo(
                f"Started the bundled A2A testbed for this run: peers at {resolved['peer_url']}, control at {resolved['testbed_url']} (private, this host only). The agents under test must be able to reach the peer address."
            )
        elif env:
            click.echo(
                f"Started the bundled {servers.LABELS[env]} testbed on {resolved['testbed_url']} for this "
                "run. The agent under test must be able to reach that address."
            )
        return _run_and_render(
            resolved,
            probe_ids,
            per_run_cap,
            report_format,
            secret_values,
            fail_on,
            skip_judged,
            trials,
            baseline_run,
            baseline_key(spec),
            **options,
        )


def run_options(
    mode: str, deep_pairs: int, max_rounds: int, seed: str | None,
) -> dict[str, str | int | None]:
    if mode == "static" and deep_pairs == 3 and max_rounds == 20 and seed is None:
        return {}
    return {"mode": mode, "deep_pairs": deep_pairs, "max_rounds": max_rounds, "seed": seed}


def _run_and_render(
    spec: dict,
    probe_ids: list[str],
    per_run_cap: float | None,
    report_format: str,
    secret_values: Iterable[str],
    fail_on: str | None,
    skip_judged: bool,
    trials: int | None = None,
    baseline_run: dict | None = None,
    target_key: str | None = None,
    mode: str = "static",
    deep_pairs: int = 3,
    max_rounds: int = 20,
    seed: str | None = None,
) -> LocalRunResult:
    from argus.local import LocalRunError, run_local
    from argus_transport.runtime_v2 import TargetRunStopped

    started_at = datetime.now(timezone.utc)
    findings: list[dict] = []
    coverage: dict | None = None
    judge: dict | None = None
    target_cleanup: dict | None = None
    deep: dict | None = None
    cleanup_diagnostic: str | None = None

    async def _consume() -> None:
        nonlocal coverage, judge, target_cleanup, deep, cleanup_diagnostic
        try:
            async for event in run_local(
                spec, probe_ids, per_run_cap_usd=per_run_cap, skip_judged=skip_judged,
                **run_options(mode, deep_pairs, max_rounds, seed),
                **({"trials": trials} if trials is not None else {})
            ):
                if event.get("type") == "estimate":
                    click.echo(f"Estimated judge/attacker cost: ${event['estimated_usd']:.4f}. Target costs are separate.")
                    continue
                if event.get("type") == "deep_run":
                    deep = event["deep"]
                    if deep.get("history") is False and deep.get("threads"):
                        click.echo("The target keeps no conversation, so deep rounds are independent.")
                    continue
                if event.get("type") == "target_cleanup":
                    target_cleanup = event["target_cleanup"]
                    continue
                if event.get("type") == "coverage":
                    coverage = event.get("coverage")
                    continue
                if event.get("type") == "judge":
                    judge = event
                    click.echo(f"Judge: {judge['judge']}")
                    click.echo(judge["disclosure"])
                    continue
                if event.get("type") == "warning":
                    click.echo(f"Warning: {event['message']}", err=True)
                    continue
                findings.append(event)
                click.echo(
                    f"  {event.get('verdict', '?'):<18} {event.get('severity', '?'):<9} {event.get('probe_id', '?')}"
                )
        except BaseException as exc:
            target_cleanup = getattr(exc, "target_cleanup", None) or target_cleanup
            cleanup_diagnostic = getattr(exc, "cleanup_diagnostic", None)
            raise

    async def _with_signals():
        from argus.cli.mcp_sdk import cancel_on_stop_signals

        task = asyncio.create_task(_consume())
        with cancel_on_stop_signals(task) as stopped:
            try:
                await task
            except BaseException:
                if not stopped:
                    raise
            if stopped:
                return StopSignalReceived(stopped[0], target_cleanup, cleanup_diagnostic)

    stopped_by: Exception | None = None
    stop_reason: str | None = None
    stopped = None
    try:
        stopped = asyncio.run(_with_signals())
    except Exception as e:
        # A run that never started (no key, bad spec, over the cap) has nothing to report.
        if isinstance(e, LocalRunError) and not findings:
            raise
        stopped_by = e
        if isinstance(e, LocalRunError):
            stop_reason = str(e)
        elif isinstance(e, TargetRunStopped):
            stop_reason = f"target stopped the run: {run_error_detail(e)}"
        else:
            stop_reason = f"{type(e).__name__}: {run_error_detail(e)}" if run_error_detail(e) else type(e).__name__
        if coverage is None:
            # The engine emits coverage only at the end; build it from what did run.
            from argus.api import PROBES_DIR
            from argus.coverage import build_coverage
            from argus.probe import load_probe_library

            coverage = build_coverage(load_probe_library(PROBES_DIR), findings)

    if isinstance(stopped, StopSignalReceived):
        raise stopped
    if target_cleanup is not None and not target_cleanup["complete"] and stopped_by is None:
        stop_reason = f"target cleanup incomplete: {len(target_cleanup['open'])} item(s) left on the target"
        stopped_by = TargetCleanupIncomplete(stop_reason)

    incomplete = [line.strip() for line in incomplete_lines(findings, stop_reason)]
    notes = list(incomplete)
    if warning := blocked_warning(findings):
        notes.append(warning)
    if skip_note := judge_skip_line(findings):
        notes.append(skip_note)
    if judge:
        notes.append(f"Judged by {judge['judge']}")
    run = {
        "id": str(uuid.uuid4()),
        "status": "incomplete" if incomplete else "completed",
        "started_at": started_at.isoformat(),
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "target_spec": spec,
        "baseline_key": target_key if target_key is not None else baseline_key(spec),
        "coverage": coverage,
        "findings": findings,
    }
    if deep is not None:
        run["deep"] = deep
    if target_cleanup is not None:
        run["target_cleanup"] = target_cleanup
    if judge:
        run["judge"] = judge["record"]
    comparison = compare_baseline(baseline_run, findings) if baseline_run is not None else None
    if comparison is not None:
        run["baseline"] = comparison
        exit_code = (run_exit_code(findings, stopped_by, None)
                     or run_exit_code(new_failure_findings(comparison), None, fail_on))
    else:
        exit_code = run_exit_code(findings, stopped_by, fail_on)
    # SARIF's exitCode; render_json leaves it out of run.json.
    run["exit_code"] = exit_code
    if incomplete:
        run["incomplete_reason"] = "; ".join(incomplete)
    if notes:
        run["notes"] = notes
    if report_format == "json":
        return LocalRunResult(
            run_json.render_json(run, secret_values, include_notes=True),
            findings,
            stopped_by,
            stop_reason,
            exit_code,
            target_cleanup,
            comparison,
        )
    # Same scrub as run.json, so no format can leak what another one masks.
    render = {
        "html": reports.render_html,
        "sarif": reports.render_sarif,
        "junit": reports.render_junit,
    }[report_format]
    return LocalRunResult(
        render(run_json.scrub_run(run, secret_values)),
        findings,
        stopped_by,
        stop_reason,
        exit_code,
        target_cleanup,
        comparison,
    )
