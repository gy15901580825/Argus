"""argus-probe run — POST a redteam run + poll + write report."""

from __future__ import annotations

import sys
from pathlib import Path

import click
import httpx

from argus_probe import api_client
from argus_probe.target_loader import load_target_spec, TargetLoadError


@click.command()
@click.option("--target", required=True, help="Target spec: JSON object (inline) or path to JSON file.")
@click.option("--probes", "probe_ids", required=True, help="Comma-separated probe ids OR 'all'.")
@click.option("--format", "report_format", type=click.Choice(["html", "sarif", "junit"]), default="html")
@click.option("--out", "out_file", type=click.Path(), required=True, help="Output report file path.")
@click.option("--token", envvar="ARGUS_API_TOKEN", required=True, help="Your Argus API token (or env ARGUS_API_TOKEN).")
@click.option("--api-url", envvar="ARGUS_API_URL", required=True, help="Argus API base URL (or env ARGUS_API_URL).")
@click.option("--max-wait", type=float, default=1800.0, help="Max seconds to wait for run completion.")
@click.option("--per-run-cap", "per_run_cap", type=float, default=None, help="Maximum USD cost for this run (server enforces). Default: server-side default ($0.50).")
def cmd_run(target: str, probe_ids: str, report_format: str, out_file: str, token: str, api_url: str, max_wait: float, per_run_cap: float | None):
    """Submit a red-team run and write the report to disk."""
    try:
        spec = load_target_spec(target)
    except TargetLoadError as e:
        click.echo(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    tokens = [s.strip() for s in probe_ids.split(",") if s.strip()]
    if "all" in tokens:
        # Silently dropping `all` from a mixed list would run a fraction of the
        # intended probes while the run still looks successful — the worst
        # outcome for a security gate. Refuse instead.
        if len(tokens) > 1:
            raise click.UsageError("'all' cannot be combined with specific probe ids")
        # Empty probe_ids means "all" per orchestrator convention.
        tokens = []

    body = {
        "target": spec,
        "probe_ids": tokens,
    }
    if per_run_cap is not None:
        body["per_run_cap_usd"] = per_run_cap

    click.echo(f"Submitting run to {api_url}/api/v1/redteam/runs ...")
    try:
        resp = api_client.post_run(api_url, token, body=body)
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 402:
            try:
                detail = e.response.json().get("detail", "cost cap exceeded")
            except Exception:
                detail = "cost cap exceeded"
            click.echo(f"Argus rejected run for cost: {detail}", file=sys.stderr)
            sys.exit(402)
        raise
    run_id = resp["run_id"]
    click.echo(f"  run_id: {run_id}")

    click.echo("Polling until completion...")
    run = api_client.poll_until_complete(api_url, token, run_id, max_wait=max_wait)
    click.echo(f"  status: {run['status']}, findings: {len(run.get('findings', []))}")

    click.echo(f"Fetching {report_format} report...")
    report = api_client.get_report(api_url, token, run_id, report_format)
    Path(out_file).write_text(report)
    click.echo(f"Wrote report to {out_file}")
