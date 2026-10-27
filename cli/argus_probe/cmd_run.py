"""argus-probe run — POST a redteam run + poll + write report."""

from __future__ import annotations

import sys
from pathlib import Path

import click
import httpx
from click.core import ParameterSource

from argus_probe import api_client, git_context
from argus_probe.baseline_key import baseline_key
from argus_probe.local_run import LocalUnavailable, run_local_and_render
from argus_probe.severity import SEVERITY_ORDER, findings_at_or_above
from argus_probe.target_loader import load_target_spec_with_secrets, TargetLoadError

# Exit codes must fit 0-255; sys.exit(402) surfaced as 146 on Linux and macOS.
EXIT_COST_CAP = 4


@click.command()
@click.option("--target", required=True, help="Target spec: JSON object (inline) or path to JSON file.")
@click.option("--probes", "probe_ids", required=True, help="Comma-separated probe ids OR 'all'.")
@click.option("--format", "report_format", type=click.Choice(["html", "sarif", "junit", "json"]), default="html",
              help="Report format. json writes run.json and needs --local.")
@click.option("--out", "out_file", type=click.Path(), required=True, help="Output report file path.")
@click.option("--token", envvar="ARGUS_API_TOKEN", default=None, help="Your Argus API token (or env ARGUS_API_TOKEN). Not used with --local.")
@click.option("--api-url", envvar="ARGUS_API_URL", default=None, help="Argus API base URL (or env ARGUS_API_URL). Not used with --local.")
@click.option("--max-wait", type=float, default=1800.0, help="Max seconds to wait for run completion. Ignored with --local.")
@click.option("--per-run-cap", "per_run_cap", type=float, default=None, help="Maximum USD cost for this run; enforced before any LLM call in both server and local mode. Default: $0.50.")
@click.option("--fail-on", "fail_on", type=click.Choice(SEVERITY_ORDER), default=None,
              help="Exit 3 when any finding has verdict=fail and severity at or above this level.")
@click.option("--local", "local", is_flag=True, default=False,
              help="Run probes in this process instead of submitting to an Argus API server. Needs the argus-orchestrator package and a judge API key in the environment.")
@click.option("--compare-to", "compare_to", default=None,
              help="Base branch: report and gate only on failures that are new relative to the latest run on it. Server mode only.")
def cmd_run(target: str, probe_ids: str, report_format: str, out_file: str, token: str | None, api_url: str | None, max_wait: float, per_run_cap: float | None, fail_on: str | None, local: bool, compare_to: str | None):
    """Submit a red-team run and write the report to disk."""
    try:
        spec, secret_values = load_target_spec_with_secrets(target)
    except TargetLoadError as e:
        click.echo(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    tokens = [s.strip() for s in probe_ids.split(",") if s.strip()]
    if not tokens:
        # An empty list is the wire convention for "the whole library", so an
        # empty --probes must not fall through to it: `--probes ""` would
        # quietly launch a full sweep the user never asked for.
        raise click.UsageError("--probes needs at least one probe id, or 'all'")
    if "all" in tokens:
        # Silently dropping `all` from a mixed list would run a fraction of the
        # intended probes while the run still looks successful — the worst
        # outcome for a security gate. Refuse instead.
        if len(tokens) > 1:
            raise click.UsageError("'all' cannot be combined with specific probe ids")
        # Empty probe_ids means "all" per orchestrator convention.
        tokens = []

    if local:
        if compare_to:
            raise click.UsageError("--compare-to needs run history on an Argus server; it does not work with --local")
        ctx = click.get_current_context()
        typed = [
            name for name, param in (("--api-url", "api_url"), ("--token", "token"))
            if ctx.get_parameter_source(param) == ParameterSource.COMMANDLINE
        ]
        if typed:
            raise click.UsageError(f"--local runs in this process; do not pass {' or '.join(typed)}")
        _run_locally(spec, tokens, per_run_cap, report_format, out_file, fail_on, secret_values)
        return
    trap = sorted(k for k in spec if k.startswith("trap_")) if spec.get("kind") == "browser_use" else []
    if trap:
        # The trap page is served by the CLI process only under --local.
        raise click.UsageError(f"trap_* options only apply to --local runs; remove {', '.join(trap)} or add --local")
    if report_format == "json":
        # The server's report endpoint has no json format yet.
        raise click.UsageError("--format json needs --local")
    if api_url is None:
        raise click.UsageError("Missing option '--api-url'")
    if token is None:
        raise click.UsageError("Missing option '--token'")

    body = {
        "target": spec,
        "probe_ids": tokens,
    }
    if per_run_cap is not None:
        body["per_run_cap_usd"] = per_run_cap
    body.update(git_context.detect())
    if compare_to and "repo" not in body:
        raise click.UsageError("--compare-to needs the repository name; run inside a git checkout with an origin remote, or set GITHUB_REPOSITORY")
    body["baseline_key"] = baseline_key(spec)

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
            sys.exit(EXIT_COST_CAP)
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
    if run["status"] != "completed":
        click.echo(f"Error: run {run_id} ended with status {run['status']}", file=sys.stderr)
        sys.exit(1)
    if compare_to:
        try:
            d = api_client.get_diff(api_url, token, run_id, compare_to)
        except httpx.HTTPStatusError as e:
            try:
                detail = e.response.json().get("detail", e.response.status_code)
            except Exception:
                detail = e.response.status_code
            click.echo(f"Error: could not compare with {compare_to}: {detail}", file=sys.stderr)
            sys.exit(1)
        base = d.get("base_run_id") or "none (first run on this branch)"
        click.echo(f"Compared with {compare_to} (baseline run {base}): "
                   f"new: {len(d['new'])}, fixed: {len(d['fixed'])}, still failing: {len(d['still_failing'])}, "
                   f"not run: {len(d['not_run'])}")
        for item in d["new"]:
            click.echo(f"  new  {item['severity']:<9} {item['probe_id']}")
        _apply_fail_on([{"verdict": "fail", **i} for i in d["new"]], fail_on)
    else:
        _apply_fail_on(run.get("findings", []), fail_on)


def _apply_fail_on(findings: list[dict], fail_on: str | None) -> None:
    """Exit 3 when findings cross the --fail-on threshold. Report is already on disk."""
    if fail_on is None:
        return
    hits = findings_at_or_above(findings, fail_on)
    if hits:
        ids = ", ".join(sorted({h.get("probe_id", "?") for h in hits}))
        click.echo(
            f"{len(hits)} finding(s) at or above {fail_on}: {ids}",
            file=sys.stderr,
        )
        sys.exit(3)


def _run_locally(spec, tokens, per_run_cap, report_format, out_file, fail_on, secret_values=()) -> None:
    click.echo(f"Running {('all probes' if not tokens else f'{len(tokens)} probe(s)')} locally ...")
    try:
        report, findings = run_local_and_render(spec, tokens, per_run_cap, report_format, secret_values)
    except LocalUnavailable as e:
        click.echo(f"Error: {e}", file=sys.stderr)
        sys.exit(2)
    except Exception as e:  # LocalRunError or a mid-run failure; no traceback for the operator
        code = getattr(e, "code", None)
        if code == "cost":
            click.echo(f"Run rejected for cost: {e}", file=sys.stderr)
            sys.exit(EXIT_COST_CAP)
        click.echo(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    Path(out_file).write_text(report)
    click.echo(f"Wrote report to {out_file}")
    _apply_fail_on(findings, fail_on)
