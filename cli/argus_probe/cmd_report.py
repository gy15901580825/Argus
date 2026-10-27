"""argus-probe report — render the report of a run stored on a server."""

from pathlib import Path

import click

from argus_probe import api_client


@click.command()
@click.option("--run-id", required=True)
@click.option("--format", "report_format", type=click.Choice(["html", "sarif", "junit"]), default="html")
@click.option("--out", "out_file", type=click.Path(), required=True)
@click.option("--token", envvar="ARGUS_API_TOKEN", required=True)
@click.option("--api-url", envvar="ARGUS_API_URL", required=True, help="Base URL of a server implementing the /api/v1/redteam API (or env ARGUS_API_URL).")
def cmd_report(run_id: str, report_format: str, out_file: str, token: str, api_url: str):
    """Read a run from a server implementing the /api/v1/redteam API and write its report to disk."""
    report = api_client.get_report(api_url, token, run_id, report_format)
    Path(out_file).write_text(report)
    click.echo(f"Wrote {report_format} report for run {run_id} to {out_file}")
