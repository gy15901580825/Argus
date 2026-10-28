"""argus-probe report — render the report of a run stored on a server."""

import click

from argus.cli import api_client
from argus.cli.cmd_run import _check_out_dir, _write_report


@click.command()
@click.option("--run-id", required=True)
@click.option("--format", "report_format", type=click.Choice(["html", "sarif", "junit"]), default="html")
@click.option("--out", "out_file", type=click.Path(), required=True)
@click.option("--token", envvar="ARGUS_API_TOKEN", required=True)
@click.option("--api-url", envvar="ARGUS_API_URL", required=True, help="Base URL of a server implementing the /api/v1/redteam API (or env ARGUS_API_URL).")
def cmd_report(run_id: str, report_format: str, out_file: str, token: str, api_url: str):
    """Read a run from a server implementing the /api/v1/redteam API and write its report to disk."""
    _check_out_dir(out_file)
    report = api_client.get_report(api_url, token, run_id, report_format)
    _write_report(out_file, report)
    click.echo(f"Wrote {report_format} report for run {run_id} to {out_file}")
