"""argus-probe report: render a local run.json or a server-stored run."""

import json
from pathlib import Path

import click
from jinja2 import TemplateError

from argus.cli import api_client, reports, run_json
from argus.cli.report_format import resolve_report_format
from argus.cli.cmd_run import _check_out_dir, _write_report


def _load_run_record(file: str) -> dict:
    try:
        text = Path(file).read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise click.ClickException(f"--from {file}: cannot read run.json ({exc})") from None
    try:
        record = json.loads(text)
    except ValueError:
        raise click.ClickException(f"--from {file}: invalid JSON") from None

    def invalid(reason: str) -> None:
        raise click.ClickException(f"--from {file}: {reason}")

    if not isinstance(record, dict):
        invalid("run.json must be an object")
    if "schema_version" not in record:
        invalid("missing schema_version")
    if record["schema_version"] != run_json.SCHEMA_VERSION:
        invalid(f"unsupported schema_version; expected {run_json.SCHEMA_VERSION!r}")
    if not isinstance(record.get("id"), str) or not record["id"]:
        invalid("id must be a non-empty string")
    if not isinstance(record.get("status"), str):
        invalid("status must be a string")
    if not isinstance(record.get("target_spec"), dict):
        invalid("target_spec must be an object")
    findings = record.get("findings")
    if not isinstance(findings, list) or any(not isinstance(f, dict) for f in findings):
        invalid("findings must be a list of objects")
    return record


@click.command()
@click.option("--from", "from_file", type=click.Path(), help="Local run.json to re-render offline; mutually exclusive with --run-id.")
@click.option("--run-id", help="Server-stored run id; mutually exclusive with --from.")
@click.option("--format", "report_format", type=click.Choice(["html", "sarif", "junit"]), default="html", show_default=True,
              help="Report format, inferred from --out when omitted.")
@click.option("--out", "out_file", type=click.Path(), required=True)
@click.option("--token", envvar="ARGUS_API_TOKEN", help="API token, required with --run-id (or env ARGUS_API_TOKEN).")
@click.option("--api-url", envvar="ARGUS_API_URL", help="Server base URL, required with --run-id (or env ARGUS_API_URL).")
def cmd_report(from_file: str | None, run_id: str | None, report_format: str, out_file: str,
               token: str | None, api_url: str | None):
    """Write HTML, SARIF or JUnit from a local run.json (--from) or server run (--run-id).

    Exactly one source is required. Local re-rendering makes no network or model calls.
    """
    if (from_file is None) == (run_id is None):
        raise click.UsageError("provide exactly one of --from or --run-id")
    if run_id is not None:
        for flag, value in (("--token", token), ("--api-url", api_url)):
            if not value:
                raise click.UsageError(f"{flag} is required with --run-id")
    report_format = resolve_report_format(report_format, out_file, ("html", "sarif", "junit"))
    _check_out_dir(out_file)
    if from_file is not None:
        record = _load_run_record(from_file)
        render = {"html": reports.render_html, "sarif": reports.render_sarif,
                  "junit": reports.render_junit}[report_format]
        try:
            # run.json is already redacted. Leave exit_code absent: the scan's
            # --fail-on policy is not recorded, so SARIF uses its status fallback.
            report = render(record)
        except (KeyError, TypeError, ValueError, AttributeError, TemplateError):
            raise click.ClickException(f"--from {from_file}: invalid run record for {report_format}") from None
        run_id = record["id"]
    else:
        report = api_client.get_report(api_url, token, run_id, report_format)
    _write_report(out_file, report)
    click.echo(f"Wrote {report_format} report for run {run_id} to {out_file}")
