"""Choose a report format without writing one format under another's extension."""
from pathlib import Path

import click
from click.core import ParameterSource

EXTENSIONS = {"html": "html", "sarif": "sarif", "junit": "xml", "json": "json"}


def resolve_report_format(report_format: str, out_file: str | None, formats=EXTENSIONS) -> str:
    inferred = next((fmt for fmt, ext in EXTENSIONS.items()
                     if out_file and Path(out_file).suffix.lower() == f".{ext}"), None)
    if inferred is None:
        return report_format
    explicit = click.get_current_context().get_parameter_source("report_format") != ParameterSource.DEFAULT
    if explicit and report_format != inferred:
        raise click.UsageError(f"--format {report_format} and --out {out_file} disagree: "
                               f"the extension requires --format {inferred}. Change --format or --out.")
    if inferred not in formats:
        raise click.UsageError(f"--out {out_file} requires --format {inferred}, which this command "
                               "does not support. Use run --local --format json for a run.json record.")
    return inferred
