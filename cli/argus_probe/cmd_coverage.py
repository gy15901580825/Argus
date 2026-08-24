"""argus-probe coverage — show what the probe library covers.

Runs no probes and costs nothing: a prospect must be able to ask what we
cover before paying for a scan. Prints every cell of each standard,
including the empty ones — silently omitting what we do not cover would
invert the point of this command.
"""

import json

import click

from argus_probe import api_client

STANDARDS = ["owasp-llm-top10", "mitre-atlas", "nist-ai-rmf", "eu-ai-act"]


@click.command()
@click.option("--token", envvar="ARGUS_API_TOKEN", required=True)
@click.option("--api-url", envvar="ARGUS_API_URL", required=True, help="Argus API base URL (or env ARGUS_API_URL).")
@click.option("--standard", "standard", type=click.Choice(STANDARDS), default=None,
              help="Show only this standard (default: all).")
@click.option("--json", "as_json", is_flag=True, help="Emit the raw coverage manifest as JSON.")
def cmd_coverage(token: str, api_url: str, standard: str, as_json: bool):
    """Show what the probe library covers, offline — no probes run."""
    coverage = api_client.get_coverage(api_url, token)
    if as_json:
        click.echo(json.dumps(coverage))
        return

    keys = [standard] if standard else STANDARDS
    for key in keys:
        data = coverage["standards"][key]
        click.echo(f"\n{key} ({data['universe']} universe)")
        for cell in data["cells"]:
            name = cell.get("name", "")
            click.echo(
                f"  {cell['id']:<8} {name:<40} {cell['probes_in_library']:>4} probes  {cell['library_status']}"
            )

    totals = coverage["totals"]
    click.echo(f"\n{totals['probes_in_library']} probes in library, {totals['probes_run']} run this scan")
