"""`argus-probe quickstart`: a real report against a bundled demo agent, no API key."""
from __future__ import annotations

import sys

import click

from argus.cli.local_run import run_local_and_render
from argus.demo import bypass_proxy_for_localhost


@click.command("quickstart")
@click.option("--out", default="argus-quickstart.html", show_default=True,
              type=click.Path(dir_okay=False), help="Where to write the HTML report.")
def cmd_quickstart(out: str) -> None:
    """Run 12 MCP probes against a built-in vulnerable demo agent. No API key needed."""
    bypass_proxy_for_localhost()
    from argus.demo.servers import PROBE_IDS, start_mcp_demo

    click.echo("Starting the demo MCP agent and a hostile MCP testbed on 127.0.0.1 (no API key needed) ...")
    try:
        with start_mcp_demo() as spec:
            result = run_local_and_render(spec, list(PROBE_IDS), None, "html", fail_on=None)
            if result.stopped_by is not None:
                raise result.stopped_by
            report, findings = result.report, result.findings
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    with open(out, "w", encoding="utf-8") as f:
        f.write(report)
    n_fail = sum(1 for x in findings if x.get("verdict") == "fail")
    click.echo(f"Wrote report to {out}")
    click.echo(f"{n_fail} of {len(findings)} probes caught the demo agent doing something unsafe.")
    click.echo("The demo agent is deliberately insecure. To test your own agent:")
    click.echo("  argus-probe init")
    click.echo("  argus-probe run --local --target argus-target.json --probes owasp_07_system_prompt_leakage --out report.html")
    click.echo("Judged probes (prompt injection, data leakage, ...) need ANTHROPIC_API_KEY or OPENAI_API_KEY.")
