"""`argus-probe quickstart`: a real report against a bundled demo agent, no API key."""
from __future__ import annotations

import os
import sys

import click

from argus_probe.local_run import _INSTALL_HINT, run_local_and_render


def _bypass_proxy_for_localhost() -> None:
    # The demo servers are on 127.0.0.1; a proxied shell must not route them out.
    for name in ("NO_PROXY", "no_proxy"):
        current = os.environ.get(name, "")
        hosts = [h.strip() for h in current.split(",") if h.strip()]
        if "127.0.0.1" not in hosts:
            os.environ[name] = f"{current},127.0.0.1" if current else "127.0.0.1"


@click.command("quickstart")
@click.option("--out", default="argus-quickstart.html", show_default=True,
              type=click.Path(dir_okay=False), help="Where to write the HTML report.")
def cmd_quickstart(out: str) -> None:
    """Run 12 MCP probes against a built-in vulnerable demo agent. No API key needed."""
    _bypass_proxy_for_localhost()
    try:
        from orchestrator.redteam.demo.servers import PROBE_IDS, start_mcp_demo
    except ModuleNotFoundError as e:
        if e.name == "orchestrator" or (e.name or "").startswith("orchestrator."):
            click.echo(f"Error: {_INSTALL_HINT}", err=True)
            sys.exit(2)
        raise

    click.echo("Starting the demo MCP agent and a hostile MCP testbed on 127.0.0.1 (no API key needed) ...")
    try:
        with start_mcp_demo() as spec:
            report, findings = run_local_and_render(spec, list(PROBE_IDS), None, "html")
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
