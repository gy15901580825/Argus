"""`argus-probe mcp-trap`: point your agent at a hostile MCP server on this machine and report what it did."""
from __future__ import annotations

import asyncio
import signal
import sys
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

import click

from argus.cli import mcp_sdk, reports, run_json
from argus.cli.cmd_run import _apply_fail_on, _check_out_dir, _write_report
from argus.cli.severity import SEVERITY_ORDER
from argus.cli.target_loader import TargetLoadError, load_target_spec_with_secrets
from argus.mcp_trap import wiring
from argus.mcp_trap.trap.scenarios import SCENARIO_NAMES

_EXTENSIONS = {"html": "html", "sarif": "sarif", "junit": "xml", "json": "json"}
_CONTROL_RE = mcp_sdk.CONTROL_RE
_STOP_MESSAGES = mcp_sdk.STOP_MESSAGES
_cancel_on_stop_signals = mcp_sdk.cancel_on_stop_signals
_REFUSED = ("The trap refused {n} requests (Host/Origin/Content-Type check): your agent sent a Host, Origin or "
            "Content-Type header the trap does not accept. Give the agent the trap URL above, or pass the address "
            "the agent uses with --trap-public-url.")


@dataclass(frozen=True)
class _Stopped:
    signum: int


def _parse_scenarios(ctx: click.Context, param: click.Parameter, value: str) -> list[str]:
    tokens = [t.strip() for t in value.split(",") if t.strip()]
    if not tokens:
        raise click.BadParameter("needs at least one scenario name, or 'all'")
    if "all" in tokens:
        if len(tokens) > 1:
            raise click.BadParameter("'all' cannot be combined with scenario names")
        return list(SCENARIO_NAMES)
    unknown = [t for t in tokens if t not in SCENARIO_NAMES]
    if unknown:
        raise click.BadParameter(f"unknown scenario(s): {', '.join(unknown)}; valid: {', '.join(SCENARIO_NAMES)}")
    return list(dict.fromkeys(tokens))


def _sdk_problem() -> str | None:
    return mcp_sdk.sdk_problem("mcp-trap")


async def _drive(trap, chat, probes, rounds, say, mask, wait_s, url):
    from argus.mcp_trap import driver

    if wait_s:
        say(f"Trap is up at {url}. Start or restart your agent now; waiting up to {wait_s} s for it to connect...")
        if await driver.wait_for_agent(trap, wait_s):
            say("Your agent connected; sending the warm-up task ...")
        else:
            say(f"No MCP request reached the trap within {wait_s} s; sending the warm-up task anyway ...")
    warmup = await driver.warm_up(trap, chat, mask=mask)
    if warmup.status != "wired":
        return warmup
    return await driver.run_scenarios(trap, chat, probes, rounds, echo=say, mask=mask)


async def _session(sock, address, chat, probes, rounds, say, mask, wait_s):
    """Serve the trap on `sock` while driving the agent. Returns a Warmup, a TrapRun, or _Stopped."""
    from argus.mcp_trap.trap.server import TrapServer
    from argus.mcp_trap.trap.state import TrapState

    trap = TrapServer(TrapState(), allowed_hosts=address.allowed_hosts)
    async with trap.serving(sock):
        work = asyncio.create_task(_drive(trap, chat, probes, rounds, say, mask, wait_s, address.mcp_url))
        with _cancel_on_stop_signals(work) as stopped:
            try:
                return await work
            except asyncio.CancelledError:
                if not stopped:
                    raise
                return _Stopped(stopped[0])


@click.command("mcp-trap")
@click.option("--target", required=True,
              help="Your agent's chat API: a target spec (JSON object or path) of kind openai_compat, custom_http "
                   "or grpc.")
@click.option("--rounds", type=click.IntRange(1, 20), default=3, show_default=True,
              help="Conversations per scenario.")
@click.option("--scenarios", default="all", show_default=True, callback=_parse_scenarios,
              help=f"'all' or a comma list of: {', '.join(SCENARIO_NAMES)}.")
@click.option("--out", "out_file", type=click.Path(dir_okay=False), default=None,
              help="Report path. Default: argus-mcp-trap-report.<html|sarif|xml|json> by --format.")
@click.option("--format", "report_format", type=click.Choice(list(_EXTENSIONS)), default="html", show_default=True)
@click.option("--fail-on", "fail_on", type=click.Choice(SEVERITY_ORDER), default=None,
              help="Exit 3 when any finding has verdict=fail and severity at or above this level.")
@click.option("--print-config", is_flag=True, default=False,
              help="Print the MCP server entry to add to your agent, then exit. Sends nothing.")
@click.option("--trap-host", default="127.0.0.1", show_default=True, help="IPv4 address the trap listens on.")
@click.option("--trap-port", type=int, default=wiring.DEFAULT_TRAP_PORT, show_default=True,
              help="Port the trap listens on.")
@click.option("--trap-public-url", default="",
              help="URL your agent uses to reach the trap, when it runs on another host "
                   "(e.g. http://192.168.1.20:8765).")
@click.option("--wait-for-agent", "wait_s", type=click.IntRange(0, 3600), default=0, show_default=True,
              metavar="SECONDS",
              help="Start the trap, then wait up to this long for your agent to connect before the warm-up. "
                   "Use it for an agent that connects to MCP servers only at startup.")
def cmd_mcp_trap(target: str, rounds: int, scenarios: list[str], out_file: str | None, report_format: str,
                 fail_on: str | None, print_config: bool, trap_host: str, trap_port: int,
                 trap_public_url: str, wait_s: int) -> None:
    """Point your agent at a hostile MCP server on this machine and report what it did."""
    try:
        address = wiring.TrapAddress(trap_host, trap_port, trap_public_url)
    except wiring.TrapAddressError as e:
        raise click.UsageError(str(e)) from None
    try:
        spec, secret_values = load_target_spec_with_secrets(target)
    except TargetLoadError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    from argus.mcp_trap import driver

    if spec["kind"] not in driver.CHAT_KINDS:
        raise click.UsageError(f"mcp-trap talks to your agent through its chat API; the target kind must be "
                               f"openai_compat, custom_http or grpc, got {spec['kind']!r}")
    if print_config:
        click.echo(wiring.config_entry(address))
        return
    _check_out_dir(out_file)
    problem = _sdk_problem()
    if problem:
        click.echo(problem, err=True)
        sys.exit(2)

    # The same values, masked the same way, as in every report format.
    secrets = run_json.run_secrets(spec, secret_values)

    def mask(text: str) -> str:
        return run_json.mask_text(text, secrets)

    def say(text: str, err: bool = False) -> None:
        click.echo(mask(_CONTROL_RE.sub("", text)), err=err)

    import argus.targets as targets

    try:
        chat = targets.build_target(spec)
    except (ValueError, TypeError) as e:
        say(f"Error: {e}", err=True)
        sys.exit(1)
    probes = driver.load_trap_probes(scenarios)
    try:
        sock = wiring.bind_trap_socket(address)
    except wiring.TrapPortInUse as e:
        click.echo(str(e), err=True)
        sys.exit(2)
    except OSError as e:
        click.echo(f"Error: cannot listen on {address.host}:{address.port}: {e.strerror or e}", err=True)
        sys.exit(2)

    if not wait_s:
        say(f"Trap listening at {address.mcp_url}; sending the warm-up task to your agent ...")
    started_at = datetime.now(timezone.utc)
    try:
        outcome = asyncio.run(_session(sock, address, chat, probes, rounds, say, mask, wait_s))
    except KeyboardInterrupt:
        outcome = _Stopped(signal.SIGINT)
    except Exception as e:  # no traceback for the operator
        say(f"Error: {e}", err=True)
        sys.exit(1)
    finally:
        sock.close()

    if isinstance(outcome, _Stopped):
        say(f"{_STOP_MESSAGES[outcome.signum]}: the run was stopped before it finished; no report was written.",
            err=True)
        sys.exit(128 + outcome.signum)
    if isinstance(outcome, driver.Warmup):
        if outcome.status == "chat_error":
            say(f"Error: could not reach the agent's chat API: {outcome.detail}", err=True)
            sys.exit(1)
        if outcome.status == "refused_only":
            say(_REFUSED.format(n=outcome.detail), err=True)
            sys.exit(2)
        if outcome.status == "stale_only":
            say("The trap only got requests from an MCP session it no longer knows, left over from an earlier "
                "run. Restart your agent so it reconnects, then run this command again.", err=True)
            sys.exit(2)
        say(f"The trap at {address.mcp_url} got no MCP request during the warm-up task. This is expected on a "
            f"first run. Add this MCP server to the agent you are testing:\n\n{wiring.config_entry(address)}",
            err=True)
        sys.exit(2)

    from argus.coverage import build_coverage

    trap_run = outcome
    for note in trap_run.notes:
        say(note)
    run = {
        "id": str(uuid.uuid4()),
        # An inconclusive scenario exits 1 below; the report must not read as a finished run.
        "status": "incomplete" if trap_run.all_inconclusive or trap_run.inconclusive_scenarios else "completed",
        "started_at": started_at.isoformat(),
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "target_spec": spec,
        "coverage": build_coverage(driver.load_trap_probes(SCENARIO_NAMES), trap_run.findings),
        "findings": trap_run.findings,
        "notes": trap_run.notes,
    }
    if report_format == "json":
        report = run_json.render_json(run, secret_values)
    else:
        render = {"html": reports.render_html, "sarif": reports.render_sarif,
                  "junit": reports.render_junit}[report_format]
        # Same scrub as run.json, so no format can leak what another one masks.
        report = render(run_json.scrub_run(run, secret_values))
    out_file = out_file or f"argus-mcp-trap-report.{_EXTENSIONS[report_format]}"
    _write_report(out_file, report, encoding="utf-8", echo=say)
    say(f"Wrote report to {out_file}")

    refused = trap_run.refused_only_requests
    if refused:
        say(_REFUSED.format(n=refused), err=True)
    if trap_run.all_inconclusive:
        # The not-wired message and config entry fit only a run where no round reached the trap.
        talked = trap_run.talked_reason
        if talked == driver.NOT_LISTED:
            say("No round reached a verdict: your agent talked to the trap but did not re-fetch tools after "
                "notifications/tools/list_changed.", err=True)
        elif talked:
            say(f"No round reached a verdict: your agent talked to the trap, but {talked}.", err=True)
        elif refused:
            say("No round reached a verdict.", err=True)
        else:
            say("No round reached a verdict: the agent does not appear to be wired to the trap.\n\n"
                + wiring.config_entry(address), err=True)
        sys.exit(1)
    if trap_run.inconclusive_scenarios:
        say(f"No round of {', '.join(trap_run.inconclusive_scenarios)} reached a verdict, "
            "so those scenarios were not tested.", err=True)
        sys.exit(1)
    _apply_fail_on(trap_run.findings, fail_on)
