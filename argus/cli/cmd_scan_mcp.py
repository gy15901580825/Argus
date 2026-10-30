"""`argus-probe scan-mcp`: connect to an MCP server, call its tools with inert payloads and report what came back."""
from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import math
import re
import signal
import sys
import urllib.parse
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import click

from argus.cli import reports, run_json
from argus.cli.cmd_run import _apply_fail_on, _check_out_dir, _count_fail_on, _write_report
from argus.cli.judge_options import judge_options
from argus.cli.mcp_sdk import CONTROL_RE, STOP_MESSAGES, cancel_on_stop_signals, sdk_problem
from argus.cli.severity import SEVERITY_ORDER

# Phase A: stdio runs only on the host, and only when asked; the sandbox task replaces this switch.
STDIO_REQUIRES_ON_HOST = True

_EXTENSIONS = {"html": "html", "sarif": "sarif", "junit": "xml", "json": "json"}
_USAGE = ("Give an MCP server URL or a command to start one: scan-mcp <url> [--header 'Name: value']... "
          "or scan-mcp [options] -- <command> [args...]")
_ON_HOST = ("stdio servers need --on-host for now: it runs the server's code on this machine with your privileges. "
            "Use it only for code you trust, or start the server yourself and scan its URL.")
_HOST_NOTE = "Running the server on this machine (--on-host); child processes it starts may outlive the scan."
_HEADER_RE = re.compile(r"\s*([!#$%&'*+.^_`|~0-9A-Za-z-]+)\s*:\s*(\S.*?)\s*")
_EXCERPT_MAX = 100
_SDK_LOGGERS = ("mcp", "client")
_NAMES_SHOWN = 10
_INVENTORY_SHOWN = 20


@dataclass(frozen=True)
class _Stopped:
    signum: int


def _finite(ctx: click.Context, param: click.Parameter, value: float) -> float:
    if not math.isfinite(value):
        raise click.BadParameter("must be a finite number")
    return value


def _parse_call_tools(ctx: click.Context, param: click.Parameter, value: str | None):
    if value is None:
        return None
    tokens = [t.strip() for t in value.split(",") if t.strip()]
    if not tokens:
        raise click.BadParameter("needs at least one tool name, or 'all'")
    if "all" in tokens:
        if len(tokens) > 1:
            raise click.BadParameter("'all' cannot be combined with tool names")
        return "all"
    return frozenset(tokens)


def _parse_headers(ctx: click.Context, param: click.Parameter, values: tuple[str, ...]) -> tuple[tuple[str, str], ...]:
    out = []
    for value in values:
        m = _HEADER_RE.fullmatch(value)
        if m is None:
            # The value may be a credential, so it is not echoed back.
            raise click.BadParameter("each --header must be 'Name: value'")
        out.append((m.group(1), m.group(2)))
    return tuple(out)


def _load_args(ctx: click.Context, param: click.Parameter, value: str | None) -> dict:
    if value is None:
        return {}
    try:
        data = json.loads(Path(value).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as e:
        raise click.BadParameter(f"cannot read JSON from {value}: {e}") from None
    if not isinstance(data, dict) or not all(isinstance(v, dict) for v in data.values()):
        raise click.BadParameter("must be a JSON object mapping each tool name to an object of arguments")
    return data


def _is_http_url(arg: str) -> bool:
    try:
        return urllib.parse.urlsplit(arg).scheme.lower() in ("http", "https")
    except ValueError:
        return False


class _SdkErrors(logging.Handler):
    """Shows the SDK's own errors as one masked line; its warnings quote server text and are dropped."""

    def __init__(self, say) -> None:
        super().__init__(logging.ERROR)
        self._say = say

    def emit(self, record: logging.LogRecord) -> None:
        from argus.mcp_scan import rules

        try:
            text = record.getMessage()
        except Exception:
            text = str(record.msg)
        # The message can quote server text; say() then masks the known secrets.
        self._say(f"MCP SDK error: {' '.join(rules.redact(text).split())}", err=True)


@contextlib.contextmanager
def _sdk_logs(say):
    # Without a handler, logging's last resort prints SDK warnings and their tracebacks, which quote server text.
    # The SDK's client session logs under the bare name "client", outside "mcp".
    handler = _SdkErrors(say)
    saved = [(log, log.propagate) for log in map(logging.getLogger, _SDK_LOGGERS)]
    for log, _ in saved:
        log.addHandler(handler)
        log.propagate = False
    try:
        yield
    finally:
        for log, propagate in saved:
            log.removeHandler(handler)
            log.propagate = propagate


async def _scan(cfg, mask, say):
    from argus.mcp_scan import scan

    work = asyncio.create_task(scan.scan_mcp(cfg, mask=mask, echo=say))
    with cancel_on_stop_signals(work) as stopped:
        try:
            return await work
        except asyncio.CancelledError:
            if not stopped:
                raise
            return _Stopped(stopped[0])


def _console_line(f: dict, clean) -> str:
    ev = f.get("evidence") or {}
    judged = "judged  " if ev.get("decided_by") == "judge" else ""
    # Masked before the cut, so the cut cannot leave part of a secret behind.
    text = " ".join(clean(str(ev.get("excerpt") or f.get("reasoning") or "")).split())
    if len(text) > _EXCERPT_MAX:
        text = text[:_EXCERPT_MAX - 3] + "..."
    return f"  {f.get('severity', '?'):<9} {f.get('probe_id', '?'):<36} {ev.get('tool') or '-'}  {judged}{text}"


@click.command("scan-mcp")
@click.argument("argv", nargs=-1, metavar="URL | -- COMMAND [ARGS]...")
@click.option("--call-tools", "call_tools", default=None, callback=_parse_call_tools, metavar="NAMES|all",
              help="Comma list of tools to call besides the read-only ones, or 'all' (env-like tools only by name).")
@click.option("--args", "tool_args", type=click.Path(dir_okay=False), default=None, callback=_load_args,
              metavar="FILE", help="JSON object of tool name to baseline arguments, for tools that need real values.")
@click.option("--header", "headers", multiple=True, callback=_parse_headers, metavar="'Name: value'",
              help="HTTP only, repeatable: a header a legitimate client sends, such as credentials.")
@click.option("--env", "env_names", multiple=True, metavar="NAME",
              help="stdio only, repeatable: pass this environment variable to the server. Values are masked.")
@click.option("--on-host", is_flag=True, default=False,
              help="stdio only: run the server on this machine with your privileges. Only for code you trust.")
@click.option("--timeout", "timeout_s", type=click.FloatRange(min=1), default=30.0, show_default=True,
              callback=_finite, metavar="SECONDS", help="Per request.")
@click.option("--max-runtime", "max_runtime_s", type=click.FloatRange(min=0, min_open=True), default=1800.0,
              show_default=True, callback=_finite, metavar="SECONDS",
              help="Whole run. Past it no more tool calls are made, and the command exits 1.")
@click.option("--per-run-cap", "per_run_cap", type=click.FloatRange(min=0), default=0.50, show_default=True,
              callback=_finite, metavar="USD", help="Judge spend limit. 0 turns the judge off.")
@click.option("--out", "out_file", type=click.Path(dir_okay=False), default=None,
              help="Report path. Default: argus-mcp-scan-report.<html|sarif|xml|json> by --format.")
@click.option("--format", "report_format", type=click.Choice(list(_EXTENSIONS)), default="html", show_default=True)
@click.option("--fail-on", "fail_on", type=click.Choice(SEVERITY_ORDER), default=None,
              help="Exit 3 when any finding has verdict=fail and severity at or above this level.")
@judge_options
def cmd_scan_mcp(argv: tuple[str, ...], call_tools, tool_args: dict, headers: tuple[tuple[str, str], ...],
                 env_names: tuple[str, ...], on_host: bool, timeout_s: float, max_runtime_s: float, per_run_cap: float,
                 out_file: str | None, report_format: str, fail_on: str | None) -> None:
    """Scan an MCP server over Streamable HTTP (URL) or stdio (a command after --) and report what its tools do."""
    from argus.mcp_scan import known_secrets
    from argus.mcp_scan.client import ConnectError, HttpServer, StdioServer, host_env

    _check_out_dir(out_file)
    if not argv or (_is_http_url(argv[0]) and len(argv) > 1):
        raise click.UsageError(_USAGE)
    url = argv[0] if _is_http_url(argv[0]) else None
    env: dict[str, str] = {}
    if url is not None:
        for flag, used in (("--env", env_names), ("--on-host", on_host)):
            if used:
                raise click.UsageError(f"{flag} applies to stdio servers only (a command after --).")
    else:
        if headers:
            raise click.UsageError("--header applies to HTTP servers only; pass a stdio server's credentials "
                                   "with --env NAME.")
        try:
            env = host_env(env_names)
        except ValueError as e:
            raise click.UsageError(str(e)) from None
    if url is None and STDIO_REQUIRES_ON_HOST and not on_host:
        click.echo(_ON_HOST, err=True)
        sys.exit(2)
    problem = sdk_problem("scan-mcp")
    if problem:
        click.echo(problem, err=True)
        sys.exit(2)

    from argus import llm

    judge_config, judge_off = None, ""
    if per_run_cap == 0:
        judge_off = "--per-run-cap 0 turns the judge off"
    else:
        try:
            resolved = llm.resolve_config()
        except ValueError as e:
            judge_off = str(e)
        else:
            judge_off = llm.credential_error(resolved) or ""
            judge_config = None if judge_off else resolved

    # Header values are masked at any length; --env values share known_secrets' floor, so DEBUG=1 masks no "1".
    found = [v for _, v in headers] + [env[n] for n in env_names if len(env[n]) >= known_secrets.VALUE_MIN]
    found += known_secrets.url_secrets(url) if url is not None else known_secrets.command_secrets(argv)
    found += known_secrets.args_secrets(tool_args)
    # Printed text has control bytes stripped, so a secret holding one must match in stripped form too.
    found += [CONTROL_RE.sub("", v) for v in found if CONTROL_RE.search(v)]
    secret_values = [v for v in dict.fromkeys(found) if v]
    if url is not None:
        target_spec = {"kind": "mcp_server", "url": known_secrets.safe_url(url), "headers": dict(headers)}
        target = HttpServer(url=url, headers=headers)
    else:
        target_spec = {"kind": "mcp_stdio", "command": known_secrets.mask_argv(argv, secret_values), "sandbox": False}
        target = StdioServer(argv=tuple(argv), env=env)
    secrets = run_json.run_secrets(target_spec, secret_values)

    def mask(text: str) -> str:
        return run_json.mask_text(text, secrets)

    # The engine masks server text before its checks, so it skips values under VALUE_MIN: X-Trace: 1 would blank every 1.
    engine_mask = known_secrets.value_mask(secrets)

    def clean(text: str) -> str:
        # Strip control bytes first, so one hidden inside a secret cannot dodge the mask.
        return mask(CONTROL_RE.sub("", text))

    def say(text: str, err: bool = False) -> None:
        click.echo(clean(text), err=err)

    from argus.mcp_scan import scan

    cfg = scan.ScanConfig(target=target, call_tools=call_tools, args=tool_args, timeout_s=timeout_s,
                          max_runtime_s=max_runtime_s, per_run_cap_usd=per_run_cap, judge_config=judge_config,
                          judge_off_reason=judge_off, transport="http" if url is not None else "stdio-host")
    if on_host:
        say(_HOST_NOTE)
    judged_by = [f"Judged by {llm.describe(judge_config)}"] if judge_config is not None else []
    if judge_config is not None:
        say(f"Judge: {llm.describe(judge_config)}")
    started_at = datetime.now(timezone.utc)
    try:
        with _sdk_logs(say):
            outcome = asyncio.run(_scan(cfg, engine_mask, say))
    except KeyboardInterrupt:
        outcome = _Stopped(signal.SIGINT)
    except ConnectError as e:
        if e.code == "auth":
            say(f"Error: {e}", err=True)
            sys.exit(2)
        say(f"Error: could not connect: {e}", err=True)
        if e.stderr_tail:
            from argus.mcp_scan import rules

            say(f"The server's stderr ended with:\n{rules.redact(e.stderr_tail)}", err=True)
        sys.exit(1)
    except scan.UnknownTools as e:
        shown = ", ".join(e.valid[:_NAMES_SHOWN]) or "no tools"
        if len(e.valid) > _NAMES_SHOWN:
            shown += f" and {len(e.valid) - _NAMES_SHOWN} more"
        say(f"Error: {e}. The server lists: {shown}.", err=True)
        sys.exit(2)
    except Exception as e:  # no traceback for the operator
        say(f"Error: {e}", err=True)
        sys.exit(1)

    if isinstance(outcome, _Stopped):
        say(f"{STOP_MESSAGES[outcome.signum]}: the scan was stopped before it finished; no report was written.",
            err=True)
        sys.exit(128 + outcome.signum)

    from argus.coverage import build_coverage
    from argus.mcp_scan.server_checks import server_probes
    from argus.probe import load_all_probes

    result = outcome
    run = {
        "id": str(uuid.uuid4()),
        # These cases exit 1 below; the report must not read as a finished scan.
        "status": ("incomplete" if result.out_of_time or result.all_selected_unexercised or result.unjudged
                   else "completed"),
        "started_at": started_at.isoformat(),
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "target_spec": target_spec,
        "coverage": build_coverage([*load_all_probes(scan.SCAN_PROBES_DIR), *server_probes()], result.findings),
        "findings": result.findings,
        "notes": [*result.notes, *judged_by],
    }
    if judge_config is not None:
        run["judge"] = llm.judge_record(judge_config)
    for f in result.findings:
        if f.get("verdict") == "fail":
            say(_console_line(f, clean))
    if report_format == "json":
        report = run_json.render_json(run, secret_values)
    else:
        render = {"html": reports.render_html, "sarif": reports.render_sarif,
                  "junit": reports.render_junit}[report_format]
        # Same scrub as run.json, so no format can leak what another one masks.
        report = render(run_json.scrub_run(run, secret_values))
    out_file = out_file or f"argus-mcp-scan-report.{_EXTENSIONS[report_format]}"
    _write_report(out_file, report, encoding="utf-8", echo=say)
    say(f"Wrote report to {out_file}")
    notes = result.notes
    # A server may list 1000 tools: the console shows a count and the first lines, the report every line.
    if result.inventory > _INVENTORY_SHOWN:
        notes = [result.inventory_summary, *notes[:_INVENTORY_SHOWN],
                 f"... and {result.inventory - _INVENTORY_SHOWN} more tool(s); the report lists every one.",
                 *notes[result.inventory:]]
    for note in notes:
        say(note)

    if result.out_of_time:
        _count_fail_on(result.findings, fail_on)
        # The limit can pass after the last tool's calls, during the relist or the replays.
        say(f"The run time limit (--max-runtime {max_runtime_s:g} s) was reached before the scan finished, so it is "
            "incomplete; raise --max-runtime to finish it.", err=True)
        sys.exit(1)
    if result.all_selected_unexercised:
        _count_fail_on(result.findings, fail_on)
        say("No tool selected for calling could be exercised, so the call checks did not run; the notes above say "
            "why.", err=True)
        sys.exit(1)
    if result.unjudged:
        from argus.mcp_scan.findings import unjudged_count
        from argus.mcp_scan.judging import CAP_REASON, ERROR_REASON

        _count_fail_on(result.findings, fail_on)
        # Raising the cap does not help when the provider failed, so each cause gets its own hint.
        if capped := unjudged_count(result.findings, (CAP_REASON,)):
            say(f"{capped} probe result(s) were left unjudged by the cost cap, so the scan is inconclusive; raise "
                "--per-run-cap to judge them.", err=True)
        if failed := unjudged_count(result.findings, (ERROR_REASON,)):
            say(f"{failed} probe result(s) were left unjudged because the judge's reply could not be used (a "
                "provider error or a malformed reply), so the scan is inconclusive; check the judge provider and "
                "its key, then run again.", err=True)
        sys.exit(1)
    _apply_fail_on(result.findings, fail_on)
