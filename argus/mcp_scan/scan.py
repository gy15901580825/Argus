"""scan_mcp(): connect, list, run the static and mcp_server checks, call the selected tools, judge, report."""
from __future__ import annotations

import functools
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Literal, Mapping

import argus
from argus.llm import LLMConfig
from argus.mcp_scan import checks, policy
from argus.mcp_scan.calls import CallHooks, CallRun, run_calls, show_text
from argus.mcp_scan.client import HttpServer, StdioServer, open_session
from argus.mcp_scan.findings import (SNYK_LINE, all_selected_unexercised, build_findings, inventory_notes,
                                     inventory_summary, unjudged_count)
from argus.mcp_scan.judging import CAP_REASON, JudgeGate
from argus.mcp_scan.models import CallRecord, ServerInfo
from argus.mcp_scan.payloads import new_run_id
from argus.mcp_scan.policy import CallTools
from argus.mcp_scan.server_checks import http_server_findings, stdio_server_findings
from argus.probe import Probe, load_all_probes

SCAN_PROBES_DIR = Path(argus.__file__).parent / "probes" / "mcp_scan"
RUBRIC_PATH = Path(argus.__file__).parent / "rubrics" / "mcp_tool_output_injection.md"
HOST_NOTE = "Annotations are the server's own claims; host mode cannot see a read-only tool that writes."
CALL_TOOLS_NOTE = ("No tool was called, so only the static checks ran; pass --call-tools NAMES or --call-tools all "
                   "to call more.")
ARGS_NOTE = "Some tools could not be exercised with generated arguments; pass --args FILE with arguments they accept."
_ARGS_MARK = "pass --args"
# Bytes read from each --witness-log file, from where it ended before the first call.
WITNESS_LOG_MAX = 16 * 1024 * 1024
WITNESS_LOG_LINES_MAX = 200


@dataclass(frozen=True)
class ScanConfig:
    target: HttpServer | StdioServer
    call_tools: CallTools = None
    args: Mapping[str, dict] = field(default_factory=dict)
    timeout_s: float = 30.0
    max_runtime_s: float = 1800.0
    per_run_cap_usd: float = 0.50
    judge_config: LLMConfig | None = None
    judge_off_reason: str = ""
    transport: Literal["http", "stdio-host", "stdio-sandbox"] = "http"
    decoys: tuple[tuple[str, str], ...] = ()
    extra_paths: tuple[str, ...] = ()
    hooks: CallHooks | None = None
    witness_logs: tuple[str, ...] = ()  # files the operator can read, such as the server's access log; never written


class UnknownTools(ValueError):
    def __init__(self, names: list[str], valid: list[str]) -> None:
        super().__init__(f"--call-tools names tools the server does not list: {', '.join(names)}")
        self.names = names
        self.valid = valid


@dataclass
class ScanResult:
    findings: list[dict]
    notes: list[str]
    server_info: ServerInfo | None
    all_selected_unexercised: bool
    unjudged: int
    no_tool_called: bool
    out_of_time: bool = False
    inventory: int = 0  # how many leading notes are per-tool inventory lines
    inventory_summary: str = ""


@functools.lru_cache(maxsize=1)
def _scan_probes() -> tuple[Probe, ...]:
    return tuple(load_all_probes(SCAN_PROBES_DIR))


async def scan_mcp(cfg: ScanConfig, *, mask: Callable[[str], str], echo: Callable[[str], None]) -> ScanResult:
    """Raises client.ConnectError when session A or the first tools/list fails, UnknownTools for a bad --call-tools."""
    deadline = time.monotonic() + cfg.max_runtime_s
    run_id = new_run_id()
    log_sizes = {path: _size(path) for path in cfg.witness_logs}
    opener = functools.partial(open_session, cfg.target, timeout_s=cfg.timeout_s, mask=mask)
    calls: CallRun | None = None
    async with opener() as session:
        listed, list_notes = await session.list_tools()
        unknown = policy.unknown_names(listed, cfg.call_tools)
        if unknown:
            raise UnknownTools(unknown, sorted({t.name for t in listed}))
        echo(f"Listed {len(listed)} tool(s)")
        server_info = session.server_info
        truncated, tools_listed = session.list_truncated, session.tools_listed
        hits, cands = checks.static_hits(listed, decoys=cfg.decoys)
        if isinstance(cfg.target, HttpServer):
            server = await http_server_findings(cfg.target.url, cfg.target.headers, cfg.timeout_s, mask)
        else:
            server = stdio_server_findings(listed, server_info, mask)
        chosen, reasons = policy.select(listed, cfg.call_tools)
        if chosen:
            echo(f"Calling {len(chosen)} tool(s)")
            calls = await run_calls(session, opener, chosen, overrides=cfg.args, run_id=run_id,
                                    extra_paths=cfg.extra_paths, hooks=cfg.hooks, echo=echo, deadline=deadline)
    if calls is not None:
        dyn, dyn_cands = checks.dynamic_hits(calls.records, listed, calls.final_tools, calls.list_changed,
                                             decoys=cfg.decoys, mask=mask)
        hits += dyn + calls.hook_hits
        cands += dyn_cands
        witness, witness_notes, witness_sources = _witnesses(cfg, calls.records, calls.sessions, run_id, log_sizes,
                                                             mask)
        hits += witness
    else:
        witness_notes, witness_sources = [], None
    gate = JudgeGate(cfg.per_run_cap_usd, cfg.judge_config, RUBRIC_PATH.read_text(encoding="utf-8"))
    if cands and gate.config is not None and cfg.per_run_cap_usd > 0:
        echo(f"Judging {len(cands)} text(s)")
    outcomes = await gate.judge_all(cands, mask, hits=hits)
    scan = build_findings(probes={p.id: p for p in _scan_probes()}, hits=hits, outcomes=outcomes, calls=calls,
                          listed=listed, transport=cfg.transport, sandbox=cfg.transport == "stdio-sandbox",
                          decoys=cfg.decoys, mask=mask, truncated=truncated, tools_listed=tools_listed,
                          witness_sources=witness_sources)

    inventory = inventory_notes(listed, reasons, calls)
    notes = inventory + list_notes + (calls.notes if calls is not None else []) + witness_notes
    # A replay often returns the baseline's text again: list each (probe, tool, text) once.
    off = list(dict.fromkeys(
        f"not judged: {o.candidate.probe_id} {show_text(o.candidate.tool)}: {show_text(o.candidate.text)}"
        for o in outcomes if o.status == "off"))
    if off:
        # The reason is often a full sentence; drop its period so the note does not read ".;".
        reason = cfg.judge_off_reason.rstrip(".") or "no judge is configured"
        notes.append(f"Judge skipped: {reason}; {len(off)} text(s) that looked aimed at a model were not judged:")
        notes += off
    if not chosen:
        notes.append(CALL_TOOLS_NOTE)
    if cfg.transport == "stdio-host":
        notes.append(HOST_NOTE)
    if calls is not None and any(o.status != "called" and _ARGS_MARK in o.detail for o in calls.outcomes.values()):
        notes.append(ARGS_NOTE)
    if blocked := sum(o.error_code == "content_filter" for o in outcomes):
        notes.append(f"The provider content filter blocked {blocked} judge item(s); review the filter policy.")
    if capped := unjudged_count(scan, (CAP_REASON,)):
        notes.append(f"Cost cap: {capped} probe result(s) were not judged; raise --per-run-cap to judge them.")
    notes.append(SNYK_LINE)
    return ScanResult(findings=scan + server, notes=notes, server_info=server_info,
                      all_selected_unexercised=all_selected_unexercised(calls), unjudged=unjudged_count(scan),
                      no_tool_called=not chosen, out_of_time=calls is not None and calls.out_of_time,
                      inventory=len(inventory), inventory_summary=inventory_summary(listed, reasons, calls))


def _size(path: str) -> int | None:
    try:
        return os.stat(path).st_size
    except OSError:
        return None


def _read_log(path: str, start: int | None, run_id: str) -> tuple[list[str] | None, str]:
    """The lines appended since `start` that hold one of this run's markers (None when unread), and what was read."""
    if start is None:
        return None, "could not be read before the calls, so it was not checked"
    try:
        with open(path, "rb") as f:
            size = os.fstat(f.fileno()).st_size
            shrank = size < start
            if shrank:
                start = 0
            f.seek(start)
            data = f.read(WITNESS_LOG_MAX)
    except OSError as exc:
        return None, f"could not be read after the calls ({exc.strerror or type(exc).__name__}), so it was not checked"
    appended = size - start
    what = f"{appended} byte(s) appended during the scan"
    if shrank:
        what = f"it shrank during the scan (rotated or truncated), so it was read from its start: {appended} byte(s)"
    if appended > WITNESS_LOG_MAX:
        what += f", of which the first {WITNESS_LOG_MAX} were read"
    tag = f"argus-trav-{run_id}".encode()
    lines = [line.decode("utf-8", "replace") for line in data.split(b"\n") if tag in line]
    return lines[:WITNESS_LOG_LINES_MAX], what


def _witnesses(cfg: ScanConfig, records: list[CallRecord], sessions: list, run_id: str,
               log_sizes: dict[str, int | None], mask: Callable[[str], str]) -> tuple[list, list[str], list[str] | None]:
    """Traversal escape witnesses from results, a stdio server's stderr and each --witness-log file, with notes that
    say which of those sources this scan could read."""
    if not any(r.call.family == "path" and r.call.expect for r in records):
        return [], [], None
    lines: list[tuple[str, str]] = []
    read = ["tool results"]
    unread = []
    sources = ["result"]
    if isinstance(cfg.target, StdioServer):
        marked = [line for s in sessions for line in s.stderr_marked]
        lines += [("stderr", mask(line)) for line in marked]
        read.append(f"the server's stderr ({len(marked)} line(s) held a marker)")
        sources.append("stderr")
    else:
        unread.append("the server's stderr (not visible over HTTP)")
    for path in cfg.witness_logs:
        found, what = _read_log(path, log_sizes.get(path), run_id)
        shown = f"witness log {show_text(mask(path))} ({what})"
        if found is None:
            unread.append(shown)
            continue
        lines += [("witness_log", mask(line)) for line in found]
        read.append(shown)
        if "witness_log" not in sources:
            sources.append("witness_log")
    if not cfg.witness_logs:
        unread.append("a log of the server or its upstream (pass --witness-log PATH for one you can read)")
    hits, notes = checks.witness_hits(records, lines, run_id, decoys=cfg.decoys)
    head = "Path traversal escape witnesses were looked for in: " + "; ".join(read) + "."
    if unread:
        head += " Not looked for in: " + "; ".join(unread) + "."
    return hits, [head, *notes], sources
