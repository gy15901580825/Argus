"""scan_mcp(): connect, list, run the static and mcp_server checks, call the selected tools, judge, report."""
from __future__ import annotations

import functools
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Literal, Mapping

import argus
from argus.llm import LLMConfig
from argus.mcp_scan import checks, policy
from argus.mcp_scan.calls import CallHooks, CallRun, run_calls, show_text
from argus.mcp_scan.client import HttpServer, StdioServer, open_session
from argus.mcp_scan.findings import (SNYK_LINE, all_selected_unexercised, build_findings, inventory_notes,
                                     unjudged_count)
from argus.mcp_scan.judging import JudgeGate
from argus.mcp_scan.models import ServerInfo
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


@dataclass(frozen=True)
class ScanConfig:
    target: HttpServer | StdioServer
    call_tools: CallTools = None
    args: Mapping[str, dict] = field(default_factory=dict)
    timeout_s: float = 30.0
    per_run_cap_usd: float = 0.50
    judge_config: LLMConfig | None = None
    judge_off_reason: str = ""
    transport: Literal["http", "stdio-host", "stdio-sandbox"] = "http"
    decoys: tuple[tuple[str, str], ...] = ()
    extra_paths: tuple[str, ...] = ()
    hooks: CallHooks | None = None


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


@functools.lru_cache(maxsize=1)
def _scan_probes() -> tuple[Probe, ...]:
    return tuple(load_all_probes(SCAN_PROBES_DIR))


async def scan_mcp(cfg: ScanConfig, *, mask: Callable[[str], str], echo: Callable[[str], None]) -> ScanResult:
    """Raises client.ConnectError when session A or the first tools/list fails, UnknownTools for a bad --call-tools."""
    opener = functools.partial(open_session, cfg.target, timeout_s=cfg.timeout_s, mask=mask)
    calls: CallRun | None = None
    async with opener() as session:
        listed, list_notes = await session.list_tools()
        unknown = policy.unknown_names(listed, cfg.call_tools)
        if unknown:
            raise UnknownTools(unknown, sorted({t.name for t in listed}))
        echo(f"Listed {len(listed)} tool(s)")
        server_info = session.server_info
        hits, cands = checks.static_hits(listed, decoys=cfg.decoys)
        if isinstance(cfg.target, HttpServer):
            server = await http_server_findings(cfg.target.url, cfg.target.headers, cfg.timeout_s, mask)
        else:
            server = stdio_server_findings(listed, server_info)
        chosen, reasons = policy.select(listed, cfg.call_tools)
        if chosen:
            echo(f"Calling {len(chosen)} tool(s)")
            calls = await run_calls(session, opener, chosen, overrides=cfg.args, run_id=new_run_id(),
                                    extra_paths=cfg.extra_paths, hooks=cfg.hooks, echo=echo)
    if calls is not None:
        dyn, dyn_cands = checks.dynamic_hits(calls.records, listed, calls.final_tools, calls.list_changed,
                                             decoys=cfg.decoys)
        hits += dyn + calls.hook_hits
        cands += dyn_cands
    gate = JudgeGate(cfg.per_run_cap_usd, cfg.judge_config, RUBRIC_PATH.read_text(encoding="utf-8"))
    if cands and gate.config is not None and cfg.per_run_cap_usd > 0:
        echo(f"Judging {len(cands)} text(s)")
    outcomes = await gate.judge_all(cands, mask)
    scan = build_findings(probes={p.id: p for p in _scan_probes()}, hits=hits, outcomes=outcomes, calls=calls,
                          listed=listed, transport=cfg.transport, sandbox=cfg.transport == "stdio-sandbox",
                          decoys=cfg.decoys, mask=mask)

    notes = inventory_notes(listed, reasons, calls) + list_notes + (calls.notes if calls is not None else [])
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
    notes.append(SNYK_LINE)
    return ScanResult(findings=scan + server, notes=notes, server_info=server_info,
                      all_selected_unexercised=all_selected_unexercised(calls), unjudged=unjudged_count(scan),
                      no_tool_called=not chosen)
