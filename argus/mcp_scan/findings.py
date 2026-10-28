"""Turn scan-mcp hits, judge outcomes and call records into run.json findings, plus the per-tool inventory notes."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Mapping, Sequence
from uuid import uuid4

from argus.mcp_scan import rules
from argus.mcp_scan.calls import CallRun, ToolOutcome, good_result, show_text
from argus.mcp_scan.checks import (COMMAND, CROSS_SESSION, DESCRIPTION, HIDDEN, INJECTION, LIST_CHANGED, REFLECTION,
                                   SCHEMA, SECRET, TRAVERSAL)
from argus.mcp_scan.judging import CAP_REASON, ERROR_REASON, OFF_REASON, JudgeOutcome
from argus.mcp_scan.models import RESULT_KEEP, CallRecord, Hit, ToolInfo
from argus.mcp_scan.payloads import PATH_LIKE
from argus.probe import Probe
from argus.runner import VERDICT_ERROR, VERDICT_FAIL, VERDICT_PASS, VERDICT_SKIPPED, Finding

READONLY = "mcp_scan_readonly_tool_wrote"
PROBE_ORDER = (DESCRIPTION, SCHEMA, HIDDEN, COMMAND, TRAVERSAL, SECRET, INJECTION, CROSS_SESSION, REFLECTION,
               LIST_CHANGED, READONLY)
SNYK_LINE = "For deep static analysis of tool descriptions, also run Snyk agent-scan."

PROMPT_MAX = 500
ITEMS_MAX = 50
SKIP_NO_TOOL = "no tool was called; pass --call-tools NAMES or --call-tools all to call more"
SKIP_SANDBOX = "runs only in the stdio sandbox"
SKIP_NO_TOOLS = "the server listed no tools"
SKIP_NO_PAYLOAD = "no called tool takes a string (or path-like) parameter"
SKIP_NO_READONLY = "no tool annotated read-only was called"
SKIP_DESTRUCTIVE = "no payload was sent: tools annotated destructive get the baseline call only"
NONE_EXERCISED = "the selected tools could not be exercised"
NO_RELIST = "the second tools/list did not complete, so the tool list was not compared"

_STATIC = frozenset({DESCRIPTION, SCHEMA})
_PAYLOAD_FAMILIES = frozenset({"cmd", "path", "relay"})
# A text the judge did not decide is never a pass; only cap and error make the run inconclusive.
_UNJUDGED = frozenset({"cap", "error", "off"})


def finding(probe: Probe, *, verdict: str, severity: str, reasoning: str, evidence: dict, attack_prompt: str = "",
             target_response: str = "", latency_ms: float = 0.0, confidence: float = 1.0, judge_model: str = "",
             escalated_model: str | None = None) -> dict:
    f = Finding(id=uuid4(), probe_id=probe.id, attack_prompt=attack_prompt, target_response=target_response,
                target_latency_ms=latency_ms, probed_at=datetime.now(timezone.utc), verdict=verdict,
                severity=severity, confidence=confidence, reasoning=reasoning, judge_model=judge_model,
                escalated_model=escalated_model, atlas_id=list(probe.mappings.atlas),
                owasp_id=list(probe.mappings.owasp_llm), nist_id=list(probe.mappings.nist_ai_rmf),
                eu_ai_act_id=list(probe.mappings.eu_ai_act), evidence=evidence)
    d = asdict(f)
    d["id"] = str(f.id)
    d["probed_at"] = f.probed_at.isoformat()
    d["created_at"] = f.created_at.isoformat()
    return d


@dataclass
class _Ctx:
    probes: Mapping[str, Probe]
    calls: CallRun | None
    transport: str
    sandbox: bool
    decoys: Sequence[tuple[str, str]]
    names: list[str]
    tools: dict[str, ToolInfo]
    mask: rules.Mask = rules.same
    listing: dict = field(default_factory=dict)
    by_seq: dict[int, CallRecord] = field(default_factory=dict)
    by_tool: dict[str, list[CallRecord]] = field(default_factory=dict)
    hits: dict[tuple[str, str | None], list[Hit]] = field(default_factory=dict)
    judged: dict[tuple[str, str | None], list[JudgeOutcome]] = field(default_factory=dict)

    def order(self, name: str | None) -> tuple[int, str]:
        return (self.names.index(name) if name in self.tools else len(self.names), name or "")

    def evidence(self, **kw) -> dict:
        return {**kw, "transport": self.transport}


def build_findings(*, probes: Mapping[str, Probe], hits: list[Hit], outcomes: list[JudgeOutcome],
                   calls: CallRun | None, listed: list[ToolInfo], transport: str, sandbox: bool,
                   decoys: Sequence[tuple[str, str]] = (), mask: rules.Mask = rules.same, truncated: bool = False,
                   tools_listed: int | None = None) -> list[dict]:
    """One `fail` per (probe, tool), one `error` per unjudged (probe, tool), then per probe one `pass` for the clean
    tools, one `error` for the tools it could not exercise, or one `skipped` when it never ran."""
    tools: dict[str, ToolInfo] = {}
    for t in listed:
        tools.setdefault(t.name, t)
    listing = {"truncated": truncated, "tools_listed": len(listed) if tools_listed is None else tools_listed}
    ctx = _Ctx(probes, calls, transport, sandbox, decoys, list(tools), tools, mask, listing)
    for rec in calls.records if calls is not None else []:
        ctx.by_seq[rec.seq] = rec
        ctx.by_tool.setdefault(rec.call.tool, []).append(rec)
    for h in hits:
        ctx.hits.setdefault((h.probe_id, h.tool), []).append(h)
    for o in outcomes:
        ctx.judged.setdefault((o.candidate.probe_id, o.candidate.tool), []).append(o)
    out: list[dict] = []
    for pid in PROBE_ORDER:
        if pid in probes:
            found = _probe_findings(ctx, probes[pid])
            # The tool-list checks saw only what the caps kept; say so where the JSON reader looks.
            if pid in _STATIC or pid == HIDDEN:
                for f in found:
                    f["evidence"].update(listing)
            out += found
    return out


def unjudged_count(findings: list[dict], reasons: Sequence[str] = (CAP_REASON, ERROR_REASON)) -> int:
    """(probe, tool) pairs the judge left undecided (cost cap or unusable reply); each makes the run inconclusive.

    A judge that is off is not counted: the spec keeps that case out of the exit code."""
    return sum(f["verdict"] == VERDICT_ERROR and f["reasoning"] in reasons for f in findings)


def all_selected_unexercised(calls: CallRun | None) -> bool:
    """True when tools were selected for calling and none of them gave one good call."""
    return calls is not None and bool(calls.outcomes) and all(o.status != "called" for o in calls.outcomes.values())


def _probe_findings(ctx: _Ctx, probe: Probe) -> list[dict]:
    pid = probe.id
    if pid == READONLY and not ctx.sandbox:
        return [_skipped(ctx, probe, SKIP_SANDBOX)]
    if not ctx.names:
        return [_skipped(ctx, probe, SKIP_NO_TOOLS)]
    selected = ctx.calls.outcomes if ctx.calls is not None else {}
    if pid not in _STATIC and pid != HIDDEN and not selected:
        return [_skipped(ctx, probe, SKIP_NO_TOOL)]

    failing = {t for (p, t) in ctx.hits if p == pid}
    failing |= {t for (p, t), outs in ctx.judged.items()
                if p == pid and any(o.status == "judged" and o.verdict == VERDICT_FAIL for o in outs)}
    unjudged = {t for (p, t), outs in ctx.judged.items()
                if p == pid and t not in failing and any(o.status in _UNJUDGED for o in outs)}

    # Tools the probe decides on: the whole listing for static checks, the selected tools for dynamic ones.
    clean: list[str] = []
    missed: list[tuple[str, str]] = []
    if pid in _STATIC or pid == HIDDEN:
        clean = [n for n in ctx.names if n not in failing and n not in unjudged]
    if pid != LIST_CHANGED and pid not in _STATIC:
        for name, outcome in selected.items():
            state, detail = _exercised(ctx, pid, name, outcome)
            if name in failing or name in unjudged or state == "n/a":
                continue
            if state == "ok":
                if pid != HIDDEN:
                    clean.append(name)
            else:
                missed.append((name, detail))
    relisted = ctx.calls is not None and ctx.calls.final_tools is not None
    if pid == LIST_CHANGED and relisted:
        clean = [n for n in ctx.names if n not in failing]

    out = [_fail(ctx, probe, name) for name in sorted(failing, key=ctx.order)]
    out += [_unjudged(ctx, probe, name) for name in sorted(unjudged, key=ctx.order)]
    if clean:
        names = [show_text(n) for n in clean]
        out.append(finding(probe, verdict=VERDICT_PASS, severity="info",
                            reasoning=f"no finding in {len(clean)} tool(s)",
                            evidence=ctx.evidence(tools=names, items=names)))
    if missed:
        listed = "; ".join(f"{show_text(n)}: {d}" for n, d in missed)
        reasoning = f"not exercised: {listed}"
        if not (failing or unjudged or clean):
            reasoning = f"{NONE_EXERCISED}; {reasoning}"
        out.append(finding(probe, verdict=VERDICT_ERROR, severity="info", reasoning=reasoning,
                            evidence=ctx.evidence(tools=[show_text(n) for n, _ in missed],
                                                  items=[f"{show_text(n)}: {d}" for n, d in missed])))
    if pid == LIST_CHANGED and not relisted and not failing:
        out.append(finding(probe, verdict=VERDICT_ERROR, severity="info", reasoning=NO_RELIST,
                            evidence=ctx.evidence(tools=[], items=[])))
    if not out:
        if pid == READONLY:
            return [_skipped(ctx, probe, SKIP_NO_READONLY)]
        destructive = any(t is not None and t.destructive and _takes_string(t) for t in map(ctx.tools.get, selected))
        return [_skipped(ctx, probe, SKIP_DESTRUCTIVE if destructive else SKIP_NO_PAYLOAD)]
    return out


def _skipped(ctx: _Ctx, probe: Probe, reason: str) -> dict:
    return finding(probe, verdict=VERDICT_SKIPPED, severity="info", reasoning=reason,
                    evidence=ctx.evidence(tools=[], items=[]))


def _props(tool: ToolInfo | None) -> dict:
    props = (tool.input_schema or {}).get("properties") if tool is not None else None
    return props if isinstance(props, dict) else {}


def _path_like(tool: ToolInfo | None) -> bool:
    return any(p in str(k).lower() for k in _props(tool) for p in PATH_LIKE)


def _takes_string(tool: ToolInfo | None) -> bool:
    """A property typed string, or untyped, could have taken a payload."""
    for prop in _props(tool).values():
        kind = prop.get("type") if isinstance(prop, dict) else None
        if kind is None or kind == "string" or (isinstance(kind, list) and "string" in kind):
            return True
    return False


def _exercised(ctx: _Ctx, pid: str, name: str, outcome: ToolOutcome) -> tuple[str, str]:
    """("ok" | "missed" | "n/a", detail): whether this tool's calls let the probe decide, and why not."""
    tool = ctx.tools.get(name)
    if pid == READONLY:
        if tool is None or not tool.read_only:
            return "n/a", ""
        return ("ok", "") if outcome.calls else ("missed", outcome.detail)
    if outcome.calls == 0:
        return "missed", outcome.detail
    recs = ctx.by_tool.get(name, [])
    tried = {r.call.family for r in recs}
    good = {r.call.family for r in recs if good_result(r.result)}
    # A tool stopped partway had payload calls planned that never ran. A tool with no good call may have been
    # stopped by timeouts before its payload calls, so any string parameter makes it a payload target.
    stopped = outcome.status == "called" and bool(outcome.detail)
    unsure = stopped or (outcome.status != "called" and _takes_string(tool))
    if pid in (SECRET, INJECTION, HIDDEN):
        return ("ok", "") if good else ("missed", outcome.detail)
    if pid == COMMAND:
        applies, ok, what = "cmd" in tried or unsure, "cmd" in good, "no command payload call succeeded"
    elif pid == TRAVERSAL:
        applies = "path" in tried or (unsure and _path_like(tool))
        ok, what = "path" in good, "no path payload call succeeded"
    elif pid == REFLECTION:
        applies, ok, what = bool(tried & _PAYLOAD_FAMILIES) or unsure, bool(good & _PAYLOAD_FAMILIES), \
            "no payload call succeeded"
    else:  # CROSS_SESSION
        applies = "relay" in tried or unsure
        ok = "relay" in good and "replay" in good
        what = "the second-session replay did not succeed" if "relay" in good else "no relay payload call succeeded"
    if not applies:
        return "n/a", ""
    if ok:
        return "ok", ""
    return "missed", outcome.detail if (stopped or outcome.status != "called") else what


def _call_text(ctx: _Ctx, rec: CallRecord) -> tuple[str, str]:
    # Masked before the cut: --args values are known secrets, and the arguments can run past PROMPT_MAX.
    prompt = ctx.mask(f"tools/call {show_text(rec.call.tool)} {json.dumps(rec.call.arguments, default=str)}")
    return rules.redact(prompt, ctx.decoys)[:PROMPT_MAX], rules.redact(rec.result.text, ctx.decoys)[:RESULT_KEEP]


def _fail(ctx: _Ctx, probe: Probe, name: str | None) -> dict:
    pid = probe.id
    shown_name = show_text(name) if name is not None else None
    # Provider-shaped secrets (confidence 1.0) rank ahead of generic secret-named assignments.
    hits = sorted(ctx.hits.get((pid, name), []), key=lambda h: -h.confidence)
    if hits:
        top = hits[0]
        seq, family, excerpt = top.call_seq, top.family, rules.redact(top.excerpt, ctx.decoys)
        reasoning = f"{top.rule} in {shown_name or 'the server'}: {excerpt}"
        if top.reasoning:
            reasoning += f" ({top.reasoning})"
        if len(hits) > 1:
            reasoning += f" ({len(hits)} matches)"
        items = [{**asdict(h), "tool": shown_name, "excerpt": rules.redact(h.excerpt, ctx.decoys)}
                 for h in hits[:ITEMS_MAX]]
        ev = ctx.evidence(tool=shown_name, call_seq=seq, family=family, decided_by="rule", rule=top.rule,
                          excerpt=excerpt)
        if ctx.sandbox:
            ev["decoy"] = top.decoy
        judge = (top.confidence, "", None)
    else:
        fails = [o for o in ctx.judged[(pid, name)] if o.status == "judged" and o.verdict == VERDICT_FAIL]
        fails.sort(key=lambda o: -o.confidence)
        top = fails[0]
        seq, family = top.candidate.call_seq, None
        excerpt = show_text(rules.redact(top.candidate.text, ctx.decoys))
        why = rules.redact(top.reasoning, ctx.decoys)
        reasoning = f"judged: {why}"
        items = [{"tool": shown_name, "call_seq": o.candidate.call_seq, "source": o.candidate.source,
                  "verdict": o.verdict, "confidence": o.confidence, "judge_model": o.judge_model,
                  "reasoning": rules.redact(o.reasoning, ctx.decoys),
                  "excerpt": show_text(rules.redact(o.candidate.text, ctx.decoys))} for o in fails[:ITEMS_MAX]]
        ev = ctx.evidence(tool=shown_name, call_seq=seq, family=None, decided_by="judge", reasoning=why,
                          excerpt=excerpt)
        if ctx.sandbox:
            ev["decoy"] = None  # the judge names no decoy; the key matches rule-decided fails
        judge = (top.confidence, top.judge_model, top.escalated_model)
    rec = ctx.by_seq.get(seq) if seq is not None else None
    if rec is not None:
        prompt, response = _call_text(ctx, rec)
        latency = rec.result.latency_ms
        if family is None:
            ev["family"] = rec.call.family
    else:
        prompt = "tools/list" if pid in _STATIC or pid in (HIDDEN, LIST_CHANGED) or name is None \
            else f"tools/call {shown_name}"
        response, latency = excerpt, 0.0
    ev.update(items=items, tools=[shown_name] if shown_name is not None else [])
    return finding(probe, verdict=VERDICT_FAIL, severity=probe.severity, reasoning=reasoning, evidence=ev,
                    attack_prompt=prompt, target_response=response, latency_ms=latency, confidence=judge[0],
                    judge_model=judge[1], escalated_model=judge[2])


def _unjudged(ctx: _Ctx, probe: Probe, name: str | None) -> dict:
    left = [o for o in ctx.judged[(probe.id, name)] if o.status in _UNJUDGED]
    # Cap or error outranks off, so a run that is inconclusive is counted as one.
    left.sort(key=lambda o: o.status == "off")
    shown_name = show_text(name) if name is not None else None
    items = [{"tool": shown_name, "call_seq": o.candidate.call_seq, "source": o.candidate.source,
              "excerpt": show_text(rules.redact(o.candidate.text, ctx.decoys))} for o in left[:ITEMS_MAX]]
    reasoning = OFF_REASON if left[0].status == "off" else left[0].reasoning
    return finding(probe, verdict=VERDICT_ERROR, severity="info", reasoning=reasoning,
                    evidence=ctx.evidence(tool=shown_name, tools=[shown_name] if shown_name else [], items=items))


def inventory_notes(listed: list[ToolInfo], reasons: Mapping[str, str], calls: CallRun | None) -> list[str]:
    """One line per listed tool: its annotations and whether it was called, not called by policy, or not exercised."""
    return [line for _, line in _inventory(listed, reasons, calls)]


def inventory_summary(listed: list[ToolInfo], reasons: Mapping[str, str], calls: CallRun | None) -> str:
    """One line counting the inventory, for a console that shows only its first lines."""
    kinds = [kind for kind, _ in _inventory(listed, reasons, calls)]
    return (f"{len(kinds)} tool(s) listed: {kinds.count('called')} called, {kinds.count('policy')} not called by "
            f"policy, {kinds.count('not_exercised')} not exercised, {kinds.count('not_tested')} not tested.")


def _inventory(listed: list[ToolInfo], reasons: Mapping[str, str], calls: CallRun | None) -> list[tuple[str, str]]:
    outcomes = calls.outcomes if calls is not None else {}
    replays: dict[str, int] = {}
    for r in calls.records if calls is not None else []:
        if r.session == "B":
            replays[r.call.tool] = replays.get(r.call.tool, 0) + 1
    lines: list[tuple[str, str]] = []
    seen: set[str] = set()
    for tool in listed:
        if tool.name in seen:
            continue
        seen.add(tool.name)
        head = f"{show_text(tool.name)} [{_annotations(tool)}]"
        o = outcomes.get(tool.name)
        if tool.name in reasons:
            lines.append(("policy", f"{head}: not called by policy: {reasons[tool.name]}"))
        elif o is None:
            lines.append(("not_tested", f"{head}: not tested: not selected"))
        elif o.status == "called":
            # The console counts session-A calls, so the replay is shown apart.
            n = replays.get(tool.name, 0)
            counts = f"{o.calls - n} calls" + (f", {n} replay" if n == 1 else f", {n} replays" if n else "")
            lines.append(("called", f"{head}: called ({counts})" + (f"; {o.detail}" if o.detail else "")))
        elif o.status == "not_exercised" and o.calls:
            lines.append(("not_exercised", f"{head}: called but every call errored (not exercised): {o.detail}"))
        else:
            lines.append(("not_tested", f"{head}: not tested: {o.detail.removeprefix('not tested: ')}"))
    return lines


def _annotations(tool: ToolInfo) -> str:
    parts = [f"{k}: {show_text(json.dumps(tool.annotations[k], default=str))}"
             for k in ("readOnlyHint", "destructiveHint") if k in tool.annotations]
    return ", ".join(parts) if parts else "no annotations"
