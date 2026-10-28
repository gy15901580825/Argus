"""Call the selected tools in session A, re-list, then replay each baseline in a fresh session B, under hard caps."""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, AsyncContextManager, Callable, Literal, Mapping, Protocol, Sequence

from argus.mcp_scan import rules
from argus.mcp_scan.client import ConnectError
from argus.mcp_scan.models import CallRecord, CallResult, Hit, PlannedCall, ToolInfo
from argus.mcp_scan.payloads import Baseline, baseline, baseline_call, payload_calls
from argus.mcp_scan.policy import REASON_CAP

if TYPE_CHECKING:
    from argus.mcp_scan.client import McpSession

CALLS_MAX = 400
TOOL_TIMEOUTS_MAX = 2
RESTARTS_MAX = 3

REASON_SERVER = "not tested: the server session kept closing"
_NO_SCHEMA = "no inputSchema"  # the hint payloads.baseline gives a tool without a usable schema
_INVALID_PARAMS = "JSON-RPC error -32602"  # how client.McpSession formats an invalid-params reply
_ARGS_HINT = "; pass --args with arguments this tool accepts"


class CallHooks(Protocol):
    """What the sandbox (Phase B) does around the calls; host mode passes None."""

    async def before_calls(self) -> None: ...

    async def after_tool(self, tool: ToolInfo) -> list[Hit]: ...


@dataclass
class ToolOutcome:
    status: Literal["called", "not_exercised", "not_tested_cap", "not_tested_server"]
    calls: int
    detail: str


@dataclass
class CallRun:
    records: list[CallRecord]
    final_tools: list[ToolInfo] | None
    list_changed: bool
    outcomes: dict[str, ToolOutcome]
    hook_hits: list[Hit]
    notes: list[str]


def _show(text: str) -> str:
    """Server text made safe to keep or print: redacted, then bounded, hidden characters shown, on one line."""
    return " ".join(rules.excerpt(text, 0, len(text)).split())


def _good(result: CallResult) -> bool:
    return result.status == "ok" and not result.is_error


def _error_detail(result: CallResult, hint: str) -> str:
    if result.status == "ok":
        shown = _show(result.text)
        detail = f"the tool returned an error: {shown}" if shown else "the tool returned an error with no text"
    else:
        detail = f"{result.status}: {_show(result.detail)}"
    if hint or (result.status == "rpc_error" and result.detail.startswith(_INVALID_PARAMS)):
        detail += _ARGS_HINT
    return detail


def _plan(tool: ToolInfo, base: Baseline, run_id: str, start: int,
          extra_paths: Sequence[str]) -> list[PlannedCall]:
    """The tool's session-A calls; call i gets seq start + i, and each relay canary carries its own call's seq."""
    first = baseline_call(tool.name, base)
    if base.hint == _NO_SCHEMA:
        return [first]
    # A dry run finds where the relay calls sit, so canary seq equals record seq without assuming the layout.
    shape = payload_calls(tool.name, base, run_id, lambda: 0, extra_paths=extra_paths)
    slots = iter([start + 1 + i for i, c in enumerate(shape) if c.family == "relay"])
    return [first, *payload_calls(tool.name, base, run_id, lambda: next(slots), extra_paths=extra_paths)]


class _Runner:
    def __init__(self, session_a: McpSession, open_session: Callable[[], AsyncContextManager[McpSession]]) -> None:
        self.current: Any = session_a
        self.open_session = open_session
        self.sessions: list[Any] = [session_a]
        self.restart_cm: AsyncContextManager[Any] | None = None
        self.restarts = 0
        self.notes: list[str] = []

    async def close_restart(self) -> None:
        cm, self.restart_cm = self.restart_cm, None
        if cm is not None:
            await cm.__aexit__(None, None, None)

    async def restart(self) -> bool:
        """Replace a dead session A; False once RESTARTS_MAX new sessions have been used."""
        while self.restarts < RESTARTS_MAX:
            self.restarts += 1
            await self.close_restart()
            cm = self.open_session()
            try:
                session = await cm.__aenter__()
            except Exception as exc:
                self.notes.append(f"Restart {self.restarts} of {RESTARTS_MAX} could not open a new session "
                                  f"({_reason(exc)}).")
                continue
            self.restart_cm, self.current = cm, session
            self.sessions.append(session)
            self.notes.append(f"The server session closed; opened a new one (restart {self.restarts} of "
                              f"{RESTARTS_MAX}).")
            return True
        return False


def _reason(exc: Exception) -> str:
    return _show(str(exc)) if isinstance(exc, ConnectError) else type(exc).__name__


async def run_calls(session_a: McpSession, open_session: Callable[[], AsyncContextManager[McpSession]],
                    tools: list[ToolInfo], *, overrides: Mapping[str, dict], run_id: str,
                    extra_paths: Sequence[str] = (), hooks: CallHooks | None = None,
                    echo: Callable[[str], None] = lambda s: None) -> CallRun:
    """Call `tools` (already selected by policy) and account for every one of them in `outcomes`."""
    run = _Runner(session_a, open_session)
    records: list[CallRecord] = []
    hook_hits: list[Hit] = []
    skipped: dict[str, ToolOutcome] = {}
    bases: dict[str, Baseline] = {}
    stopped: dict[str, str] = {}
    next_seq = 1
    called = 0
    try:
        if hooks is not None:
            await hooks.before_calls()
        for tool in tools:
            if skipped:  # once the cap or the restarts run out, every later tool is untested too
                skipped[tool.name] = dataclasses.replace(next(iter(skipped.values())))
                continue
            base = baseline(tool.input_schema, overrides.get(tool.name))
            plan = _plan(tool, base, run_id, next_seq, extra_paths)
            # Room for this tool's calls plus one replay for it and for every tool already called.
            if len(records) + len(plan) + called + 1 > CALLS_MAX:
                skipped[tool.name] = ToolOutcome("not_tested_cap", 0, REASON_CAP)
                continue
            if not run.current.alive and not await run.restart():
                skipped[tool.name] = ToolOutcome("not_tested_server", 0, REASON_SERVER)
                continue
            bases[tool.name] = base
            timeouts = 0
            for i, call in enumerate(plan):
                result = await run.current.call(call.tool, call.arguments)
                records.append(CallRecord(next_seq + i, "A", call, result))
                if not run.current.alive:
                    break
                timeouts = timeouts + 1 if result.status == "timeout" else 0
                if timeouts >= TOOL_TIMEOUTS_MAX:
                    stopped[tool.name] = f"stopped after {TOOL_TIMEOUTS_MAX} consecutive timeouts"
                    break
            next_seq += len(plan)
            called += 1
            echo(f"  {_show(tool.name)}: {i + 1} call(s)")
            if hooks is not None and tool.read_only:
                hook_hits.extend(await hooks.after_tool(tool))
        _note_skipped(skipped, run.notes)

        final_tools = None
        if run.current.alive:
            try:
                final_tools, list_notes = await run.current.list_tools()
                run.notes.extend(list_notes)
            except ConnectError as exc:
                run.notes.append(f"The second tools/list failed ({_reason(exc)}).")
        else:
            run.notes.append("The second tools/list did not run: the session had closed.")

        good = {r.call.tool for r in records if _good(r.result)}
        replay = [t for t in tools if t.name in good]
        if replay:
            echo(f"  replaying {len(replay)} tool(s) in a second session")
            cm = open_session()
            try:
                session_b = await cm.__aenter__()
            except Exception as exc:
                run.notes.append(f"The second session could not be opened, so no tool was replayed ({_reason(exc)}).")
            else:
                run.sessions.append(session_b)
                try:
                    for tool in replay:
                        if not session_b.alive:
                            run.notes.append("The second session closed before every tool was replayed.")
                            break
                        if len(records) >= CALLS_MAX:  # the reservation above should make this unreachable
                            break
                        call = dataclasses.replace(baseline_call(tool.name, bases[tool.name]), family="replay")
                        records.append(CallRecord(next_seq, "B", call, await session_b.call(call.tool, call.arguments)))
                        next_seq += 1
                finally:
                    await cm.__aexit__(None, None, None)
    finally:
        await run.close_restart()

    outcomes = _outcomes(tools, records, bases, skipped, stopped)
    return CallRun(records=records, final_tools=final_tools, list_changed=any(s.list_changed for s in run.sessions),
                   outcomes=outcomes, hook_hits=hook_hits, notes=run.notes)


def _note_skipped(skipped: dict[str, ToolOutcome], notes: list[str]) -> None:
    if not skipped:
        return
    status = next(iter(skipped.values())).status
    if status == "not_tested_cap":
        notes.append(f"The call cap of {CALLS_MAX} was reached; {len(skipped)} tool(s) were not tested.")
    else:
        notes.append(f"The server session kept closing and all {RESTARTS_MAX} restarts were used; "
                     f"{len(skipped)} tool(s) were not tested.")


def _outcomes(tools: list[ToolInfo], records: list[CallRecord], bases: dict[str, Baseline],
              skipped: dict[str, ToolOutcome], stopped: dict[str, str]) -> dict[str, ToolOutcome]:
    by_tool: dict[str, list[CallRecord]] = {}
    for r in records:
        by_tool.setdefault(r.call.tool, []).append(r)
    outcomes: dict[str, ToolOutcome] = {}
    for tool in tools:
        if tool.name in skipped:
            outcomes[tool.name] = skipped[tool.name]
            continue
        recs = by_tool.get(tool.name, [])
        if any(_good(r.result) for r in recs):
            outcomes[tool.name] = ToolOutcome("called", len(recs), stopped.get(tool.name, ""))
        else:
            outcomes[tool.name] = ToolOutcome("not_exercised", len(recs),
                                              _error_detail(recs[0].result, bases[tool.name].hint))
    return outcomes
