"""Deterministic scan-mcp checks on tool-list texts and call results; text they cannot decide becomes a judge candidate."""
from __future__ import annotations

import json
import re
from typing import Iterator, Sequence

from argus.mcp_scan import rules
from argus.mcp_scan.models import CallRecord, Candidate, Hit, ToolInfo
from argus.skillscan.decoys import make_decoys

DESCRIPTION = "mcp_scan_description_instructions"
SCHEMA = "mcp_scan_schema_instructions"
HIDDEN = "mcp_scan_hidden_characters"
COMMAND = "mcp_scan_command_execution"
TRAVERSAL = "mcp_scan_path_traversal"
SECRET = "mcp_scan_secret_in_result"
INJECTION = "mcp_scan_result_injection"
CROSS_SESSION = "mcp_scan_cross_session_leak"
REFLECTION = "mcp_scan_input_reflection"
LIST_CHANGED = "mcp_scan_tool_list_changed"

ETC_PASSWD = "root:x:0:0:"
_CANARY = re.compile(r"ARGUS-[a-z0-9]{6}-\d+(?!\d)")
# Sandbox decoys are named by env var or by file kind; only a file decoy's marker proves a file read.
FILE_DECOY_NAMES = frozenset(d.kind for d in make_decoys(seed="") if d.kind != "env")

# A secret-named assignment such as {"key": "forecast_today"} is often an ordinary value, so it ranks
# below the provider-shaped kinds and sorts after them.
GENERIC_SECRET_CONFIDENCE = 0.5
_GENERIC_SECRET_KINDS = frozenset({"assignment"})
_GENERIC_SECRET_REASON = "A secret-named field with an ordinary-looking value; it may not be a secret."
# Schema keywords whose values map names to subschemas, so a property called "default" is not the keyword.
_SCHEMA_MAPS = frozenset({"properties", "patternProperties", "$defs", "definitions", "dependentSchemas"})


def secret_confidence(kind: str) -> float:
    """1.0 for provider-shaped secrets, key blocks, URL credentials and auth headers; lower for generic assignments."""
    return GENERIC_SECRET_CONFIDENCE if kind in _GENERIC_SECRET_KINDS else 1.0


def _strings(value) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from _strings(v)


def _schema_strings(node) -> Iterator[str]:
    """Every description, default, enum item and examples item in a JSON schema, at any depth."""
    if isinstance(node, list):
        for item in node:
            yield from _schema_strings(item)
        return
    if not isinstance(node, dict):
        return
    for key, value in node.items():
        if key in _SCHEMA_MAPS and isinstance(value, dict):
            for sub in value.values():
                yield from _schema_strings(sub)
        elif key == "description" and isinstance(value, str):
            yield value
        elif key in ("default", "enum", "examples"):
            yield from _strings(value)
        else:
            yield from _schema_strings(value)


def _first_by_rule(matches) -> dict:
    """The first (start, end) of each rule, so each text is excerpted once per rule."""
    first: dict = {}
    for rule, start, end in matches:
        first.setdefault(rule, (start, end))
    return first


def _hit(probe, tool, rule, text, span, decoys, *, seq=None, family=None, decoy=None, confidence=1.0, reasoning=""):
    return Hit(probe_id=probe, tool=tool, rule=rule, excerpt=rules.excerpt(text, span[0], span[1], decoys),
               call_seq=seq, family=family, decided_by="rule", decoy=decoy, confidence=confidence,
               reasoning=reasoning)


def _phrase_and_hidden(probe, tool, text, decoys, *, seq=None, family=None) -> tuple[list[Hit], bool]:
    hits = [_hit(probe, tool, f"phrase:{r}", text, span, decoys, seq=seq, family=family)
            for r, span in _first_by_rule(rules.injection_phrases(text)).items()]
    phrased = bool(hits)
    hidden = _first_by_rule((kind, i, i + 1) for kind, i in rules.hidden_chars(text))
    hits += [_hit(HIDDEN, tool, f"hidden:{k}", text, span, decoys, seq=seq, family=family) for k, span in hidden.items()]
    return hits, phrased


def static_hits(tools: list[ToolInfo], *, decoys: Sequence[tuple[str, str]] = ()) -> tuple[list[Hit], list[Candidate]]:
    """Phrase and hidden-character hits in tool names, titles, descriptions, annotations and schema strings."""
    hits: list[Hit] = []
    cands: list[Candidate] = []
    for tool in tools:
        others = [t.name for t in tools if t.name != tool.name]
        texts = [(DESCRIPTION, "description", s) for s in (tool.name, tool.title, tool.description)]
        texts += [(DESCRIPTION, "description", s) for s in _strings(tool.annotations)]
        texts += [(SCHEMA, "schema", s) for s in _schema_strings(tool.input_schema)]
        for probe, source, text in texts:
            if not text:
                continue
            found, phrased = _phrase_and_hidden(probe, tool.name, text, decoys)
            hits += found
            if not phrased and rules.looks_aimed_at_model(text, others):
                cands.append(Candidate(probe_id=probe, tool=tool.name, text=rules.redact(text, decoys),
                                       call_seq=None, source=source))
    return hits, cands


def _marker_spans(text: str, decoys: Sequence[tuple[str, str]]) -> list[tuple[int, int]]:
    spans = []
    for _, marker in decoys:
        i = text.find(marker) if marker else -1
        while i >= 0:
            spans.append((i, i + len(marker)))
            i = text.find(marker, i + len(marker))
    return spans


def _secret_hits(rec: CallRecord, text: str, decoys) -> list[Hit]:
    tool, seq, family = rec.call.tool, rec.seq, rec.call.family
    out = []
    for name, marker in decoys:
        i = text.find(marker) if marker else -1
        if i < 0:
            continue
        span = (i, i + len(marker))
        if name in FILE_DECOY_NAMES:
            out.append(_hit(TRAVERSAL, tool, f"decoy_file:{name}", text, span, decoys, seq=seq, family=family, decoy=name))
        out.append(_hit(SECRET, tool, f"decoy:{name}", text, span, decoys, seq=seq, family=family, decoy=name))
    # A decoy is reported as a decoy, not again as the secret shape it imitates.
    markers = _marker_spans(text, decoys)
    spans = [(k, s, e) for k, s, e in rules.secret_hits(text) if not any(s < me and ms < e for ms, me in markers)]
    first = sorted(_first_by_rule(spans).items(), key=lambda kv: (-secret_confidence(kv[0]), kv[1][0]))
    for kind, span in first:
        generic = kind in _GENERIC_SECRET_KINDS
        out.append(_hit(SECRET, tool, f"secret:{kind}", text, span, decoys, seq=seq, family=family,
                        confidence=secret_confidence(kind), reasoning=_GENERIC_SECRET_REASON if generic else ""))
    return out


def _canaries(text: str) -> set[str]:
    return set(_CANARY.findall(text))


def _list_changes(first: list[ToolInfo], final: list[ToolInfo]) -> list[tuple[str, str]]:
    """(tool name, what changed) for each tool added, removed, or relisted with another description or schema."""
    a = {t.name: t for t in first}
    b = {t.name: t for t in final}
    out = []
    for name in list(a) + [n for n in b if n not in a]:
        old, new = a.get(name), b.get(name)
        if new is None:
            out.append((name, f"removed: {old.description}"))
        elif old is None:
            out.append((name, f"added: {new.description}"))
        elif old.description != new.description:
            out.append((name, f"description was: {old.description} | now: {new.description}"))
        elif old.input_schema != new.input_schema:
            out.append((name, f"input schema now: {json.dumps(new.input_schema, sort_keys=True)}"))
    return out


def dynamic_hits(records: list[CallRecord], first_tools: list[ToolInfo], final_tools: list[ToolInfo] | None,
                 list_changed: bool, *, decoys: Sequence[tuple[str, str]] = ()) -> tuple[list[Hit], list[Candidate]]:
    """Rule hits in every call result that has text, plus tool-list changes; aimed-at-model text becomes a candidate."""
    hits: list[Hit] = []
    cands: list[Candidate] = []
    names = [t.name for t in first_tools]
    planted = set()
    for rec in records:
        if rec.session == "A" and rec.call.family == "relay" and rec.call.payload:
            planted |= _canaries(rec.call.payload)
    for rec in records:
        text, call = rec.result.text, rec.call
        if not text:
            continue
        tool, seq, family = call.tool, rec.seq, call.family
        if family == "cmd" and call.expect and call.expect in text:
            i = text.index(call.expect)
            hits.append(_hit(COMMAND, tool, "cmd_marker", text, (i, i + len(call.expect)), decoys, seq=seq, family=family))
        if ETC_PASSWD in text:
            i = text.index(ETC_PASSWD)
            hits.append(_hit(TRAVERSAL, tool, "etc_passwd", text, (i, i + len(ETC_PASSWD)), decoys, seq=seq, family=family))
        hits += _secret_hits(rec, text, decoys)
        # The server's own words only: an echo of the payload is reflection, not injection.
        stripped = rules.strip_payload(text, call.payload)
        found, phrased = _phrase_and_hidden(INJECTION, tool, stripped, decoys, seq=seq, family=family)
        hits += found
        if rec.session == "B" and planted:
            own = _canaries(call.payload or "")
            for m in _CANARY.finditer(stripped):
                if m.group() in planted and m.group() not in own:
                    hits.append(_hit(CROSS_SESSION, tool, "canary_from_session_a", stripped, m.span(), decoys,
                                     seq=seq, family=family))
                    break
        if call.payload and rec.result.status == "ok" and not rec.result.is_error and call.payload in text:
            i = text.index(call.payload)
            hits.append(_hit(REFLECTION, tool, "reflected_payload", text, (i, i + len(call.payload)), decoys,
                             seq=seq, family=family))
        if not phrased and rules.looks_aimed_at_model(stripped, [n for n in names if n != tool]):
            cands.append(Candidate(probe_id=INJECTION, tool=tool, text=rules.redact(stripped, decoys),
                                   call_seq=seq, source="result"))
    if final_tools is not None:
        for name, change in _list_changes(first_tools, final_tools):
            hits.append(_hit(LIST_CHANGED, name, "relisted_differs", change, (0, len(change)), decoys))
    if list_changed:
        note = "notifications/tools/list_changed"
        hits.append(_hit(LIST_CHANGED, None, "list_changed_notification", note, (0, len(note)), decoys))
    return hits, cands
