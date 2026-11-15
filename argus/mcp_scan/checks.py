"""Deterministic scan-mcp checks on tool-list texts and call results; text they cannot decide becomes a judge candidate."""
from __future__ import annotations

import json
import os
import re
from typing import Iterator, Sequence

from argus.mcp_scan import rules
from argus.mcp_scan.models import CallRecord, Candidate, Hit, ToolInfo
from argus.mcp_scan.payloads import TRAV_DIR
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
# A traversal witness: the marker file's path seen resolved outside the root, with no file content needed.
WITNESS = "escape_witness"
WITNESS_SOURCES = ("result", "stderr", "witness_log")
WITNESS_NOTES_MAX = 5
_SOURCE_NAMES = {"result": "Tool result", "stderr": "Server stderr", "witness_log": "Witness log"}
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
    names = tuple(t.name for t in tools)
    for tool in tools:
        texts = [(DESCRIPTION, "description", s) for s in (tool.name, tool.title, tool.description)]
        texts += [(DESCRIPTION, "description", s) for s in _strings(tool.annotations)]
        texts += [(SCHEMA, "schema", s) for s in _schema_strings(tool.input_schema)]
        for probe, source, text in texts:
            if not text:
                continue
            found, phrased = _phrase_and_hidden(probe, tool.name, text, decoys)
            hits += found
            if not phrased and rules.looks_aimed_at_model(text, names, own=tool.name):
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


def _secret_hits(rec: CallRecord, text: str, decoys, mask: rules.Mask) -> list[Hit]:
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
    echoes = _marker_spans(text, [("sent", mask(value)) for value in _strings(rec.call.arguments)])
    spans = [(k, s, e) for k, s, e in rules.secret_hits(text) if not any(s < me and ms < e for ms, me in markers)
             and not any(es <= s and e <= ee for es, ee in echoes)]
    first = sorted(_first_by_rule(spans).items(), key=lambda kv: (-secret_confidence(kv[0]), kv[1][0]))
    for kind, span in first:
        generic = kind in _GENERIC_SECRET_KINDS
        out.append(_hit(SECRET, tool, f"secret:{kind}", text, span, decoys, seq=seq, family=family,
                        confidence=secret_confidence(kind), reasoning=_GENERIC_SECRET_REASON if generic else ""))
    return out


def _strip_sent(text: str, sent: Sequence[str]) -> str:
    """The text without any payload this run sent; every relay and cmd payload carries ARGUS."""
    if "ARGUS" not in text:
        return text
    for payload in sent:
        text = text.replace(payload, "")
    return text


def _canaries(text: str) -> set[str]:
    return set(_CANARY.findall(text))


def _changed_at(old: str, new: str) -> tuple[str, tuple[int, int]]:
    """The new text and a span from the first character that differs, so the excerpt shows the change."""
    if not new:
        return "(now empty)", (0, 0)
    i = len(os.path.commonprefix([old, new]))
    return new, (i, len(new))


def _list_changes(first: list[ToolInfo], final: list[ToolInfo]) -> list[tuple[str, str, tuple[int, int]]]:
    """(tool name, text, span) for each tool added, removed, or relisted with another description or schema."""
    a = {t.name: t for t in first}
    b = {t.name: t for t in final}
    out = []
    for name in list(a) + [n for n in b if n not in a]:
        old, new = a.get(name), b.get(name)
        if new is None:
            text = f"removed: {old.description}"
            out.append((name, text, (0, len(text))))
        elif old is None:
            text = f"added: {new.description}"
            out.append((name, text, (0, len(text))))
        elif old.description != new.description:
            out.append((name, *_changed_at(old.description, new.description)))
        elif old.input_schema != new.input_schema:
            dump = lambda s: json.dumps(s, sort_keys=True, default=str)  # noqa: E731
            out.append((name, *_changed_at(dump(old.input_schema), dump(new.input_schema))))
    return out


def dynamic_hits(records: list[CallRecord], first_tools: list[ToolInfo], final_tools: list[ToolInfo] | None,
                 list_changed: bool, *, decoys: Sequence[tuple[str, str]] = (),
                 mask: rules.Mask = rules.same) -> tuple[list[Hit], list[Candidate]]:
    """Rule hits in every call result that has text, plus tool-list changes; aimed-at-model text becomes a candidate.

    `mask` is the one the result texts went through, so payloads are compared in the same masked form."""
    hits: list[Hit] = []
    cands: list[Candidate] = []
    names = tuple(t.name for t in first_tools)
    planted = set()
    for rec in records:
        if rec.session == "A" and rec.call.family == "relay" and rec.call.payload:
            planted |= _canaries(rec.call.payload)
    # A store-and-recall tool returns a payload from another call; that text is Argus's, not the server's.
    sent = sorted({mask(r.call.payload) for r in records if r.call.family in ("relay", "cmd") and r.call.payload},
                  key=len, reverse=True)
    for rec in records:
        text, call = rec.result.text, rec.call
        if not text:
            continue
        tool, seq, family = call.tool, rec.seq, call.family
        payload, expect = mask(call.payload or ""), mask(call.expect or "")
        if family == "cmd" and expect and expect in text:
            i = text.index(expect)
            hits.append(_hit(COMMAND, tool, "cmd_marker", text, (i, i + len(expect)), decoys, seq=seq, family=family))
        if ETC_PASSWD in text:
            i = text.index(ETC_PASSWD)
            hits.append(_hit(TRAVERSAL, tool, "etc_passwd", text, (i, i + len(ETC_PASSWD)), decoys, seq=seq, family=family))
        hits += _secret_hits(rec, text, decoys, mask)
        # The server's own words only: an echo of any payload is reflection or a cross-session leak, not injection.
        stripped = rules.strip_payload(text, payload)
        own_words = _strip_sent(stripped, sent)
        found, phrased = _phrase_and_hidden(INJECTION, tool, own_words, decoys, seq=seq, family=family)
        hits += found
        if rec.session == "B" and planted:
            own = _canaries(call.payload or "")
            for m in _CANARY.finditer(stripped):
                if m.group() in planted and m.group() not in own:
                    hits.append(_hit(CROSS_SESSION, tool, "canary_from_session_a", stripped, m.span(), decoys,
                                     seq=seq, family=family))
                    break
        if payload and rec.result.status == "ok" and not rec.result.is_error and payload in text:
            i = text.index(payload)
            hits.append(_hit(REFLECTION, tool, "reflected_payload", text, (i, i + len(payload)), decoys,
                             seq=seq, family=family))
        if not phrased and rules.looks_aimed_at_model(own_words, names, own=tool):
            cands.append(Candidate(probe_id=INJECTION, tool=tool, text=rules.redact(own_words, decoys),
                                   call_seq=seq, source="result"))
    if final_tools is not None:
        for name, text, span in _list_changes(first_tools, final_tools):
            hits.append(_hit(LIST_CHANGED, name, "relisted_differs", text, span, decoys))
    if list_changed:
        note = "notifications/tools/list_changed"
        hits.append(_hit(LIST_CHANGED, None, "list_changed_notification", note, (0, len(note)), decoys))
    return hits, cands



def _resolved(run_id: str) -> re.Pattern:
    """This run's marker path with every `../` collapsed: /tmp/<marker> at a word start or a URL's path root.

    Raw (`../../tmp/<marker>`), encoded and still-contained (`/srv/root/tmp/<marker>`) forms do not match."""
    return re.compile(r"(?:(?<![^\s\"'`=(\[<,;|>])|\b[a-z][a-z0-9+.-]*://[^/\s\"'<>]*)" + re.escape(TRAV_DIR)
                      + r"(argus-trav-" + re.escape(run_id) + r"-(\d+))(?!\d)", re.I)


def _one_line(text: str, start: int, end: int, decoys: Sequence[tuple[str, str]]) -> str:
    return " ".join(rules.excerpt(text, start, end, decoys).split())


def witness_hits(records: list[CallRecord], lines: Sequence[tuple[str, str]], run_id: str, *,
                 decoys: Sequence[tuple[str, str]] = ()) -> tuple[list[Hit], list[str]]:
    """Traversal hits from this run's markers seen resolved, in call results and in `lines` of (source, text), plus
    a note per stderr or log line where a marker arrived only unresolved or still inside the root.

    `lines` must already be masked; a marker maps to its own call by the seq it carries, wherever it shows up."""
    marked = {r.seq: r for r in records if r.call.family == "path" and r.call.expect}
    if not marked:
        return [], []
    resolved = _resolved(run_id)
    raw = re.compile(r"argus-trav-" + re.escape(run_id) + r"-(\d+)(?!\d)")
    sent = sorted({r.call.payload for r in marked.values() if r.call.payload}, key=len, reverse=True)
    texts: list[tuple[str, str]] = []
    for rec in records:
        text = rec.result.text or (rec.result.detail if rec.result.status == "rpc_error" else "")
        # An echo of what Argus sent never counts: only the server's own resolved path does.
        for payload in sent:
            text = rules.strip_payload(text, payload)
        if raw.search(text):
            texts.append(("result", text))
    texts += [(src, line) for src, line in lines if raw.search(line)]
    hits: list[Hit] = []
    seen: set[tuple[str, int]] = set()
    notes: dict[str, list[str]] = {}
    for source, text in texts:
        found = False
        for m in resolved.finditer(text):
            rec = marked.get(int(m.group(2)))
            if rec is None or rec.call.expect != m.group(1).lower():
                continue
            found = True
            if (source, rec.seq) not in seen:
                seen.add((source, rec.seq))
                hits.append(_hit(TRAVERSAL, rec.call.tool, f"{WITNESS}:{source}", text, m.span(), decoys,
                                 seq=rec.seq, family="path"))
        if found or source == "result":
            continue
        m = next((m for m in raw.finditer(text) if int(m.group(1)) in marked), None)
        if m is not None:
            rec = marked[int(m.group(1))]
            tool = _one_line(rec.call.tool, 0, len(rec.call.tool), ())
            notes.setdefault(source, []).append(
                f"{_SOURCE_NAMES[source]}: the traversal payload of call {rec.seq} ({tool}, {rec.call.param}) "
                f"arrived unresolved or still inside the root, so it is not counted as an escape: "
                f"{_one_line(text, m.start(), m.end(), decoys)}")
    out: list[str] = []
    for source, found_notes in notes.items():
        out += found_notes[:WITNESS_NOTES_MAX]
        if len(found_notes) > WITNESS_NOTES_MAX:
            out.append(f"{_SOURCE_NAMES[source]}: {len(found_notes) - WITNESS_NOTES_MAX} more line(s) held a "
                       "traversal payload unresolved.")
    return hits, out
