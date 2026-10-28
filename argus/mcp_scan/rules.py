"""Text rules for scan-mcp: hidden characters, injection phrases, secret patterns, redaction, judge pre-filter."""
from __future__ import annotations

import re
from typing import Sequence

EXCERPT = 300

_HIDDEN = re.compile(
    r"(?P<zero_width>[​-‍⁠﻿])"
    r"|(?P<bidi>[‪-‮⁦-⁩])"
    r"|(?P<tag>[\U000e0000-\U000e007f])"
    r"|(?P<control>[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f])")

_PHRASES = [(rule, re.compile(p, re.I)) for rule, p in (
    ("ignore_previous", r"ignore\s+(all\s+)?(previous|prior)\s+instructions"),
    ("important_tag", r"<\s*important\s*>"),
    ("dont_tell_user", r"do\s+not\s+(tell|mention)\b[^.\n]{0,40}\bthe\s+user"),
    ("before_using", r"before\s+using\s+this\s+tool"),
    ("role_tag", r"<\s*/?\s*(system|assistant)\s*>"),
    ("ssh_ref", r"~/\.ssh|\bid_(rsa|ed25519|ecdsa)\b"),
    ("dotenv_ref", r"(?<![\w.])\.env\b"),
    ("mcp_json_ref", r"\bmcp\.json\b"),
)]

# Specific kinds before `assignment`, so a value both match is reported as the specific kind.
_SECRETS = [(kind, re.compile(p)) for kind, p in (
    ("private_key", r"-----BEGIN ([A-Z ]*)PRIVATE KEY-----"),
    ("aws_access_key", r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("github_token", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}"),
    ("sk_key", r"\bsk-[A-Za-z0-9_-]{20,}"),
    ("stripe_key", r"\b[rs]k_live_[A-Za-z0-9]{16,}"),
    ("slack_token", r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    ("jwt", r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    ("assignment", r"(?i)\b(password|passwd|secret|token|api[_-]?key|access[_-]?key)\s*[:=]\s*[\"']?([^\s\"',;]{8,})"),
)]
_KEY_SPAN_MAX = 4000
_PLACEHOLDER = re.compile(r"\[(?:DECOY|REDACTED):[^\]\s]*\]")
_VALUE_MIN = 8

_IMPERATIVE = re.compile(
    r"(?:^|[.!?]\s+|\n)\s*(?:you\s+(?:must|should|need\s+to)|always|never|make\s+sure|remember\s+to|first,?\s+call)\b",
    re.I)
_USER_OR_ASSISTANT = re.compile(r"\bthe\s+(?:user|assistant)\b", re.I)
_URL = re.compile(r"https?://[^\s<>\"')]+", re.I)
_SEND_VERB = re.compile(r"\b(?:send|post|upload|forward|submit)(?:s|ed|ing|ted|ting)?\b", re.I)
_URL_VERB_GAP = 40


def hidden_chars(text: str) -> list[tuple[str, int]]:
    """(kind, index) of every zero-width, bidi, tag or control character. Tab, LF and CR are not hidden."""
    return [(m.lastgroup, m.start()) for m in _HIDDEN.finditer(text)]


def injection_phrases(text: str) -> list[tuple[str, int, int]]:
    """(rule, start, end) of every known injection phrase, in text order."""
    hits = [(rule, m.start(), m.end()) for rule, rx in _PHRASES for m in rx.finditer(text)]
    return sorted(hits, key=lambda h: (h[1], h[2]))


def _skipped(value: str) -> bool:
    # Argus canaries, and values that are only an earlier pass's placeholders, so redact is idempotent.
    return value.startswith("ARGUS") or bool(_PLACEHOLDER.search(value)
                                             and len(_PLACEHOLDER.sub("", value)) < _VALUE_MIN)


def secret_hits(text: str) -> list[tuple[str, int, int]]:
    """(kind, start, end) of every secret-shaped value, merged so that no two spans overlap."""
    found = []
    for rank, (kind, rx) in enumerate(_SECRETS):
        for m in rx.finditer(text):
            if kind == "private_key":
                end_marker = f"-----END {m.group(1)}PRIVATE KEY-----"
                i = text.find(end_marker, m.end())
                s, e = m.start(), (i + len(end_marker) if i >= 0 else min(m.start() + _KEY_SPAN_MAX, len(text)))
            elif kind == "assignment":
                s, e = m.span(2)
            else:
                s, e = m.span()
            if not _skipped(text[s:e]):
                found.append((s, rank, e, kind))
    merged: list[list] = []  # [start, end, rank, kind]
    for s, rank, e, kind in sorted(found):
        if merged and s < merged[-1][1]:
            last = merged[-1]
            last[1] = max(last[1], e)
            if rank < last[2]:
                last[2], last[3] = rank, kind
        else:
            merged.append([s, e, rank, kind])
    return [(kind, s, e) for s, e, _, kind in merged]


def _decoy_spans(text: str, decoys: Sequence[tuple[str, str]]) -> list[tuple[int, int, str]]:
    spans: list[tuple[int, int, str]] = []
    for name, marker in sorted(decoys, key=lambda d: len(d[1]), reverse=True):
        if not marker:
            continue
        i = text.find(marker)
        while i >= 0:
            j = i + len(marker)
            if all(j <= s or i >= e for s, e, _ in spans):
                spans.append((i, j, f"[DECOY:{name}]"))
            i = text.find(marker, j if j > i else i + 1)
    return sorted(spans)


def _apply(text: str, spans: list[tuple[int, int, str]]) -> tuple[str, list[tuple[int, int, int, int]]]:
    """Replace sorted, non-overlapping spans. Returns the text and (old_start, old_end, new_start, new_end)."""
    out, regions, pos, n = [], [], 0, 0
    for s, e, repl in spans:
        out.append(text[pos:s])
        n += s - pos
        regions.append((s, e, n, n + len(repl)))
        out.append(repl)
        n += len(repl)
        pos = e
    out.append(text[pos:])
    return "".join(out), regions


def _map(p: int, regions: list[tuple[int, int, int, int]], is_end: bool) -> int:
    """Where position p of the old text lands in the new one; inside a replaced span, at its edge."""
    out = p
    for os_, oe, ns, ne in regions:
        if p >= oe:
            out = ne + (p - oe)
        elif p > os_:
            return ne if is_end else ns
        else:
            break
    return out


def _redacted(text: str, decoys: Sequence[tuple[str, str]]):
    s1, r1 = _apply(text, _decoy_spans(text, decoys))
    out, r2 = _apply(s1, [(s, e, f"[REDACTED:{kind}]") for kind, s, e in secret_hits(s1)])
    return out, r1, r2


def redact(text: str, decoys: Sequence[tuple[str, str]] = ()) -> str:
    """Each decoy marker becomes [DECOY:<name>], then each secret-shaped value becomes [REDACTED:<kind>]."""
    return _redacted(text, decoys)[0]


def _render(text: str) -> str:
    return _HIDDEN.sub(lambda m: f"<U+{ord(m.group()):04X}>", text)


def excerpt(text: str, start: int, end: int, decoys: Sequence[tuple[str, str]] = ()) -> str:
    """At most EXCERPT characters centred on text[start:end], redacted, hidden characters shown as <U+XXXX>."""
    # Redact the whole text before cutting: a window edge inside a secret would keep a prefix no pattern matches.
    red, r1, r2 = _redacted(text, decoys)
    rs, re_ = _map(_map(start, r1, False), r2, False), _map(_map(end, r1, True), r2, True)
    if re_ - rs >= EXCERPT:
        ws, we = rs, rs + EXCERPT
    else:
        ws = max(0, rs - (EXCERPT - (re_ - rs)) // 2)
        we = min(len(red), ws + EXCERPT)
        ws = max(0, we - EXCERPT)
    # Do not show half a placeholder at either edge.
    placeholders = [(ns, ne) for _, _, ns, ne in r2]
    placeholders += [(_map(ns, r2, False), _map(ne, r2, True)) for _, _, ns, ne in r1]
    for a, b in placeholders:
        if a < ws < b:
            ws = b
        if a < we < b:
            we = a
    return _render(red[ws:we])


def strip_payload(text: str, payload: str | None) -> str:
    """The text with every verbatim copy of the payload removed."""
    return text.replace(payload, "") if payload else text


def looks_aimed_at_model(text: str, tool_names: Sequence[str]) -> bool:
    """Cheap judge pre-filter: text that talks to a model rather than describing data.

    `tool_names` are the other tools the server listed."""
    if _IMPERATIVE.search(text) or _USER_OR_ASSISTANT.search(text):
        return True
    names = [re.escape(n) for n in tool_names if n]
    if names and re.search(r"(?<![\w-])(?:" + "|".join(names) + r")(?![\w-])", text):
        return True
    verbs = [m.span() for m in _SEND_VERB.finditer(text)]
    for u in _URL.finditer(text):
        if any(ve >= u.start() - _URL_VERB_GAP and vs <= u.end() + _URL_VERB_GAP for vs, ve in verbs):
            return True
    return False
