"""Text rules for scan-mcp: hidden characters, injection phrases, secret patterns, redaction, judge pre-filter."""
from __future__ import annotations

import bisect
import functools
import re
from typing import Sequence

from argus.skillscan.urls import url_userinfo

EXCERPT = 300

_HIDDEN = re.compile(
    r"(?P<zero_width>[\U0000200B-\U0000200D\U00002060\U0000FEFF])"
    r"|(?P<bidi>[\U0000202A-\U0000202E\U00002066-\U00002069])"
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

# Specific kinds before the generic ones, so a value several match is reported as the specific kind.
_SECRETS = [(kind, re.compile(p)) for kind, p in (
    ("private_key", r"-----BEGIN ([A-Z ]*)PRIVATE KEY( BLOCK)?-----"),
    ("aws_access_key", r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("github_token", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}"),
    ("gitlab_token", r"\bglpat-[A-Za-z0-9_-]{20,}"),
    ("google_api_key", r"\bAIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])"),
    ("hf_token", r"\bhf_[A-Za-z0-9]{30,}"),
    ("npm_token", r"\bnpm_[A-Za-z0-9]{36,}"),
    ("sk_key", r"\bsk-[A-Za-z0-9_-]{20,}"),
    ("stripe_key", r"\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}"),
    ("slack_token", r"\bxox[abeprs]-[A-Za-z0-9-]{10,}|\bxapp-[0-9]+-[A-Za-z0-9-]{10,}"),
    ("jwt", r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    ("url_credentials", r"(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]{0,30}://[^\s\"'<>`]+"),
    ("auth_header", r"(?i)\bauthorization\\?[\"']?[ \t]*[:=][ \t]*\\?[\"']?(?:[a-z]{1,20}[ \t]+)?([A-Za-z0-9._~+/=-]{8,})"),
    ("bearer_token", r"\b[Bb]earer[ \t]+([A-Za-z0-9._~+/=-]{8,})"),
    # A name, its optional closing quote (plain or JSON-escaped), then : or =. The value is read by hand.
    ("assignment", r"(?<![\w.-])([A-Za-z_][\w.-]{0,63})(\\?[\"'])?[ \t]*[:=][ \t]*"),
)]
SECRET_WORDS = frozenset({"password", "passwd", "pwd", "passphrase", "secret", "secrets", "token", "key", "apikey",
                          "accesskey", "privatekey", "auth", "credential", "credentials"})
# Name parts: split on _ . - and camelCase, so keyboard, monkey and oauth are not secret names.
_NAME_SPLIT = re.compile(r"[_.\-]+|(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")
_BARE_VALUE = re.compile(r"(?:[^\s\",;\\]|\\(?![\"']))+")  # a backslash ends it only before an escaped quote
_TOKENISH = re.compile(r"[0-9._~+/=-]")
_BLANK_LINE = re.compile(r"\n[ \t]*\r?\n")
_PLACEHOLDER = re.compile(r"\[(?:DECOY|REDACTED):[^\]\s]*\]")
_VALUE_MIN = 8

# Matched alone, then the text before it is checked by hand: a regex lookbehind over whitespace backtracks.
_IMPERATIVE = re.compile(
    r"\b(?:you[ \t]+(?:must|should|need[ \t]+to)|always|never|make[ \t]+sure|remember[ \t]+to|first,?[ \t]+call)\b",
    re.I)
_BULLETS = "-*>"
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


def secret_name(name: str) -> bool:
    """True when a whole part of the name (split on _ . - and camelCase) is a secret word."""
    return any(p.lower() in SECRET_WORDS for p in _NAME_SPLIT.split(name) if p)


def _closing(text: str, quote: str, start: int) -> int:
    i = text.find(quote, start)
    while len(quote) == 1 and i > 0 and text[i - 1] == "\\":
        i = text.find(quote, i + 1)
    return i


def _assigned_value(text: str, m: re.Match) -> tuple[int, int] | None:
    if not secret_name(m.group(1)):
        return None
    pos = m.end()
    quote = text[pos:pos + 2] if text.startswith(("\\\"", "\\'"), pos) else text[pos:pos + 1]
    if quote not in ("\"", "'", "\\\"", "\\'"):
        quote = ""
    vs = pos + len(quote)
    if quote:
        ve = _closing(text, quote, vs)
        if ve >= 0 and text.find("\n", vs, ve) < 0:
            return vs, ve
    bare = _BARE_VALUE.match(text, vs)
    return (vs, bare.end()) if bare else None


def _url_credentials(text: str, m: re.Match) -> tuple[int, int] | None:
    try:
        ui = url_userinfo(m.group())
    except ValueError:
        return None
    if not ui:
        return None
    at = m.start() + m.group().index("://") + 3
    user, sep, password = ui.partition(":")
    if sep and password:
        return at + len(user) + 1, at + len(ui)
    return (at, at + len(ui)) if len(ui) >= _VALUE_MIN else None  # a short user name such as git is no secret


def secret_hits(text: str) -> list[tuple[str, int, int]]:
    """(kind, start, end) of every secret-shaped value, merged so that no two spans overlap."""
    found = []
    end_at: dict[str, int] = {}  # END marker -> where it was last found, or -1 once none is left
    key_end = value_end = -1  # a match inside the previous key or value is part of it; skipping keeps this linear
    for rank, (kind, rx) in enumerate(_SECRETS):
        for m in rx.finditer(text):
            if kind == "private_key":
                if m.start() < key_end:
                    continue
                marker = f"-----END {m.group(1)}PRIVATE KEY{m.group(2) or ''}-----"
                i = end_at.get(marker)
                if i is None or 0 <= i < m.end():
                    i = end_at[marker] = text.find(marker, m.end())
                if i >= 0:
                    span = (m.start(), i + len(marker))
                else:  # no END: to the first blank line or the end of the text
                    blank = _BLANK_LINE.search(text, m.end())
                    span = (m.start(), blank.start() if blank else len(text))
                key_end = span[1]
            elif kind == "assignment":
                if m.start() < value_end:
                    continue
                span = _assigned_value(text, m)
                if span:
                    value_end = span[1]
                if span and span[1] - span[0] < _VALUE_MIN:
                    span = None
            elif kind == "url_credentials":
                span = _url_credentials(text, m)
            elif kind in ("auth_header", "bearer_token"):
                span = m.span(1)
                if kind == "bearer_token" and not _TOKENISH.search(m.group(1)):
                    span = None  # "Bearer authentication": a word, not a token
            else:
                span = m.span()
            if span and not _skipped(text[span[0]:span[1]]):
                found.append((span[0], rank, span[1], kind))
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
    starts: list[int] = []
    spans: dict[int, tuple[int, str]] = {}
    for name, marker in sorted(decoys, key=lambda d: len(d[1]), reverse=True):
        if not marker:
            continue
        i = text.find(marker)
        while i >= 0:
            j = i + len(marker)
            k = bisect.bisect_right(starts, i)
            if (k == 0 or spans[starts[k - 1]][0] <= i) and (k == len(starts) or starts[k] >= j):
                starts.insert(k, i)
                spans[i] = (j, f"[DECOY:{name}]")
            i = text.find(marker, j)
    return [(i, *spans[i]) for i in starts]


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
    k = bisect.bisect_right(regions, p, key=lambda r: r[1])  # regions that end at or before p
    if k < len(regions) and regions[k][0] < p:
        return regions[k][3] if is_end else regions[k][2]
    return regions[k - 1][3] + (p - regions[k - 1][1]) if k else p


# Callers excerpt one result many times; keep the last few redactions instead of redoing each.
@functools.lru_cache(maxsize=16)
def _redacted_cached(text: str, decoys: tuple[tuple[str, str], ...]):
    s1, r1 = _apply(text, _decoy_spans(text, decoys))
    out, r2 = _apply(s1, [(s, e, f"[REDACTED:{kind}]") for kind, s, e in secret_hits(s1)])
    # Every placeholder's (start, end) in the redacted text, sorted, for trimming excerpt edges.
    holes = sorted([(ns, ne) for _, _, ns, ne in r2] + [(_map(ns, r2, False), _map(ne, r2, True)) for _, _, ns, ne in r1])
    return out, r1, r2, holes


def _redacted(text: str, decoys: Sequence[tuple[str, str]]):
    return _redacted_cached(text, tuple((n, m) for n, m in decoys))


def redact(text: str, decoys: Sequence[tuple[str, str]] = ()) -> str:
    """Each decoy marker becomes [DECOY:<name>], then each secret-shaped value becomes [REDACTED:<kind>]."""
    return _redacted(text, decoys)[0]


def _hole_at(holes: list[tuple[int, int]], x: int) -> tuple[int, int] | None:
    k = bisect.bisect_left(holes, (x,)) - 1  # the last placeholder starting before x
    return holes[k] if k >= 0 and holes[k][1] > x else None


def _render(text: str) -> str:
    return _HIDDEN.sub(lambda m: f"<U+{ord(m.group()):04X}>", text)


def excerpt(text: str, start: int, end: int, decoys: Sequence[tuple[str, str]] = ()) -> str:
    """At most EXCERPT characters centred on text[start:end], redacted, hidden characters shown as <U+XXXX>."""
    # Redact the whole text before cutting: a window edge inside a secret would keep a prefix no pattern matches.
    red, r1, r2, holes = _redacted(text, decoys)
    rs, re_ = _map(_map(start, r1, False), r2, False), _map(_map(end, r1, True), r2, True)
    if re_ - rs >= EXCERPT:
        ws, we = rs, rs + EXCERPT
    else:
        ws = max(0, rs - (EXCERPT - (re_ - rs)) // 2)
        we = min(len(red), ws + EXCERPT)
        ws = max(0, we - EXCERPT)
    # Do not show half a placeholder at either edge.
    left, right = _hole_at(holes, ws), _hole_at(holes, we)
    if left:
        ws = left[1]
    if right:
        we = right[0]
    return _render(red[ws:we])


def strip_payload(text: str, payload: str | None) -> str:
    """The text with every verbatim copy of the payload removed."""
    return text.replace(payload, "") if payload else text


def looks_aimed_at_model(text: str, tool_names: Sequence[str]) -> bool:
    """Cheap judge pre-filter: text that talks to a model rather than describing data.

    `tool_names` are the other tools the server listed."""
    if _USER_OR_ASSISTANT.search(text) or any(_starts_sentence(text, m.start()) for m in _IMPERATIVE.finditer(text)):
        return True
    names = [re.escape(n) for n in tool_names if n]
    if names and re.search(r"(?<![\w-])(?:" + "|".join(names) + r")(?![\w-])", text):
        return True
    verbs = [m.span() for m in _SEND_VERB.finditer(text)]
    ends = [ve for _, ve in verbs]  # verbs do not overlap, so starts and ends are both sorted
    for u in _URL.finditer(text):
        k = bisect.bisect_left(ends, u.start() - _URL_VERB_GAP)
        if k < len(verbs) and verbs[k][0] <= u.end() + _URL_VERB_GAP:
            return True
    return False


def _starts_sentence(text: str, i: int) -> bool:
    """True when position i opens the text, a line, a bullet or quote line, or follows . ! or ? and a space."""
    j = i - 1
    while j >= 0 and text[j].isspace():
        if text[j] == "\n":
            return True
        j -= 1
    if j < 0:
        return True
    if text[j] in ".!?":
        return j < i - 1
    if text[j] in _BULLETS and j < i - 1:
        k = j - 1
        while k >= 0 and text[k] in " \t":
            k -= 1
        return k < 0 or text[k] == "\n"
    return False
