"""Deterministic fact checks in JSON fields and titled reply sections."""

from __future__ import annotations

import json
import re
import unicodedata
from functools import lru_cache

from argus.world_assertions import AssertionOutcome


FACT_CHECKS = frozenset({"fact_preserved", "fact_not_introduced"})
_DEFAULT_NORMALIZE = ("casefold", "nfkc", "collapse_space")
_NORMALIZATIONS = frozenset((*_DEFAULT_NORMALIZE, "strip_punct"))
_HEADING = re.compile(r"^ {0,3}#{1,6}(?:\s+(.+?)\s*#*\s*|\s*)$")
_FENCE = re.compile(r"\A\s*(`{3,}|~{3,})[^\n]*\n(.*?)\n\1\s*\Z", re.DOTALL)
_CJK = re.compile(r"[\u1100-\u11ff\u3040-\u30ff\u3130-\u318f\u31f0-\u31ff"
                  r"\u3400-\u4dbf\u4e00-\u9fff\ua960-\ua97f\uac00-\ud7ff"
                  r"\uf900-\ufaff\U00020000-\U000323af]")


@lru_cache(maxsize=256)
def _compile_pattern(pattern):
    return re.compile(pattern)


def normalize(text, operations):
    # Use a fixed order so compatibility forms and composed accents casefold alike.
    if "nfkc" in operations:
        text = unicodedata.normalize("NFKC", text)
    if "casefold" in operations:
        text = text.casefold()
    if "strip_punct" in operations:
        text = "".join(char for char in text if not unicodedata.category(char).startswith("P"))
    if "collapse_space" in operations:
        text = " ".join(text.split())
    return text


def validate_fact_assertion(kind, value):
    allowed = {"id", "locator", "any_of", "pattern", "normalize", "severity"}
    if not isinstance(value, dict) or set(value) - allowed:
        raise ValueError("unknown fact assertion fields")
    if not isinstance(value.get("id"), str) or not value["id"].strip():
        raise ValueError("fact assertion requires a nonempty id")
    locator = value.get("locator")
    if not isinstance(locator, dict) or len(locator) != 1:
        raise ValueError("locator requires exactly one json_path or section")
    if "json_path" in locator:
        from argus_jsonpath import path

        path(locator["json_path"])
        if kind == "fact_not_introduced" and locator["json_path"] == "$":
            raise ValueError("fact_not_introduced must locate a decision field, never $")
    elif "section" in locator:
        titles = locator["section"]
        titles = [titles] if isinstance(titles, str) else titles
        if not isinstance(titles, list) or not titles or any(
            not isinstance(title, str) or not title.strip() for title in titles
        ):
            raise ValueError("section requires a nonempty title or list of titles")
    else:
        raise ValueError("locator requires exactly one json_path or section")
    operations = value.get("normalize", list(_DEFAULT_NORMALIZE))
    if not isinstance(operations, list) or any(
        not isinstance(op, str) or op not in _NORMALIZATIONS for op in operations
    ) or len(operations) != len(set(operations)):
        raise ValueError("normalize must be a subset of the supported operations")
    if ("any_of" in value) == ("pattern" in value):
        raise ValueError("fact assertion requires exactly one any_of or pattern")
    if "any_of" in value:
        terms = value["any_of"]
        if not isinstance(terms, list) or not terms or any(
            not isinstance(term, str) or not normalize(term, operations).strip() for term in terms
        ):
            raise ValueError("any_of requires nonempty strings after normalization")
    else:
        if not isinstance(value["pattern"], str) or not value["pattern"]:
            raise ValueError("pattern requires one nonempty regex")
        try:
            _compile_pattern(value["pattern"])
        except re.error as exc:
            raise ValueError("invalid fact assertion regex") from exc
    if "severity" in value and (not isinstance(value["severity"], str) or
                               value["severity"] not in {"info", "low", "medium", "high", "critical"}):
        raise ValueError("invalid fact assertion severity")


def _heading_title(line, accepted=(), operations=_DEFAULT_NORMALIZE):
    heading = _HEADING.fullmatch(line)
    if heading:
        return (heading.group(1) or "").strip()
    stripped = line.strip()
    if stripped.endswith(":") and stripped[:-1].strip():
        title = stripped[:-1].strip()
        if normalize(title, operations) in accepted or (
            len(title.split()) <= 4
            and not any(unicodedata.category(char).startswith("P") for char in title)
        ):
            return title
    return None


def _section(text, titles, operations):
    titles = [titles] if isinstance(titles, str) else titles
    accepted = {normalize(title, operations) for title in titles}
    lines = text.splitlines()
    for index, line in enumerate(lines):
        title = _heading_title(line, accepted, operations)
        if title is not None and normalize(title, operations) in accepted:
            end = index + 1
            while end < len(lines) and _heading_title(lines[end], accepted, operations) is None:
                end += 1
            return title, "\n".join(lines[index + 1:end])
    return None, None


def _flatten(value, path):
    if isinstance(value, dict):
        for key, child in value.items():
            field = f".{key}" if re.fullmatch(r"[A-Za-z_][\w-]*", key) else f"[{key!r}]"
            yield from _flatten(child, path + field)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _flatten(child, f"{path}[{index}]")
    elif value is not None:
        yield path, value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)


def parse_json_reply(response_text):
    """Parse one JSON reply, allowing one surrounding markdown code fence."""
    fence = _FENCE.fullmatch(response_text)
    return json.loads(fence.group(2) if fence else response_text, parse_constant=_reject_constant)


def _word_char(char):
    return bool(re.fullmatch(r"\w", char)) and not _CJK.search(char)


def _match(value, text, operations):
    if "pattern" in value:
        match = _compile_pattern(value["pattern"]).search(text)
        return (match.group(), match.start()) if match else (None, 0)
    for term in value["any_of"]:
        normalized = normalize(term, operations)
        for match in re.finditer(re.escape(normalized), text):
            start, end = match.span()
            if _CJK.search(normalized) or (
                (start == 0 or not _word_char(text[start - 1]))
                and (end == len(text) or not _word_char(text[end]))
            ):
                return term, start
    return None, 0


def _reject_constant(_):
    raise ValueError("invalid JSON constant")


def check_fact(kind, value, evidence, response_text):
    validate_fact_assertion(kind, value)
    operations = value.get("normalize", _DEFAULT_NORMALIZE)
    locator = value["locator"]
    reason = "locator_absent"
    matched_title = matched_path = matched_term = None
    excerpt = ""
    located = []
    if "json_path" in locator:
        from jsonpath_ng import parse

        try:
            response = parse_json_reply(response_text)
        except (ValueError, TypeError, RecursionError):
            reason = "output_not_json"
        else:
            matches = parse(locator["json_path"]).find(response)
            if matches:
                matched_path = locator["json_path"]
                reason = "empty_value"
                for match in matches:
                    located.extend(_flatten(match.value, matched_path))
    else:
        matched_title, text = _section(response_text, locator["section"], operations)
        if matched_title is not None:
            reason = "empty_value"
            located = [(None, text)]
    for path, text in located:
        text = normalize(text, operations)
        if not text.strip():
            continue
        reason = "no_term_matched"
        if not excerpt:
            excerpt = text[:200]
        term, position = _match(value, text, operations)
        if term is not None:
            reason = "term_present"
            matched_term = term
            if path is not None:
                matched_path = path
            excerpt = text[max(0, position - 80):max(0, position - 80) + 200]
            break
    violated = reason != "term_present" if kind == "fact_preserved" else reason == "term_present"
    evidence.setdefault("facts", {})[value["id"]] = {
        "id": value["id"], "kind": kind, "locator": dict(locator),
        "matched_title": matched_title, "matched_path": matched_path,
        "violated": violated, "reason": reason, "matched_term": matched_term,
        "excerpt": excerpt,
    }
    return AssertionOutcome("fail" if violated else "pass", f"{kind} {value['id']}: {reason}", value.get("severity"))


def fact_preserved(value, evidence, response_text):
    return check_fact("fact_preserved", value, evidence, response_text)


def fact_not_introduced(value, evidence, response_text):
    return check_fact("fact_not_introduced", value, evidence, response_text)
