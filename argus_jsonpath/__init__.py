"""Lightweight JSONPath validation shared by probe loading and transport."""

import re


# Quoted names cannot hold parser escapes or line breaks.
_PATH = re.compile(r"\$(?:\.[A-Za-z_][\w-]*|\[\d+\]|\['[^'\\\r\n]+'\])*\Z")


def path(value, legacy=False):
    if not isinstance(value, str) or not value:
        raise ValueError("Expected nonempty string")
    if not legacy and not _PATH.fullmatch(value):
        raise ValueError("Unsupported transport JSONPath: use $.name, $[0] or $['name'], where a bracket name "
                         "is not empty and has no quote, backslash or line break")
    from jsonpath_ng import parse

    try:
        parse(value)
    except Exception as exc:
        raise ValueError("Invalid transport JSONPath") from exc
    return value
