"""Credentials in skill source URLs. Standard library only: the CLI tests load this file directly."""
from __future__ import annotations

import re
import urllib.parse

# A real host before the first / ? #: then any later "@" belongs to the path, not to credentials.
_HOST_LIKE = re.compile(r"(\[[0-9A-Fa-f:.]+\]|localhost|[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+)(:\d+)?")
_PATH_START = re.compile(r"[/?#]")


def url_userinfo(source: str) -> str:
    """The `user:password` part of a URL source, or "". Raises ValueError for a malformed URL."""
    if "://" not in source:
        return ""  # a path, or scp-style git@host:path, which carries no secret
    netloc = urllib.parse.urlsplit(source).netloc
    if "@" in netloc:
        return netloc.rpartition("@")[0]
    # urlsplit cut the netloc at an unescaped / ? or # inside the credentials, e.g. https://tok/en@host/.
    rest = source.split("://", 1)[1]
    if _HOST_LIKE.fullmatch(_PATH_START.split(rest, maxsplit=1)[0]):
        return ""
    for m in re.finditer("@", rest):
        i = m.start()
        if i == 0 or rest[i - 1] in "/?#":
            continue  # "host:8080/@scope/pkg": a port, then a path
        return rest[:i] if _PATH_START.split(rest[i + 1:], maxsplit=1)[0] else ""
    return ""


def url_secrets(source: str) -> list[tuple[str, str]]:
    """(text, replacement) pairs that remove URL credentials from any text, raw and percent-decoded."""
    ui = url_userinfo(source)
    if not ui:
        return []
    pairs, tokens = [], set()
    for form in {ui, urllib.parse.unquote(ui)}:
        pairs.append((form + "@", ""))
        user, _, password = form.partition(":")
        # A short user name such as "git" is not a secret and would blank out ordinary words.
        tokens.update(t for t in (form, password, user) if len(t) >= 8)
    pairs += [(t, "[REDACTED]") for t in sorted(tokens, key=len, reverse=True)]
    return pairs


def safe_source(source: str) -> str:
    """The source with any URL credentials removed; host and path are kept."""
    ui = url_userinfo(source)
    return source.replace(ui + "@", "", 1) if ui else source
