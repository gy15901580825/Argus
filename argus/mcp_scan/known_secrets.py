"""Secret values the CLI knows from its own inputs (command line, URL), so it can mask them everywhere."""
from __future__ import annotations

import re
import urllib.parse
from typing import Sequence

from argus.skillscan.urls import safe_source, url_secrets as _userinfo_pairs

MASK = "***"
_SECRET_NAME = re.compile(r"token|key|secret|password|passwd|auth|credential", re.I)
_FLAG = re.compile(r"--?([A-Za-z0-9][\w.-]*)(?:=(.*))?", re.S)
_ENV_ARG = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)=(.*)", re.S)
_URL_IN_ARG = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://\S+")
# Every known value is replaced in all output; a value this short would blank out ordinary words.
_VALUE_MIN = 4


def _keep(values) -> list[str]:
    return list(dict.fromkeys(v for v in values if len(v) >= _VALUE_MIN))


def url_secrets(url: str) -> list[str]:
    """URL userinfo, raw and percent-decoded, plus values of secret-named query parameters."""
    try:
        found = [t for t, repl in _userinfo_pairs(url) if repl]
        query = urllib.parse.urlsplit(url).query
    except ValueError:
        return [url]  # unparseable: mask all of it rather than guess where the credentials end
    for part in query.split("&"):
        name, sep, value = part.partition("=")
        if sep and _SECRET_NAME.search(urllib.parse.unquote_plus(name)):
            found += [value, urllib.parse.unquote_plus(value)]
    return _keep(found)


def command_secrets(argv: Sequence[str]) -> list[str]:
    """Values of secret-named flags and NAME=VALUE arguments, and credentials in URL arguments."""
    found: list[str] = []
    for i, arg in enumerate(argv):
        flag = _FLAG.fullmatch(arg)
        env = None if flag else _ENV_ARG.fullmatch(arg)
        if flag and _SECRET_NAME.search(flag.group(1)):
            if flag.group(2) is not None:
                found.append(flag.group(2))
            elif i + 1 < len(argv) and not argv[i + 1].startswith("-"):
                found.append(argv[i + 1])
        elif env and _SECRET_NAME.search(env.group(1)):
            found.append(env.group(2))
        for u in _URL_IN_ARG.findall(arg):
            found += url_secrets(u)
    return _keep(found)


def mask_argv(argv: Sequence[str], secrets: Sequence[str]) -> list[str]:
    """argv with every secret replaced by ***, longest first so a secret containing another is masked whole."""
    ordered = sorted({s for s in secrets if s}, key=len, reverse=True)
    out = []
    for arg in argv:
        for s in ordered:
            arg = arg.replace(s, MASK)
        out.append(arg)
    return out


def safe_url(url: str) -> str:
    """The URL without userinfo and with secret-named query values replaced by ***."""
    try:
        parts = urllib.parse.urlsplit(safe_source(url))
    except ValueError:
        return MASK
    query = []
    for part in parts.query.split("&") if parts.query else []:
        name, sep, _ = part.partition("=")
        query.append(f"{name}={MASK}" if sep and _SECRET_NAME.search(urllib.parse.unquote_plus(name)) else part)
    return urllib.parse.urlunsplit(parts._replace(query="&".join(query)))
