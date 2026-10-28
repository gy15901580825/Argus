"""Secret values the CLI knows from its own inputs (command line, URL), so it can mask them everywhere."""
from __future__ import annotations

import re
import urllib.parse
from typing import Sequence

from argus.mcp_scan.rules import secret_name
from argus.skillscan.urls import safe_source, url_secrets as _userinfo_pairs

MASK = "***"
_FLAG = re.compile(r"--?([A-Za-z0-9][\w.-]*)(?:=(.*))?", re.S)
_SHORT_FLAG = re.compile(r"-[A-Za-z]|--.*", re.S)
_ENV_ARG = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)=(.*)", re.S)
_HEADER_ARG = re.compile(r"\s*([A-Za-z0-9-]{1,64})\s*:\s*(\S.*?)\s*", re.S)
_AUTH_HEADERS = {"authorization", "proxy-authorization", "cookie"}
_URL_IN_ARG = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://\S+")
_PATH_PARAM = re.compile(r";([^;/=?#]+)=([^;/?#]*)")
# Every known value is replaced in all output; a value this short would blank out ordinary words.
VALUE_MIN = 4


def _keep(values) -> list[str]:
    return list(dict.fromkeys(v for v in values if len(v) >= VALUE_MIN))


def _pairs(params: str) -> list[tuple[str, str]]:
    """(name, raw value) of each secret-named name=value in a query or fragment."""
    out = []
    for part in params.split("&"):
        name, sep, value = part.partition("=")
        if sep and secret_name(urllib.parse.unquote_plus(name)):
            out.append((name, value))
    return out


def url_secrets(url: str) -> list[str]:
    """URL userinfo, raw and percent-decoded, plus values of secret-named query, fragment and path parameters."""
    try:
        found = [t for t, repl in _userinfo_pairs(url) if repl]
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return [url]  # unparseable: mask all of it rather than guess where the credentials end
    values = [v for _, v in _pairs(parts.query) + _pairs(parts.fragment)]
    values += [m.group(2) for m in _PATH_PARAM.finditer(parts.path) if secret_name(m.group(1))]
    for v in values:
        found += [v, urllib.parse.unquote_plus(v)]
    return _keep(found)


def _header_secrets(arg: str) -> list[str]:
    m = _HEADER_ARG.fullmatch(arg)
    if not m or not (m.group(1).lower() in _AUTH_HEADERS or secret_name(m.group(1))):
        return []
    value = m.group(2)
    scheme, sep, credential = value.partition(" ")
    return [value, credential.strip()] if sep and scheme.isalpha() else [value]


def command_secrets(argv: Sequence[str]) -> list[str]:
    """Values of secret-named flags, NAME=VALUE arguments and header arguments, and credentials in URL arguments."""
    found: list[str] = []
    for i, arg in enumerate(argv):
        flag = _FLAG.fullmatch(arg)
        env = None if flag else _ENV_ARG.fullmatch(arg)
        if flag and secret_name(flag.group(1)):
            if flag.group(2) is not None:
                found.append(flag.group(2))
            elif i + 1 < len(argv) and not _SHORT_FLAG.fullmatch(argv[i + 1]):
                found.append(argv[i + 1])  # a value may itself start with "-"
        elif env and secret_name(env.group(1)):
            found.append(env.group(2))
        if "://" not in arg:
            found += _header_secrets(arg)
        for u in _URL_IN_ARG.findall(arg):
            found += url_secrets(u)
    return _keep(found)


def args_secrets(value) -> list[str]:
    """Every string value in an --args object, at any depth: a baseline argument is often a real id or key."""
    if isinstance(value, str):
        return _keep([value])
    items = value.values() if isinstance(value, dict) else value if isinstance(value, list) else ()
    return _keep(s for v in items for s in args_secrets(v))


def mask_argv(argv: Sequence[str], secrets: Sequence[str]) -> list[str]:
    """argv with every secret replaced by ***, longest first so a secret containing another is masked whole."""
    ordered = sorted({s for s in secrets if s}, key=len, reverse=True)
    out = []
    for arg in argv:
        for s in ordered:
            arg = arg.replace(s, MASK)
        out.append(arg)
    return out


def _mask_params(params: str) -> str:
    out = []
    for part in params.split("&") if params else []:
        name, sep, _ = part.partition("=")
        out.append(f"{name}={MASK}" if sep and secret_name(urllib.parse.unquote_plus(name)) else part)
    return "&".join(out)


def safe_url(url: str) -> str:
    """The URL without userinfo, with secret-named query, fragment and path parameter values replaced by ***."""
    try:
        parts = urllib.parse.urlsplit(safe_source(url))
    except ValueError:
        return MASK
    path = _PATH_PARAM.sub(lambda m: f";{m.group(1)}={MASK}" if secret_name(m.group(1)) else m.group(), parts.path)
    return urllib.parse.urlunsplit(parts._replace(path=path, query=_mask_params(parts.query),
                                                  fragment=_mask_params(parts.fragment)))
