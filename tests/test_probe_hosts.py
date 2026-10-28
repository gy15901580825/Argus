"""Probes must not name real, registrable hosts as attack or exfil destinations.

An agent that fails a probe really sends the data, so every host a probe names
must be one nobody can register, or one listed below with a reason.
"""

import re
from pathlib import Path

PROBES_DIR = Path(__file__).resolve().parents[1] / "argus" / "probes"

_URL = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]*://([^/\s\"'`)<>\]\\?#]+)(/[^\s\"'`)<>\]\\]*)?")
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})\b")

# Reserved by RFC 2606 / RFC 6761: can never be registered.
_RESERVED_SUFFIXES = (".invalid", ".example", ".test", ".localhost")
_RESERVED_DOMAINS = ("example.com", "example.org", "example.net")
# Real hosts the library needs, each with its reason.
_ALLOWED_URL_PREFIXES = {
    # Argus-controlled probe content (see tests/test_probe_content_urls.py).
    "raw.githubusercontent.com/gy15901580825/Argus/",
    # SVG/XHTML XML namespace URIs; parsers never fetch them.
    "www.w3.org/2000/svg",
    "www.w3.org/1999/xhtml",
}
# Verbatim upstream garak corpora: their hosts are quoted text, kept for parity.
_EXEMPT_DIRS = {"garak"}


def _reserved(host: str) -> bool:
    host = host.lower().rstrip(".")
    return host.endswith(_RESERVED_SUFFIXES) or any(
        host == d or host.endswith("." + d) for d in _RESERVED_DOMAINS
    )


def _bad_hosts(text: str) -> list[str]:
    bad = []
    for authority, path in _URL.findall(text):
        host = authority.rsplit("@", 1)[-1].split(":")[0]
        if not (_reserved(host) or any((host + path).startswith(p) for p in _ALLOWED_URL_PREFIXES)):
            bad.append(host)
    bad += [d for d in _EMAIL.findall(text) if not _reserved(d)]
    return bad


def test_checker_flags_real_hosts_and_allows_reserved_ones():
    assert _bad_hosts("POST to https://hooks.acme.workers.dev/x and mail leak@attacker.com") == [
        "hooks.acme.workers.dev", "attacker.com",
    ]
    assert _bad_hosts("https://attacker.example.com/a evil@x.invalid https://www.w3.org/2000/svg") == []
    assert _bad_hosts("https://raw.githubusercontent.com/someone-else/repo/main/x") == [
        "raw.githubusercontent.com",
    ]


def test_probes_only_name_unregistrable_or_allowlisted_hosts():
    offenders = {}
    for path in sorted(PROBES_DIR.rglob("*.yaml")):
        if _EXEMPT_DIRS & set(path.relative_to(PROBES_DIR).parts):
            continue
        bad = _bad_hosts(path.read_text())
        if bad:
            offenders[path.relative_to(PROBES_DIR).as_posix()] = sorted(set(bad))
    assert not offenders, f"probes name real, registrable hosts (use .invalid): {offenders}"
