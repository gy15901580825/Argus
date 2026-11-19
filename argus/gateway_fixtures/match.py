"""Match in memory before redaction.

The decoding policy is deliberately duplicated in hosted_testbed/testbed/markers.py:
that independently deployed service cannot import the Argus engine.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import re
from dataclasses import dataclass
from urllib.parse import unquote, unquote_plus

TEXT_MAX = 64 * 1024
VARIANTS_MAX = 128
_BASE64 = re.compile(r'(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{8,}={0,2}(?![A-Za-z0-9+/_=-])')


@dataclass(frozen=True)
class MatchResult:
    hits: list[str]
    complete: bool
    canary_hits: tuple[str, ...] = ()


def decoded_variants(value: str) -> tuple[list[str], bool]:
    encoded = value.encode('utf-8', errors='surrogatepass')
    complete = len(encoded) <= TEXT_MAX
    values = [value if complete else encoded[:TEXT_MAX].decode('utf-8', errors='ignore')]
    try:
        value.encode('utf-8')
    except UnicodeError:
        complete = False

    def add(text: str) -> None:
        nonlocal complete
        if text not in values:
            if len(values) == VARIANTS_MAX:
                complete = False
            else:
                values.append(text)

    for plus in (False, True):
        decode = unquote_plus if plus else unquote
        text = values[0]
        for _ in range(3):
            next_text = decode(text)
            if next_text == text:
                break
            add(next_text)
            text = next_text
        if unquote(text) != text:
            complete = False
    for text in tuple(values):
        add(text.replace('+', ' '))
    for text in tuple(values):
        unicode_text = re.sub(r'\\u([0-9a-fA-F]{4})', lambda m: chr(int(m[1], 16)), text)
        try:
            unicode_text = unicode_text.encode('utf-16', errors='surrogatepass').decode('utf-16')
        except UnicodeError:
            complete = False
        add(unicode_text)
    for text in tuple(values):
        for token in _BASE64.findall(text):
            try:
                decoded = base64.b64decode(token + '=' * (-len(token) % 4),
                    altchars=b'-_', validate=True).decode('utf-8')
            except (ValueError, UnicodeError):
                continue
            add(decoded)
    return values, complete


class WatchMatcher:
    """Raw synthetic canaries and keyed digests of external credentials only."""

    def __init__(self, canaries: dict[str, str], secrets: dict[str, str], *, watch_key: bytes):
        if len(watch_key) != 32:
            raise ValueError('watch_key must be 32 bytes')
        if any(not value for value in canaries.values()):
            raise ValueError('canaries must not be empty')
        if any(not re.fullmatch(r'[0-9a-fA-F]{64}', digest) for digest in secrets.values()):
            raise ValueError('secret watches must be SHA256 hex digests')
        self._canaries = dict(canaries)
        self._secrets = {label: digest.lower() for label, digest in secrets.items()}
        self._watch_key = watch_key

    def match(self, value: str, *, include_secrets: bool = True) -> MatchResult:
        if self._watch_key is None:
            raise RuntimeError('matcher is sealed')
        variants, complete = decoded_variants(value)
        candidates = set(variants)
        for text in tuple(variants):
            scheme, separator, remainder = text.partition(' ')
            if separator and re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]*', scheme):
                candidates.update((remainder, remainder.strip()))
                if scheme.lower() == 'basic':
                    payload = remainder.strip()
                    try:
                        credential = base64.b64decode(payload + '=' * (-len(payload) % 4),
                            altchars=b'-_', validate=True).decode('utf-8')
                    except (ValueError, UnicodeError):
                        credential = ''
                    if ':' in credential:
                        if credential not in variants:
                            if len(variants) < VARIANTS_MAX:
                                variants.append(credential)
                            else:
                                complete = False
                        candidates.add(credential)
                        candidates.update(credential.split(':', 1))
                    basic, basic_complete = decoded_variants(payload)
                    complete &= basic_complete
                    for credential in basic:
                        if ':' in credential:
                            candidates.update(credential.split(':', 1))
        hits = {label for label, canary in self._canaries.items()
                if any(canary in text for text in variants)}
        canary_hits = tuple(sorted(hits))
        if include_secrets:
            for candidate in candidates:
                try:
                    encoded = candidate.encode('utf-8')
                except UnicodeError:
                    complete = False
                    continue
                digest = hmac.new(self._watch_key, encoded, hashlib.sha256).hexdigest()
                hits.update(label for label, expected in self._secrets.items()
                            if hmac.compare_digest(digest, expected))
        return MatchResult(sorted(hits), complete, canary_hits)

    def clear(self) -> None:
        """Release raw canaries and the watch key at case seal."""
        self._canaries.clear()
        self._secrets.clear()
        self._watch_key = None
