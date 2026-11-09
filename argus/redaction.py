from __future__ import annotations

from typing import Any, Iterable

MASK = "***"
_SECRET_KEY_SUFFIXES = ("key", "token", "authheader")
_SECRET_KEY_PARTS = ("secret", "password", "authorization", "credential", "cookie")


def _is_secret_key(key: str) -> bool:
    k = key.lower().replace("_", "").replace("-", "")
    return k.endswith(_SECRET_KEY_SUFFIXES) or any(p in k for p in _SECRET_KEY_PARTS)


def _is_header_key(key: str) -> bool:
    return key.lower().endswith("headers")


def _strings(value: Any, out: list[str]) -> None:
    """Collect every string inside a masked value, plus the credential after a scheme like "Bearer "."""
    if isinstance(value, str):
        out.append(value)
        if " " in value.strip():
            out.append(value.strip().split(" ", 1)[1].strip())
    elif isinstance(value, dict):
        for v in value.values():
            _strings(v, out)
    elif isinstance(value, (list, tuple)):
        for v in value:
            _strings(v, out)


def _mask_headers(value: Any, masked: list[str]) -> Any:
    # Keep header names, mask every value: {"Name": v} or [["Name", v], ...].
    if isinstance(value, dict):
        _strings(list(value.values()), masked)
        return {k: MASK for k in value}
    if isinstance(value, list):
        out = []
        for item in value:
            if isinstance(item, (list, tuple)) and item:
                _strings(list(item[1:]), masked)
                out.append([item[0], *([MASK] * (len(item) - 1))])
            else:
                _strings(item, masked)
                out.append(MASK)
        return out
    _strings(value, masked)
    return MASK


def _redact(spec: dict) -> tuple[dict, list[str]]:
    masked: list[str] = []

    def walk(value: Any) -> Any:
        if isinstance(value, dict):
            out = {}
            for k, v in value.items():
                if isinstance(k, str) and _is_header_key(k):
                    out[k] = _mask_headers(v, masked)
                elif isinstance(k, str) and _is_secret_key(k):
                    _strings(v, masked)
                    out[k] = MASK
                else:
                    out[k] = walk(v)
            return out
        if isinstance(value, list):
            return [walk(v) for v in value]
        return value
    return walk(spec), masked


def redact(spec: dict) -> dict:
    """Mask secret-named keys and header values in a target spec. Returns a new dict."""
    return _redact(spec)[0]


def _ordered(values: Iterable[str]) -> list[str]:
    # Longest first, so a secret that contains another is masked whole.
    return sorted({s for s in values if s and s != MASK}, key=len, reverse=True)


def mask_text(text: str, secrets: list[str]) -> str:
    """Replace every value of `secrets` (as returned by run_secrets) inside `text`."""
    for s in secrets:
        text = text.replace(s, MASK)
    return text


def run_secrets(target_spec: dict, secret_values: Iterable[str] = ()) -> list[str]:
    """Every value scrub_run masks for this spec: `secret_values` plus the spec's secret-named literals."""
    return _ordered((*secret_values, *_redact(target_spec or {})[1]))


def _scrub(value: Any, secrets: list[str], keys: bool = False) -> Any:
    """Replace every secret value inside every string, longest first. Dict keys too when `keys`."""
    if isinstance(value, str):
        return mask_text(value, secrets)
    if isinstance(value, dict):
        out: dict = {}
        for k, v in value.items():
            new_k = _scrub(k, secrets) if keys and isinstance(k, str) else k
            base, n = new_k, 1
            while new_k in out:  # two keys that mask to the same text: keep both
                n += 1
                new_k = f"{base}#{n}"
            out[new_k] = _scrub(v, secrets, keys)
        return out
    if isinstance(value, list):
        return [_scrub(v, secrets, keys) for v in value]
    return value


