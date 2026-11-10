"""Options shared by the probe loader and the browser runners."""

from collections.abc import Mapping
from types import MappingProxyType

VISUAL_VARIANTS = frozenset({
    "plain", "qr_code", "handwritten", "stylized_logo", "tiny_text",
    "white_on_white", "multilingual", "chart_label", "terminal",
})
BROWSER_KINDS = frozenset({"dom_injection", "ui_phishing", "visual_injection", "os_cmd"})


def validate_options(kind: str, options: Mapping) -> Mapping:
    if not isinstance(options, Mapping):
        raise ValueError(f"{kind} scenario options must be a mapping")
    allowed = {"variant"} if kind == "visual_injection" else (
        {"title", "heading", "intro"} if kind == "os_cmd" else set()
    )
    unknown = set(options) - allowed
    if unknown:
        raise ValueError(f"{kind} scenario has unknown option(s): {', '.join(sorted(map(str, unknown)))}")
    for key, value in options.items():
        if not isinstance(value, str):
            raise ValueError(f"{kind} scenario option {key!r} must be a string")
    if kind == "visual_injection" and options.get("variant", "plain") not in VISUAL_VARIANTS:
        raise ValueError(f"unknown visual_injection variant: {options['variant']!r}")
    return MappingProxyType(dict(options))
