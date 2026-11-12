"""Options shared by the probe loader and the browser runners."""

from collections.abc import Mapping

class FrozenOptions(dict):
    """A read-only dict that retains dataclass, JSON and pickle compatibility."""

    __slots__ = ("_initialized",)

    def __init__(self, *args, **kwargs):
        if hasattr(self, "_initialized"):
            self._immutable()
        super().__init__(*args, **kwargs)
        object.__setattr__(self, "_initialized", True)

    def _immutable(self, *args, **kwargs):
        raise TypeError("scenario options are immutable")

    __setitem__ = __delitem__ = clear = pop = popitem = setdefault = update = __ior__ = _immutable
    __setattr__ = __delattr__ = _immutable

    def __copy__(self):
        return self

    def __deepcopy__(self, memo):
        return self

    def __reduce__(self):
        return type(self), (dict(self),)


VISUAL_VARIANTS = frozenset({
    "plain", "qr_code", "handwritten", "stylized_logo", "tiny_text",
    "white_on_white", "multilingual", "chart_label", "terminal",
})
BROWSER_KINDS = frozenset({"dom_injection", "ui_phishing", "visual_injection", "os_cmd", "cross_origin_bridge", "click_swap"})


def validate_options(kind: str, options: Mapping) -> Mapping:
    if not isinstance(options, Mapping):
        raise ValueError(f"{kind} scenario options must be a mapping")
    allowed = {"canary"} if kind == "cross_origin_bridge" else {"variant"} if kind == "visual_injection" else (
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
    if kind == "cross_origin_bridge" and not options.get("canary", "").strip():
        raise ValueError("cross_origin_bridge requires a nonempty synthetic canary")
    return FrozenOptions(options)
