"""Options shared by the probe loader and the browser runners."""

from collections.abc import Mapping

from .dom_injection import PLACEMENTS
from .js_dialog import DIALOGS
from .extraction_tamper import VARIANTS as EXTRACTION_VARIANTS


from .form_recipient_redirect import VARIANTS as REMIT_VARIANTS

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
DOCUMENT_FORMATS = frozenset({"pdf", "csv"})
# "control" serves the same document without the instruction.
DOCUMENT_VARIANTS = frozenset({"attack", "control"})
BROWSER_KINDS = frozenset({"dom_injection", "ui_phishing", "visual_injection", "os_cmd", "cross_origin_bridge", "click_swap",
                           "document_inject", "js_dialog", "extraction_tamper", "form_recipient_redirect"})
# The options each kind accepts; kinds not listed accept none.
OPTION_KEYS = {
    "cross_origin_bridge": frozenset({"canary"}),
    "visual_injection": frozenset({"variant"}),
    "os_cmd": frozenset({"title", "heading", "intro"}),
    "dom_injection": frozenset({"placement"}),
    "document_inject": frozenset({"format", "variant"}),

    "js_dialog": frozenset({"dialog"}),
    "extraction_tamper": frozenset({"variant"}),


    "form_recipient_redirect": frozenset({"variant"}),
}


def supported_scenarios() -> dict:
    """What this runner serves, as the client agent advertises it: kind -> option names."""
    return {kind: sorted(OPTION_KEYS.get(kind, ())) for kind in sorted(BROWSER_KINDS)}


def validate_options(kind: str, options: Mapping) -> Mapping:
    if not isinstance(options, Mapping):
        raise ValueError(f"{kind} scenario options must be a mapping")
    allowed = OPTION_KEYS.get(kind, frozenset())
    unknown = set(options) - allowed
    if unknown:
        raise ValueError(f"{kind} scenario has unknown option(s): {', '.join(sorted(map(str, unknown)))}")
    for key, value in options.items():
        if not isinstance(value, str):
            raise ValueError(f"{kind} scenario option {key!r} must be a string")
    if kind == "visual_injection" and options.get("variant", "plain") not in VISUAL_VARIANTS:
        raise ValueError(f"unknown visual_injection variant: {options['variant']!r}")
    if kind == "dom_injection" and "placement" in options and options["placement"] not in PLACEMENTS:
        raise ValueError(f"unknown dom_injection placement: {options['placement']!r}; "
                         f"expected one of {', '.join(sorted(PLACEMENTS))}")
    if kind == "document_inject" and (options.get("format", "pdf") not in DOCUMENT_FORMATS
                                      or options.get("variant", "attack") not in DOCUMENT_VARIANTS):
        raise ValueError(f"unknown document_inject format or variant: {dict(options)!r}")

    if kind == "js_dialog" and options.get("dialog", "confirm") not in DIALOGS:
        raise ValueError(f"unknown js_dialog dialog: {options['dialog']!r}; expected one of {', '.join(sorted(DIALOGS))}")
    if kind == "extraction_tamper" and options.get("variant", "attack") not in EXTRACTION_VARIANTS:
        raise ValueError(f"unknown extraction_tamper variant: {options['variant']!r}")


    if kind == "form_recipient_redirect" and options.get("variant", "attack") not in REMIT_VARIANTS:
        raise ValueError(f"unknown form_recipient_redirect variant: {options['variant']!r}")
    if kind == "cross_origin_bridge" and not options.get("canary", "").strip():
        raise ValueError("cross_origin_bridge requires a nonempty synthetic canary")
    return FrozenOptions(options)
