"""Jinja rendering for templates that come from a target spec.

A spec can arrive from a caller of `argus.server`, so its templates render in
Jinja's immutable sandbox with no default globals. Failures become ValueError
naming the spec field, the error type build_target() callers already report as
a bad spec. The sandbox is only as good as Jinja's: pyproject pins jinja2>=3.1.6.
"""
from __future__ import annotations

from typing import Any

from jinja2 import Template, TemplateError, TemplateSyntaxError
from jinja2.sandbox import ImmutableSandboxedEnvironment, SecurityError


class _StrictSandbox(ImmutableSandboxedEnvironment):
    def unsafe_undefined(self, obj: Any, attribute: str) -> Any:
        # Jinja's default renders one blocked access as ''; make it an error instead.
        raise SecurityError(
            f"access to attribute {attribute!r} of {type(obj).__name__!r} object is unsafe."
        )


_env = _StrictSandbox(autoescape=False)
# Documented templates use only the context variables (prompt, history, api_key, ...).
_env.globals.clear()


def compile_template(source: str, field: str, dry_run_ctx: dict[str, Any]) -> Template:
    """Compile `source` and render it once with `dry_run_ctx` to catch unsafe access early.

    Only sandbox refusals and overflows fail the dry run; other render errors may
    depend on real data (e.g. indexing an empty history) and are left to send time.
    """
    try:
        tpl = _env.from_string(source)
    except TemplateSyntaxError as e:
        raise ValueError(f"{field}: template syntax error: {e}") from e
    try:
        tpl.render(**dry_run_ctx)
    except (SecurityError, OverflowError) as e:
        raise _refused(field, e) from e
    except Exception:
        pass
    return tpl


def render(tpl: Template, field: str, ctx: dict[str, Any]) -> str:
    try:
        return tpl.render(**ctx)
    except (SecurityError, OverflowError) as e:
        raise _refused(field, e) from e
    except TemplateError as e:
        raise ValueError(f"{field}: template error: {e}") from e


def _refused(field: str, e: Exception) -> ValueError:
    return ValueError(f"{field}: template refused by the sandbox ({type(e).__name__}: {e})")
