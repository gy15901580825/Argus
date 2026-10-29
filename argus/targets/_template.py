"""Jinja rendering for templates that come from a target spec.

A spec can arrive from a caller of `argus.server`, so its templates render in
Jinja's sandbox: no access to underscore attributes or other unsafe objects.
Failures become ValueError naming the spec field, the error type build_target()
callers already report as a bad spec.
"""
from __future__ import annotations

from typing import Any

from jinja2 import Template, TemplateSyntaxError
from jinja2.sandbox import SandboxedEnvironment, SecurityError

_env = SandboxedEnvironment(autoescape=False)


def compile_template(source: str, field: str, dry_run_ctx: dict[str, Any]) -> Template:
    """Compile `source` and render it once with `dry_run_ctx` to catch unsafe access early.

    Only sandbox refusals fail the dry run; other render errors may depend on
    real data (e.g. indexing an empty history) and are left to send time.
    """
    try:
        tpl = _env.from_string(source)
    except TemplateSyntaxError as e:
        raise ValueError(f"{field}: template syntax error: {e}") from e
    try:
        tpl.render(**dry_run_ctx)
    except SecurityError as e:
        raise _refused(field, e) from e
    except Exception:
        pass
    return tpl


def render(tpl: Template, field: str, ctx: dict[str, Any]) -> str:
    try:
        return tpl.render(**ctx)
    except SecurityError as e:
        raise _refused(field, e) from e


def _refused(field: str, e: SecurityError) -> ValueError:
    return ValueError(f"{field}: template refused by the sandbox ({e})")
