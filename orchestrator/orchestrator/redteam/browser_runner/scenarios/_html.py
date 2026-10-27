"""HTML escaping helper for scenario primitives.

Adversarial payloads will frequently contain HTML metachars (--></script>",
{}, etc.). Templates substitute payload via str.format() which doesn't
escape, so without this helper a payload could break out of comments or
attributes and inject live DOM that wasn't part of the YAML scenario.

Findings must remain attributable to the YAML-declared scenario, not to
whatever metachars the LLM-author/attacker happens to type.
"""

from __future__ import annotations

import html


def esc(s: str) -> str:
    """HTML-escape a string for safe substitution into HTML body or attribute."""
    return html.escape(s, quote=True)
