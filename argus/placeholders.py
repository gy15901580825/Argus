"""Placeholders in probe prompts that Argus fills in before a prompt is sent."""

from __future__ import annotations

_GENERATOR_NAME = "{generator.name}"
_FALLBACK_NAME = "the assistant"
# A fill-in slot left in garak's in-the-wild DAN text; sending it literally would
# send a template, so it gets neutral text.
_CHARACTER_SLOT = "{describe character here}"
_CHARACTER_TEXT = "a friendly pirate captain"


def target_model_name(target) -> str:
    """The model name in the target's spec, or "" when it has none (custom_http, mcp_agent...)."""
    for obj in (target, getattr(target, "_inner", None)):
        name = getattr(getattr(obj, "spec", None), "model", "")
        if isinstance(name, str) and name:
            return name
    return ""


def render_generator_name(prompt: str, model_name: str) -> str:
    """garak's DAN prompts address the target as {generator.name}; sending that
    literal would test a prompt nobody wrote."""
    return prompt.replace(_GENERATOR_NAME, model_name or _FALLBACK_NAME).replace(
        _CHARACTER_SLOT, _CHARACTER_TEXT
    )


def needs_rendering(prompt: str) -> bool:
    return _GENERATOR_NAME in prompt or _CHARACTER_SLOT in prompt
