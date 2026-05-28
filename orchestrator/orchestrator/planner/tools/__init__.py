"""Planner tool implementations and registry.

Exports ToolRegistry with `.names()`, `.get(name)`, and a compile-time map.
"""

from __future__ import annotations

from typing import Any, AsyncGenerator, Awaitable, Callable

from .discover_apis import discover_apis
from .run_api_test import run_api_test
from .run_web_ui_local import run_web_ui_local
from .run_web_ui_cloud import run_web_ui_cloud
from .fetch_page import fetch_page
from .ask_user import ask_user
from .extract_url import extract_url
from .offer_choices import offer_choices


ToolFn = Callable[..., AsyncGenerator[dict, None]]

_REGISTRY: dict[str, ToolFn] = {
    "discover_apis": discover_apis,
    "run_api_test": run_api_test,
    "run_web_ui_local": run_web_ui_local,
    "run_web_ui_cloud": run_web_ui_cloud,
    "fetch_page": fetch_page,
    "ask_user": ask_user,
    "extract_url": extract_url,
    "offer_choices": offer_choices,
}


class ToolRegistry:
    @staticmethod
    def names() -> list[str]:
        return list(_REGISTRY.keys())

    @staticmethod
    def get(name: str) -> ToolFn:
        if name not in _REGISTRY:
            raise KeyError(f"Unknown tool: {name}")
        return _REGISTRY[name]
