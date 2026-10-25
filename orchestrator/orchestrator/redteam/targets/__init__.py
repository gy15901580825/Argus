"""Factory: dict-spec → Target instance."""
from __future__ import annotations

import functools
import logging
from importlib.metadata import entry_points
from typing import Any

from orchestrator.redteam.targets._base import Target
from orchestrator.redteam.targets.anthropic_native import AnthropicNativeSpec, AnthropicNativeTarget
from orchestrator.redteam.targets.browser_use import BrowserUseSpec, BrowserUseTarget
from orchestrator.redteam.targets.custom_http import CustomHTTPSpec, CustomHTTPTarget
from orchestrator.redteam.targets.grpc import GRPCSpec, GRPCTarget
from orchestrator.redteam.targets.http_upload import HTTPUploadSpec, HTTPUploadTarget
from orchestrator.redteam.targets.mcp_agent import MCPAgentSpec, MCPAgentTarget
from orchestrator.redteam.targets.mcp_server import MCPServerSpec, MCPServerTarget
from orchestrator.redteam.targets.openai_compat import OpenAICompatSpec, OpenAICompatTarget
from orchestrator.redteam.targets.payment_agent import PaymentAgentSpec, PaymentAgentTarget
from orchestrator.redteam.targets.testbed_agent import GenericTestbedAgentTarget, TestbedAgentSpec
from orchestrator.redteam.targets.vllm_server import VLLMServerSpec, VLLMServerTarget

_BUILDERS = {
    "anthropic_native": (AnthropicNativeSpec, AnthropicNativeTarget),
    "browser_use": (BrowserUseSpec, BrowserUseTarget),
    "custom_http": (CustomHTTPSpec, CustomHTTPTarget),
    "grpc": (GRPCSpec, GRPCTarget),
    "http_upload": (HTTPUploadSpec, HTTPUploadTarget),
    "mcp_agent": (MCPAgentSpec, MCPAgentTarget),
    "mcp_server": (MCPServerSpec, MCPServerTarget),
    "openai_compat": (OpenAICompatSpec, OpenAICompatTarget),
    "payment_agent": (PaymentAgentSpec, PaymentAgentTarget),
    "testbed_agent": (TestbedAgentSpec, GenericTestbedAgentTarget),
    "vllm_server": (VLLMServerSpec, VLLMServerTarget),
}

logger = logging.getLogger(__name__)

# Third-party adapters: `[project.entry-points."argus.targets"]`, name = kind,
# value loads to a (SpecClass, TargetClass) tuple. Kept out of _BUILDERS, which
# test_redteam_target_kind_wiring treats as the list of built-in kinds.
ENTRY_POINT_GROUP = "argus.targets"


@functools.cache
def _plugin_builders() -> dict[str, tuple[type, type]]:
    builders: dict[str, tuple[type, type]] = {}
    # Sorted so that, when two plugins claim one kind, the winner doesn't depend on install order.
    for ep in sorted(entry_points(group=ENTRY_POINT_GROUP), key=lambda e: (e.name, e.value)):
        if ep.name in _BUILDERS:
            logger.warning("target plugin %r ignored: %r is a built-in kind", ep.value, ep.name)
            continue
        if ep.name in builders:
            logger.warning("target plugin %r ignored: kind %r already registered", ep.value, ep.name)
            continue
        try:
            SpecClass, TargetClass = ep.load()
        except Exception:
            logger.warning("target plugin %r (%s) failed to load; skipped", ep.name, ep.value, exc_info=True)
            continue
        builders[ep.name] = (SpecClass, TargetClass)
    return builders


def build_target(spec: dict[str, Any]) -> Target:
    kind = spec.get("kind")
    builder = _BUILDERS.get(kind) or _plugin_builders().get(kind)
    if builder is None:
        raise ValueError(f"unknown target kind: {kind!r}")
    SpecClass, TargetClass = builder
    spec_obj = SpecClass(**spec)
    return TargetClass(spec_obj)


