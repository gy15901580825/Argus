"""Factory: dict-spec → Target instance."""
from __future__ import annotations

from typing import Any

from orchestrator.redteam.targets._base import Target
from orchestrator.redteam.targets.anthropic_native import AnthropicNativeSpec, AnthropicNativeTarget
from orchestrator.redteam.targets.browser_use import BrowserUseSpec, BrowserUseTarget
from orchestrator.redteam.targets.custom_http import CustomHTTPSpec, CustomHTTPTarget
from orchestrator.redteam.targets.grpc import GRPCSpec, GRPCTarget
from orchestrator.redteam.targets.http_upload import HTTPUploadSpec, HTTPUploadTarget
from orchestrator.redteam.targets.mcp_agent import MCPAgentSpec, MCPAgentTarget
from orchestrator.redteam.targets.openai_compat import OpenAICompatSpec, OpenAICompatTarget
from orchestrator.redteam.targets.payment_agent import PaymentAgentSpec, PaymentAgentTarget

_BUILDERS = {
    "anthropic_native": (AnthropicNativeSpec, AnthropicNativeTarget),
    "browser_use": (BrowserUseSpec, BrowserUseTarget),
    "custom_http": (CustomHTTPSpec, CustomHTTPTarget),
    "grpc": (GRPCSpec, GRPCTarget),
    "http_upload": (HTTPUploadSpec, HTTPUploadTarget),
    "mcp_agent": (MCPAgentSpec, MCPAgentTarget),
    "openai_compat": (OpenAICompatSpec, OpenAICompatTarget),
    "payment_agent": (PaymentAgentSpec, PaymentAgentTarget),
}


def build_target(spec: dict[str, Any]) -> Target:
    kind = spec.get("kind")
    if kind not in _BUILDERS:
        raise ValueError(f"unknown target kind: {kind!r}")
    SpecClass, TargetClass = _BUILDERS[kind]
    spec_obj = SpecClass(**spec)
    return TargetClass(spec_obj)


