"""Discriminated union TargetSpec for /redteam/runs API.

Mirrors the 6 adapter spec classes in
orchestrator/orchestrator/redteam/targets/*.py. Field names must
stay in lockstep — api_service forwards the JSON body verbatim. If a field
diverges, orchestrator rejects with ValueError → 500.
"""
from __future__ import annotations

from typing import Annotated, Any, Literal, Optional, Union
from pydantic import BaseModel, Field


class OpenAICompatTarget(BaseModel):
    kind: Literal["openai_compat"] = "openai_compat"
    endpoint_url: str
    model: str
    api_key: Optional[str] = None
    extra_headers: list[tuple[str, str]] = Field(default_factory=list)
    timeout_s: float = 30.0


class AnthropicNativeTarget(BaseModel):
    kind: Literal["anthropic_native"] = "anthropic_native"
    model: str
    api_key: str
    max_tokens: int = 1024
    timeout_s: float = 60.0


class CustomHTTPTarget(BaseModel):
    kind: Literal["custom_http"] = "custom_http"
    request_url: str
    request_method: str = "POST"
    request_headers: list[tuple[str, str]] = Field(default_factory=list)
    api_key: Optional[str] = None
    request_body_template: str
    response_jsonpath: str
    response_latency_jsonpath: Optional[str] = None
    timeout_s: float = 60.0


class GRPCTarget(BaseModel):
    kind: Literal["grpc"] = "grpc"
    endpoint: str
    service_method: str
    prompt_field: str = "user_input"
    response_field: str = "response"
    tls: bool = True
    timeout_s: float = 60.0


class BrowserUseTarget(BaseModel):
    kind: Literal["browser_use"] = "browser_use"
    agent_url: str
    scenario_kind: Literal["dom_injection", "ui_phishing", "visual_injection", "os_cmd"]
    timeout_s: float = 60.0
    extra_context: dict[str, str] = Field(default_factory=dict)


class PaymentAgentTarget(BaseModel):
    kind: Literal["payment_agent"] = "payment_agent"
    testbed_url: str
    inner: dict[str, Any]
    script: dict[str, Any] = Field(default_factory=dict)
    # This adapter drives an agent that spends money. sandbox must be
    # present and true — not just true by default — so a customer cannot
    # reach real funds by omitting the field. The orchestrator enforces the
    # same rule; this is not the only place it may be checked.
    sandbox: Literal[True]
    timeout_s: float = 60.0


TargetSpec = Annotated[
    Union[
        OpenAICompatTarget,
        AnthropicNativeTarget,
        CustomHTTPTarget,
        GRPCTarget,
        BrowserUseTarget,
        PaymentAgentTarget,
    ],
    Field(discriminator="kind"),
]
