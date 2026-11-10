"""Factory: dict-spec → Target instance."""

from __future__ import annotations

import functools
import logging
from dataclasses import MISSING, _FIELD_INITVAR, fields, is_dataclass
from importlib.metadata import entry_points
from pathlib import Path
from typing import Any

from argus.input_budget import InputLimits

from argus_transport.cleanup import CleanupReport
from argus_transport.stops import RunStopped, TargetRunStopped

from argus.targets._base import KindInfo, Target
from argus.targets.a2a_agent import A2AAgentSpec, A2AAgentTarget
from argus.targets.a2a_server import A2AServerSpec, A2AServerTarget
from argus.targets.anthropic_native import AnthropicNativeSpec, AnthropicNativeTarget
from argus.targets.browser_use import BrowserUseSpec, BrowserUseTarget
from argus.targets.custom_http import CustomHTTPSpec, CustomHTTPTarget
from argus.targets.grpc import GRPCSpec, GRPCTarget
from argus.targets.http_upload import HTTPUploadSpec, HTTPUploadTarget
from argus.targets.mcp_agent import MCPAgentSpec, MCPAgentTarget
from argus.targets.mcp_server import MCPServerSpec, MCPServerTarget
from argus.targets.openai_compat import OpenAICompatSpec, OpenAICompatTarget
from argus.targets.payment_agent import PaymentAgentSpec, PaymentAgentTarget
from argus.targets.python_target import PythonSpec, PythonTarget
from argus.targets.testbed_agent import GenericTestbedAgentTarget, TestbedAgentSpec
from argus.targets.vllm_server import VLLMServerSpec, VLLMServerTarget
from argus.targets.web_chat import WebChatSpec, WebChatTarget

_BUILDERS = {
    "a2a_server": (A2AServerSpec, A2AServerTarget),
    "anthropic_native": (AnthropicNativeSpec, AnthropicNativeTarget),
    "browser_use": (BrowserUseSpec, BrowserUseTarget),
    "custom_http": (CustomHTTPSpec, CustomHTTPTarget),
    "grpc": (GRPCSpec, GRPCTarget),
    "http_upload": (HTTPUploadSpec, HTTPUploadTarget),
    "a2a_agent": (A2AAgentSpec, A2AAgentTarget),
    "mcp_agent": (MCPAgentSpec, MCPAgentTarget),
    "mcp_server": (MCPServerSpec, MCPServerTarget),
    "openai_compat": (OpenAICompatSpec, OpenAICompatTarget),
    "payment_agent": (PaymentAgentSpec, PaymentAgentTarget),
    "python": (PythonSpec, PythonTarget),
    "testbed_agent": (TestbedAgentSpec, GenericTestbedAgentTarget),
    "vllm_server": (VLLMServerSpec, VLLMServerTarget),
    "web_chat": (WebChatSpec, WebChatTarget),
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
    for ep in sorted(
        entry_points(group=ENTRY_POINT_GROUP), key=lambda e: (e.name, e.value)
    ):
        if ep.name in _BUILDERS:
            logger.warning(
                "target plugin %r ignored: %r is a built-in kind", ep.value, ep.name
            )
            continue
        if ep.name in builders:
            logger.warning(
                "target plugin %r ignored: kind %r already registered",
                ep.value,
                ep.name,
            )
            continue
        try:
            SpecClass, TargetClass = ep.load()
        except (Exception, SystemExit):
            logger.warning(
                "target plugin %r (%s) failed to load; skipped",
                ep.name,
                ep.value,
            )
            logger.debug("target plugin %r load traceback", ep.name, exc_info=True)
            continue
        info = getattr(TargetClass, "kind_info", None)
        if info is not None and (
            not isinstance(info, KindInfo) or info.kind != ep.name
        ):
            logger.warning(
                "target plugin %r kind_info must be a KindInfo with matching kind; skipped",
                ep.name,
            )
            continue
        builders[ep.name] = (SpecClass, TargetClass)
    return builders


def _has_nested_python(spec: dict[str, Any]) -> bool:
    inner = spec.get("inner")
    return isinstance(inner, dict) and (
        inner.get("kind") == "python" or _has_nested_python(inner)
    )


def build_target(spec: dict[str, Any], *, trusted_code: bool = False) -> Target:
    input_limits = InputLimits.from_spec(spec)
    kind = spec.get("kind")
    # A python target runs the caller's code: only the local run path may build one,
    # and an adapter that nests another target never passes trusted_code down.
    if _has_nested_python(spec):
        raise ValueError("a python target cannot be nested in inner")
    if kind == "python" and not trusted_code:
        raise ValueError(
            "python targets run only on the local machine: use argus-probe run --local"
        )
    builder = _BUILDERS.get(kind) or _plugin_builders().get(kind)
    if builder is None:
        raise ValueError(f"unknown target kind: {kind!r}")
    SpecClass, TargetClass = builder
    if kind == "custom_http" and "transport" in spec:
        from argus.targets.custom_http import LEGACY_TRANSPORT_FIELDS

        if set(spec) & LEGACY_TRANSPORT_FIELDS:
            raise ValueError("transport and legacy transport fields conflict")
    adapter_spec = {key: value for key, value in spec.items() if key != "input_limits"}
    spec_obj = SpecClass(**adapter_spec)
    target = TargetClass(spec_obj)
    target.input_limits = input_limits
    return target


class _BuiltinValidation:
    """Preserve the built-in CLI boundary, including transport alternatives."""

    def __init__(self, kind: str, required: frozenset[str], sandbox_reason: str | None):
        self.kind = kind
        self.required = required
        self.sandbox_reason = sandbox_reason

    def __call__(self, spec: dict[str, Any]) -> None:
        required = self.required
        if "transport" in spec:
            if self.kind not in {"custom_http", "browser_use"}:
                raise ValueError(
                    "transport is supported only by custom_http and browser_use"
                )
            from argus.targets.custom_http import LEGACY_TRANSPORT_FIELDS

            legacy_fields = (
                LEGACY_TRANSPORT_FIELDS
                if self.kind == "custom_http"
                else {"agent_url", "timeout_s"}
            )
            if set(spec) & legacy_fields:
                raise ValueError("transport and legacy transport fields conflict")
            required = set() if self.kind == "custom_http" else {"scenario_kind"}
        _check_required(spec, required)
        _check_sandbox(spec, self.sandbox_reason)

    def anchor(self, spec: dict[str, Any], base_dir: Path | None) -> dict[str, Any]:
        if self.kind != "python" or base_dir is None:
            return spec
        from argus.targets.python_target import is_path_entry, split_entry

        anchored = dict(spec)
        for name in ("entry", "cleanup", "close"):
            if name != "entry" and anchored.get(name) is None:
                continue
            try:
                target, func = split_entry(anchored[name])
            except (ValueError, AttributeError):
                continue
            if is_path_entry(target) and not Path(target).is_absolute():
                anchored[name] = f"{base_dir / target}:{func}"
        return anchored

    def transport_version(self, spec: dict[str, Any]) -> int | None:
        """Select built-in validation routing; plugin transport fields are opaque."""
        if self.kind == "custom_http" and "transport" in spec:
            transport = spec["transport"]
            if (
                isinstance(transport, dict)
                and type(transport.get("version")) is int
                and transport["version"] == 2
            ):
                return 2
            return 1
        if self.kind == "browser_use":
            return 1
        return None


def _check_required(spec: dict[str, Any], required) -> None:
    missing = required - spec.keys()
    if missing:
        raise ValueError(
            f"target.kind={spec['kind']!r} missing required fields: {sorted(missing)}"
        )


def _check_sandbox(spec: dict[str, Any], reason: str | None) -> None:
    if reason is not None and spec.get("sandbox") is not True:
        raise ValueError(
            f"target.kind={spec['kind']!r} requires sandbox: true — this adapter "
            f"{reason} and may only be pointed at a simulated testbed"
        )


def _builtin_info(kind: str, **metadata) -> KindInfo:
    return KindInfo(
        kind=kind,
        **metadata,
        validate=_BuiltinValidation(
            kind, metadata["required"], metadata.get("sandbox_reason")
        ),
    )


_BUILTIN_KINDS = {
    "openai_compat": _builtin_info(
        "openai_compat",
        required=frozenset(["endpoint_url", "model"]),
        description="An HTTP endpoint that speaks the OpenAI Chat Completions protocol",
        chat=True,
        no_text_hint="the endpoint returned no message content",
        init_questions=(
            (
                "endpoint_url",
                "Endpoint URL",
                "https://api.openai.com/v1/chat/completions",
            ),
            ("model", "Model name", None),
            ("api_key_env", "API key env var", "OPENAI_API_KEY"),
        ),
    ),
    "anthropic_native": _builtin_info(
        "anthropic_native",
        required=frozenset(["api_key", "model"]),
        description="The Anthropic Messages API",
        chat=True,
        no_text_hint="the endpoint returned no message content",
        init_questions=(
            ("model", "Model name", "claude-haiku-4-5-20251001"),
            ("api_key_env", "API key env var", "ANTHROPIC_API_KEY"),
        ),
    ),
    "custom_http": _builtin_info(
        "custom_http",
        required=frozenset(
            ["request_body_template", "request_url", "response_jsonpath"]
        ),
        description="An agent behind its own HTTP request and response shape",
        chat=True,
        no_text_hint="check response_jsonpath or the endpoint",
        init_questions=(
            ("request_url", "Request URL", None),
            (
                "request_body_template",
                "Request body template (Jinja2 with {{prompt}})",
                '{"input": {{prompt|tojson}}}',
            ),
            ("response_jsonpath", "Response JSONPath", "$.output"),
        ),
    ),
    "web_chat": _builtin_info(
        "web_chat",
        required=frozenset(["input_selector", "response_selector", "url"]),
        description="An agent reachable only through a web chat page",
        chat=True,
        no_text_hint="check response_selector",
        init_questions=(
            ("url", "Chat page URL", None),
            ("input_selector", "CSS selector of the message box", "textarea"),
            (
                "response_selector",
                "CSS selector matching every assistant message",
                None,
            ),
            (
                "send_selector",
                "CSS selector of the send button (empty: press Enter)",
                "",
            ),
        ),
    ),
    "python": _builtin_info(
        "python",
        required=frozenset(["entry"]),
        description="An agent you can call as a Python function",
        chat=True,
        init_questions=(
            (
                "entry",
                "Python entry (module:func or path/to/file.py:func)",
                "argus_target.py:call",
            ),
        ),
    ),
    "grpc": _builtin_info(
        "grpc",
        required=frozenset(["endpoint", "service_method"]),
        description="A gRPC service with server reflection enabled",
        init_questions=(
            ("endpoint", "Endpoint (host:port)", "localhost:50051"),
            ("service_method", "Service method (pkg.Service/Method)", None),
            ("prompt_field", "Prompt field name", "user_input"),
            ("response_field", "Response field name", "response"),
        ),
    ),
    "browser_use": _builtin_info(
        "browser_use",
        required=frozenset(["agent_url", "scenario_kind"]),
        description="A browser-using agent",
        init_questions=(
            ("agent_url", "Browser-using agent URL", None),
            (
                "scenario_kind",
                "Scenario kind (dom_injection/ui_phishing/visual_injection/os_cmd)",
                "dom_injection",
            ),
        ),
    ),
    "http_upload": _builtin_info(
        "http_upload",
        required=frozenset(["upload_url"]),
        description="A file upload endpoint that renders what it stores",
        init_questions=(
            ("upload_url", "Upload URL", None),
            ("upload_field_name", "Upload form field name", "file"),
            ("upload_filename", "Upload filename", "payload.svg"),
            ("upload_content_type", "Upload content type", "image/svg+xml"),
            (
                "render_url_jsonpath",
                "Render URL JSONPath (extracts the render URL from the upload response)",
                "$.url",
            ),
        ),
    ),
    "mcp_agent": _builtin_info(
        "mcp_agent",
        required=frozenset(["inner", "sandbox", "testbed_url"]),
        description="An agent that uses MCP tools, run against a hostile MCP testbed",
        sandbox_reason="drives an agent against a live MCP server",
        init_questions=(
            (
                "testbed_url",
                'MCP testbed URL ("local" starts the bundled one on 127.0.0.1 for each run)',
                "local",
            ),
            (
                "inner_json",
                "Inner target spec (JSON) for the transport that talks to your agent",
                '{"kind": "openai_compat", "endpoint_url": "http://127.0.0.1:8093/v1/chat/completions", "model": "argus-demo-mcp-agent"}',
            ),
        ),
    ),
    "payment_agent": _builtin_info(
        "payment_agent",
        required=frozenset(["inner", "sandbox", "testbed_url"]),
        description="An agent that spends money, run against a payment testbed",
        sandbox_reason="drives an agent that spends money",
        init_questions=(
            (
                "testbed_url",
                'Payment testbed URL ("local" starts the bundled one on 127.0.0.1 for each run)',
                "local",
            ),
            (
                "inner_json",
                "Inner target spec (JSON) for the transport that talks to your agent",
                '{"kind": "openai_compat", "endpoint_url": "http://127.0.0.1:8091/v1/chat/completions", "model": "argus-demo-payment-agent"}',
            ),
        ),
    ),
    "a2a_agent": _builtin_info(
        "a2a_agent",
        required=frozenset(["inner", "sandbox", "testbed_url"]),
        description="An agent that talks to A2A peers, run against an A2A peer testbed",
        sandbox_reason="drives an agent that sends messages to A2A peers and requests actions",
        init_questions=(
            (
                "testbed_url",
                "A2A control URL (local starts the bundled peer world)",
                "local",
            ),
            (
                "inner_json",
                "Inner target spec (JSON)",
                '{"kind":"openai_compat","endpoint_url":"http://127.0.0.1:8095/v1/chat/completions","model":"demo"}',
            ),
            (
                "capabilities_csv",
                "Capabilities (comma-separated)",
                "peer_http_json_1_0",
            ),
        ),
    ),
    "testbed_agent": _builtin_info(
        "testbed_agent",
        required=frozenset(["environment", "inner", "sandbox", "testbed_url"]),
        description="The general form of mcp_agent, payment_agent and a2a_agent",
        sandbox_reason="drives an agent inside a simulated environment",
        init_questions=(
            ("environment", "Environment (mcp/payment/a2a)", "mcp"),
            (
                "testbed_url",
                'Testbed URL ("local" starts the bundled one on 127.0.0.1 for each run)',
                "local",
            ),
            (
                "inner_json",
                "Inner target spec (JSON) for the transport that talks to your agent",
                '{"kind": "openai_compat", "endpoint_url": "http://127.0.0.1:8093/v1/chat/completions", "model": "argus-demo-mcp-agent"}',
            ),
        ),
    ),
    "mcp_server": _builtin_info(
        "mcp_server",
        required=frozenset(["url"]),
        description="An MCP server you run over HTTP (tests the server, not an agent)",
        init_questions=(
            (
                "url",
                "MCP server Streamable HTTP endpoint (e.g. http://127.0.0.1:3001/mcp)",
                None,
            ),
        ),
    ),
    "a2a_server": _builtin_info(
        "a2a_server",
        required=frozenset(["url"]),
        description="An A2A server (tests the server, not an agent)",
        init_questions=(
            (
                "url",
                "A2A server base URL (the Agent Card is at <url>/.well-known/agent-card.json)",
                None,
            ),
        ),
    ),
    "vllm_server": _builtin_info(
        "vllm_server",
        required=frozenset(["url"]),
        description="A vLLM model server (tests the server, not an agent)",
        init_questions=(
            (
                "url",
                "vLLM server root URL, not the /v1 path (e.g. http://10.0.0.5:8000)",
                None,
            ),
        ),
    ),
}


def kinds() -> dict[str, KindInfo]:
    """Built-in and installed plugin kinds, with the factory's precedence.

    Without kind_info, dataclass plugins require non-defaulted init fields (including InitVar),
    excluding kind. Other schema types need explicit metadata for requiredness.
    """
    result = dict(_BUILTIN_KINDS)
    for kind, (spec_class, target_class) in _plugin_builders().items():
        info = getattr(target_class, "kind_info", None)
        if info is None:
            required = (
                frozenset(
                    f.name
                    for f in (
                        *fields(spec_class),
                        *(f for f in spec_class.__dataclass_fields__.values()
                          if f._field_type is _FIELD_INITVAR),
                    )
                    if f.init
                    and f.name != "kind"
                    and f.default is MISSING
                    and f.default_factory is MISSING
                )
                if is_dataclass(spec_class)
                else frozenset()
            )
            info = KindInfo(
                kind=kind, required=required, description=f"Plugin target: {kind}"
            )
        result[kind] = info
    return result
