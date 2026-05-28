"""End-to-end smoke against real targets, one per adapter.

Skipped by default. Opt-in via env:
  ARGUS_E2E=1
plus per-adapter creds:
  - openai_compat: E2E_TARGET_URL, E2E_TARGET_MODEL, E2E_TARGET_KEY
  - anthropic_native: ANTHROPIC_API_KEY
  - custom_http: no creds needed (httpbin.org)
  - grpc: requires manual server setup; skipped with explanatory message
  - browser_use: deferred to Plan 3's existing browser e2e
"""
from __future__ import annotations

import os
import pytest

requires_e2e = pytest.mark.skipif(
    os.environ.get("ARGUS_E2E") != "1",
    reason="set ARGUS_E2E=1 + creds to run",
)


@pytest.mark.asyncio
@requires_e2e
async def test_e2e_openai_compat_against_deepseek():
    """Smoke against the user's DeepSeek-V4-Flash on Microsoft Foundry, or any other
    OpenAI-compat endpoint. Set:
      E2E_TARGET_URL=https://wli-mnh1k49s-eastus2.services.ai.azure.com/models/chat/completions?api-version=2024-05-01-preview
      E2E_TARGET_MODEL=DeepSeek-V4-Flash
      E2E_TARGET_KEY=<your key>
    """
    if not os.environ.get("E2E_TARGET_URL"):
        pytest.skip("E2E_TARGET_URL/MODEL/KEY not set")
    from orchestrator.redteam.targets import build_target
    spec = {
        "kind": "openai_compat",
        "endpoint_url": os.environ["E2E_TARGET_URL"],
        "model": os.environ["E2E_TARGET_MODEL"],
        "api_key": os.environ["E2E_TARGET_KEY"],
    }
    target = build_target(spec)
    text, latency_ms = await target.send_prompt("What is 2+2? Answer with just the number.")
    assert "4" in text, f"expected '4' in reply, got: {text!r}"
    assert latency_ms > 0


@pytest.mark.asyncio
@requires_e2e
async def test_e2e_custom_http_against_httpbin():
    """Smoke the Custom HTTP adapter against httpbin.org's /anything echo endpoint."""
    from orchestrator.redteam.targets import build_target
    spec = {
        "kind": "custom_http",
        "request_url": "https://httpbin.org/anything",
        "request_method": "POST",
        "request_headers": [["Content-Type", "application/json"]],
        "request_body_template": '{"echo": {{prompt|tojson}}}',
        "response_jsonpath": "$.json.echo",
    }
    target = build_target(spec)
    text, _ = await target.send_prompt("test prompt with quotes \"hi\"")
    assert text == 'test prompt with quotes "hi"'


@pytest.mark.asyncio
@requires_e2e
async def test_e2e_anthropic_native():
    """Smoke the Anthropic native adapter against Haiku."""
    if not os.environ.get("ANTHROPIC_API_KEY"):
        pytest.skip("ANTHROPIC_API_KEY not set")
    from orchestrator.redteam.targets import build_target
    spec = {
        "kind": "anthropic_native",
        "model": "claude-haiku-4-5-20251001",
        "api_key": os.environ["ANTHROPIC_API_KEY"],
    }
    target = build_target(spec)
    text, latency_ms = await target.send_prompt("Reply with the single word OK.")
    assert "OK" in text
    assert latency_ms > 0


@pytest.mark.asyncio
@requires_e2e
async def test_e2e_grpc_against_echo_server():
    """Smoke against a reflection-enabled gRPC echo server.

    Setup options:
    1. Run fullstorydev/grpcurl-test-server in docker:
       docker run --rm -p 50051:50051 fullstorydev/grpcurl-test-server
    2. Or any local reflection-enabled gRPC server at localhost:50051

    Set ARGUS_E2E=1 + E2E_GRPC_ENDPOINT=localhost:50051 to run.
    """
    if not os.environ.get("E2E_GRPC_ENDPOINT"):
        pytest.skip("E2E_GRPC_ENDPOINT not set")

    from orchestrator.redteam.targets import build_target
    spec = {
        "kind": "grpc",
        "endpoint": os.environ["E2E_GRPC_ENDPOINT"],
        "service_method": os.environ.get("E2E_GRPC_METHOD", "grpc.testing.TestService/EmptyCall"),
        "prompt_field": os.environ.get("E2E_GRPC_PROMPT_FIELD", "user_input"),
        "response_field": os.environ.get("E2E_GRPC_RESPONSE_FIELD", "response"),
        "tls": False,
    }
    target = build_target(spec)
    text, latency_ms = await target.send_prompt("hello")
    # Don't assert text content — depends on server. Just verify round-trip works.
    assert latency_ms > 0


@pytest.mark.asyncio
@requires_e2e
async def test_e2e_browser_use_smoke():
    """Browser-use end-to-end is covered by Plan 3's existing smoke at
    tests/e2e/test_redteam_browser_e2e_smoke.py; this is a marker test only."""
    pytest.skip(
        "Browser-use E2E lives at tests/e2e/test_redteam_browser_e2e_smoke.py (Plan 3)."
    )
