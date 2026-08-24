"""Tests for target_loader module."""
import json
import pytest
from argus_probe.target_loader import load_target_spec, TargetLoadError


def test_load_inline_json():
    spec = load_target_spec('{"kind": "openai_compat", "endpoint_url": "https://x", "model": "y", "api_key": "k"}')
    assert spec["kind"] == "openai_compat"


def test_load_from_file(tmp_path):
    p = tmp_path / "t.json"
    p.write_text('{"kind": "anthropic_native", "model": "claude-haiku-4-5-20251001", "api_key": "k"}')
    spec = load_target_spec(str(p))
    assert spec["kind"] == "anthropic_native"


def test_rejects_missing_kind():
    with pytest.raises(TargetLoadError, match="kind"):
        load_target_spec('{"endpoint_url": "x"}')


def test_rejects_unknown_kind():
    with pytest.raises(TargetLoadError, match="unknown"):
        load_target_spec('{"kind": "telepathy"}')


def test_rejects_malformed_json():
    with pytest.raises(TargetLoadError, match="malformed"):
        load_target_spec('{"kind": "openai_compat",}')  # trailing comma


def test_rejects_non_object_json():
    with pytest.raises(TargetLoadError, match="object"):
        load_target_spec('["not", "an", "object"]')


def test_rejects_nonexistent_file_or_invalid_arg():
    with pytest.raises(TargetLoadError):
        load_target_spec("/tmp/this-file-does-not-exist-anywhere.json")


@pytest.mark.parametrize("kind,minimum", [
    ("openai_compat", {"endpoint_url": "x", "model": "y"}),
    ("anthropic_native", {"model": "x", "api_key": "y"}),
    ("custom_http", {"request_url": "x", "request_body_template": "{}", "response_jsonpath": "$.x"}),
    ("grpc", {"endpoint": "h:1", "service_method": "p.S/M"}),
    ("browser_use", {"agent_url": "x", "scenario_kind": "dom_injection"}),
    ("payment_agent", {"testbed_url": "x", "inner": {"kind": "openai_compat"}, "sandbox": True}),
    ("mcp_agent", {"testbed_url": "x", "inner": {"kind": "openai_compat"}, "sandbox": True}),
    ("http_upload", {"upload_url": "https://x/upload", "render_url_jsonpath": "$.url"}),
])
def test_each_kind_passes_minimal_validation(kind, minimum):
    blob = json.dumps({"kind": kind, **minimum})
    spec = load_target_spec(blob)
    assert spec["kind"] == kind


@pytest.mark.parametrize("kind,partial", [
    ("openai_compat", {"endpoint_url": "x"}),  # missing model
    ("anthropic_native", {"model": "x"}),  # missing api_key
    ("custom_http", {"request_url": "x", "request_body_template": "{}"}),  # missing response_jsonpath
    ("grpc", {"endpoint": "h:1"}),  # missing service_method
    ("browser_use", {"agent_url": "x"}),  # missing scenario_kind
    ("payment_agent", {"testbed_url": "x", "sandbox": True}),  # missing inner
    ("mcp_agent", {"testbed_url": "x", "sandbox": True}),  # missing inner
    ("http_upload", {"render_url_jsonpath": "$.url"}),  # missing upload_url
])
def test_missing_required_fields_per_kind(kind, partial):
    blob = json.dumps({"kind": kind, **partial})
    with pytest.raises(TargetLoadError, match="missing required"):
        load_target_spec(blob)


@pytest.mark.parametrize("payment_spec", [
    {"testbed_url": "x", "inner": {"kind": "openai_compat"}},  # sandbox absent
    {"testbed_url": "x", "inner": {"kind": "openai_compat"}, "sandbox": False},
])
def test_payment_agent_requires_sandbox_true(payment_spec):
    """sandbox must stay mandatory-and-true client-side too — this adapter
    drives an agent that spends money and the orchestrator-side guard must
    not be the only place that is enforced."""
    blob = json.dumps({"kind": "payment_agent", **payment_spec})
    with pytest.raises(TargetLoadError, match="sandbox"):
        load_target_spec(blob)


@pytest.mark.parametrize("mcp_spec", [
    {"testbed_url": "x", "inner": {"kind": "openai_compat"}},  # sandbox absent
    {"testbed_url": "x", "inner": {"kind": "openai_compat"}, "sandbox": False},
])
def test_mcp_agent_requires_sandbox_true(mcp_spec):
    """Same interlock as payment_agent, same reason: a run that could reach a
    real MCP server is not a configuration mistake we recover from, so the
    orchestrator-side refusal must not be the only one."""
    blob = json.dumps({"kind": "mcp_agent", **mcp_spec})
    with pytest.raises(TargetLoadError, match="sandbox"):
        load_target_spec(blob)


def test_load_expands_env_vars_in_string_values(tmp_path, monkeypatch):
    """${VAR} references in spec string values are expanded at load time."""
    monkeypatch.setenv("MY_TEST_KEY", "secret-value-123")
    target_path = tmp_path / "target.json"
    target_path.write_text('{"kind": "openai_compat", "endpoint_url": "https://x", "model": "y", "api_key": "${MY_TEST_KEY}"}')
    spec = load_target_spec(str(target_path))
    assert spec["api_key"] == "secret-value-123"


def test_load_unset_env_var_leaves_literal(tmp_path, monkeypatch):
    """Unset env var: os.path.expandvars leaves the literal $VAR; we don't error.
    Operator gets a 401 from the server with the literal string visible in the
    error trail, which is debuggable."""
    monkeypatch.delenv("DEFINITELY_UNSET_VAR_XYZ", raising=False)
    target_path = tmp_path / "target.json"
    target_path.write_text('{"kind": "openai_compat", "endpoint_url": "https://x", "model": "y", "api_key": "${DEFINITELY_UNSET_VAR_XYZ}"}')
    spec = load_target_spec(str(target_path))
    # os.path.expandvars on unset var returns the literal $VAR or ${VAR}
    assert spec["api_key"].startswith("$")  # literal preserved
