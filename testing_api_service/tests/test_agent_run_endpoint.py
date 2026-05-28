"""L3 tests for the POST /agent/run SSE endpoint.

The endpoint is a streaming generator that chains:
  1. Azure OpenAI streaming (or Google ADK)  ─► accumulates `full_response`
  2. extract_code_blocks(full_response)      ─► dict of filename→code
  3. CloudflareR2Manager upload + presigned url
  4. Remote test execution: SSH OR test-runner HTTP

Patch boundaries (module-level names on `server`):
  - server.AsyncAzureOpenAI        → fake async client yielding text deltas
  - server.CloudflareR2Manager     → MagicMock instance with upload/presign
  - server.RemoteExecutor          → MagicMock for SSH path
  - server.httpx.AsyncClient       → respx-style / manual async mock
  - server.asyncio.sleep           → no-op so polling loop terminates quickly
"""
from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# A response that lists exactly 5 FILE markers so extract_code_blocks returns
# all five files cleanly.
LLM_RESPONSE = (
    "<!-- FILE: conftest.py -->\n"
    "```python\n"
    "import pytest\n"
    "@pytest.fixture\n"
    "def base_url(): return 'http://x'\n"
    "```\n"
    "<!-- FILE: test_functional.py -->\n"
    "```python\n"
    "def test_happy():\n"
    "    assert True\n"
    "```\n"
    "<!-- FILE: test_security.py -->\n"
    "```python\n"
    "def test_bypass():\n"
    "    assert True\n"
    "```\n"
    "<!-- FILE: requirements.txt -->\n"
    "```\n"
    "pytest\nrequests\nfaker\n"
    "```\n"
    "<!-- FILE: README.md -->\n"
    "```\n"
    "# Tests\nRun pytest\nDone\n"
    "```\n"
)


def _chunks_from(text: str, chunk_size: int = 64):
    """Split LLM_RESPONSE into OpenAI-style streaming chunks."""
    for i in range(0, len(text), chunk_size):
        part = text[i:i + chunk_size]
        yield SimpleNamespace(
            choices=[SimpleNamespace(delta=SimpleNamespace(content=part))]
        )


def _make_fake_azure_client(text: str = LLM_RESPONSE):
    """Return a MagicMock class whose instance streams `text` over .chat.completions.create."""
    chunks = list(_chunks_from(text))

    async def _astream():
        for c in chunks:
            yield c

    async def _create(*args, **kwargs):
        # Must return an async-iterable directly
        return _astream()

    instance = MagicMock()
    instance.chat.completions.create = AsyncMock(side_effect=_create)
    instance.close = AsyncMock(return_value=None)

    # The class itself, when called, returns our instance
    cls = MagicMock(return_value=instance)
    return cls, instance


def _make_fake_r2():
    """Return a MagicMock CloudflareR2Manager class and its instance."""
    instance = MagicMock()
    instance.upload_file_object.return_value = {
        "success": True,
        "object_key": "api-tests/x.zip",
        "download_url": "https://pub.invalid/api-tests/x.zip",
    }
    instance.generate_presigned_url.return_value = {
        "success": True,
        "presigned_url": "https://pub.invalid/presigned?sig=abc",
    }
    cls = MagicMock(return_value=instance)
    return cls, instance


def _parse_ndjson(body: str):
    """Split an ND-JSON stream into a list of decoded dicts."""
    out = []
    for line in body.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        out.append(json.loads(line))
    return out


@pytest.fixture
def client():
    import server
    with TestClient(server.app) as c:
        yield c


# ---------------------------------------------------------------------------
# Happy path: azure stream → artifact only (no remote execution)
# ---------------------------------------------------------------------------

def test_agent_run_streams_azure_text_and_emits_artifact(client):
    """Without remote_test_enabled/ssh_config, we get text deltas + artifact."""
    fake_azure_cls, fake_azure_inst = _make_fake_azure_client()
    fake_r2_cls, fake_r2_inst = _make_fake_r2()

    with patch("server.AsyncAzureOpenAI", fake_azure_cls), \
         patch("server.CloudflareR2Manager", fake_r2_cls):
        with client.stream(
            "POST",
            "/agent/run",
            json={
                "session_state": {"content_analysis": {"crawled_apis": []}},
                "invocation_id": "inv-1",
                "model_provider": "azure",
            },
        ) as resp:
            assert resp.status_code == 200
            assert resp.headers["content-type"].startswith("application/x-ndjson")
            body = "".join(resp.iter_text())

    events = _parse_ndjson(body)
    assert len(events) >= 2

    # Text-chunk events have author=ApiTestingAgent and textual content
    text_events = [e for e in events if "content" in e and isinstance(e["content"], dict)]
    assert any("FILE: conftest.py" in e["content"]["parts"][0]["text"]
               for e in text_events)

    # Artifact event (final) has a nested JSON string inside parts[0].text
    artifact_events = [
        e for e in events
        if "content" in e
        and "parts" in e["content"]
        and e["content"]["parts"]
        and '"type": "artifacts"' in e["content"]["parts"][0].get("text", "")
    ]
    assert artifact_events, "expected an artifacts event"
    inner = json.loads(artifact_events[0]["content"]["parts"][0]["text"])
    assert inner["type"] == "artifacts"
    assert inner["files"][0]["filename"].startswith("api_tests_inv-1_")
    assert inner["files"][0]["download_url"].startswith("https://pub.invalid/presigned")

    # R2 upload was called exactly once with a zip content-type
    fake_r2_inst.upload_file_object.assert_called_once()
    call_kwargs = fake_r2_inst.upload_file_object.call_args.kwargs
    assert call_kwargs["content_type"] == "application/zip"
    assert call_kwargs["metadata"]["invocation_id"] == "inv-1"
    # Azure client was closed
    fake_azure_inst.close.assert_awaited()


# ---------------------------------------------------------------------------
# Test-runner HTTP path: remote_test_enabled=True, no ssh_config
# ---------------------------------------------------------------------------

def test_agent_run_uses_test_runner_when_remote_enabled(client):
    fake_azure_cls, _ = _make_fake_azure_client()
    fake_r2_cls, _ = _make_fake_r2()

    # Fake httpx.AsyncClient: POST /api/v1/run → task_id, GET /status → completed
    class _FakeResp:
        def __init__(self, payload):
            self._payload = payload
        def json(self):
            return self._payload

    class _FakeHTTPX:
        def __init__(self, *a, **kw):
            pass
        async def __aenter__(self):
            return self
        async def __aexit__(self, *a):
            return False
        async def post(self, url, json=None):
            assert url.endswith("/api/v1/run")
            assert json["task_id"] == "inv-run-2"
            assert json["test_type"] == "api"
            return _FakeResp({"task_id": "runner-task-99"})
        async def get(self, url):
            assert "/api/v1/status/runner-task-99" in url
            return _FakeResp({
                "status": "completed",
                "exit_code": 0,
                "stdout": "2 passed",
                "stderr": "",
                "summary": {"passed": 2, "failed": 0},
            })

    # sleep must return immediately to avoid waiting 3s per poll
    async def _no_sleep(_):
        return None

    with patch("server.AsyncAzureOpenAI", fake_azure_cls), \
         patch("server.CloudflareR2Manager", fake_r2_cls), \
         patch("server.httpx.AsyncClient", _FakeHTTPX), \
         patch("asyncio.sleep", _no_sleep):
        with client.stream(
            "POST",
            "/agent/run",
            json={
                "session_state": {
                    "content_analysis": {"crawled_apis": []},
                    "remote_test_enabled": True,
                    "target_url": "https://api.example.invalid",
                },
                "invocation_id": "inv-run-2",
            },
        ) as resp:
            assert resp.status_code == 200
            body = "".join(resp.iter_text())

    events = _parse_ndjson(body)

    # One of the final events is an ssh_result with exit_code=0 + summary
    ssh_results = []
    for e in events:
        try:
            inner = json.loads(e["content"]["parts"][0]["text"])
        except Exception:
            continue
        if inner.get("type") == "ssh_result":
            ssh_results.append(inner["ssh_result"])
    assert ssh_results, "expected an ssh_result event from test-runner branch"
    final = ssh_results[-1]
    assert final["success"] is True
    assert final["exit_code"] == 0
    assert final["stdout"] == "2 passed"
    assert final["summary"] == {"passed": 2, "failed": 0}


# ---------------------------------------------------------------------------
# SSH path: ssh_config with all three required fields
# ---------------------------------------------------------------------------

def test_agent_run_uses_ssh_when_full_ssh_config_provided(client, monkeypatch):
    import base64

    fake_azure_cls, _ = _make_fake_azure_client()
    fake_r2_cls, _ = _make_fake_r2()

    # Fake RemoteExecutor that behaves as a context manager and records commands
    executed_commands = []
    sftp = MagicMock()
    sftp.open.return_value.__enter__ = lambda self: self  # noqa: E731
    sftp.open.return_value.__exit__ = lambda self, *a: False  # noqa: E731

    fake_exec_instance = MagicMock()
    fake_exec_instance._client.open_sftp.return_value = sftp

    def _execute(cmd):
        executed_commands.append(cmd)
        if "mktemp" in cmd:
            return {"stdout": "/tmp/argus_tests_abc\n", "stderr": "", "exit_code": 0}
        if "pytest" in cmd and "pip install" not in cmd:
            return {"stdout": "1 passed", "stderr": "", "exit_code": 0}
        return {"stdout": "", "stderr": "", "exit_code": 0}

    fake_exec_instance.execute.side_effect = _execute
    fake_exec_instance.download_directory = MagicMock()
    fake_exec_instance.__enter__ = MagicMock(return_value=fake_exec_instance)
    fake_exec_instance.__exit__ = MagicMock(return_value=False)

    fake_exec_cls = MagicMock(return_value=fake_exec_instance)

    pem_b64 = base64.b64encode(b"-----BEGIN FAKE KEY-----\nABC\n").decode()

    with patch("server.AsyncAzureOpenAI", fake_azure_cls), \
         patch("server.CloudflareR2Manager", fake_r2_cls), \
         patch("server.RemoteExecutor", fake_exec_cls):
        with client.stream(
            "POST",
            "/agent/run",
            json={
                "session_state": {
                    "content_analysis": {"crawled_apis": []},
                    "ssh_config": {
                        "remote_ip": "10.0.0.5",
                        "username": "ubuntu",
                        "pem_key_base64": pem_b64,
                        "pytest_args": "-v",
                    },
                },
                "invocation_id": "inv-ssh",
            },
        ) as resp:
            assert resp.status_code == 200
            body = "".join(resp.iter_text())

    events = _parse_ndjson(body)

    # RemoteExecutor was called with the decoded PEM
    fake_exec_cls.assert_called_once()
    ctor_kwargs = fake_exec_cls.call_args.kwargs
    assert ctor_kwargs["host"] == "10.0.0.5"
    assert ctor_kwargs["username"] == "ubuntu"
    assert "-----BEGIN FAKE KEY-----" in ctor_kwargs["pkey_data"]

    # pytest was invoked inside the docker runner container
    assert any("docker exec -i runner" in c and "pytest" in c for c in executed_commands)

    # Final ssh_result event
    ssh_results = []
    for e in events:
        try:
            inner = json.loads(e["content"]["parts"][0]["text"])
        except Exception:
            continue
        if inner.get("type") == "ssh_result":
            ssh_results.append(inner["ssh_result"])
    assert ssh_results
    assert ssh_results[-1]["success"] is True


# ---------------------------------------------------------------------------
# Error branches
# ---------------------------------------------------------------------------

def test_agent_run_emits_error_event_when_azure_fails(client):
    """If Azure OpenAI raises, endpoint yields an error payload and moves on."""
    fake_r2_cls, _ = _make_fake_r2()
    bad_client = MagicMock()
    bad_client.chat.completions.create = AsyncMock(side_effect=RuntimeError("azure down"))
    bad_client.close = AsyncMock()

    with patch("server.AsyncAzureOpenAI", MagicMock(return_value=bad_client)), \
         patch("server.CloudflareR2Manager", fake_r2_cls):
        with client.stream(
            "POST",
            "/agent/run",
            json={
                "session_state": {"content_analysis": {}},
                "invocation_id": "inv-err",
            },
        ) as resp:
            body = "".join(resp.iter_text())

    events = _parse_ndjson(body)
    # We get ONE error-payload event, no artifacts
    error_event_present = any(
        "content" in e
        and "parts" in e["content"]
        and "Error calling Azure OpenAI" in e["content"]["parts"][0].get("text", "")
        for e in events
    )
    assert error_event_present


def test_agent_run_ssh_path_reports_failure_on_base64_error(client):
    """Invalid base64 in pem_key_base64 → ssh_result with success=False."""
    fake_azure_cls, _ = _make_fake_azure_client()
    fake_r2_cls, _ = _make_fake_r2()

    with patch("server.AsyncAzureOpenAI", fake_azure_cls), \
         patch("server.CloudflareR2Manager", fake_r2_cls):
        with client.stream(
            "POST",
            "/agent/run",
            json={
                "session_state": {
                    "content_analysis": {},
                    "ssh_config": {
                        "remote_ip": "10.0.0.5",
                        "username": "ubuntu",
                        # Not valid base64 → b64decode raises binascii.Error
                        "pem_key_base64": "!!!not-base64!!!",
                    },
                },
                "invocation_id": "inv-bad-pem",
            },
        ) as resp:
            body = "".join(resp.iter_text())

    events = _parse_ndjson(body)
    ssh_failures = []
    for e in events:
        try:
            inner = json.loads(e["content"]["parts"][0]["text"])
        except Exception:
            continue
        if inner.get("type") == "ssh_result" and inner["ssh_result"]["success"] is False:
            ssh_failures.append(inner["ssh_result"])
    assert ssh_failures, "expected a failed ssh_result event"


def test_agent_run_skips_remote_when_no_config_and_not_enabled(client):
    """Without remote_test_enabled/ssh_config: only artifact, no ssh_result."""
    fake_azure_cls, _ = _make_fake_azure_client()
    fake_r2_cls, _ = _make_fake_r2()

    with patch("server.AsyncAzureOpenAI", fake_azure_cls), \
         patch("server.CloudflareR2Manager", fake_r2_cls):
        with client.stream(
            "POST",
            "/agent/run",
            json={
                "session_state": {"content_analysis": {}},
                "invocation_id": "inv-no-remote",
            },
        ) as resp:
            body = "".join(resp.iter_text())

    events = _parse_ndjson(body)
    ssh_results = []
    for e in events:
        try:
            inner = json.loads(e["content"]["parts"][0]["text"])
        except Exception:
            continue
        if inner.get("type") == "ssh_result":
            ssh_results.append(inner)
    assert not ssh_results


# ---------------------------------------------------------------------------
# Model provider routing
# ---------------------------------------------------------------------------

def test_agent_run_claude_provider_uses_azure_path(client):
    """`model_provider=claude` routes to the Azure code path (by design)."""
    fake_azure_cls, fake_azure_inst = _make_fake_azure_client()
    fake_r2_cls, _ = _make_fake_r2()

    with patch("server.AsyncAzureOpenAI", fake_azure_cls), \
         patch("server.CloudflareR2Manager", fake_r2_cls):
        with client.stream(
            "POST",
            "/agent/run",
            json={
                "session_state": {"content_analysis": {}},
                "invocation_id": "inv-claude",
                "model_provider": "claude",
            },
        ) as resp:
            "".join(resp.iter_text())

    # Proof: Azure client was instantiated and invoked
    fake_azure_cls.assert_called_once()
    fake_azure_inst.chat.completions.create.assert_awaited_once()


def test_agent_run_truncates_oversized_content_analysis(client):
    """content_analysis > 100000 chars gets a [TRUNCATED] suffix in the prompt."""
    fake_azure_cls, fake_azure_inst = _make_fake_azure_client()
    fake_r2_cls, _ = _make_fake_r2()

    huge = "x" * 150_000
    with patch("server.AsyncAzureOpenAI", fake_azure_cls), \
         patch("server.CloudflareR2Manager", fake_r2_cls):
        with client.stream(
            "POST",
            "/agent/run",
            json={
                "session_state": {"content_analysis": huge},
                "invocation_id": "inv-huge",
            },
        ) as resp:
            "".join(resp.iter_text())

    # Inspect the messages passed to Azure
    create_call = fake_azure_inst.chat.completions.create.await_args
    user_msg = create_call.kwargs["messages"][1]["content"]
    assert "[TRUNCATED" in user_msg
    # And must not be longer than the cap + truncation suffix
    assert len(user_msg) < 200_000


# ---------------------------------------------------------------------------
# Request-level validation
# ---------------------------------------------------------------------------

def test_agent_run_missing_session_state_is_422(client):
    resp = client.post("/agent/run", json={})
    assert resp.status_code == 422
