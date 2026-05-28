"""Tests for orchestrator/utils/r2_uploader.py — boto3 client patched."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def fake_boto_client():
    """Patch boto3.client so R2Uploader() never hits the network, and return the mock."""
    with patch("orchestrator.utils.r2_uploader.boto3.client") as mock_boto:
        client = MagicMock()
        client.put_object = MagicMock(return_value={})
        client.delete_object = MagicMock(return_value={})
        client.generate_presigned_url = MagicMock(
            return_value="https://example.invalid/scripts/foo.py?sig=abc"
        )
        client.list_objects_v2 = MagicMock(return_value={"Contents": []})
        mock_boto.return_value = client
        yield mock_boto, client


def test_init_uses_env_and_builds_endpoint(fake_boto_client, monkeypatch):
    mock_boto, _ = fake_boto_client
    monkeypatch.setenv("R2_ACCOUNT_ID", "acct-xyz")
    monkeypatch.setenv("R2_BUCKET_NAME", "my-bucket")

    from orchestrator.utils.r2_uploader import R2Uploader

    u = R2Uploader()
    assert u.bucket_name == "my-bucket"
    assert u.endpoint_url == "https://acct-xyz.r2.cloudflarestorage.com"
    # boto3.client called with service 's3' and R2-specific kwargs
    call = mock_boto.call_args
    assert call.args[0] == "s3"
    assert call.kwargs["endpoint_url"] == "https://acct-xyz.r2.cloudflarestorage.com"
    assert call.kwargs["region_name"] == "auto"


def test_upload_script_with_user_id(fake_boto_client):
    _, client = fake_boto_client
    from orchestrator.utils.r2_uploader import R2Uploader

    u = R2Uploader()
    url = u.upload_script("print('hi')\n", user_id="user-1", filename="hello.py")

    # put_object called with scripts/user-1/hello.py
    assert client.put_object.call_count == 1
    kwargs = client.put_object.call_args.kwargs
    assert kwargs["Bucket"] == u.bucket_name
    assert kwargs["Key"] == "scripts/user-1/hello.py"
    assert kwargs["ContentType"] == "text/x-python"
    assert kwargs["Body"] == b"print('hi')\n"
    assert kwargs["Metadata"]["user_id"] == "user-1"

    # URL comes from presigned
    assert url.startswith("https://example.invalid/")
    presigned_kwargs = client.generate_presigned_url.call_args
    assert presigned_kwargs.args[0] == "get_object"
    assert presigned_kwargs.kwargs["ExpiresIn"] == 3600
    assert presigned_kwargs.kwargs["Params"]["Key"] == "scripts/user-1/hello.py"


def test_upload_script_without_user_id_uses_root_prefix(fake_boto_client):
    _, client = fake_boto_client
    from orchestrator.utils.r2_uploader import R2Uploader

    u = R2Uploader()
    u.upload_script("x = 1", filename="anon.py")

    kwargs = client.put_object.call_args.kwargs
    assert kwargs["Key"] == "scripts/anon.py"
    assert kwargs["Metadata"]["user_id"] == "anonymous"


def test_upload_script_autogenerates_filename(fake_boto_client):
    _, client = fake_boto_client
    from orchestrator.utils.r2_uploader import R2Uploader

    u = R2Uploader()
    u.upload_script("pytest_code", user_id="u2")

    key = client.put_object.call_args.kwargs["Key"]
    # Format: scripts/u2/test_script_YYYYMMDD_HHMMSS_<uuid8>.py
    assert key.startswith("scripts/u2/test_script_")
    assert key.endswith(".py")


def test_upload_script_wraps_boto_error(fake_boto_client):
    _, client = fake_boto_client
    client.put_object.side_effect = RuntimeError("network down")
    from orchestrator.utils.r2_uploader import R2Uploader

    u = R2Uploader()
    with pytest.raises(Exception) as exc_info:
        u.upload_script("x", user_id="u", filename="f.py")
    assert "R2 upload failed" in str(exc_info.value)


def test_delete_script_success(fake_boto_client):
    _, client = fake_boto_client
    from orchestrator.utils.r2_uploader import R2Uploader

    u = R2Uploader()
    assert u.delete_script("scripts/u/foo.py") is True
    client.delete_object.assert_called_once_with(
        Bucket=u.bucket_name, Key="scripts/u/foo.py"
    )


def test_delete_script_wraps_boto_error(fake_boto_client):
    _, client = fake_boto_client
    client.delete_object.side_effect = RuntimeError("access denied")
    from orchestrator.utils.r2_uploader import R2Uploader

    u = R2Uploader()
    with pytest.raises(Exception) as exc_info:
        u.delete_script("scripts/u/x.py")
    assert "R2 deletion failed" in str(exc_info.value)


def test_list_user_scripts_empty(fake_boto_client):
    _, client = fake_boto_client
    client.list_objects_v2.return_value = {}  # no Contents key
    from orchestrator.utils.r2_uploader import R2Uploader

    u = R2Uploader()
    assert u.list_user_scripts("u1") == []
    call = client.list_objects_v2.call_args.kwargs
    assert call["Prefix"] == "scripts/u1/"


def test_list_user_scripts_non_empty(fake_boto_client):
    _, client = fake_boto_client
    client.list_objects_v2.return_value = {
        "Contents": [
            {"Key": "scripts/u1/a.py"},
            {"Key": "scripts/u1/b.py"},
        ]
    }
    from orchestrator.utils.r2_uploader import R2Uploader

    u = R2Uploader()
    assert u.list_user_scripts("u1") == ["scripts/u1/a.py", "scripts/u1/b.py"]


def test_list_user_scripts_swallows_error(fake_boto_client):
    _, client = fake_boto_client
    client.list_objects_v2.side_effect = RuntimeError("nope")
    from orchestrator.utils.r2_uploader import R2Uploader

    u = R2Uploader()
    assert u.list_user_scripts("u1") == []  # best-effort: returns [] on error


def test_get_r2_uploader_returns_singleton(fake_boto_client):
    from orchestrator.utils import r2_uploader as mod
    mod._r2_uploader = None  # reset the module-level cache

    first = mod.get_r2_uploader()
    second = mod.get_r2_uploader()
    assert first is second
