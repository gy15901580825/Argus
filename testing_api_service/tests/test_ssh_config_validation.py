"""Validation tests for `server.SSHConfigRequest`.

Ensures the Pydantic model rejects malformed IPs and usernames before they
can be used to open an SSH connection.
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

def test_valid_ip_and_username_accepted():
    from server import SSHConfigRequest

    cfg = SSHConfigRequest(remote_ip="192.168.1.10", username="test_user")
    assert cfg.remote_ip == "192.168.1.10"
    assert cfg.username == "test_user"


def test_username_may_contain_hyphens_and_digits():
    from server import SSHConfigRequest

    cfg = SSHConfigRequest(remote_ip="10.0.0.1", username="svc-2-ci")
    assert cfg.username == "svc-2-ci"


# ---------------------------------------------------------------------------
# IP validation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "bad_ip",
    [
        "not-an-ip",
        "256.1.1.1",       # octet overflow
        "192.168.1",       # incomplete
        "::1",             # IPv6 not allowed
        "192.168.1.1.1",   # too many octets
        "",
    ],
)
def test_invalid_ipv4_rejected(bad_ip):
    from server import SSHConfigRequest

    with pytest.raises(ValidationError) as excinfo:
        SSHConfigRequest(remote_ip=bad_ip, username="user")
    assert "Invalid IPv4" in str(excinfo.value) or "validation error" in str(excinfo.value).lower()


# ---------------------------------------------------------------------------
# Username validation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "bad_username",
    [
        "",                       # empty
        "user with spaces",
        "user;rm -rf /",          # injection attempt
        "x" * 33,                 # 33 chars, over the 32 limit
        "user$",
        "user!",
        "user`whoami`",
    ],
)
def test_invalid_username_rejected(bad_username):
    from server import SSHConfigRequest

    with pytest.raises(ValidationError):
        SSHConfigRequest(remote_ip="10.0.0.1", username=bad_username)


def test_username_at_max_length_accepted():
    from server import SSHConfigRequest

    long_name = "a" * 32  # exactly the limit
    cfg = SSHConfigRequest(remote_ip="10.0.0.1", username=long_name)
    assert cfg.username == long_name
