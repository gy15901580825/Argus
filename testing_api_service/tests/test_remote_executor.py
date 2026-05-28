"""L3 tests for remote_executor.RemoteExecutor.

Patch boundary: `paramiko.SSHClient` (class) is replaced with a MagicMock so
the executor's public API exercises real logic without opening real sockets.
Key-parse tests also monkeypatch the three `from_private_key` classmethods.
"""
from __future__ import annotations

import stat
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# connect() — chooses first working key class, calls SSHClient.connect()
# ---------------------------------------------------------------------------

def test_load_private_key_uses_rsa_first():
    """When RSA parses, Ed25519/ECDSA are not attempted."""
    from remote_executor import RemoteExecutor

    fake_key = object()
    with patch("remote_executor.RSAKey.from_private_key", return_value=fake_key) as rsa_mock, \
         patch("remote_executor.Ed25519Key.from_private_key") as ed_mock, \
         patch("remote_executor.ECDSAKey.from_private_key") as ec_mock:
        key = RemoteExecutor._load_private_key("FAKE-PEM-DATA")

    assert key is fake_key
    rsa_mock.assert_called_once()
    ed_mock.assert_not_called()
    ec_mock.assert_not_called()


def test_load_private_key_falls_through_to_ed25519():
    """If RSA raises SSHException, Ed25519 is attempted next."""
    from paramiko import SSHException
    from remote_executor import RemoteExecutor

    fake_key = object()
    with patch("remote_executor.RSAKey.from_private_key", side_effect=SSHException("not rsa")), \
         patch("remote_executor.Ed25519Key.from_private_key", return_value=fake_key), \
         patch("remote_executor.ECDSAKey.from_private_key") as ec_mock:
        key = RemoteExecutor._load_private_key("FAKE")

    assert key is fake_key
    ec_mock.assert_not_called()


def test_load_private_key_all_fail_raises():
    """When all three parsers fail, an SSHException is raised."""
    from paramiko import SSHException
    from remote_executor import RemoteExecutor

    with patch("remote_executor.RSAKey.from_private_key", side_effect=SSHException("x")), \
         patch("remote_executor.Ed25519Key.from_private_key", side_effect=ValueError("y")), \
         patch("remote_executor.ECDSAKey.from_private_key", side_effect=SSHException("z")):
        with pytest.raises(SSHException) as excinfo:
            RemoteExecutor._load_private_key("FAKE")

    assert "Unable to parse private key" in str(excinfo.value)


def test_connect_invokes_sshclient_and_auto_add_policy():
    """connect() builds an SSHClient, sets AutoAddPolicy, calls .connect()."""
    from remote_executor import RemoteExecutor

    fake_key = object()
    fake_client = MagicMock()

    with patch("remote_executor.RSAKey.from_private_key", return_value=fake_key), \
         patch("remote_executor.SSHClient", return_value=fake_client):
        ex = RemoteExecutor(host="10.0.0.1", username="alice", pkey_data="PEM",
                            connect_timeout=7)
        ex.connect()

    fake_client.set_missing_host_key_policy.assert_called_once()
    fake_client.connect.assert_called_once_with(
        hostname="10.0.0.1",
        username="alice",
        pkey=fake_key,
        timeout=7,
        look_for_keys=False,
        allow_agent=False,
    )
    assert ex._client is fake_client


def test_context_manager_closes_client_on_exit():
    """`with RemoteExecutor(...)` closes the SSHClient on exit."""
    from remote_executor import RemoteExecutor

    fake_client = MagicMock()
    with patch("remote_executor.RSAKey.from_private_key", return_value=object()), \
         patch("remote_executor.SSHClient", return_value=fake_client):
        with RemoteExecutor(host="h", username="u", pkey_data="p") as ex:
            assert ex._client is fake_client

    fake_client.close.assert_called_once()
    assert ex._client is None


# ---------------------------------------------------------------------------
# execute() — wraps exec_command(), decodes bytes, returns dict
# ---------------------------------------------------------------------------

def test_execute_returns_stdout_stderr_exit_code():
    from remote_executor import RemoteExecutor

    stdout_ch = MagicMock()
    stdout_ch.read.return_value = b"hello\n"
    stdout_ch.channel.recv_exit_status.return_value = 0
    stderr_ch = MagicMock()
    stderr_ch.read.return_value = b""

    fake_client = MagicMock()
    fake_client.exec_command.return_value = (MagicMock(), stdout_ch, stderr_ch)

    with patch("remote_executor.RSAKey.from_private_key", return_value=object()), \
         patch("remote_executor.SSHClient", return_value=fake_client):
        ex = RemoteExecutor(host="h", username="u", pkey_data="p", exec_timeout=42)
        ex.connect()
        result = ex.execute("ls -la")

    assert result == {"stdout": "hello\n", "stderr": "", "exit_code": 0}
    fake_client.exec_command.assert_called_once_with("ls -la", timeout=42)


def test_execute_decodes_invalid_utf8_with_replacement():
    """Garbled bytes in stderr/stdout don't crash — they get replaced."""
    from remote_executor import RemoteExecutor

    stdout_ch = MagicMock()
    stdout_ch.read.return_value = b"\xff\xfeok"
    stdout_ch.channel.recv_exit_status.return_value = 2
    stderr_ch = MagicMock()
    stderr_ch.read.return_value = b"\xff"

    fake_client = MagicMock()
    fake_client.exec_command.return_value = (MagicMock(), stdout_ch, stderr_ch)

    with patch("remote_executor.RSAKey.from_private_key", return_value=object()), \
         patch("remote_executor.SSHClient", return_value=fake_client):
        ex = RemoteExecutor(host="h", username="u", pkey_data="p")
        ex.connect()
        result = ex.execute("cmd")

    assert result["exit_code"] == 2
    # Decoding with errors='replace' yields U+FFFD placeholders
    assert "ok" in result["stdout"]


def test_execute_without_connect_raises():
    from remote_executor import RemoteExecutor

    ex = RemoteExecutor(host="h", username="u", pkey_data="p")
    with pytest.raises(RuntimeError, match="Not connected"):
        ex.execute("echo hi")


def test_download_directory_without_connect_raises():
    from remote_executor import RemoteExecutor

    ex = RemoteExecutor(host="h", username="u", pkey_data="p")
    with pytest.raises(RuntimeError, match="Not connected"):
        ex.download_directory("/remote", "/local")


# ---------------------------------------------------------------------------
# download_directory() — recursive SFTP walk
# ---------------------------------------------------------------------------

def test_download_directory_recurses_and_gets_files(tmp_path):
    from remote_executor import RemoteExecutor

    # Build a fake SFTP that pretends /remote/ has subdir/ and file.txt
    file_attr = SimpleNamespace(filename="file.txt", st_mode=stat.S_IFREG | 0o644)
    dir_attr = SimpleNamespace(filename="sub", st_mode=stat.S_IFDIR | 0o755)
    nested_attr = SimpleNamespace(filename="nested.log", st_mode=stat.S_IFREG | 0o644)

    def listdir_attr(path):
        if path == "/remote":
            return [file_attr, dir_attr]
        if path == "/remote/sub":
            return [nested_attr]
        return []

    sftp = MagicMock()
    sftp.listdir_attr.side_effect = listdir_attr

    fake_client = MagicMock()
    fake_client.open_sftp.return_value = sftp

    with patch("remote_executor.RSAKey.from_private_key", return_value=object()), \
         patch("remote_executor.SSHClient", return_value=fake_client):
        ex = RemoteExecutor(host="h", username="u", pkey_data="p")
        ex.connect()
        local = ex.download_directory("/remote", str(tmp_path / "out"))

    assert local == str(tmp_path / "out")
    # Two files got downloaded: /remote/file.txt and /remote/sub/nested.log
    calls = [c.args for c in sftp.get.call_args_list]
    assert ("/remote/file.txt", str(tmp_path / "out" / "file.txt")) in calls
    assert ("/remote/sub/nested.log", str(tmp_path / "out" / "sub" / "nested.log")) in calls
    sftp.close.assert_called_once()


def test_close_is_idempotent():
    """Calling close() twice (manually then via __exit__) doesn't blow up."""
    from remote_executor import RemoteExecutor

    fake_client = MagicMock()
    with patch("remote_executor.RSAKey.from_private_key", return_value=object()), \
         patch("remote_executor.SSHClient", return_value=fake_client):
        ex = RemoteExecutor(host="h", username="u", pkey_data="p")
        ex.connect()
        ex.close()
        # Second close is a no-op
        ex.close()

    fake_client.close.assert_called_once()
