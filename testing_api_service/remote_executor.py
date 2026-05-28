import io
import os
import stat
import logging
from typing import Dict, Any

import paramiko
from paramiko import (
    SSHClient,
    AutoAddPolicy,
    RSAKey,
    Ed25519Key,
    ECDSAKey,
    SSHException,
    AuthenticationException,
)
from paramiko.ssh_exception import NoValidConnectionsError

logger = logging.getLogger(__name__)


class RemoteExecutor:
    """SSH execution strategy — decoupled from FastAPI routes."""

    def __init__(
        self,
        host: str,
        username: str,
        pkey_data: str,
        connect_timeout: int = 30,
        exec_timeout: int = 300,
    ):
        self.host = host
        self.username = username
        self.pkey_data = pkey_data
        self.connect_timeout = connect_timeout
        self.exec_timeout = exec_timeout
        self._client: SSHClient | None = None

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------
    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False

    # ------------------------------------------------------------------
    # Connection
    # ------------------------------------------------------------------
    def connect(self) -> None:
        """Open an SSH connection using the in-memory PEM key."""
        pkey = self._load_private_key(self.pkey_data)
        self._client = SSHClient()
        self._client.set_missing_host_key_policy(AutoAddPolicy())
        self._client.connect(
            hostname=self.host,
            username=self.username,
            pkey=pkey,
            timeout=self.connect_timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        logger.info("SSH connection established to %s@%s", self.username, self.host)

    # ------------------------------------------------------------------
    # Command execution
    # ------------------------------------------------------------------
    def execute(self, command: str) -> Dict[str, Any]:
        """Run *command* on the remote host and return stdout/stderr/exit_code."""
        if self._client is None:
            raise RuntimeError("Not connected — call connect() first")

        logger.info("Executing remote command: %s", command)
        _, stdout_ch, stderr_ch = self._client.exec_command(
            command, timeout=self.exec_timeout
        )
        exit_code = stdout_ch.channel.recv_exit_status()
        stdout = stdout_ch.read().decode("utf-8", errors="replace")
        stderr = stderr_ch.read().decode("utf-8", errors="replace")

        logger.info("Command finished with exit code %d", exit_code)
        return {"stdout": stdout, "stderr": stderr, "exit_code": exit_code}

    # ------------------------------------------------------------------
    # SFTP helpers
    # ------------------------------------------------------------------
    def download_directory(self, remote_path: str, local_path: str) -> str:
        """Recursively download *remote_path* into *local_path* via SFTP.

        Returns the local_path for convenience.
        """
        if self._client is None:
            raise RuntimeError("Not connected — call connect() first")

        sftp = self._client.open_sftp()
        try:
            self._sftp_walk_download(sftp, remote_path, local_path)
        finally:
            sftp.close()
        return local_path

    def _sftp_walk_download(
        self, sftp: paramiko.SFTPClient, remote_dir: str, local_dir: str
    ) -> None:
        os.makedirs(local_dir, exist_ok=True)
        for entry in sftp.listdir_attr(remote_dir):
            remote_entry = f"{remote_dir}/{entry.filename}"
            local_entry = os.path.join(local_dir, entry.filename)
            if stat.S_ISDIR(entry.st_mode):
                self._sftp_walk_download(sftp, remote_entry, local_entry)
            else:
                logger.debug("Downloading %s -> %s", remote_entry, local_entry)
                sftp.get(remote_entry, local_entry)

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------
    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None
            logger.info("SSH connection closed")

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _load_private_key(pkey_data: str) -> paramiko.PKey:
        """Try RSA, Ed25519, then ECDSA — return the first that parses."""
        key_classes = [RSAKey, Ed25519Key, ECDSAKey]
        last_exc: Exception | None = None
        for cls in key_classes:
            try:
                return cls.from_private_key(io.StringIO(pkey_data))
            except (SSHException, ValueError) as exc:
                last_exc = exc
                continue
        raise SSHException(
            f"Unable to parse private key (tried RSA/Ed25519/ECDSA): {last_exc}"
        )
