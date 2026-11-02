from __future__ import annotations

import base64
import contextvars
import ipaddress
import os
import socket
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote, quote_plus, urlsplit

from .models import SecretRef, origin


@dataclass(frozen=True)
class ExecutionPolicy:
    allowed_origins: frozenset[str] = frozenset()
    allowed_secret_roots: tuple[Path, ...] | None = ()
    allowed_env_names: frozenset[str] | None = frozenset()

    @classmethod
    def local(cls, spec):
        urls = [spec.request.url]
        if hasattr(spec.delivery, "request"):
            urls.append(spec.delivery.request.url)
        return cls(frozenset(origin(url) for url in urls), None, None)

    async def endpoint_ip(self, url):
        import asyncio

        p = urlsplit(url)
        addresses = await asyncio.get_running_loop().getaddrinfo(
            p.hostname,
            p.port or (443 if p.scheme == "https" else 80),
            type=socket.SOCK_STREAM,
        )
        ips = list(dict.fromkeys(item[4][0] for item in addresses))
        if not ips:
            raise ValueError("Endpoint resolution failed")
        if origin(url) not in self.allowed_origins and any(
            not ipaddress.ip_address(ip).is_global for ip in ips
        ):
            raise ValueError("Endpoint address denied")
        return ips[0]


_LOCAL_MODE = contextvars.ContextVar("transport_local_mode", default=False)


@contextmanager
def local_transport_mode():
    token = _LOCAL_MODE.set(True)
    try:
        yield
    finally:
        _LOCAL_MODE.reset(token)


def execution_policy(spec):
    return ExecutionPolicy.local(spec) if _LOCAL_MODE.get() else ExecutionPolicy()


class Redactor:
    def __init__(self, secrets=()):
        self.values = set()
        for secret in secrets:
            self.add(secret)

    def add(self, secret):
        if not secret:
            return
        self.values.update(
            {
                secret,
                quote(secret, safe=""),
                quote_plus(secret),
                base64.b64encode(secret.encode()).decode(),
            }
        )

    def clean(self, value):
        if isinstance(value, str):
            for secret in sorted(self.values, key=len, reverse=True):
                value = value.replace(secret, "<redacted>")
            return value
        if isinstance(value, dict):
            return {self.clean(str(k)): self.clean(v) for k, v in value.items()}
        if isinstance(value, (tuple, list)):
            return [self.clean(v) for v in value]
        return value


def resolve_secret(ref: SecretRef, policy: ExecutionPolicy):
    if ref.source == "env":
        if (
            policy.allowed_env_names is not None
            and ref.name not in policy.allowed_env_names
        ):
            raise ValueError("Secret reference denied")
        value = os.getenv(ref.name)
    else:
        path = Path(os.path.abspath(Path(ref.path).expanduser()))
        if policy.allowed_secret_roots is not None:
            if not any(
                path.is_relative_to(Path(os.path.abspath(Path(root).expanduser())))
                for root in policy.allowed_secret_roots
            ):
                raise ValueError("Secret reference denied")
        directory_fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY)
        try:
            for component in path.parts[1:-1]:
                next_fd = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=directory_fd,
                )
                os.close(directory_fd)
                directory_fd = next_fd
            fd = os.open(
                path.name,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                dir_fd=directory_fd,
            )
        finally:
            os.close(directory_fd)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size > 65536:
                raise ValueError("Secret file is not a bounded regular file")
            data = os.read(fd, 65537)
            if len(data) > 65536:
                raise ValueError("Secret file exceeds maximum")
            value = data.decode("utf-8")
        finally:
            os.close(fd)
    if not isinstance(value, str) or not value or len(value.encode()) > 65536:
        raise ValueError("Secret reference is empty or exceeds maximum")
    if ref.strip_final_newline:
        value = (
            value[:-2]
            if value.endswith("\r\n")
            else value[:-1] if value.endswith("\n") else value
        )
    if not value or "\r" in value or "\n" in value:
        raise ValueError("Secret is invalid for HTTP authentication")
    return value
