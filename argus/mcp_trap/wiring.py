"""Where the trap listens, what the agent is told, and binding its port before the run starts."""

from __future__ import annotations

import errno
import ipaddress
import json
import os
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

DEFAULT_TRAP_PORT = 8765


class TrapAddressError(ValueError):
    pass


class TrapPortInUse(RuntimeError):
    pass


@dataclass(frozen=True)
class TrapAddress:
    host: str = "127.0.0.1"
    port: int = DEFAULT_TRAP_PORT
    public_url: str = ""

    def __post_init__(self) -> None:
        # Same rules as BrowserUseSpec._validate_trap, except the port and the URL path (see below).
        try:
            host = ipaddress.IPv4Address(self.host)
        except ValueError:
            raise TrapAddressError(f"--trap-host must be an IPv4 address, got {self.host!r}") from None
        # Port 0 is rejected: the agent's MCP config names the port before the trap starts.
        if isinstance(self.port, bool) or not isinstance(self.port, int) or not 1 <= self.port <= 65535:
            raise TrapAddressError(f"--trap-port must be an integer from 1 to 65535, got {self.port!r}")
        if not self.public_url:
            if host.is_unspecified:
                raise TrapAddressError(
                    f"--trap-host {self.host} listens on every interface; set --trap-public-url "
                    "to the address your agent should connect to"
                )
            return
        parts = urlsplit(self.public_url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise TrapAddressError(
                f"--trap-public-url must be an http(s) URL such as http://192.168.1.20:8765, "
                f"got {self.public_url!r}"
            )
        if parts.query or parts.fragment:
            raise TrapAddressError("--trap-public-url must not carry a query string or fragment")
        if parts.username is not None or parts.password is not None:
            raise TrapAddressError("--trap-public-url must not carry a user name or password (user:pass@)")
        if parts.path not in ("", "/", "/mcp"):
            raise TrapAddressError(
                f"--trap-public-url path must be empty, / or /mcp (the trap serves /mcp), got {parts.path!r}"
            )

    @property
    def mcp_url(self) -> str:
        if self.public_url:
            parts = urlsplit(self.public_url)
            return f"{parts.scheme}://{parts.netloc}/mcp"
        return f"http://{self.host}:{self.port}/mcp"

    @property
    def allowed_hosts(self) -> list[str]:
        names = ["127.0.0.1", "localhost"]
        if self.public_url:
            host = urlsplit(self.public_url).hostname
            # An IPv6 Host header is bracketed.
            names.append(f"[{host}]" if ":" in host else host)
        # Bare form for a Host header without a port (default 80/443, e.g. behind a proxy).
        return [form for name in names for form in (name, f"{name}:*")]


def config_entry(address: TrapAddress) -> str:
    url = address.mcp_url
    entry = json.dumps({"mcpServers": {"argus-trap": {"type": "http", "url": url}}})
    return "\n".join([
        entry,
        "",
        f"URL only: {url}",
        "",
        "Attach only this MCP server to the agent you are testing: "
        "Argus sees only what the agent does through the trap's tools.",
        "If your agent reads its MCP configuration only at startup, restart it after adding the entry.",
    ])


def bind_trap_socket(address: TrapAddress) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        # asyncio's rule: on Windows SO_REUSEADDR lets a second process bind a port already in use.
        if os.name != "nt":
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((address.host, address.port))
        sock.listen()
    except OSError as exc:
        sock.close()
        if exc.errno == errno.EADDRINUSE:
            raise TrapPortInUse(
                f"port {address.port} on {address.host} is already in use; "
                "stop whatever holds it or pick another with --trap-port"
            ) from None
        raise
    return sock
