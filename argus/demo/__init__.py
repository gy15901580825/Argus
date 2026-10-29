"""Bundled testbeds and demo agents, served in-process by `argus.demo.servers`.

Kept light: the CLI imports this package at startup, so the servers stay in their own module."""
from __future__ import annotations

import os


def bypass_proxy_for_localhost() -> None:
    # The local servers are on 127.0.0.1; a proxied shell must not route them out.
    for name in ("NO_PROXY", "no_proxy"):
        current = os.environ.get(name, "")
        hosts = [h.strip() for h in current.split(",") if h.strip()]
        if "127.0.0.1" not in hosts:
            os.environ[name] = f"{current},127.0.0.1" if current else "127.0.0.1"
