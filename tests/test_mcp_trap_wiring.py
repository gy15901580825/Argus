import json
import socket

import pytest

from argus.mcp_trap.wiring import (
    TrapAddress,
    TrapAddressError,
    TrapPortInUse,
    bind_trap_socket,
    config_entry,
)
from argus.targets.browser_use import BrowserUseSpec


def test_defaults():
    assert TrapAddress().mcp_url == "http://127.0.0.1:8765/mcp"
    assert TrapAddress().allowed_hosts == ["127.0.0.1", "127.0.0.1:*", "localhost", "localhost:*"]


def test_public_url_is_what_the_agent_is_told():
    address = TrapAddress("0.0.0.0", 8765, "http://192.168.1.20:8765")
    assert address.mcp_url == "http://192.168.1.20:8765/mcp"
    assert "192.168.1.20:*" in address.allowed_hosts


def test_ipv6_public_host_is_bracketed_like_the_host_header():
    address = TrapAddress("0.0.0.0", 8765, "http://[fe80::1]:8765")
    assert address.mcp_url == "http://[fe80::1]:8765/mcp"
    assert address.allowed_hosts[-2:] == ["[fe80::1]", "[fe80::1]:*"]


def test_portless_public_url_allows_the_bare_host():
    # Behind a proxy on 443 the agent sends `Host: trap.example`, which no `:*` pattern matches.
    hosts = TrapAddress("127.0.0.1", 8765, "https://trap.example/").allowed_hosts
    assert "trap.example" in hosts and "trap.example:*" in hosts


@pytest.mark.parametrize("public_url", ["https://trap.example/", "https://trap.example/mcp"])
def test_public_url_path_root_or_mcp_is_accepted(public_url):
    assert TrapAddress("127.0.0.1", 8765, public_url).mcp_url == "https://trap.example/mcp"


@pytest.mark.parametrize("host, port, public_url, match", [
    ("localhost", 8765, "", "IPv4"),
    ("0.0.0.0", 8765, "", "--trap-public-url"),
    ("127.0.0.1", 0, "", "--trap-port"),
    ("127.0.0.1", 65536, "", "--trap-port"),
    ("127.0.0.1", 8765, "ftp://x", "http"),
    ("127.0.0.1", 8765, "http://h:1/other", "/mcp"),
    ("127.0.0.1", 8765, "http://h:1/?a=1", "query"),
    ("127.0.0.1", 8765, "http://user:pw@h:1", "user name or password"),
    ("127.0.0.1", 8765, "http://user@h:1/mcp", "user name or password"),
])
def test_rejects(host, port, public_url, match):
    with pytest.raises(TrapAddressError, match=match):
        TrapAddress(host, port, public_url)


def _raises(build) -> bool:
    try:
        build()
    except ValueError:
        return True
    return False


@pytest.mark.parametrize("host, public_url", [
    ("127.0.0.1", ""), ("0.0.0.0", ""), ("0.0.0.0", "http://10.0.0.5:8765"), ("::1", ""),
    ("127.0.0.1", "http://h:1#f"),
])
def test_rules_match_browser_use(host, public_url):
    browser = _raises(lambda: BrowserUseSpec(
        agent_url="http://a", scenario_kind="dom_injection",
        trap_host=host, trap_port=8765, trap_public_url=public_url,
    ))
    assert _raises(lambda: TrapAddress(host, 8765, public_url)) == browser


def test_config_entry_shape():
    text = config_entry(TrapAddress())
    lines = text.splitlines()
    assert json.loads(lines[0]) == {
        "mcpServers": {"argus-trap": {"type": "http", "url": "http://127.0.0.1:8765/mcp"}}
    }
    assert "URL only: http://127.0.0.1:8765/mcp" in text
    assert "Attach only this MCP server" in text
    assert "restart it" in text


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def test_second_bind_on_same_port_is_port_in_use():
    address = TrapAddress(port=_free_port())
    first = bind_trap_socket(address)
    try:
        assert first.getsockname() == ("127.0.0.1", address.port)
        with pytest.raises(TrapPortInUse) as exc:
            bind_trap_socket(address)
        assert "already in use" in str(exc.value)
        assert "--trap-port" in str(exc.value)
    finally:
        first.close()
