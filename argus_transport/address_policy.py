"""Opt-in address policy for built-in target connections."""
from __future__ import annotations

import ipaddress
import os
import socket

import anyio
import httpx


class TargetAddressPolicyError(RuntimeError):
    """A target connection was refused before opening a socket."""

    def __init__(self):
        super().__init__('target address not allowed by the address policy')


def public_only() -> bool:
    value = os.getenv('ARGUS_TARGET_ADDRESS_POLICY', '')
    if value not in ('', 'public_only'):
        raise ValueError('ARGUS_TARGET_ADDRESS_POLICY must be empty or public_only')
    return value == 'public_only'


_EMBEDDED_IPV4_PREFIXES = tuple(ipaddress.IPv6Network(prefix) for prefix in (
    '64:ff9b::/96', '::/96', '::ffff:0:0:0/96',
))


def is_global_address(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    if ip.is_multicast:
        return False
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        elif any(ip in prefix for prefix in _EMBEDDED_IPV4_PREFIXES):
            ip = ipaddress.IPv4Address(int(ip) & 0xffffffff)
    return ip.is_global and not ip.is_multicast


async def resolve_addresses(host: str, port: int) -> list[str]:
    addresses = await anyio.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return list(dict.fromkeys(item[4][0] for item in addresses))


def require_global(addresses: list[str]) -> None:
    if not addresses or any(not is_global_address(ip) for ip in addresses):
        raise TargetAddressPolicyError()


async def checked_address(host: str, port: int) -> str:
    try:
        addresses = await resolve_addresses(host, port)
    except OSError:
        raise ConnectionError('target address resolution failed') from None
    require_global(addresses)
    return addresses[0]


class _PublicNetworkBackend:
    def __init__(self, backend, core, on_refusal=None):
        self._backend = backend
        self._core = core
        self._on_refusal = on_refusal

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        # The timeout includes DNS. Delegate only a numeric address, preserving
        # the HTTP origin and TLS hostname in the connection above this backend.
        try:
            with anyio.fail_after(timeout):
                ip = await checked_address(host, port)
                return await self._backend.connect_tcp(
                    ip, port, timeout=timeout, local_address=local_address,
                    socket_options=socket_options,
                )
        except TargetAddressPolicyError:
            if self._on_refusal is not None:
                self._on_refusal()
            raise
        except TimeoutError:
            raise self._core.ConnectTimeout('target connection timed out') from None
        except OSError:
            raise self._core.ConnectError('target connection failed') from None

    async def connect_unix_socket(self, *args, **kwargs):
        raise TargetAddressPolicyError()

    async def sleep(self, seconds):
        await self._backend.sleep(seconds)


def target_client(module=httpx, *, on_address_refused=None, **kwargs):
    """Create the ordinary client when off, or a directly guarded client when on.

    Proxies are disabled under public_only: a proxy resolving a target itself
    would bypass the local address check. The transport's pool backend is the
    HTTPX integration point; both supported HTTP client implementations use it.
    """
    if public_only():
        if any(kwargs.get(option) is not None for option in ('transport', 'proxy', 'mounts')):
            raise ValueError('custom target routing is unavailable under public_only')
        if module is httpx:
            import httpcore as core
        else:
            import httpcore2 as core
        transport = module.AsyncHTTPTransport(trust_env=False)
        pool = getattr(transport, '_pool', None)
        backend = getattr(pool, '_network_backend', None)
        if not isinstance(backend, core.AsyncNetworkBackend):
            raise TargetAddressPolicyError()
        pool._network_backend = _PublicNetworkBackend(core.AnyIOBackend(), core, on_address_refused)
        kwargs.update(transport=transport, trust_env=False)
    return module.AsyncClient(**kwargs)


def require_guarded_client(client) -> None:
    """Refuse supplied clients whose routing could bypass the shared backend."""
    if not public_only():
        return
    pool = getattr(getattr(client, '_transport', None), '_pool', None)
    backend = getattr(pool, '_network_backend', None)
    mounts = getattr(client, '_mounts', {})
    if not isinstance(backend, _PublicNetworkBackend) or any(
        transport is not None for transport in mounts.values()
    ):
        raise TargetAddressPolicyError()


async def startup_self_check() -> None:
    """Refuse startup unless the real target client blocks a loopback request."""
    if not public_only():
        return
    try:
        async with target_client(timeout=1) as client:
            await client.get('http://127.0.0.1:9/')
    except TargetAddressPolicyError:
        return
    except Exception:
        raise RuntimeError('target address policy self-check failed') from None
    raise RuntimeError('target address policy self-check failed')
