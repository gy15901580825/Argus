"""Target adapter for deterministic A2A 1.0 server checks."""
from __future__ import annotations

import ipaddress
import json
import math
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import httpx
from argus.targets._base import Target
from argus.a2a.client import A2AClient
from argus.a2a.checks import ALL_CHECKS, run_check


def _headers(value: object) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, (list, tuple)) or any(not isinstance(pair, (list, tuple)) or len(pair) != 2 or any(not isinstance(v, str) for v in pair) or not pair[0] for pair in value):
        raise ValueError('headers must be pairs of strings')
    return tuple(tuple(pair) for pair in value)


def _http_url(value: object, name: str):
    if not isinstance(value, str):
        raise ValueError(f'{name} must be an http(s) URL')
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError()
        parsed.port
    except ValueError:
        raise ValueError(f'{name} must be an http(s) URL without embedded credentials') from None
    return parsed

@dataclass(frozen=True)
class A2AServerSpec:
    kind: str = 'a2a_server'
    url: str = ''
    credentials: dict = field(default_factory=dict)
    second_client: dict | None = None
    jsonrpc_auth_error_codes: dict = field(default_factory=dict)
    push_callback_policy: str | None = None
    push_control_url: str = 'https://argus-push-control.invalid/a2a-callback'
    allow_send: bool = False
    timeout_s: float = 30.0
    primary_headers: tuple[tuple[str, str], ...] = field(init=False)
    second_headers: tuple[tuple[str, str], ...] | None = field(init=False)
    forbidden_on_primary_tasks: frozenset[str] = field(init=False)
    authentication_codes: frozenset[int] = field(init=False)
    authorization_codes: frozenset[int] = field(init=False)

    def __post_init__(self):
        if self.kind != 'a2a_server':
            raise ValueError('kind must be a2a_server')
        _http_url(self.url, 'url')
        if not isinstance(self.credentials, dict) or set(self.credentials) - {'headers'}:
            raise ValueError('credentials supports only headers')
        object.__setattr__(self, 'primary_headers', _headers(self.credentials.get('headers', [])))
        second = self.second_client
        if second is not None and (not isinstance(second, dict) or set(second) - {'headers', 'forbidden_on_primary_tasks'}):
            raise ValueError('second_client supports headers and forbidden_on_primary_tasks only')
        second_headers = _headers(second.get('headers', [])) if second is not None else None
        if second is not None and not second_headers:
            raise ValueError('second_client.headers must not be empty')
        forbidden = second.get('forbidden_on_primary_tasks', []) if second is not None else []
        if not isinstance(forbidden, (list, tuple)) or any(not isinstance(v, str) or v not in {'get', 'list', 'cancel'} for v in forbidden):
            raise ValueError('forbidden_on_primary_tasks supports get, list, cancel only')
        object.__setattr__(self, 'second_headers', second_headers)
        object.__setattr__(self, 'forbidden_on_primary_tasks', frozenset(forbidden))
        codes = self.jsonrpc_auth_error_codes
        if not isinstance(codes, dict) or set(codes) - {'authentication', 'authorization'}:
            raise ValueError('jsonrpc_auth_error_codes supports authentication and authorization only')
        for key in ('authentication', 'authorization'):
            values = codes.get(key, [])
            if not isinstance(values, (list, tuple)) or any(type(v) is not int for v in values):
                raise ValueError('jsonrpc_auth_error_codes values must be integer lists')
            object.__setattr__(self, key+'_codes', frozenset(values))
        if self.push_callback_policy not in (None, 'deny_private'):
            raise ValueError('push_callback_policy must be deny_private or null')
        if type(self.allow_send) is not bool:
            raise ValueError('allow_send must be a boolean')
        parsed = _http_url(self.push_control_url, 'push_control_url')
        host = parsed.hostname.lower().rstrip('.')
        if host == 'localhost':
            raise ValueError('push_control_url must not point at localhost or private addresses')
        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            addr = None
        if addr is not None and (addr.is_loopback or addr.is_private or addr.is_link_local):
            raise ValueError('push_control_url must not point at localhost or private addresses')
        if isinstance(self.timeout_s, bool) or not isinstance(self.timeout_s, (int, float)) or not math.isfinite(self.timeout_s) or self.timeout_s <= 0:
            raise ValueError('timeout_s must be a positive finite number')


class A2AServerTarget(Target):
    compatible_classes = frozenset({'a2a_server'})

    def __init__(self, spec: A2AServerSpec):
        self.spec = spec
        self._transport: httpx.AsyncBaseTransport | None = None
        self._evidence: dict = {}
        self._check: str | None = None

    async def begin_probe(self, probe):
        checks = [value for entry in probe.assertions for key, value in entry.items() if key == 'a2a_server']
        if hasattr(probe, 'base') or len(checks) != 1 or checks[0] not in ALL_CHECKS:
            raise ValueError('a2a_server needs one recognized A2A assertion and does not support deep wrappers')
        self._check = checks[0]
        self._evidence = {}

    async def send_prompt(self, prompt, history=()):
        started = time.monotonic()
        if self._check is None:
            raise ValueError('begin_probe must select an A2A check')
        if not self._evidence:
            self._evidence = await run_check(self._check, A2AClient(self.spec, self._transport), self.spec)
        return json.dumps(self._evidence, sort_keys=True), (time.monotonic()-started)*1000

    async def collect_evidence(self):
        return dict(self._evidence)
