"""A2A HTTP transport with mutation gating and credential-free evidence."""
from __future__ import annotations

import json
import secrets
from dataclasses import dataclass, asdict
from typing import Literal, TYPE_CHECKING
import httpx
from argus.a2a.protocol import A2A_VERSION, CARD_PATH, LEGACY_CARD_PATH, MUTATING_OPS, Interface, Op, build_request, decode_response

if TYPE_CHECKING:
    from argus.targets.a2a_server import A2AServerSpec

Principal = Literal['primary', 'second', 'none', 'forged']

@dataclass(frozen=True)
class Exchange:
    step: str
    op: Op
    principal: Principal
    http_status: int | None
    outcome: Literal['success', 'jsonrpc_error', 'http_error', 'undecodable', 'transport_error']
    jsonrpc_code: int | None
    result_kind: str | None
    task_id: str | None
    task_state: str | None
    detail: dict

    def to_dict(self):
        return asdict(self)

class MutationNotAllowed(Exception):
    pass


class A2AClient:
    def __init__(self, spec: A2AServerSpec, transport: httpx.AsyncBaseTransport | None = None):
        self.spec = spec
        self._transport = transport
        self.interaction_count = 0
        self.state_changing_requests = 0
        self.exchanges: list[Exchange] = []
        self._rpc_id = 0

    async def _request(self, method, url, **kwargs):
        try:
            async with httpx.AsyncClient(timeout=self.spec.timeout_s, transport=self._transport) as client:
                response = await client.request(method, url, **kwargs)
        except httpx.HTTPError:
            return None
        self.interaction_count += 1
        return response

    async def fetch_card(self):
        response = await self._request('GET', self.spec.url.rstrip('/')+CARD_PATH, headers={'A2A-Version': A2A_VERSION})
        if response is None:
            return None, None
        try:
            return response.status_code, response.json()
        except (ValueError, RecursionError):
            return response.status_code, None

    async def fetch_legacy_card_status(self):
        response = await self._request('GET', self.spec.url.rstrip('/')+LEGACY_CARD_PATH, headers={'A2A-Version': A2A_VERSION})
        return response.status_code if response is not None else None

    async def call(self, step: str, op: Op, args: dict, principal: Principal, *, iface: Interface, detail: dict | None = None):
        if op in MUTATING_OPS and self.spec.allow_send is not True:
            raise MutationNotAllowed(op)
        pairs = self.spec.primary_headers if principal in ('primary', 'forged') else self.spec.second_headers if principal == 'second' else ()
        headers = httpx.Headers(pairs or ())
        if principal == 'forged':
            headers = httpx.Headers({name: (value.split(None, 1)[0]+' ' if len(value.split(None, 1)) == 2 else '')+'argus-forged-'+secrets.token_hex(8) for name, value in headers.items()})
        headers.update({'A2A-Version': A2A_VERSION, 'Content-Type': 'application/json' if iface.binding == 'JSONRPC' else 'application/a2a+json'})
        self._rpc_id += 1
        wire = build_request(iface, op, args, self._rpc_id)
        if op in MUTATING_OPS:
            self.state_changing_requests += 1
        response = await self._request(wire.method, wire.url, headers=headers, json=wire.json, params=wire.params)
        facts = dict(detail or {})
        if response is None:
            ex = Exchange(step, op, principal, None, 'transport_error', None, None, None, None, facts)
        else:
            decoded = decode_response(iface.binding, op, response.status_code, response.content)
            task = None
            if decoded.result_kind == 'task':
                task = decoded.result.get('task') if op == 'SendMessage' else decoded.result
            if decoded.result_kind == 'push_config':
                config_id = decoded.result.get('id')
                if isinstance(config_id, str) and config_id:
                    facts['config_id'] = config_id
            if decoded.result_kind == 'task_list' and 'list_has_primary_task' in facts:
                needles = facts['list_has_primary_task']
                text = json.dumps(decoded.result)
                facts['list_has_primary_task'] = any(needle in text for needle in needles)
            state = task.get('status', {}).get('state') if task else None
            ex = Exchange(step, op, principal, decoded.http_status, decoded.outcome, decoded.jsonrpc_code, decoded.result_kind,
                          task.get('id') if task else None, state if isinstance(state, str) else None, facts)
        self.exchanges.append(ex)
        return ex
