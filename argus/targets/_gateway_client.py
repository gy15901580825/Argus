"""Bounded legacy MCP exchanges through an operator's gateway."""
from __future__ import annotations

import json
import re

import httpx

from argus.gateway_fixtures.upstream import ERAS
from argus.gateway_filter_assertions import capture, classify
from argus.targets._base import ProbeNotApplicable, TargetTransportError
from argus_transport.address_policy import target_client

LIST_PAGES_MAX = 20
TOOLS_MAX = 1000


class GatewayClient:
    def __init__(self, gateway: dict, timeout_s: float):
        self.gateway = gateway
        auth = gateway.get('auth', {})
        self.client = target_client(httpx, timeout=timeout_s, trust_env=False,
                                    headers=auth.get('headers', {}), cookies=auth.get('cookies', {}))
        self.era = gateway.get('protocol', 'auto')
        self.session = None
        self.exchanges = 0
        self.request_id = 0
        self.tools = {}

    def capture_message(self, message, channel):
        if not isinstance(message, dict) or message.get('jsonrpc') != '2.0':
            raise TargetTransportError('gateway returned a malformed MCP message')
        return capture(message, channel)

    async def aclose(self):
        await self.client.aclose()

    async def rpc(self, method, params=None, *, notification=False, headers=None, cookies=None):
        self.request_id += 1
        request_id = self.request_id
        message = {'jsonrpc': '2.0', 'method': method}
        if not notification:
            message['id'] = self.request_id
        if params is not None:
            message['params'] = params
        outgoing = httpx.Headers(headers or {})
        outgoing.update({'Accept': 'application/json, text/event-stream', 'MCP-Protocol-Version': self.era})
        if self.session:
            outgoing['Mcp-Session-Id'] = self.session
        received, messages = [], []
        channel = None
        try:
            async with self.client.stream('POST', self.gateway['url'], json=message,
                                          headers=outgoing, cookies=cookies) as response:
                self.exchanges += 1
                if response.status_code in (401, 403):
                    raise TargetTransportError(f'gateway returned HTTP {response.status_code}')
                if not response.is_success:
                    return {'status': response.status_code, 'reply': 'http_error', 'channels': [], 'markers': []}, None
                if 'Mcp-Session-Id' in response.headers:
                    self.session = response.headers['Mcp-Session-Id']
                raw = bytearray()
                channel = 'post_sse' if 'text/event-stream' in response.headers.get('content-type', '') else 'post_json'
                size = 0
                async for chunk in response.aiter_bytes():
                    size += len(chunk)
                    raw.extend(chunk)
                    if size > 65536:
                        raise TargetTransportError('gateway response exceeds 64 KiB')
                    if channel == 'post_sse':
                        raw = bytearray(raw.replace(b'\r\n', b'\n'))
                        while b'\n\n' in raw:
                            event, _, remaining = raw.partition(b'\n\n')
                            raw = bytearray(remaining)
                            data = b'\n'.join(line[5:].lstrip(b' ') for line in event.splitlines() if line.startswith(b'data:'))
                            if not data:
                                continue
                            try:
                                incoming = json.loads(data)
                            except ValueError:
                                raise TargetTransportError('gateway returned a malformed SSE message') from None
                            received.append(self.capture_message(incoming, channel))
                            messages.append(incoming)
                        if any(m.get('id') == request_id and ('result' in m or 'error' in m) for m in messages):
                            break
                text = raw.decode('utf-8', errors='replace')
                if notification and not text:
                    return {}, None
                try:
                    if channel == 'post_sse':
                        body = next((m for m in messages if m.get('id') == request_id and ('result' in m or 'error' in m)), None)
                    else:
                        body = json.loads(text)
                        received.append(self.capture_message(body, channel))
                    if not isinstance(body, dict) or body.get('jsonrpc') != '2.0' or body.get('id') != request_id or not ({'result', 'error'} & body.keys()):
                        raise ValueError
                except (ValueError, TypeError):
                    raise TargetTransportError('gateway returned a malformed MCP response') from None
                observation = {'status': response.status_code, 'reply': 'jsonrpc_error' if 'error' in body else 'result',
                               'channels': [channel], 'markers': sorted(set(re.findall(r'ARGUSFLT[0-9A-F]{20}', json.dumps(messages or [body])))),
                               'messages': received}
                return observation, body
        except httpx.TimeoutException:
            return {'status': None, 'reply': 'timeout', 'channels': [channel] if received else [],
                    'markers': sorted(set(re.findall(r'ARGUSFLT[0-9A-F]{20}', json.dumps(messages)))),
                    'messages': received}, None
        except httpx.HTTPError:
            raise TargetTransportError('gateway connection failed') from None

    async def initialize(self):
        candidates = ERAS if self.era == 'auto' else (self.era,)
        for era in candidates:
            self.era = era
            _, body = await self.rpc('initialize', {'protocolVersion': era, 'capabilities': {},
                'clientInfo': {'name': 'argus-probe', 'version': '1'}})
            result = body.get('result') if body else None
            if isinstance(result, dict) and result.get('protocolVersion') in ERAS:
                self.era = result['protocolVersion']
                await self.rpc('notifications/initialized', notification=True)
                return
        raise TargetTransportError('gateway legacy MCP initialization failed')

    async def discover(self, install_label):
        mapped = {}
        cursor = None
        count = 0
        for _ in range(LIST_PAGES_MAX):
            _, body = await self.rpc('tools/list', {'cursor': cursor} if cursor else {})
            result = body.get('result') if body else None
            if not isinstance(result, dict) or not isinstance(result.get('tools'), list):
                raise TargetTransportError('gateway tools/list failed')
            for tool in result['tools']:
                count += 1
                if count > TOOLS_MAX:
                    raise TargetTransportError('gateway tool discovery exceeds limit')
                if not isinstance(tool, dict) or not isinstance(tool.get('name'), str):
                    raise TargetTransportError('gateway returned an invalid tool')
                match = re.search(r'(?<![\w:-])argus-fixture:' + re.escape(install_label) + r':([\w-]+)\s+(echo|emit)(?!\w)', str(tool.get('description', '')))
                options = self.gateway.get('tools', {})
                if options.get('match', 'fixture_marker') == 'prefix':
                    match = re.fullmatch(re.escape(options['prefix']) + r'([\w-]+)__argus_fixture_(echo|emit)', tool['name'])
                if match:
                    key = tuple(match.groups())
                    if key in mapped:
                        raise TargetTransportError('gateway fixture tool discovery is ambiguous')
                    mapped[key] = tool['name']
            cursor = result.get('nextCursor')
            if not cursor:
                self.tools = mapped
                return
            if not isinstance(cursor, str):
                raise TargetTransportError('gateway returned an invalid cursor')
        raise TargetTransportError('gateway tool discovery exceeds page limit')

    async def call(self, install_label, entry, tool, nonce, *, headers=None, cookies=None, path=None):
        for attempt in range(2):
            name = self.tools.get((entry, tool))
            if name is None:
                raise ProbeNotApplicable(f'entry {entry}: entry not registered')
            params = {'name': name, 'arguments': {'nonce': nonce}}
            if path is not None:
                params['arguments']['path'] = path
                params['_meta'] = {'progressToken': nonce}
            observation, body = await self.rpc('tools/call', params, headers=headers, cookies=cookies)
            error = body.get('error', {}) if body else {}
            if attempt == 0 and isinstance(error, dict) and 'unknown tool' in str(error.get('message', '')).lower():
                await self.discover(install_label)
                continue
            if path is not None:
                observation['classification'] = classify(observation.get('messages', []), path, body)
            return {'nonce': nonce, **observation}
