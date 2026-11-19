"""Small legacy Streamable HTTP proxy for offline conformance tests."""
from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import secrets
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import httpx
from aiohttp import web

from argus.gateway_fixtures.host import _SafeRunner
from argus.gateway_fixtures.upstream import ERAS


def loopback_url(url: str) -> None:
    try:
        parsed = urlsplit(url)
        valid = (parsed.scheme in ('http', 'https') and not parsed.username and not parsed.password
                 and not parsed.fragment and ipaddress.ip_address(parsed.hostname).is_loopback)
        parsed.port
    except (ValueError, TypeError):
        valid = False
    if not valid:
        raise ValueError('reference gateway URLs require literal loopback addresses')


@dataclass(frozen=True)
class Entry:
    url: str
    headers: dict[str, str] = field(default_factory=dict)

    def __post_init__(self):
        loopback_url(self.url)


@dataclass(frozen=True)
class Preset:
    redirects: str = 'drop'
    passthrough: bool = False
    response_filter: str = 'all_messages'
    webhook: str = 'decision'

    def __post_init__(self):
        if (self.redirects not in ('keep', 'drop', 'no_follow')
                or self.response_filter not in ('json_only', 'all_messages', 'off')
                or self.webhook not in ('status', 'decision')):
            raise ValueError('unknown reference gateway toggle')

    @classmethod
    def vulnerable(cls):
        return cls('keep', True, 'json_only', 'status')

    @classmethod
    def safe(cls):
        return cls()


class ReferenceGateway:
    def __init__(self, entries: dict[str, Entry], *, preset: Preset | None = None,
                 filter_pattern: str = r'ARGUSFLT[0-9A-F]{20}', webhook_url: str | None = None,
                 allow_status: int = 200, allow_body: dict | None = None,
                 persist_redirects: bool = False, cache_allow: bool = False):
        if not entries or any(not re.fullmatch(r'[a-zA-Z0-9_]+', name) for name in entries):
            raise ValueError('reference gateway requires named entries')
        if webhook_url:
            loopback_url(webhook_url)
        self.entries = dict(entries)
        self.persist_redirects = persist_redirects
        self.redirect_urls = {}
        self.preset = preset or Preset.safe()
        self.pattern = re.compile(filter_pattern)
        self.webhook_url, self.allow_status = webhook_url, allow_status
        self.allow_body = {'decision': 'allow'} if allow_body is None else allow_body
        self.cache_allow, self._cached_allow = cache_allow, False
        self.session = secrets.token_urlsafe(16)
        self.upstream_sessions: dict[str, str] = {}
        self.url = ''

    async def __aenter__(self):
        self.client = httpx.AsyncClient(trust_env=False, timeout=5)
        app = web.Application(client_max_size=65536)
        app.router.add_route('*', '/mcp', self._handle)
        self.runner = _SafeRunner(app, access_log=None, handler_cancellation=True)
        await self.runner.setup()
        site = web.TCPSite(self.runner, '127.0.0.1', 0)
        await site.start()
        self.url = f'http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}/mcp'
        return self

    async def __aexit__(self, *_):
        await self.runner.cleanup()
        await self.client.aclose()

    async def upstream_headers(self, name: str) -> dict[str, str]:
        """Override here to supply an upstream authentication strategy."""
        return dict(self.entries[name].headers)

    async def _request(self, name, request, *, message=None, last_event_id=None):
        entry = self.entries[name]
        headers = httpx.Headers(await self.upstream_headers(name))
        for key in ('Accept', 'MCP-Protocol-Version'):
            if key in request.headers:
                headers[key] = request.headers[key]
        if self.preset.passthrough:
            for key in ('Authorization', 'Cookie'):
                if key in request.headers:
                    headers[key] = request.headers[key]
        if name in self.upstream_sessions:
            headers['Mcp-Session-Id'] = self.upstream_sessions[name]
        if last_event_id is not None:
            headers['Last-Event-ID'] = last_event_id
        outgoing = self.client.build_request(request.method, self.redirect_urls.get(name, entry.url), headers=headers, json=message)
        # Use httpx's redirect request construction, including its Authorization policy.
        for _ in range(11):
            loopback_url(str(outgoing.url))
            response = await self.client.send(outgoing, stream=True, follow_redirects=False)
            if 'Mcp-Session-Id' in response.headers:
                self.upstream_sessions[name] = response.headers['Mcp-Session-Id']
            following = response.next_request
            if following is None or self.preset.redirects == 'no_follow':
                return response
            if self.persist_redirects and response.status_code == 308:
                self.redirect_urls[name] = str(following.url)
            await response.aclose()
            loopback_url(str(following.url))
            if self.preset.redirects == 'drop' and outgoing.url.copy_with(path='/', query=None) != following.url.copy_with(path='/', query=None):
                for key in entry.headers:
                    following.headers.pop(key, None)
            outgoing = following
        raise ValueError('too many upstream redirects')

    async def _allowed(self, message):
        if self.cache_allow and self._cached_allow:
            return True
        allowed = await self._webhook_allowed(message)
        if self.cache_allow and allowed:
            self._cached_allow = True
        return allowed

    async def _webhook_allowed(self, message):
        if self.webhook_url is None:
            return True
        response = await self.client.post(self.webhook_url, json=message, follow_redirects=False)
        if self.preset.webhook == 'status':
            return 200 <= response.status_code < 300
        try:
            return response.status_code == self.allow_status and response.json() == self.allow_body
        except ValueError:
            return False

    def _json(self, value):
        encoded = json.dumps(value)
        return self.pattern.sub('[REDACTED]', encoded).encode() if self.preset.response_filter != 'off' else encoded.encode()

    async def _relay(self, request, responses):
        streams = [(name, response) for name, response in responses if response.headers.get('content-type', '').split(';')[0] == 'text/event-stream']
        if not streams:
            name, response = responses[0]
            try:
                body = await response.aread()
                if response.headers.get('content-type', '').split(';')[0] == 'application/json':
                    body = self._json(json.loads(body))
                return web.Response(body=body, status=response.status_code,
                                    headers={'Content-Type': response.headers.get('content-type', 'application/json'), 'Mcp-Session-Id': self.session})
            finally:
                await response.aclose()
        output = web.StreamResponse(headers={'Content-Type': 'text/event-stream', 'Mcp-Session-Id': self.session})
        await output.prepare(request)
        queue = asyncio.Queue(maxsize=32)

        async def pump(name, response):
            frame = []
            try:
                async for line in response.aiter_lines():
                    if line:
                        frame.append(line)
                        continue
                    data = '\n'.join(line[5:].lstrip(' ') for line in frame if line.startswith('data:'))
                    fields = [line for line in frame if not line.startswith('data:')]
                    fields = [f'id: {name}:{line[3:].strip()}' if line.startswith('id:') else line for line in fields]
                    if data:
                        if self.preset.response_filter == 'all_messages':
                            data = self._json(json.loads(data)).decode()
                        fields.extend('data: ' + line for line in data.split('\n'))
                    await queue.put(('\n'.join(fields) + '\n\n').encode())
                    frame = []
            finally:
                await response.aclose()
                if not asyncio.current_task().cancelling():
                    await queue.put(None)

        tasks = [asyncio.create_task(pump(name, response)) for name, response in streams]
        try:
            remaining = len(tasks)
            while remaining:
                frame = await queue.get()
                if frame is None:
                    remaining -= 1
                else:
                    await output.write(frame)
            await asyncio.gather(*tasks)
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            for _, response in responses:
                await response.aclose()
        return output

    @staticmethod
    def _error(request_id, code, message):
        return web.json_response({'jsonrpc': '2.0', 'id': request_id, 'error': {'code': code, 'message': message}})

    async def _handle(self, request):
        responses = []
        try:
            if request.headers.get('MCP-Protocol-Version', ERAS[0]) not in ERAS:
                return web.Response(status=400, text='Unsupported protocol version')
            if request.method == 'GET':
                last_id = request.headers.get('Last-Event-ID')
                names = list(self.entries)
                event_id = None
                if last_id:
                    name, separator, event_id = last_id.partition(':')
                    if not separator or name not in self.entries:
                        return web.Response(status=400)
                    names = [name]
                for name in names:
                    responses.append((name, await self._request(name, request, last_event_id=event_id)))
                return await self._relay(request, responses)
            if request.method != 'POST':
                return web.Response(status=405)
            message = await request.json()
            if not isinstance(message, dict) or message.get('jsonrpc') != '2.0':
                return self._error(None, -32600, 'Invalid request')
            method, request_id = message.get('method'), message.get('id')
            if method in ('initialize', 'tools/list'):
                tools, result = [], {}
                for name in self.entries:
                    response = await self._request(name, request, message=message)
                    responses.append((name, response))
                    body = json.loads(await response.aread())
                    await response.aclose()
                    if response.status_code != 200 or 'result' not in body:
                        return self._error(request_id, -32603, 'Upstream discovery failed')
                    result = body['result']
                    if method == 'tools/list':
                        tools.extend({**tool, 'name': name + '__' + tool['name']} for tool in result['tools'])
                if method == 'tools/list':
                    result = {'tools': tools}
                else:
                    result = {**result, 'protocolVersion': result.get('protocolVersion', ERAS[0]),
                              'serverInfo': {'name': 'reference-gateway', 'version': '1'}}
                return web.Response(body=self._json({'jsonrpc': '2.0', 'id': request_id, 'result': result}),
                                    headers={'Content-Type': 'application/json', 'Mcp-Session-Id': self.session})
            if method == 'tools/call':
                params = message['params']
                name, separator, tool = params['name'].partition('__')
                if not separator or name not in self.entries:
                    return self._error(request_id, -32602, 'Unknown tool')
                if not await self._allowed(message):
                    return self._error(request_id, -32000, 'Webhook denied')
                message = {**message, 'params': {**params, 'name': tool}}
                responses.append((name, await self._request(name, request, message=message)))
                return await self._relay(request, responses)
            for name in self.entries:
                responses.append((name, await self._request(name, request, message=message)))
            return await self._relay(request, responses)
        except (ValueError, KeyError, TypeError, httpx.HTTPError):
            return self._error(None, -32603, 'Upstream request rejected')
        finally:
            for _, response in responses:
                await response.aclose()
