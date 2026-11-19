"""Bounded dual-era MCP exchanges through an operator's gateway."""
from __future__ import annotations

import asyncio
from contextlib import AsyncExitStack
import json
import re
from urllib.parse import urlsplit

import httpx

from argus.gateway_fixtures.upstream import ERAS
from argus.gateway_fixtures.protocol import MODERN, MODERN_ERRORS, metadata, mirrored_headers
from argus.gateway_filter_assertions import capture, classify
from argus.targets._base import ProbeNotApplicable, TargetTransportError
from argus_transport.address_policy import target_client
from argus_transport.security import Redactor

LIST_PAGES_MAX = 20
TOOLS_MAX = 1000
RESUMES_MAX = 3


class GatewayClient:
    def __init__(self, gateway: dict, timeout_s: float):
        self.gateway = gateway
        self.timeout_s = timeout_s
        auth = gateway.get('auth', {})
        self.client = target_client(httpx, timeout=timeout_s, trust_env=False,
                                    headers=auth.get('headers', {}))
        for name, value in auth.get('cookies', {}).items():
            self.client.cookies.set(name, value, domain=urlsplit(gateway['url']).hostname, path='/')
        self.era = gateway.get('protocol', 'auto')
        self.session = None
        self.exchanges = 0
        self.request_id = 0
        self.tools = {}
        self.consent = None
        self.redactor = Redactor([*auth.get('headers', {}).values(), *auth.get('cookies', {}).values()])
        self.last_failure = None
        self.last_failure_body_complete = False

    async def server_request(self, message):
        if 'method' not in message or 'id' not in message:
            return
        result = {'jsonrpc': '2.0', 'id': message['id']}
        navigate = None
        if message['method'] == 'elicitation/create':
            params = message.get('params', {})
            if isinstance(params, dict) and params.get('mode') == 'url' and self.consent:
                self.consent.validate(params)
                if self.consent.mode == 'follow_url':
                    navigate = params
                else:
                    await self.consent.open(params)
                result['result'] = {'action': 'accept'}
            else:
                result['result'] = {'action': 'decline'}
        else:
            result['error'] = {'code': -32601, 'message': 'Server request unsupported'}
        headers = self._headers()
        async with self.client.stream('POST', self.gateway['url'], json=result, headers=headers) as response:
            self.exchanges += 1
            if not response.is_success:
                await self.record_failure(response, rpc_method='server_response')
                raise TargetTransportError('gateway rejected the server request response')
        if navigate:
            await self.consent.open(navigate)

    def capture_message(self, message, channel):
        if not isinstance(message, dict) or message.get('jsonrpc') != '2.0':
            raise TargetTransportError('gateway returned a malformed MCP message')
        if self.era == MODERN and 'method' in message and 'id' in message:
            raise TargetTransportError('modern gateway sent a server-initiated request')
        return capture(message, channel)

    async def aclose(self):
        await self.client.aclose()

    def _headers(self, headers=None, *, get=False):
        outgoing = httpx.Headers(headers or {})
        outgoing.update({'Accept': 'text/event-stream' if get else 'application/json, text/event-stream',
                         'MCP-Protocol-Version': self.era})
        if self.session and self.era != MODERN:
            outgoing['Mcp-Session-Id'] = self.session
        return outgoing

    def failure_context(self, method, url, status=None, *, rpc_method=None):
        path = urlsplit(str(url)).path
        context = {'method': method,
                   'path_class': 'mcp' if path == urlsplit(self.gateway['url']).path else 'other',
                   'status': status, 'body': {'kind': 'unavailable'}}
        if rpc_method:
            context['rpc_method'] = rpc_method
        return context

    async def record_failure(self, response, *, path_class=None, rpc_method=None):
        failure = self.failure_context(response.request.method, response.request.url, response.status_code, rpc_method=rpc_method)
        if path_class:
            failure['path_class'] = path_class
        self.last_failure = failure
        self.last_failure_body_complete = False
        for cookie in self.client.cookies.jar:
            self.redactor.add(cookie.value)
        raw = bytearray()
        truncated = False
        try:
            async for chunk in response.aiter_bytes():
                raw.extend(chunk[:65536 - len(raw)])
                if len(raw) >= 65536:
                    truncated = True
                    break
        except httpx.HTTPError:
            truncated = True
        except asyncio.CancelledError:
            failure['body'] = self.failure_body(raw, truncated=True)
            raise
        failure['body'] = self.failure_body(raw, truncated=truncated)
        self.last_failure_body_complete = not truncated
        if self.consent_signal(raw):
            failure['consent_signal'] = True

    @staticmethod
    def consent_signal(raw):
        try:
            messages = [json.loads(raw)]
        except (ValueError, RecursionError):
            messages = []
            for event in bytes(raw).replace(b'\r\n', b'\n').split(b'\n\n'):
                data = b'\n'.join(line[5:].lstrip() for line in event.splitlines() if line.startswith(b'data:'))
                try:
                    messages.append(json.loads(data))
                except (ValueError, RecursionError):
                    continue
        for message in messages:
            if not isinstance(message, dict):
                continue
            if message.get('method') == 'elicitation/create':
                params = message.get('params', {})
                if isinstance(params, dict) and params.get('mode') == 'url' and isinstance(params.get('url'), str):
                    return True
            error = message.get('error', {})
            if isinstance(error, dict) and error.get('code') == -32042:
                data = error.get('data', {})
                elicitations = data.get('elicitations', []) if isinstance(data, dict) else []
                if isinstance(elicitations, list) and any(isinstance(item, dict) and isinstance(item.get('url'), str) for item in elicitations):
                    return True
            result = message.get('result', {})
            if isinstance(result, dict) and result.get('resultType') == 'input_required' and result.get('inputRequests'):
                return True
        return False

    def failure_body(self, raw, *, truncated=False):
        text = raw.decode('utf-8', errors='replace')
        try:
            body = self.redactor.clean(json.loads(text))
        except (ValueError, RecursionError):
            body = None
        error = body.get('error') if isinstance(body, dict) and body.get('jsonrpc') == '2.0' else None
        if isinstance(error, dict) and type(error.get('code')) is int and isinstance(error.get('message'), str):
            message = error['message'].encode()[:512].decode('utf-8', errors='ignore')
            return {'kind': 'jsonrpc_error', 'code': error['code'], 'message': message,
                    'truncated': truncated or len(error['message'].encode()) > 512}
        text = self.redactor.clean(text) if body is None else json.dumps(body, ensure_ascii=False)
        return {'kind': 'text', 'text': text.encode()[:512].decode('utf-8', errors='ignore'),
                'truncated': truncated or len(text.encode()) > 512}

    async def _read_sse(self, response, channel, received, messages, state, request_id=None):
        raw = bytearray()
        async for chunk in response.aiter_bytes():
            state.setdefault('response_prefix', bytearray()).extend(chunk[:65536 - len(state.get('response_prefix', b''))])
            state['budget']['size'] += len(chunk)
            if state['budget']['size'] > 65536:
                raise TargetTransportError('gateway response exceeds 64 KiB')
            raw.extend(chunk)
            raw = bytearray(raw.replace(b'\r\n', b'\n'))
            while b'\n\n' in raw:
                event, _, remaining = raw.partition(b'\n\n')
                raw = bytearray(remaining)
                data = []
                for line in event.splitlines():
                    name, _, value = line.partition(b':')
                    value = value.removeprefix(b' ')
                    if name == b'id' and b'\x00' not in value:
                        state['cursor'] = value.decode('utf-8', errors='replace')
                    elif name == b'retry' and value.isdigit():
                        state['retry_s'] = int(value) / 1000 if len(value) <= 9 else self.timeout_s + 1
                    elif name == b'data':
                        data.append(value)
                if not b'\n'.join(data):
                    continue
                try:
                    incoming = json.loads(b'\n'.join(data))
                except ValueError:
                    raise TargetTransportError('gateway returned a malformed SSE message') from None
                if channel == 'get_sse' and isinstance(incoming, dict) and 'id' in incoming and ('result' in incoming or 'error' in incoming):
                    raise TargetTransportError('gateway sent a response on a standalone GET stream')
                received.append(self.capture_message(incoming, channel))
                messages.append(incoming)
                await self.server_request(incoming)
            if request_id is not None and any(m.get('id') == request_id and ('result' in m or 'error' in m) for m in messages):
                return

    @staticmethod
    def _observation(status, reply, received, messages):
        return {'status': status, 'reply': reply,
                'channels': sorted({m['channel'] for m in received}),
                'markers': sorted(set(re.findall(r'ARGUSFLT[0-9A-F]{20}', json.dumps(messages)))),
                'messages': received}

    async def rpc(self, method, params=None, *, notification=False, headers=None, cookies=None, _budget=None):
        self.request_id += 1
        request_id = self.request_id
        message = {'jsonrpc': '2.0', 'method': method}
        if not notification:
            message['id'] = request_id
        if params is not None:
            message['params'] = params
        if self.era == MODERN:
            message['params'] = {**(params or {}), '_meta': {**(params or {}).get('_meta', {}), **metadata()}}
            if self.consent:
                message['params']['_meta']['io.modelcontextprotocol/clientCapabilities']['elicitation']['url'] = {}
        received, messages = [], []
        state = {'budget': _budget if _budget is not None else {'size': 0}, 'cursor': '', 'retry_s': 0}
        verb, outgoing, body = 'POST', self._headers(headers), None
        if self.era == MODERN:
            outgoing.update(mirrored_headers(message))
        status = None
        raw = bytearray()
        self.last_failure = None
        try:
            async with asyncio.timeout(self.timeout_s):
                for attempt in range(RESUMES_MAX + 1):
                    async with self.client.stream(verb, self.gateway['url'],
                                                  json=message if verb == 'POST' else None,
                                                  headers=outgoing, cookies=cookies) as response:
                        self.exchanges += 1
                        status = response.status_code
                        if status in (401, 403) or status >= 500:
                            await self.record_failure(response, rpc_method=method)
                            raise TargetTransportError(f'gateway returned HTTP {status}')
                        if not response.is_success:
                            raw = bytearray()
                            async for chunk in response.aiter_bytes():
                                state['budget']['size'] += len(chunk)
                                if state['budget']['size'] > 65536:
                                    raise TargetTransportError('gateway response exceeds 64 KiB')
                                raw.extend(chunk)
                            try:
                                error_body = json.loads(raw)
                            except (ValueError, TypeError):
                                error_body = None
                            if (isinstance(error_body, dict) and error_body.get('jsonrpc') == '2.0'
                                    and error_body.get('id') == request_id and isinstance(error_body.get('error'), dict)):
                                received.append(self.capture_message(error_body, 'post_json'))
                                messages.append(error_body)
                                return self._observation(status, 'jsonrpc_error', received, messages), error_body
                            return self._observation(status, 'http_error', received, messages), None
                        if self.era != MODERN and 'Mcp-Session-Id' in response.headers:
                            self.session = response.headers['Mcp-Session-Id']
                            self.redactor.add(self.session)
                        if 'text/event-stream' in response.headers.get('content-type', ''):
                            state['response_prefix'] = raw = bytearray()
                            channel = 'post_sse' if verb == 'POST' else 'resumed_sse'
                            try:
                                await self._read_sse(response, channel, received, messages, state, request_id)
                            except httpx.TransportError:
                                if not state['cursor']:
                                    raise
                            body = next((m for m in messages if m.get('id') == request_id and ('result' in m or 'error' in m)), None)
                        else:
                            if verb == 'GET':
                                raise TargetTransportError('gateway resumption did not return an SSE stream')
                            raw = bytearray()
                            async for chunk in response.aiter_bytes():
                                state['budget']['size'] += len(chunk)
                                if state['budget']['size'] > 65536:
                                    raise TargetTransportError('gateway response exceeds 64 KiB')
                                raw.extend(chunk)
                            if notification and not raw:
                                return {}, None
                            try:
                                body = json.loads(raw)
                            except (ValueError, TypeError):
                                raise TargetTransportError('gateway returned a malformed MCP response') from None
                            received.append(self.capture_message(body, 'post_json'))
                            messages.append(body)
                        if body is not None:
                            break
                    if self.era == MODERN or not state['cursor'] or attempt == RESUMES_MAX:
                        return self._observation(status, 'timeout', received, messages), None
                    await asyncio.sleep(state['retry_s'])
                    verb, outgoing = 'GET', self._headers(headers, get=True)
                    outgoing['Last-Event-ID'] = state['cursor']
                if (not isinstance(body, dict) or body.get('jsonrpc') != '2.0'
                        or body.get('id') != request_id or not ({'result', 'error'} & body.keys())):
                    raise TargetTransportError('gateway returned a malformed MCP response')
                return self._observation(status, 'jsonrpc_error' if 'error' in body else 'result', received, messages), body
        except (httpx.TimeoutException, TimeoutError):
            if self.last_failure is not None:
                raise TargetTransportError('gateway error response body timed out') from None
            return self._observation(None, 'timeout', received, messages), None
        except TargetTransportError:
            if self.last_failure is None:
                self.last_failure = self.failure_context(verb, self.gateway['url'], status, rpc_method=method)
                if status is not None:
                    self.last_failure['body'] = self.failure_body(raw, truncated=state['budget']['size'] > 65536)
            raise
        except httpx.HTTPError:
            self.last_failure = self.failure_context(verb, self.gateway['url'], status, rpc_method=method)
            raise TargetTransportError('gateway connection failed') from None

    async def _get_call(self, params, *, headers=None, cookies=None):
        received, messages = [], []
        state = {'budget': {'size': 0}, 'cursor': '', 'retry_s': 0}
        task = None
        self.last_failure = None
        observation, body = self._observation(None, 'timeout', [], []), None
        try:
            async with asyncio.timeout(self.timeout_s), AsyncExitStack() as stack:
                response = await stack.enter_async_context(self.client.stream(
                    'GET', self.gateway['url'], headers=self._headers(headers, get=True), cookies=cookies))
                self.exchanges += 1
                if response.status_code in (401, 403):
                    await self.record_failure(response)
                    raise TargetTransportError(f'gateway returned HTTP {response.status_code}')
                if response.status_code == 405:
                    return await self.rpc('tools/call', params, headers=headers, cookies=cookies)
                if not response.is_success or 'text/event-stream' not in response.headers.get('content-type', ''):
                    await self.record_failure(response)
                    raise TargetTransportError('gateway standalone GET stream failed')
                task = asyncio.create_task(self._read_sse(response, 'get_sse', received, messages, state))
                observation, body = await self.rpc('tools/call', params, headers=headers, cookies=cookies, _budget=state['budget'])
                await task
        except (httpx.TimeoutException, TimeoutError):
            if self.last_failure is not None:
                raise TargetTransportError('gateway error response body timed out') from None
            if body is None:
                observation['reply'] = 'timeout'
        except TargetTransportError:
            if self.last_failure is None:
                self.last_failure = self.failure_context('GET', self.gateway['url'])
                if 'response_prefix' in state:
                    self.last_failure['body'] = self.failure_body(state['response_prefix'])
            raise
        except httpx.HTTPError:
            self.last_failure = self.failure_context('GET', self.gateway['url'])
            raise TargetTransportError('gateway connection failed') from None
        finally:
            if task is not None:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
        observation['messages'].extend(received)
        observation['markers'] = sorted(set(observation['markers']) | set(self._observation(None, '', received, messages)['markers']))
        observation['channels'] = sorted(set(observation['channels']) | {m['channel'] for m in received})
        return observation, body

    async def initialize(self):
        requested = self.era
        if requested in ('auto', MODERN):
            self.era = MODERN
            observation, body = await self.rpc('server/discover', {})
            error = body.get('error', {}) if body else {}
            if body and 'result' in body:
                return
            if error.get('code') in MODERN_ERRORS or error.get('code') == -32601 and observation['status'] == 404:
                raise TargetTransportError('gateway modern MCP negotiation failed; no compatible modern version')
            if requested == MODERN or observation.get('status') != 400:
                raise TargetTransportError('gateway modern MCP discovery failed')
            self.session = None
        candidates = ERAS if requested == 'auto' else (requested,)
        for era in candidates:
            self.era = era
            _, body = await self.rpc('initialize', {'protocolVersion': era, 'capabilities': {'elicitation': {'url': {}}} if self.consent else {},
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

    async def _tool_call(self, params, *, headers=None, cookies=None):
        observation = self._observation(None, 'timeout', [], [])
        body, budget = None, {'size': 0}
        try:
            async with asyncio.timeout(self.timeout_s):
                for round_trip in range(3):
                    current, body = await self.rpc('tools/call', params, headers=headers, cookies=cookies, _budget=budget)
                    observation['status'], observation['reply'] = current['status'], current['reply']
                    observation['messages'].extend(current['messages'])
                    observation['channels'] = sorted(set(observation['channels']) | set(current['channels']))
                    observation['markers'] = sorted(set(observation['markers']) | set(current['markers']))
                    result = body.get('result') if body else None
                    if self.era != MODERN or not isinstance(result, dict) or result.get('resultType') != 'input_required':
                        return observation, body
                    if round_trip == 2:
                        return observation, body
                    if 'inputRequests' not in result and 'requestState' not in result:
                        raise TargetTransportError('gateway returned malformed input-required result')
                    if 'requestState' in result and not isinstance(result['requestState'], str):
                        raise TargetTransportError('gateway returned malformed request state')
                    requests = result.get('inputRequests', {})
                    if not isinstance(requests, dict) or len(requests) > 10:
                        raise TargetTransportError('gateway returned malformed input requests')
                    responses = {}
                    for key, request in requests.items():
                        if not isinstance(request, dict) or request.get('method') != 'elicitation/create':
                            raise TargetTransportError('gateway requested an undeclared client capability')
                        elicitation = request.get('params', {})
                        if not isinstance(elicitation, dict):
                            raise TargetTransportError('gateway returned malformed elicitation')
                        action = 'decline'
                        if elicitation.get('mode') == 'url' and self.consent:
                            await self.consent.open(elicitation)
                            action = 'accept'
                        responses[key] = {'action': action}
                    params = {**params, 'inputResponses': responses}
                    params.pop('requestState', None)
                    if 'requestState' in result:
                        params['requestState'] = result['requestState']
                return observation, body
        except TimeoutError:
            if self.last_failure is not None:
                raise TargetTransportError('gateway error response body timed out') from None
            observation['status'], observation['reply'] = None, 'timeout'
            return observation, None

    async def call(self, install_label, entry, tool, nonce, *, headers=None, cookies=None, path=None):
        for attempt in range(2):
            name = self.tools.get((entry, tool))
            if name is None:
                raise ProbeNotApplicable(f'entry {entry}: entry not registered')
            params = {'name': name, 'arguments': {'nonce': nonce}}
            if path is not None:
                params['arguments']['path'] = path
                params['_meta'] = {'progressToken': nonce}
            for consent_attempt in range(2):
                if path == 'get_stream_notification':
                    observation, body = await self._get_call(params, headers=headers, cookies=cookies)
                else:
                    observation, body = await self._tool_call(params, headers=headers, cookies=cookies)
                error = body.get('error', {}) if body else {}
                if not (isinstance(error, dict) and error.get('code') == -32042 and self.consent):
                    break
                elicitations = error.get('data', {}).get('elicitations') if isinstance(error.get('data'), dict) else None
                if not isinstance(elicitations, list) or not 1 <= len(elicitations) <= 10:
                    raise TargetTransportError('gateway returned a malformed URL elicitation error')
                for elicitation in elicitations:
                    self.consent.validate(elicitation)
                if consent_attempt == 1:
                    raise ProbeNotApplicable('gateway still requires authorization after consent')
                for elicitation in elicitations:
                    await self.consent.open(elicitation)
            error = body.get('error', {}) if body else {}
            if attempt == 0 and isinstance(error, dict) and 'unknown tool' in str(error.get('message', '')).lower():
                await self.discover(install_label)
                continue
            if path is not None:
                observation['classification'] = classify(observation.get('messages', []), path, body)
            return {'nonce': nonce, **observation}
