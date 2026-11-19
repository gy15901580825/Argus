"""Passive multi-origin listeners and case epochs with bounded recording."""
from __future__ import annotations

import asyncio
import copy
import hmac
import ipaddress
import json
import logging
import math
import secrets
import ssl
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import aiohttp.web as web

from .install import parse_listen, validate_install
from .match import WatchMatcher
from .record import BODY_MAX, RequestRecorder
from .registry import DefinitionError, Registry, load_registry
from .upstream import ERAS, idle


class _SafeHandler(web.RequestHandler):
    def handle_error(self, request, status=500, exc=None, message=None):
        if request.writer.output_size:
            raise ConnectionError('response already started')
        response = web.json_response({'error': 'request_rejected'}, status=status)
        response.force_close()
        return response


class _SafeServer(web.Server):
    def __call__(self):
        return _SafeHandler(self, loop=self._loop, **self._kwargs)


class _SafeRunner(web.AppRunner):
    async def _make_server(self):
        # Parser errors bypass app middleware and can contain raw request bytes.
        original = await super()._make_server()
        logger = logging.getLogger('argus.gateway_fixtures.http')
        logger.disabled = True
        return _SafeServer(original.request_handler, request_factory=original.request_factory,
                           handler_cancellation=original.handler_cancellation,
                           loop=asyncio.get_running_loop(),
                           **{**original._kwargs, 'access_log': None, 'logger': logger, 'debug': False})


@dataclass
class RequestContext:
    request: web.Request
    body: bytes
    message: Any
    install: dict
    origin: str
    route: str
    entry: str | None
    case_id: str | None
    nonce: str | None
    state: dict
    ext: dict = field(default_factory=dict)


@dataclass
class _Case:
    seq: int
    case_id: str
    probe_id: str
    nonce: str
    recorder: RequestRecorder
    behaviors: dict
    started: float = field(default_factory=time.monotonic)
    state: dict = field(default_factory=dict)
    tasks: set = field(default_factory=set)
    drained: asyncio.Event = field(default_factory=asyncio.Event)
    accepting: bool = True


def _seconds(value, *, minimum=0, maximum=3600) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not minimum <= value <= maximum:
        raise DefinitionError('invalid duration')
    return float(value)


class FixtureHost:
    def __init__(self, install: dict, *, control_token: str, control_bind: str = '127.0.0.1:8470',
                 allow_remote_control: bool = False, registry: Registry | None = None,
                 settle_s: float = 0.3, case_window_s: float = 10, body_timeout_s: float = 5):
        self.registry = registry or load_registry()
        validate_install(install, self.registry)
        if not isinstance(control_token, str) or not control_token or not control_token.isascii():
            raise DefinitionError('a nonempty ASCII control token is required')
        control_host, _ = parse_listen(control_bind)
        if not ipaddress.ip_address(control_host).is_loopback and not (allow_remote_control and install.get('tls')):
            raise DefinitionError('non-loopback control bind requires --allow-remote-control and TLS')
        if any(parse_listen(origin['listen']) == parse_listen(control_bind) and parse_listen(control_bind)[1] != 0
               for origin in install['origins'].values()):
            raise DefinitionError('control must use a separate listener')
        self.install = copy.deepcopy(install)
        self.control_token, self.control_bind = control_token, control_bind
        self.settle_s = _seconds(settle_s, maximum=30)
        self.case_window_s = _seconds(case_window_s)
        self.body_timeout_s = _seconds(body_timeout_s, minimum=0.001, maximum=5)
        self.seq, self.case_seq = 0, 0
        self.case: _Case | None = None
        self.last_evidence: dict | None = None
        self.lease_id: str | None = None
        self.lease_until = 0.0
        self._lease_task: asyncio.Task | None = None
        self._lock = asyncio.Lock()
        self._runners: list[web.AppRunner] = []
        self.origin_urls: dict[str, str] = {}
        self.control_url = ''
        self._canaries = {f'upstream_header:{name}': value.partition(' ')[2] if name.lower() == 'authorization' and ' ' in value else value
                          for entry in install['entries'].values()
                          for name, value in entry.get('headers', {}).items()}
        self.seen = {entry: {'first': None, 'last': None, 'methods': [], 'hits': []} for entry in install['entries']}
        self._idle_handlers = {origin: factory({}) for (origin, name), factory in self.registry.behaviors.items() if name == 'idle'}

    def _recorder(self, case_id=None, nonce=None, canaries=None, secrets_watch=None, watch_key=None, case_key=None):
        matcher = WatchMatcher(canaries if canaries is not None else self._canaries, secrets_watch or {},
                               watch_key=watch_key if watch_key is not None else secrets.token_bytes(32))
        return RequestRecorder(case_id=case_id, case_key=case_key if case_key is not None else secrets.token_bytes(32), matcher=matcher,
                               path_token=self.install['path_token'], nonce=nonce, seq_start=self.seq)

    async def start(self) -> 'FixtureHost':
        tls_context = None
        if self.install.get('tls'):
            tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls_context.load_cert_chain(self.install['tls']['cert'], self.install['tls']['key'])
        groups: dict[str, list[str]] = {}
        for name, origin in self.install['origins'].items():
            groups.setdefault(origin['listen'], []).append(name)
        try:
            for listen, names in groups.items():
                app = web.Application()
                app.router.add_route('*', '/{tail:.*}', self._fixture_handler(names))
                address = await self._listen(app, listen, tls_context)
                for name in names:
                    self.origin_urls[name] = address
            control = web.Application(client_max_size=BODY_MAX)
            control.router.add_route('*', '/{tail:.*}', self._control)
            # Finish atomic control operations even if their client disconnects.
            control_host, _ = parse_listen(self.control_bind)
            control_tls = None if ipaddress.ip_address(control_host).is_loopback else tls_context
            self.control_url = await self._listen(control, self.control_bind, control_tls, handler_cancellation=False)
        except BaseException:
            await self.close()
            raise
        return self

    async def _listen(self, app, listen, tls_context, *, handler_cancellation=True):
        runner = _SafeRunner(app, access_log=None, handler_cancellation=handler_cancellation)
        self._runners.append(runner)
        await runner.setup()
        host, port = parse_listen(listen)
        site = web.TCPSite(runner, host, port, ssl_context=tls_context)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        authority = f'[{host}]' if ':' in host else host
        return f"{'https' if tls_context else 'http'}://{authority}:{port}"

    async def close(self):
        if self._lease_task:
            self._lease_task.cancel()
            await asyncio.gather(self._lease_task, return_exceptions=True)
            self._lease_task = None
        async with self._lock:
            await self._release()
        for runner in reversed(self._runners):
            await runner.cleanup()
        self._runners.clear()

    async def __aenter__(self):
        return await self.start()

    async def __aexit__(self, *_):
        await self.close()

    def _fixture_handler(self, names):
        async def handle(request):
            authority = request.headers.get('Host', '').lower()
            origin = None
            for name in names:
                configured = self.install['origins'][name]
                public = urlsplit(configured['public'])
                expected = {public.netloc.lower()}
                if public.port is None or public.port == (443 if public.scheme == 'https' else 80):
                    expected.add(configured['host'].lower())
                if authority in expected:
                    origin = name
                    break
            if origin is None or self.install['path_token'] not in request.path.split('/'):
                return web.json_response({'error': 'not_found'}, status=404)
            return await self._request(request, origin)
        return handle

    async def _request(self, request, origin):
        case = self.case
        if case is not None and (not case.accepting or time.monotonic() >= self.lease_until):
            case = None
        task = asyncio.current_task()
        if case:
            case.tasks.add(task)
            case.drained.clear()
        self.seq += 1
        arrival_seq = self.seq
        arrived = time.monotonic()
        route, entry = 'other', None
        for name, info in self.install['entries'].items():
            if request.path == info['path'].replace('{path_token}', self.install['path_token']):
                route, entry = 'mcp', name
                break
        body = bytearray()
        complete = True
        recorder = case.recorder if case else self._recorder()
        record = None
        try:
            try:
                async with asyncio.timeout(self.body_timeout_s):
                    while len(body) <= BODY_MAX:
                        chunk = await request.content.read(min(8192, BODY_MAX + 1 - len(body)))
                        if not chunk:
                            break
                        body.extend(chunk)
                    complete = len(body) <= BODY_MAX
            except (TimeoutError, ConnectionError):
                complete = False
            record = recorder.record(origin=origin, route=route, entry=entry, method=request.method,
                                     path=request.path, query=request.query_string, headers=request.headers.items(),
                                     body=bytes(body), body_complete=complete, peer=request.remote,
                                     actor='argus_user_agent' if case and request.headers.get('X-Argus-Consent-Agent') == case.nonce else 'gateway',
                                     t_ms=int((arrived - case.started) * 1000) if case else 0)
            if record:
                # Body reads may finish out of order; sequence reflects arrival.
                record['seq'] = arrival_seq
                self._update_seen(record)
            try:
                message = json.loads(body) if complete and body else None
            except (ValueError, RecursionError):
                message = None
            context = RequestContext(request, bytes(body), message, self.install, origin, route, entry,
                                     case.case_id if case else None, case.nonce if case else None,
                                     case.state if case else {})
            response, behavior = None, origin + '.idle'
            if complete and case:
                for name, handler in case.behaviors.get(origin, []):
                    response = await handler(context)
                    if response is not None:
                        behavior = origin + '.' + name
                        break
            if not complete:
                response = web.json_response({'error': 'request_incomplete'}, status=413)
            elif response is None:
                if origin in self._idle_handlers:
                    response = await self._idle_handlers[origin](context)
                if response is None:
                    response = idle(context) if origin == 'upstream' else web.json_response({'error': 'not_found'}, status=404)
            if record:
                record['response'] = {'status': response.status, 'behavior': behavior}
                record['route'], record['entry'] = context.route, context.entry
                record['ext'] = copy.deepcopy(context.ext)
            if not complete:
                response.force_close()
            return response
        except asyncio.CancelledError:
            if case:
                case.recorder.complete = False
            raise
        except Exception:
            if case:
                case.recorder.complete = False
            if record:
                record['response'] = {'status': 500, 'behavior': origin + '.error'}
            return web.json_response({'error': 'request_failed'}, status=500)
        finally:
            if case:
                case.tasks.discard(task)
                if not case.tasks:
                    case.drained.set()
            else:
                recorder.seal()

    def _update_seen(self, record):
        if record['entry'] is None or record['actor'] != 'gateway':
            return
        seen = self.seen[record['entry']]
        now = time.time()
        seen['first'] = seen['first'] or now
        seen['last'] = now
        method = record['body'].get('jsonrpc', {}).get('method')
        if method and method not in seen['methods']:
            seen['methods'].append(method)
        seen['hits'] = sorted(set(seen['hits']) | (set(record['hits']) & self._canaries.keys()))

    async def _control(self, request):
        expected = 'Bearer ' + self.control_token
        supplied = request.headers.get('Authorization', '')
        if not hmac.compare_digest(supplied.encode(), expected.encode()):
            return web.json_response({'error': 'unauthorized'}, status=401)
        try:
            async with self._lock:
                if self.lease_id and time.monotonic() >= self.lease_until:
                    await self._release()
                if request.method == 'GET' and request.path == '/v1/health':
                    return web.json_response({'install_label': self.install['install_label'],
                                              'origins': self.install['origins'], 'plugins': self.registry.plugins,
                                              'eras': list(ERAS)})
                if request.method == 'GET' and request.path == '/v1/seen':
                    return web.json_response(self.seen)
                if request.method == 'POST' and request.path == '/v1/lease':
                    data = await self._control_json(request)
                    ttl = _seconds(data['ttl_s'], minimum=0.01)
                    if self.lease_id:
                        return web.json_response({'error': 'fixtures in use', 'expires_in_s': math.ceil(self.lease_until - time.monotonic())}, status=409)
                    self.lease_id = secrets.token_urlsafe(24)
                    self.lease_until = time.monotonic() + ttl
                    if self._lease_task:
                        self._lease_task.cancel()
                    self._lease_task = asyncio.create_task(self._expire(self.lease_id, ttl))
                    return web.json_response({'lease_id': self.lease_id})
                if request.method == 'POST' and request.path == '/v1/cases':
                    data = await self._control_json(request)
                    if not self.lease_id or data.get('lease_id') != self.lease_id:
                        return web.json_response({'error': 'invalid lease'}, status=409)
                    behaviors = self.registry.build_behaviors(data['toggles'])
                    watch = data['watch']
                    canaries = watch.get('canaries', [])
                    if isinstance(canaries, list):
                        if any(label not in self._canaries for label in canaries):
                            raise DefinitionError('unknown canary label')
                        canaries = {label: self._canaries[label] for label in canaries}
                    elif not isinstance(canaries, dict):
                        raise DefinitionError('canaries must be labels or a synthetic value map')
                    for name in ('probe_id', 'case_id', 'nonce'):
                        if not isinstance(data[name], str) or not data[name] or len(data[name]) > 120:
                            raise DefinitionError('invalid case identifier or nonce')
                    recorder = self._recorder(data['case_id'], data['nonce'], canaries,
                                              watch.get('secrets', {}), bytes.fromhex(watch['watch_key']),
                                              bytes.fromhex(watch['case_key']))
                    if self.case:
                        await self._seal()
                    if time.monotonic() >= self.lease_until:
                        recorder.seal(complete=False)
                        return web.json_response({'error': 'invalid lease'}, status=409)
                    self.case_seq += 1
                    self.case = _Case(self.case_seq, data['case_id'], data['probe_id'], data['nonce'], recorder, behaviors)
                    self.case.drained.set()
                    self.last_evidence = None
                    return web.json_response({'case_seq': self.case_seq})
                parts = request.path.strip('/').split('/')
                if request.method == 'POST' and len(parts) == 4 and parts[:2] == ['v1', 'cases'] and parts[3] == 'seal':
                    seq = int(parts[2])
                    if self.case and self.case.seq == seq:
                        return web.json_response(await self._seal())
                    if self.last_evidence and self.last_evidence['case_seq'] == seq:
                        return web.json_response(self.last_evidence)
                    return web.json_response({'error': 'unknown case'}, status=404)
                if request.method == 'DELETE' and len(parts) == 3 and parts[:2] == ['v1', 'lease']:
                    if parts[2] != self.lease_id:
                        return web.json_response({'error': 'invalid lease'}, status=409)
                    await self._release()
                    return web.json_response({'released': True})
                return web.json_response({'error': 'not_found'}, status=404)
        except (ValueError, TypeError, KeyError, TimeoutError, web.HTTPException):
            return web.json_response({'error': 'definition_error'}, status=400)
        except Exception:
            return web.json_response({'error': 'control_failed'}, status=500)

    async def _control_json(self, request):
        async with asyncio.timeout(5):
            data = await request.json()
        if not isinstance(data, dict):
            raise DefinitionError('control body must be an object')
        return data

    async def _seal(self):
        case = self.case
        complete = True
        try:
            await asyncio.sleep(self.settle_s)
            case.accepting = False
            self.case = None
            try:
                await asyncio.wait_for(case.drained.wait(), timeout=self.case_window_s)
            except TimeoutError:
                complete = False
        except asyncio.CancelledError:
            complete = False
            raise
        finally:
            # Shutdown can interrupt lease expiry while it is draining a case.
            case.accepting = False
            self.case = None
            tasks = tuple(case.tasks)
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            captured = case.recorder.seal(complete=complete)
            captured['requests'].sort(key=lambda record: record['seq'])
            self.last_evidence = {'case_seq': case.seq, 'case_id': case.case_id, 'probe_id': case.probe_id,
                                  'complete': captured['complete'], 'dropped': captured['dropped'],
                                  'fixture': {'requests': captured['requests'], 'state': copy.deepcopy(case.state)}}
        return self.last_evidence

    async def _release(self):
        if self.case:
            await self._seal()
        self.lease_id = None
        self.lease_until = 0
        self.last_evidence = None

    async def _expire(self, lease_id, ttl):
        await asyncio.sleep(ttl)
        async with self._lock:
            if self.lease_id == lease_id:
                await self._release()
