"""Only bounded, derived request observations survive case recording."""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import re
from email import policy
from email.parser import BytesParser
from http.cookies import CookieError, SimpleCookie
from typing import Any, Iterable
from urllib.parse import parse_qsl

from .match import TEXT_MAX, WatchMatcher

BODY_MAX = 64 * 1024
REQUESTS_MAX = 200
FIELDS_MAX = 128
SHAPE_DEPTH_MAX = 32
SHAPE_NODES_MAX = 2048
_HEADERS = frozenset(('content-type', 'accept', 'content-length', 'mcp-protocol-version',
    'mcp-method', 'mcp-name', 'last-event-id', 'user-agent'))
_PUBLIC_PARAMS = {'response_type': {'code'}, 'code_challenge_method': {'S256'},
                  'grant_type': {'client_credentials', 'authorization_code', 'refresh_token'}}
_METHODS = frozenset(('initialize', 'ping', 'tools/list', 'tools/call', 'notifications/initialized',
    'notifications/cancelled', 'subscriptions/listen'))
_PROTOCOLS = frozenset(('2025-06-18', '2025-11-25', '2026-07-28'))


class RequestRecorder:
    """One case's recorder; the host supplies the next sequence across cases.

    Raw headers and bodies are consumed synchronously and never retained. The host
    supplies body_complete=False on read timeout, and owns the in-flight seal gate.
    """

    def __init__(self, *, case_id: str | None, case_key: bytes, matcher: WatchMatcher,
                 path_token: str, nonce: str | None = None, seq_start: int = 0,
                 max_requests: int = REQUESTS_MAX):
        if len(case_key) != 32 or not 1 <= max_requests <= REQUESTS_MAX:
            raise ValueError('case_key must be 32 bytes and request cap must be 1..200')
        self.case_id, self._case_key, self.matcher = case_id, case_key, matcher
        self.path_token, self.nonce, self.seq = path_token, nonce, seq_start
        self.max_requests = max_requests
        self.records: list[dict[str, Any]] = []
        self.complete, self.dropped, self._sealed = True, 0, False
        self._request_complete = True
        self._request_hits: set[str] = set()

    def _match(self, value: str, *, include_secrets: bool = True) -> list[str]:
        result = self.matcher.match(value, include_secrets=include_secrets)
        self._request_complete &= result.complete
        self._request_hits.update(result.hits)
        return result.hits

    def _metadata_hits(self, value: str) -> list[str]:
        result = self.matcher.match(value)
        self._request_complete &= result.complete
        self._request_hits.update(result.canary_hits)
        return result.hits

    def _name(self, value: str) -> str:
        return '[redacted]' if self._metadata_hits(value) else value[:120]

    def _value(self, value: str) -> dict[str, Any]:
        hits = self._match(value)
        return {'len': len(value.encode('utf-8', errors='surrogatepass')),
                'corr': hmac.new(self._case_key, value.encode('utf-8', errors='surrogatepass'), hashlib.sha256).hexdigest()[:16],
                'hits': hits}

    def _parameters(self, pairs: Iterable[tuple[str, str]]) -> list[dict[str, Any]]:
        result = []
        for index, (name, value) in enumerate(pairs):
            if index == FIELDS_MAX:
                self._request_complete = False
                break
            captured = {'name': self._name(name), **self._value(value)}
            if value in _PUBLIC_PARAMS.get(name, ()) and not captured['hits']:
                captured = {'name': captured['name'], 'value': value}
            result.append(captured)
        return result

    def _shape(self, value: Any, depth: int = 0) -> dict[str, Any]:
        self._shape_nodes += 1
        if depth >= SHAPE_DEPTH_MAX or self._shape_nodes > SHAPE_NODES_MAX:
            self._request_complete = False
            return {'type': 'truncated'}
        if isinstance(value, dict):
            children = {}
            for key, child in value.items():
                if self._shape_nodes >= SHAPE_NODES_MAX:
                    self._request_complete = False
                    break
                children[self._name(key)] = self._shape(child, depth + 1)
            return {'type': 'object', 'keys': len(value), 'properties': children}
        if isinstance(value, list):
            children = []
            for child in value:
                if self._shape_nodes >= SHAPE_NODES_MAX:
                    self._request_complete = False
                    break
                children.append(self._shape(child, depth + 1))
            return {'type': 'array', 'len': len(value), 'items': children}
        if isinstance(value, str):
            return {'type': 'string', **self._value(value)}
        return {'type': 'null' if value is None else 'boolean' if isinstance(value, bool) else 'number'}

    def _envelope(self, data: Any) -> dict[str, Any]:
        if not isinstance(data, dict):
            return {}
        result = {}
        if data.get('jsonrpc') == '2.0':
            result['jsonrpc'] = '2.0'
        if type(data.get('id')) is int:
            result['id'] = data['id']
        if isinstance(data.get('method'), str) and data['method'] in _METHODS:
            result['method'] = data['method']
        params = data.get('params')
        if isinstance(params, dict):
            name = params.get('name')
            if name in ('argus_fixture_echo', 'argus_fixture_emit'):
                result['tool'] = name
            arguments = params.get('arguments')
            if isinstance(arguments, dict) and self.nonce is not None and arguments.get('nonce') == self.nonce:
                result['nonce'] = self.nonce
            meta = params.get('_meta', {})
            protocol = meta.get('protocolVersion') if isinstance(meta, dict) else None
            protocol = params.get('protocolVersion', protocol)
            if isinstance(protocol, str) and protocol in _PROTOCOLS:
                result['protocol_version'] = protocol
        return {key: value for key, value in result.items() if not self._metadata_hits(str(value))}

    def record(self, *, origin: str, route: str, method: str, path: str,
               entry: str | None = None, headers: Iterable[tuple[str, str]] = (),
               query: str = '', body: bytes = b'', body_complete: bool = True,
               peer: str | None = None, actor: str = 'gateway', t_ms: int = 0) -> dict[str, Any] | None:
        if self._sealed:
            raise RuntimeError('recorder is sealed')
        self.seq += 1
        if len(self.records) >= self.max_requests:
            self.dropped += 1
            self.complete = False
            return None
        self._request_complete = body_complete and len(body) <= BODY_MAX
        self._request_hits = set()
        self._shape_nodes = 0
        captured_headers, header_bytes, content_type = [], 0, ''
        for index, (name, value) in enumerate(headers):
            header_bytes += len(name.encode()) + len(value.encode())
            if index >= FIELDS_MAX or header_bytes > TEXT_MAX:
                self._request_complete = False
                break
            captured_name = self._name(name).lower()
            name = name.lower()
            if name == 'content-type':
                content_type = value
            captured = {'name': captured_name, **self._value(value)}
            if name in _HEADERS and not captured['hits']:
                captured = {'name': captured_name, 'value': value[:120] if name == 'user-agent' else value}
            if name == 'authorization':
                scheme, separator, _ = value.partition(' ')
                if separator and re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,31}', scheme) and not self._metadata_hits(scheme):
                    captured['scheme'] = scheme
            if name == 'cookie':
                cookie_hits = set(captured['hits'])
                for cookie in value.split(';'):
                    _, separator, candidate = cookie.strip().partition('=')
                    if separator:
                        cookie_hits.update(self._match(candidate))
                cookies = SimpleCookie()
                try:
                    cookies.load(value)
                    for cookie in cookies.values():
                        cookie_hits.update(self._match(cookie.value))
                except CookieError:
                    self._request_complete = False
                captured['hits'] = sorted(cookie_hits)
            captured_headers.append(captured)
        if len(query.encode()) > TEXT_MAX:
            self._request_complete = False
        query = query.encode()[:TEXT_MAX].decode(errors='ignore')
        self._match(query, include_secrets=False)
        query_records = self._parameters(parse_qsl(query, keep_blank_values=True))
        raw = body[:BODY_MAX]
        body_text = raw.decode('utf-8', errors='replace')
        request_hits = self._request_hits
        self._request_hits = set()
        self._match(body_text, include_secrets=False)
        media_type = content_type.partition(';')[0].strip().lower()
        body_record: dict[str, Any] = {'media_type': self._name(media_type), 'len': len(body)}
        if not raw:
            body_record['shape'] = {'type': 'empty'}
        elif media_type == 'application/json':
            try:
                data = json.loads(raw)
                body_record['shape'] = self._shape(data)
                if route == 'mcp':
                    body_record['jsonrpc'] = self._envelope(data)
            except (ValueError, RecursionError):
                body_record['shape'] = {'type': 'unparsed'}
                self._request_complete = False
        elif media_type == 'application/x-www-form-urlencoded':
            body_record['form'] = self._parameters(parse_qsl(body_text, keep_blank_values=True))
        elif media_type == 'multipart/form-data':
            message = BytesParser(policy=policy.default).parsebytes(
                b'Content-Type: ' + content_type.encode() + b'\r\nMIME-Version: 1.0\r\n\r\n' + raw)
            if not message.is_multipart() or message.defects:
                self._request_complete = False
            fields = []
            for part in message.walk():
                if part.is_multipart():
                    continue
                if part.defects:
                    self._request_complete = False
                fields.append((part.get_param('name', header='content-disposition') or '',
                    (part.get_payload(decode=True) or b'').decode('utf-8', errors='replace')))
            body_record['form'] = self._parameters(fields)
        body_record['hits'] = sorted(self._request_hits)
        self._request_hits.update(request_hits)
        try:
            address = ipaddress.ip_address(peer)
            peer_class = 'loopback' if address.is_loopback else 'private' if address.is_private else 'public'
        except ValueError:
            peer_class = 'unknown'
        self._match(path, include_secrets=False)
        if len(path.encode()) > TEXT_MAX:
            self._request_complete = False
            path = path.encode()[:TEXT_MAX].decode(errors='ignore')
        safe_path = path.replace(self.path_token, '{path_token}') if self.path_token else path
        safe_path = '/[redacted]' if self._metadata_hits(safe_path) else '/'.join(
            self._name(segment) for segment in safe_path.split('/'))
        body_record['complete'] = self._request_complete
        record = {'seq': self.seq, 'case_id': self.case_id, 't_ms': t_ms, 'origin': origin,
            'route': route, 'entry': entry, 'actor': actor, 'peer_class': peer_class,
            'method': method, 'path': safe_path, 'query': query_records, 'headers': captured_headers,
            'body': body_record, 'response': {}, 'hits': sorted(self._request_hits), 'ext': {}}
        self.complete &= self._request_complete
        self.records.append(record)
        return record

    def seal(self, *, complete: bool = True) -> dict[str, Any]:
        self.complete &= complete
        self._sealed = True
        self._case_key = None
        self.matcher.clear()
        return {'requests': self.records, 'complete': self.complete, 'dropped': self.dropped}
