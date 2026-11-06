from __future__ import annotations

import asyncio
import copy
import base64
import uuid
from datetime import date, datetime
import json
import math
import re
from dataclasses import dataclass, replace
from urllib.parse import parse_qs, unquote, urlsplit

from aiohttp import web

from argus.cli.validate_transport_v2 import execute_transport
from argus.drafting.draft import CONSTRAINT_KEYWORDS, _nullable, _type
from argus.drafting.scenario import CHECKS, MAX_BODY_BYTES, MAX_DEPTH, MAX_REQUESTS, ScenarioV1, document_cases, path_pattern
from argus.targets import build_target
from argus_transport import ExecutionPolicy, TransportSpecV2, with_origin
from argus_transport.runtime_v2 import TargetRunStopped
from argus_transport.spec_v2 import material_binding


VERIFY_DEADLINE_S = 30
_MISSING = object()


def _json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise ValueError('request_body_invalid')
        result[key] = value
    return result


def _json_number(value):
    number = float(value)
    if not math.isfinite(number): raise ValueError('request_body_invalid')
    return number


def _json_constant(value):
    raise ValueError('request_body_invalid')


def _json_structure(value, depth=0):
    if depth > MAX_DEPTH: raise ValueError('request_body_invalid')
    if isinstance(value, dict):
        for item in value.values(): _json_structure(item, depth + 1)
    elif isinstance(value, list):
        for item in value: _json_structure(item, depth + 1)
    elif isinstance(value, str) and len(value.encode('utf-8')) > MAX_BODY_BYTES:
        raise ValueError('request_body_invalid')


def _json_body(raw):
    try:
        value = json.loads(raw, object_pairs_hook=_json_object, parse_float=_json_number,
                           parse_constant=_json_constant)
        _json_structure(value)
        return value
    except RecursionError:
        raise ValueError('request_body_invalid') from None


class StrictLoopbackPolicy(ExecutionPolicy):
    def __init__(self, origin, env_names=frozenset()):
        super().__init__(frozenset({origin}), (), frozenset(env_names))
        object.__setattr__(self, 'origin', origin)
        object.__setattr__(self, 'denied', False)
        object.__setattr__(self, 'dispatches', 0)
        object.__setattr__(self, 'budget_exceeded', False)

    async def endpoint_ip(self, url):
        parsed = urlsplit(url)
        allowed = urlsplit(self.origin)
        if parsed.scheme != 'http' or parsed.netloc != allowed.netloc or parsed.hostname != '127.0.0.1' or parsed.port != allowed.port or parsed.username is not None or parsed.password is not None or parsed.fragment:
            object.__setattr__(self, 'denied', True)
            raise ValueError('unsafe_location')
        if self.dispatches >= MAX_REQUESTS:
            object.__setattr__(self, 'budget_exceeded', True)
            raise ValueError('verification_budget_exceeded')
        object.__setattr__(self, 'dispatches', self.dispatches + 1)
        return '127.0.0.1'


@dataclass(frozen=True)
class VerificationResult:
    layer: str
    status: str
    semantic_success: bool
    cleanup_complete: bool
    checks: tuple[str, ...]
    execution: dict
    resources: tuple[dict, ...]
    required_gaps: tuple[str, ...]
    trace: tuple[dict, ...]
    cases: tuple[dict, ...] = ()
    unverified: tuple[str, ...] = ()

    def as_dict(self):
        return {'version': 2, 'layer': self.layer, 'status': self.status,
                'semantic_success': self.semantic_success, 'cleanup_complete': self.cleanup_complete,
                'checks': list(self.checks), 'execution': self.execution,
                'resources': list(self.resources), 'required_gaps': list(self.required_gaps),
                'trace': list(self.trace), 'cases': list(self.cases), 'unverified': list(self.unverified)}


def _pointer(data, pointer):
    if not pointer: return data
    for part in pointer[1:].split('/'):
        key = part.replace('~1', '/').replace('~0', '~')
        if isinstance(data, dict): data = data.get(key, _MISSING)
        elif isinstance(data, list) and re.fullmatch(r'0|[1-9][0-9]*', key) and int(key) < len(data): data = data[int(key)]
        else: return _MISSING
    return data


def _schema_supported(schema, depth=0, *, value=_MISSING):
    if depth > 16 or not isinstance(schema, dict): return False
    allowed = {'type', 'properties', 'required', 'items', 'minItems', 'maxItems', 'additionalProperties',
               'allOf', 'anyOf', 'oneOf', 'enum', 'const', 'minLength', 'maxLength', 'minimum', 'maximum',
               'description', 'title', 'example', 'examples', 'default', 'deprecated', 'readOnly', 'writeOnly', 'format', 'nullable'}
    # Constraints the drafter leaves unchecked (its schema_constraints_unchecked gap) stay unchecked here.
    if set(schema) - allowed - CONSTRAINT_KEYWORDS: return False
    if 'nullable' in schema and type(schema['nullable']) is not bool: return False
    for keyword in ('allOf', 'anyOf', 'oneOf'):
        if keyword in schema and (not isinstance(schema[keyword], list) or not schema[keyword] or any(not _schema_supported(s, depth+1, value=value) for s in schema[keyword])): return False
    if 'properties' in schema:
        if not isinstance(schema['properties'], dict): return False
        for key, child in schema['properties'].items():
            if value is _MISSING:
                if not _schema_supported(child, depth+1): return False
            elif isinstance(value, dict) and key in value and not _schema_supported(child, depth+1, value=value[key]): return False
    for keyword in ('items', 'additionalProperties'):
        if keyword in schema and isinstance(schema[keyword], dict):
            if value is _MISSING:
                if not _schema_supported(schema[keyword], depth+1): return False
            else:
                children = value if keyword == 'items' and isinstance(value, list) else [item for key, item in value.items() if key not in schema.get('properties', {})] if keyword == 'additionalProperties' and isinstance(value, dict) else []
                if any(not _schema_supported(schema[keyword], depth+1, value=child) for child in children): return False
    if 'items' in schema and not isinstance(schema['items'], dict): return False
    if 'additionalProperties' in schema and not isinstance(schema['additionalProperties'], (dict, bool)): return False
    if 'required' in schema and (not isinstance(schema['required'], list) or any(not isinstance(x, str) for x in schema['required'])): return False
    if 'enum' in schema and (not isinstance(schema['enum'], list) or not schema['enum']): return False
    for keyword in ('minItems', 'maxItems', 'minLength', 'maxLength'):
        if keyword in schema and (type(schema[keyword]) is not int or schema[keyword] < 0): return False
    for keyword in ('minimum', 'maximum'):
        if keyword in schema and type(schema[keyword]) not in {int, float}: return False
    kinds = schema.get('type')
    if kinds is not None and any(kind not in {'object', 'array', 'string', 'integer', 'number', 'boolean', 'null'} for kind in (kinds if isinstance(kinds, list) else [kinds])): return False
    return True


def _schema_sample(schema, depth=0):
    if depth > 16 or not isinstance(schema, dict): raise ValueError('schema_mock_unsupported')
    schema = _nullable(schema)
    if 'enum' in schema and schema['enum']: return copy.deepcopy(next((v for v in schema['enum'] if v is not None), schema['enum'][0]))
    if 'const' in schema: return copy.deepcopy(schema['const'])
    formats = {'uuid': '00000000-0000-4000-8000-000000000001', 'date': '2026-01-01', 'date-time': '2026-01-01T00:00:00Z', 'byte': 'c2NoZW1hIHNhbXBsZQ=='}
    if schema.get('format') in formats: return formats[schema['format']]
    kind = _type(schema) or ('object' if 'properties' in schema else None)
    if kind == 'object': return {key: _schema_sample(value, depth+1) for key, value in schema.get('properties', {}).items()}
    if kind == 'array': return [_schema_sample(schema.get('items', {}), depth+1) for _ in range(min(schema.get('minItems', 0), 8))]
    if kind == 'string': return 'schema sample' + 'x' * min(schema.get('minLength', 0), 128)
    if kind in {'number', 'integer'}: return schema.get('minimum', 0)
    if kind == 'boolean': return False
    if kind == 'null': return None
    raise ValueError('schema_mock_unsupported')


def _json_equal(actual, expected, depth=0):
    if depth > MAX_DEPTH: return False
    if type(actual) in {int, float} and type(expected) in {int, float}:
        return (type(actual) is int or math.isfinite(actual)) and (type(expected) is int or math.isfinite(expected)) and actual == expected
    if type(actual) is not type(expected): return False
    if isinstance(actual, dict):
        return actual.keys() == expected.keys() and all(_json_equal(item, expected[key], depth+1) for key, item in actual.items())
    if isinstance(actual, list):
        return len(actual) == len(expected) and all(_json_equal(item, other, depth+1) for item, other in zip(actual, expected))
    return actual == expected


def _schema_valid(value, schema, depth=0):
    if depth > 16 or not isinstance(schema, dict): return False
    if type(value) is float and not math.isfinite(value): return False
    if 'enum' in schema and not any(_json_equal(value, option) for option in schema['enum']): return False
    if 'const' in schema and not _json_equal(value, schema['const']): return False
    nullable_null = value is None and schema.get('nullable') is True
    kinds = schema.get('type')
    if kinds is None and 'properties' in schema: kinds = 'object'
    if isinstance(kinds, list): return any(_schema_valid(value, {**schema, 'type': kind}, depth+1) for kind in kinds)
    valid_types = {'object': isinstance(value, dict), 'array': isinstance(value, list), 'string': isinstance(value, str),
                   'integer': type(value) is int, 'number': type(value) in {int, float}, 'boolean': type(value) is bool, 'null': value is None}
    if kinds is not None and not nullable_null and not valid_types.get(kinds, False): return False
    format = None if nullable_null else schema.get('format')
    try:
        if format == 'uuid' and (not isinstance(value, str) or str(uuid.UUID(value)) != value.lower()): return False
        if format == 'date' and (not isinstance(value, str) or date.fromisoformat(value).isoformat() != value): return False
        if format == 'date-time':
            if not isinstance(value, str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})', value): return False
            if datetime.fromisoformat(value.upper().replace('Z', '+00:00')).tzinfo is None: return False
        if format == 'byte':
            if not isinstance(value, str): return False
            base64.b64decode(value, validate=True)
        if format in {'int32', 'int64'} and (type(value) is not int or not -(2**(31 if format == 'int32' else 63)) <= value < 2**(31 if format == 'int32' else 63)): return False
        if format in {'float', 'double'} and type(value) not in {int, float}: return False
    except (ValueError, TypeError): return False
    for branch in schema.get('allOf', []):
        if not _schema_valid(value, branch, depth+1): return False
    if 'anyOf' in schema and not any(_schema_valid(value, s, depth+1) for s in schema['anyOf']): return False
    if 'oneOf' in schema and sum(_schema_valid(value, s, depth+1) for s in schema['oneOf']) != 1: return False
    if isinstance(value, dict):
        if any(key not in value for key in schema.get('required', [])): return False
        properties = schema.get('properties', {})
        for key, item in value.items():
            if key in properties and not _schema_valid(item, properties[key], depth+1): return False
            if key not in properties and schema.get('additionalProperties') is False: return False
            if key not in properties and isinstance(schema.get('additionalProperties'), dict) and not _schema_valid(item, schema['additionalProperties'], depth+1): return False
    if isinstance(value, list):
        if len(value) < schema.get('minItems', 0) or len(value) > schema.get('maxItems', MAX_REQUESTS): return False
        if 'items' in schema and any(not _schema_valid(item, schema['items'], depth+1) for item in value): return False
    if isinstance(value, str):
        if len(value) < schema.get('minLength', 0) or len(value) > schema.get('maxLength', MAX_BODY_BYTES): return False
    if type(value) in {int, float}:
        if value < schema.get('minimum', float('-inf')) or value > schema.get('maximum', float('inf')): return False
    return True


class LocalFake:
    def __init__(self, catalog, scenario, *, shutdown_s=.1):
        self.catalog = catalog
        self.scenario = scenario
        self.states = {resource.id: resource.initial for resource in scenario.resources} if scenario else {}
        self.counts = {}
        self.trace = []
        self.failures = []
        self.material_predicates = frozenset((op.id, index) for op in scenario.operations
            for index, check in enumerate(op.request) if check.check == 'material_bound') if scenario else frozenset()
        self.material_required = bool(self.material_predicates)
        self.material_observed = set()
        self.routes = [(op, *path_pattern(op.path)) for op in scenario.operations] if scenario else []
        self.catalog_routes = [(op, *path_pattern(op.path)) for op in catalog.operations] if catalog else []
        self.shutdown_s = shutdown_s
        self.runner = None
        self.origin = None

    def fail(self, name):
        if name not in self.failures: self.failures.append(name)

    async def __aenter__(self):
        app = web.Application(client_max_size=MAX_BODY_BYTES)
        app.router.add_route('*', '/{tail:.*}', self.handle)
        self.runner = web.AppRunner(app, shutdown_timeout=self.shutdown_s)
        try:
            await self.runner.setup()
            site = web.TCPSite(self.runner, '127.0.0.1', 0)
            await site.start()
            self.origin = f'http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}'
            return self
        except BaseException:
            await self.runner.cleanup()
            raise

    async def __aexit__(self, *exc):
        await self.runner.cleanup()

    async def _values(self, request):
        raw = await request.read()
        if len(raw) > MAX_BODY_BYTES: raise ValueError('request_body_limit')
        body = _json_body(raw) if raw and request.content_type == 'application/json' else _MISSING
        query = parse_qs(request.query_string, keep_blank_values=True, max_num_fields=64)
        multipart = {}
        if request.content_type.startswith('multipart/'):
            from email.parser import BytesParser
            from email.policy import default
            message = BytesParser(policy=default).parsebytes(b'Content-Type: ' + request.headers['Content-Type'].encode('ascii') + b'\r\nMIME-Version: 1.0\r\n\r\n' + raw)
            for part in message.iter_parts():
                name = part.get_param('name', header='content-disposition')
                value = part.get_payload(decode=True)
                if not isinstance(value, bytes) or len(value) > MAX_BODY_BYTES: raise ValueError('request_body_limit')
                multipart.setdefault(name, []).append((part.get_filename(), value.decode('utf-8')))
        return raw, body, query, multipart

    def _select(self, selector, raw, body, query, multipart, path):
        if selector.kind == 'json': return _pointer(body, selector.pointer)
        if selector.kind == 'path': return path.get(selector.name, _MISSING)
        if selector.kind == 'query':
            values = query.get(selector.name, [])
            return values[0] if len(values) == 1 else _MISSING
        if selector.kind == 'raw_utf8': return raw.decode('utf-8')
        parts = multipart.get(selector.name, [])
        if len(parts) != 1: return _MISSING
        filename, content = parts[0]
        if selector.kind == 'multipart_file' and filename != selector.filename: return _MISSING
        if selector.kind == 'multipart_text' and filename is not None: return _MISSING
        return content

    def _catalog_operation(self, request):
        for op, pattern, names in self.catalog_routes:
            match = pattern.fullmatch(request.path)
            if op.method.upper() == request.method and match: return op, dict(zip(names, match.groups()))
        return None, {}

    def _schema_request(self, op, body, query, path, multipart, headers, cookies, *, raw, media_type):
        for param in op.path_data.get('parameters', []) + op.data.get('parameters', []):
            location = param.get('in')
            if location not in {'query', 'path', 'header', 'cookie'}:
                self.fail('schema_mock_unsupported')
                return False
            name = param.get('name')
            values = query.get(name, []) if location == 'query' else [path[name]] if location == 'path' and name in path else [headers[name]] if location == 'header' and name in headers else [cookies[name]] if location == 'cookie' and name in cookies else []
            if len(values) > 1 or (param.get('required') and not values): return False
            if values:
                value = values[0]
                kind = param.get('schema', {}).get('type')
                try:
                    if kind == 'integer': value = int(value)
                    if kind == 'number': value = float(value)
                    if kind == 'boolean': value = {'true': True, 'false': False}[value]
                except (ValueError, KeyError): return False
                if not _schema_supported(param.get('schema', {}), value=value):
                    self.fail('schema_mock_unsupported')
                    return False
                if not _schema_valid(value, param.get('schema', {})): return False
        request_body = op.data.get('requestBody', {})
        content = request_body.get('content', {})
        if not raw: return not request_body.get('required', False)
        if media_type not in content: return False
        if media_type == 'application/json':
            if body is _MISSING: return False
            schema = content[media_type].get('schema', {})
            if not _schema_supported(schema, value=body):
                self.fail('schema_mock_unsupported')
                return False
            return _schema_valid(body, schema)
        if media_type == 'multipart/form-data':
            schema = content[media_type].get('schema', {})
            value = {name: parts[0][1] for name, parts in multipart.items() if len(parts) == 1}
            if not _schema_supported(schema, value=value):
                self.fail('schema_mock_unsupported')
                return False
            return _schema_valid(value, schema)
        self.fail('schema_mock_unsupported')
        return False

    async def handle(self, request):
        if len(self.trace) >= MAX_REQUESTS:
            self.fail('verification_budget_exceeded')
            return web.json_response({'error': 'request limit'}, status=429)
        try:
            raw, body, query, multipart = await self._values(request)
        except (ValueError, UnicodeError, web.HTTPRequestEntityTooLarge):
            self.fail('request_body_invalid')
            return web.json_response({'error': 'invalid body'}, status=400)
        op, doc_path = self._catalog_operation(request)
        if self.catalog is not None and (op is None or not self._schema_request(op, body, query, doc_path, multipart, request.headers, request.cookies,
                raw=raw, media_type=request.content_type)):
            self.fail('request_schema_invalid')
        if self.scenario is None:
            self.trace.append({'operation': op.id if op else None, 'role': 'schema', 'method': request.method, 'path': request.path})
            if op is None or self.failures: return web.json_response({'error': 'schema mismatch'}, status=400)
            try:
                responses = op.data.get('responses', {})
                status = next(key for key in responses if str(key).isdigit() and 200 <= int(key) < 300)
                response = responses[status].get('content', {}).get('application/json', {})
                if not _schema_supported(response.get('schema', {})): raise ValueError('schema_mock_unsupported')
                sample = _schema_sample(response.get('schema', {}))
                if not _schema_valid(sample, response.get('schema', {})): raise ValueError('schema_mock_unsupported')
                if len(json.dumps(sample).encode('utf-8')) > MAX_BODY_BYTES: raise ValueError('schema_mock_unsupported')
                return web.json_response(sample, status=int(status))
            except (ValueError, StopIteration, TypeError):
                self.fail('schema_mock_unsupported')
                return web.json_response({'error': 'unsupported schema'}, status=400)
        selected = None
        for candidate, pattern, names in self.routes:
            match = pattern.fullmatch(request.path)
            if candidate.method == request.method and match:
                selected = candidate
                path = {key: unquote(value) for key, value in zip(names, match.groups())}
                break
        self.trace.append({'operation': selected.id if selected else None, 'role': selected.role if selected else 'unknown', 'method': request.method, 'path': request.path})
        if selected is None:
            self.fail('unexpected_request')
            return web.json_response({'error': 'unknown route'}, status=404)
        count = self.counts.get(selected.id, 0)
        self.counts[selected.id] = count + 1
        if count >= selected.maximum:
            self.fail('operation_call_count')
            return web.json_response({'error': 'finite replies exhausted'}, status=429)
        valid = not self.failures
        for index, check in enumerate(selected.request):
            observed = self._select(check.at, raw, body, query, multipart, path)
            if observed is _MISSING or type(observed) is not type(check.equals) or observed != check.equals:
                self.fail(CHECKS[check.check])
                valid = False
            elif check.check == 'material_bound':
                self.material_observed.add((selected.id, index))
        reply = selected.replies[count]
        if op is not None:
            response = op.data.get('responses', {}).get(str(reply.status), op.data.get('responses', {}).get('default', {}))
            content = response.get('content', {})
            if reply.status not in {204, 304} and content and 'application/json' not in content:
                self.fail('schema_mock_unsupported')
                valid = False
            schema = content.get('application/json', {}).get('schema', _MISSING)
            if schema is not _MISSING and (not _schema_supported(schema, value=reply.body) or not _schema_valid(reply.body, schema)):
                self.fail('response_schema_invalid')
                valid = False
        for effect in reply.effects:
            if self.states[effect.resource] != effect.before:
                self.fail('resource_state_mismatch')
                valid = False
        if not valid: return web.json_response({'error': 'independent check failed'}, status=400)
        for effect in reply.effects: self.states[effect.resource] = effect.after
        return web.Response(status=reply.status, headers=dict(reply.headers)) if reply.status in {204, 304} else web.json_response(reply.body, status=reply.status, headers=dict(reply.headers))


def _summary(evidence):
    result = evidence.result
    if isinstance(result, TargetRunStopped):
        return {'outcome': 'stopped', 'reply': None, 'reason': result.reason, 'requests': evidence.requests, 'attempts': 1,
                'cleanup': evidence.cleanup, 'close_stop': evidence.close_stop.reason if evidence.close_stop else None}
    return {'outcome': result.outcome.value, 'reply': result.response_text, 'reason': result.reason_code.value,
            'requests': evidence.requests, 'attempts': 1, 'cleanup': evidence.cleanup, 'close_stop': evidence.close_stop.reason if evidence.close_stop else None}


def _assess(fake, execution, gaps):
    scene = fake.scenario
    failures = list(fake.failures)
    if scene is None:
        if execution.get('outcome') not in {'succeeded', 'blocked'}: failures.append(execution.get('reason', 'execution_failed'))
        return VerificationResult('schema_mock_only', 'failed' if failures else 'schema_mock_only', False, False,
                                  tuple(dict.fromkeys(failures)), execution, (), (), tuple(fake.trace))
    if fake.material_required and (not fake.material_observed or not fake.material_predicates <= fake.material_observed):
        failures.append('material_not_bound')
    if not any(fake.counts.get(op.id, 0) for op in scene.operations if op.role == 'invoke'):
        failures.append('invoke_not_called')
    for op in scene.operations:
        if not op.minimum <= fake.counts.get(op.id, 0) <= op.maximum: failures.append('operation_call_count')
    if execution.get('outcome') != scene.outcome: failures.append('terminal_outcome_mismatch')
    if execution.get('reply') != scene.reply: failures.append('reply_mismatch')
    if execution.get('reason') in {'unsafe_location', 'poll_identity_changed'}: failures.append(execution['reason'])
    if execution.get('close_stop'): failures.append(execution['close_stop'])
    resources = tuple({'id': r.id, 'state': fake.states[r.id], 'cleanup': r.cleanup} for r in scene.resources)
    if any(fake.states[r.id] != r.final for r in scene.resources): failures.append('cleanup_left_resources')
    cleanup = execution.get('cleanup')
    if cleanup and (not cleanup.get('complete') or cleanup.get('open')): failures.append('cleanup_left_resources')
    declared_residue = any(r.cleanup != 'delete' and fake.states[r.id] != 'absent' for r in scene.resources)
    known_gaps = {gap if isinstance(gap, str) else gap.code if hasattr(gap, 'code') else gap.get('code') for gap in gaps}
    if any(code not in known_gaps for code in scene.required_gaps): failures.append('cleanup_gap_missing')
    if cleanup and cleanup.get('leftover'):
        allowed = {}
        for op in scene.operations:
            if any(effect.after != 'absent' and any(r.id == effect.resource and r.cleanup == 'documented_no_delete' and fake.states[r.id] != 'absent' for r in scene.resources) for reply in op.replies for effect in reply.effects):
                allowed[(op.method, op.path)] = fake.counts.get(op.id, 0)
        for leftover in cleanup['leftover']:
            match = re.fullmatch(r"step '[^']+' ([A-Z]+) (http://[^ ]+)", leftover) if isinstance(leftover, str) else None
            admitted = None
            if match:
                url = urlsplit(match.group(2))
                if f'{url.scheme}://{url.netloc}' == fake.origin:
                    for method, path in allowed:
                        if method == match.group(1) and path_pattern(path)[0].fullmatch(url.path) and allowed[(method, path)] > 0:
                            admitted = (method, path)
                            break
            if admitted is None: failures.append('cleanup_left_resources')
            else: allowed[admitted] -= 1
    if execution.get('reason') == 'verification_budget_exceeded': failures.append('verification_budget_exceeded')
    failures = tuple(dict.fromkeys(failures))
    semantic = not failures and scene.outcome == 'succeeded'
    cleanup_complete = not failures and not declared_residue and not (cleanup and cleanup.get('leftover'))
    status = 'failed' if failures else 'verified' if semantic and cleanup_complete else 'business_only'
    return VerificationResult('independent_scenario', status, semantic, cleanup_complete, failures, execution,
                              resources, scene.required_gaps, tuple(fake.trace))


async def _attempt(spec, catalog, scenario):
    copied = copy.deepcopy(spec)
    copied['transport']['auth'] = {'kind': 'none'}
    loop = asyncio.get_running_loop()
    deadline = loop.time() + VERIFY_DEADLINE_S
    teardown_reserve = min(.2, VERIFY_DEADLINE_S / 2)
    active_deadline = deadline - teardown_reserve
    fake = LocalFake(catalog, scenario, shutdown_s=min(.1, teardown_reserve / 2))
    entered = False
    execution = {'outcome': 'stopped', 'reply': None, 'reason': 'verification_budget_exceeded', 'requests': {}, 'attempts': 0, 'cleanup': None}
    try:
        async with asyncio.timeout_at(active_deadline):
            await fake.__aenter__()
            entered = True
        copied['transport'] = with_origin(copied['transport'], fake.origin)
        transport = build_target(copied).spec.transport
        if not isinstance(transport, TransportSpecV2): raise ValueError('version 2 transport required')
        fake.material_required = fake.material_required or material_binding(transport) != 'none'
        environ = dict(scenario.environment) if scenario else {}
        policy = StrictLoopbackPolicy(fake.origin, environ)
        evidence = await execute_transport(transport, policy=policy, environ=environ, deadline_at=active_deadline)
        execution = _summary(evidence)
        if policy.denied: fake.fail('unsafe_location')
        if policy.budget_exceeded: fake.fail('verification_budget_exceeded')
    except TimeoutError:
        fake.fail('verification_budget_exceeded')
    except (ValueError, TypeError, KeyError):
        fake.fail('verification_spec_invalid')
        execution = {'outcome': 'target_error', 'reply': None, 'reason': 'verification_spec_invalid', 'requests': {}, 'attempts': 0, 'cleanup': None}
    finally:
        if entered or fake.runner is not None:
            try:
                async with asyncio.timeout_at(deadline):
                    await fake.__aexit__(None, None, None)
            except TimeoutError:
                fake.fail('verification_budget_exceeded')
    return fake, execution


def _case_row(case, result):
    row = {'name': case.name, 'origin': case.origin, 'status': case.status, 'class': case.status_class,
           'expected': None, 'outcome': None, 'passed': None, 'checks': [], 'requests': {}}
    if result is None: return row
    requests = result.execution.get('requests') or {}
    return {**row, 'expected': case.scenario.outcome, 'outcome': result.execution.get('outcome'), 'passed': not result.checks,
            'checks': list(result.checks), 'requests': {key: requests[key] for key in ('submit', 'poll') if key in requests}}


def _case_check(case, result):
    if case.origin == 'scenario': return 'scenario_case_failed'
    if case.status_class == 'pending': return 'pending_status_unrecognised'
    return 'failure_status_succeeded' if result.execution.get('outcome') == 'succeeded' else 'failure_status_mismatch'


async def verify_local(spec, *, catalog=None, scenario: ScenarioV1 | None = None, gaps=()):
    if spec is None:
        return VerificationResult('not_run', 'not_run', False, False, (), {}, (), (), ())
    # The fake strips credentials and serves every origin itself, so neither can be verified here.
    unverified = (('auth_headers',) if spec['transport'].get('auth', {}).get('kind', 'none') != 'none' else ()) + ('server_origin',)
    if scenario is None:
        return replace(_assess(*await _attempt(spec, catalog, None), gaps), unverified=unverified)
    derived = document_cases(scenario, catalog)
    cases = scenario.cases + (derived or ())
    if derived is None: unverified += ('documented_status_cases',)
    if any(case.scenario is None for case in cases): unverified += ('status_meaning',)
    runnable = [case for case in cases if case.scenario is not None]
    attempts = await asyncio.gather(_attempt(spec, catalog, scenario), *(_attempt(spec, catalog, case.scenario) for case in runnable))
    main = _assess(*attempts[0], gaps)
    results = dict(zip((case.name for case in runnable), (_assess(*attempt, gaps) for attempt in attempts[1:])))
    failed = tuple(_case_check(case, results[case.name]) for case in runnable if results[case.name].checks)
    rows = tuple(_case_row(case, results.get(case.name)) for case in cases)
    if failed:
        main = replace(main, status='failed', semantic_success=False, cleanup_complete=False,
                       checks=tuple(dict.fromkeys(main.checks + failed)))
    return replace(main, cases=rows, unverified=unverified)
