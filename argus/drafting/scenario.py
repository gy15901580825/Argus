from __future__ import annotations

import json
import math
import re
import stat
from dataclasses import dataclass, replace
from pathlib import Path
from urllib.parse import urlsplit

from argus.drafting.draft import STATUS_WORDS
from argus.drafting.openapi import OperationCatalog
from argus_transport.models import path as transport_path
from argus_transport.spec_v2 import ENV_NAME_RE, SECRET_WORDS


MAX_SCENARIO_BYTES = 256 * 1024
MAX_BODY_BYTES = 64 * 1024
MAX_REQUESTS = 64
MAX_DEPTH = 16
MAX_CASES = 8
MAX_DOCUMENTED_STATUSES = 32
OUTCOMES = frozenset({'succeeded', 'blocked', 'target_error', 'stopped'})
STATES = frozenset({'absent', 'live', 'paused'})
ROLES = frozenset({'invoke', 'poll', 'upload', 'setup', 'delete', 'confirm', 'pause'})
CHECKS = {'prompt_bound': 'prompt_not_bound', 'material_bound': 'material_not_bound',
          'poll_identity': 'poll_identity_changed', 'resource_identity': 'material_not_bound'}


@dataclass(frozen=True)
class Selector:
    kind: str
    pointer: str = ''
    name: str = ''
    filename: str = ''


@dataclass(frozen=True)
class RequestCheck:
    check: str
    at: Selector
    equals: object


@dataclass(frozen=True)
class Effect:
    resource: str
    before: str
    after: str


@dataclass(frozen=True)
class Reply:
    status: int
    body: object
    effects: tuple[Effect, ...]
    headers: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class ScenarioOperation:
    id: str
    method: str
    path: str
    role: str
    minimum: int
    maximum: int
    request: tuple[RequestCheck, ...]
    replies: tuple[Reply, ...]


@dataclass(frozen=True)
class Resource:
    id: str
    initial: str
    cleanup: str
    final: str


@dataclass(frozen=True)
class ScenarioV1:
    source: dict
    operations: tuple[ScenarioOperation, ...]
    resources: tuple[Resource, ...]
    outcome: str
    reply: str | None
    required_gaps: tuple[str, ...]
    environment: tuple[tuple[str, str], ...] = ()
    cases: tuple[OutcomeCase, ...] = ()


@dataclass(frozen=True)
class OutcomeCase:
    """Another fixed reply sequence and the outcome it must end in.

    Declared cases come from the scenario author and derived cases from the poll's documented status enum.
    `scenario` is None when the oracle cannot know what a documented value means."""
    name: str
    origin: str
    scenario: ScenarioV1 | None
    status: str | None = None
    status_class: str | None = None


def invalid(message):
    raise ValueError(f'scenario_invalid: {message}')


def _object(value, keys):
    if not isinstance(value, dict) or set(value) != set(keys):
        invalid('object has missing or unknown fields')
    return value


def _text(value, *, limit=256):
    if not isinstance(value, str) or not value or len(value.encode('utf-8')) > limit or any(ord(c) < 32 for c in value):
        invalid('expected bounded text')
    return value


def _name(value):
    if not isinstance(value, str) or not re.fullmatch(r'[a-z][a-z0-9_]{0,63}', value):
        invalid('invalid internal name')
    return value


def _list(value, maximum):
    if not isinstance(value, list) or len(value) > maximum:
        invalid('list limit exceeded')
    return value


def _integer(value, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        invalid('integer limit exceeded')
    return value


def _structure(value, depth=0):
    if depth > MAX_DEPTH:
        invalid('nesting limit exceeded')
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str): invalid('non-string key')
            _structure(item, depth + 1)
    elif isinstance(value, list):
        for item in value: _structure(item, depth + 1)
    elif isinstance(value, str):
        if len(value.encode('utf-8')) > MAX_BODY_BYTES: invalid('literal limit exceeded')
    elif value is not None and type(value) not in {bool, int, float}:
        invalid('non-JSON value')
    elif isinstance(value, float) and not math.isfinite(value):
        invalid('non-finite number')


def path_pattern(path):
    _text(path, limit=2048)
    if not path.startswith('/') or any(c in path for c in '\\?#%') or '//' in path or any(p in {'.', '..'} for p in path.split('/')):
        invalid('invalid route path')
    parts = re.split(r'(\{[^{}]*\})', path)
    names = []
    expression = ''
    for part in parts:
        if part.startswith('{') and part.endswith('}'):
            name = part[1:-1]
            # One rule with transport bracket paths, so a poll ID field a draft reads can name its route parameter.
            try:
                transport_path(f"$['{name}']")
            except ValueError:
                invalid('invalid path parameter')
            if name in names: invalid('invalid path parameter')
            names.append(name)
            expression += '([^/]+)'
        else:
            if '{' in part or '}' in part: invalid('invalid path template')
            expression += re.escape(part)
    return re.compile(expression), tuple(names)


def _selector(value):
    if not isinstance(value, dict): invalid('invalid selector')
    kind = value.get('kind')
    fields = {'json': {'kind', 'pointer'}, 'query': {'kind', 'name'}, 'path': {'kind', 'name'},
              'multipart_text': {'kind', 'name'}, 'multipart_file': {'kind', 'name', 'filename'},
              'raw_utf8': {'kind'}}
    if not isinstance(kind, str) or kind not in fields: invalid('unknown selector kind')
    _object(value, fields[kind])
    if kind == 'json':
        pointer = value['pointer']
        if not isinstance(pointer, str) or (pointer and not pointer.startswith('/')) or re.search(r'~(?![01])', pointer) or len(pointer) > 2048:
            invalid('invalid JSON pointer')
        return Selector(kind, pointer=pointer)
    if kind == 'raw_utf8': return Selector(kind)
    name = _text(value['name'], limit=128)
    filename = _text(value['filename']) if kind == 'multipart_file' else ''
    return Selector(kind, name=name, filename=filename)


def _calls(value):
    calls = _object(value, {'min', 'max'})
    minimum = _integer(calls['min'], 0, MAX_REQUESTS)
    maximum = _integer(calls['max'], 1, MAX_REQUESTS)
    if minimum > maximum: invalid('invalid call range')
    return minimum, maximum


def _replies(values, finals, maximum):
    replies = []
    for item in _list(values, 64):
        if not isinstance(item, dict) or not {'status', 'body', 'effects'} <= set(item) or set(item) - {'status', 'body', 'effects', 'headers'}:
            invalid('reply has missing or unknown fields')
        status = _integer(item['status'], 100, 599)
        if len(json.dumps(item['body'], allow_nan=False).encode('utf-8')) > MAX_BODY_BYTES: invalid('response byte limit exceeded')
        effects = []
        for effect in _list(item['effects'], 32):
            _object(effect, {'resource', 'from', 'to'})
            if not isinstance(effect['resource'], str) or effect['resource'] not in finals or not isinstance(effect['from'], str) or effect['from'] not in STATES or not isinstance(effect['to'], str) or effect['to'] not in STATES: invalid('invalid resource effect')
            effects.append(Effect(effect['resource'], effect['from'], effect['to']))
        headers = item.get('headers', {})
        if not isinstance(headers, dict) or len(headers) > 2: invalid('invalid response headers')
        names = set()
        admitted_headers = []
        for name, header_value in headers.items():
            canonical = name.lower() if isinstance(name, str) else ''
            if canonical not in {'location', 'retry-after'} or canonical in names: invalid('unknown or duplicate response header')
            names.add(canonical)
            _text(header_value, limit=2048)
            if canonical == 'location':
                parsed = urlsplit(header_value)
                if not header_value.startswith('/') or header_value.startswith('//') or parsed.scheme or parsed.netloc or parsed.fragment or any(c in header_value for c in '\\{}'):
                    invalid('Location must be a fixed relative path')
            elif not re.fullmatch(r'0|[1-9]|10', header_value):
                invalid('Retry-After must be an integer from zero to ten')
            admitted_headers.append(('Location' if canonical == 'location' else 'Retry-After', header_value))
        replies.append(Reply(status, item['body'], tuple(effects), tuple(admitted_headers)))
    if not replies or len(replies) < maximum: invalid('finite replies must cover maximum calls')
    return tuple(replies)


def _expected(value, keys):
    expected = _object(value, keys)
    if not isinstance(expected['outcome'], str) or expected['outcome'] not in OUTCOMES: invalid('invalid expected outcome')
    if expected['reply'] is not None: _text(expected['reply'], limit=MAX_BODY_BYTES)
    if expected['outcome'] == 'succeeded' and expected['reply'] is None: invalid('success requires an independent reply')
    return expected


def _sequence_limits(operations):
    if not operations or not any(op.role == 'invoke' and op.minimum > 0 for op in operations): invalid('missing required invoke')
    if sum(op.maximum for op in operations) > MAX_REQUESTS or sum(len(op.replies) for op in operations) > 64:
        invalid('request or reply limit exceeded')


def _case(value, main, finals):
    _object(value, {'name', 'operations', 'expect'})
    name = _name(value['name'])
    overrides = value['operations']
    if not isinstance(overrides, dict) or not overrides: invalid('case must replace at least one operation')
    known = {op.id for op in main.operations}
    if set(overrides) - known: invalid('case names an unknown operation')
    operations = []
    for op in main.operations:
        if op.id in overrides:
            item = _object(overrides[op.id], {'calls', 'replies'})
            minimum, maximum = _calls(item['calls'])
            op = replace(op, minimum=minimum, maximum=maximum, replies=_replies(item['replies'], finals, maximum))
        operations.append(op)
    _sequence_limits(operations)
    expected = _expected(value['expect'], {'outcome', 'reply'})
    return OutcomeCase(name, 'scenario', replace(main, operations=tuple(operations), outcome=expected['outcome'], reply=expected['reply']))


def parse_scenario(data, *, catalog: OperationCatalog | None = None) -> ScenarioV1:
    _structure(data)
    try:
        if len(json.dumps(data, allow_nan=False).encode('utf-8')) > MAX_SCENARIO_BYTES:
            invalid('byte limit exceeded')
    except (TypeError, ValueError, RecursionError):
        invalid('invalid JSON structure')
    if not isinstance(data, dict) or type(data.get('version')) is not int or data['version'] not in {1, 2, 3}: invalid('unsupported version')
    _object(data, {'version', 'source', 'resources', 'operations', 'expect'}
            | ({'environment'} if data['version'] >= 2 else set()) | ({'cases'} if data['version'] == 3 else set()))
    environment = ()
    if data['version'] >= 2:
        values = data['environment']
        if not isinstance(values, dict) or len(values) > 32: invalid('invalid synthetic environment')
        for name, value in values.items():
            # Synthetic values stand in for non-secret draft inputs only; credentials stay unresolved.
            if not ENV_NAME_RE.fullmatch(name) or not re.fullmatch(r'TARGET_INPUT_[A-Z0-9_]+', name) or any(word in name.lower() for word in SECRET_WORDS):
                invalid('synthetic environment admits only non-secret TARGET_INPUT names')
            _text(value, limit=1024)
        environment = tuple(values.items())
    source = _object(data['source'], {'document', 'pointers'})
    _text(source['document'], limit=2048)
    for pointer in _list(source['pointers'], 64): _text(pointer, limit=2048)
    expected = _expected(data['expect'], {'outcome', 'reply', 'resources', 'required_gaps'})
    required_gaps = tuple(_text(x) for x in _list(expected['required_gaps'], 32))
    if len(set(required_gaps)) != len(required_gaps): invalid('duplicate required gap')
    finals = {}
    for value in _list(expected['resources'], 32):
        _object(value, {'id', 'final'})
        name = _name(value['id'])
        if name in finals or not isinstance(value['final'], str) or value['final'] not in STATES: invalid('invalid final resource state')
        finals[name] = value['final']
    resources = []
    for value in _list(data['resources'], 32):
        _object(value, {'id', 'initial', 'cleanup'})
        name = _name(value['id'])
        if name in {r.id for r in resources} or name not in finals: invalid('resource identity mismatch')
        if not isinstance(value['initial'], str) or value['initial'] not in STATES or not isinstance(value['cleanup'], str) or value['cleanup'] not in {'delete', 'pause', 'documented_no_delete'}: invalid('invalid resource state or cleanup')
        if value['cleanup'] == 'delete' and finals[name] != 'absent': invalid('delete expectation must be absent')
        if value['cleanup'] == 'documented_no_delete' and not required_gaps: invalid('no-delete requires explicit gap')
        resources.append(Resource(name, value['initial'], value['cleanup'], finals[name]))
    if set(finals) != {r.id for r in resources}: invalid('resource identity mismatch')
    operations = []
    admitted = {op.id: op for op in catalog.operations} if catalog is not None else None
    signatures = set()
    for value in _list(data['operations'], 32):
        _object(value, {'id', 'method', 'path', 'role', 'calls', 'request', 'replies'})
        id = _text(value['id'])
        if id in {op.id for op in operations}: invalid('duplicate operation ID')
        method = value['method']
        if not isinstance(method, str) or method not in {'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'}: invalid('invalid method')
        pattern, names = path_pattern(value['path'])
        signature = (method, re.sub(r'\{[^{}]+\}', '{}', value['path']))
        if signature in signatures: invalid('ambiguous route')
        signatures.add(signature)
        if admitted is not None:
            op = admitted.get(id)
            if op is None or op.method.upper() != method or op.path != value['path']:
                invalid('operation does not match independent catalog')
        if not isinstance(value['role'], str) or value['role'] not in ROLES: invalid('invalid operation role')
        minimum, maximum = _calls(value['calls'])
        checks = []
        for item in _list(value['request'], 32):
            _object(item, {'check', 'at', 'equals'})
            if not isinstance(item['check'], str) or item['check'] not in CHECKS: invalid('invalid check kind')
            if type(item['equals']) not in {str, bool, int, float, type(None)}: invalid('equals must be a literal scalar')
            at = _selector(item['at'])
            if at.kind == 'path' and at.name not in names: invalid('unknown path field')
            if item['check'] == 'prompt_bound' and item['equals'] != 'ping': invalid('prompt oracle must use ping')
            if item['check'] == 'material_bound' and item['equals'] != 'Argus validation sample.': invalid('material oracle must use sample')
            checks.append(RequestCheck(item['check'], at, item['equals']))
        if value['role'] == 'invoke' and not any(c.check == 'prompt_bound' for c in checks): invalid('invoke requires prompt check')
        if value['role'] == 'poll' and set(names) != {c.at.name for c in checks if c.check == 'poll_identity' and c.at.kind == 'path'}:
            invalid('poll identities require independent checks')
        if value['role'] == 'upload' and not any(c.check == 'material_bound' for c in checks): invalid('upload requires material check')
        replies = _replies(value['replies'], finals, maximum)
        operations.append(ScenarioOperation(id, method, value['path'], value['role'], minimum, maximum, tuple(checks), replies))
    _sequence_limits(operations)
    if any(op.role == 'upload' for op in operations) and not any(c.check == 'resource_identity' for op in operations if op.role == 'invoke' for c in op.request):
        invalid('upload requires invoke reference check')
    main = ScenarioV1(source, tuple(operations), tuple(resources), expected['outcome'], expected['reply'], required_gaps, environment)
    cases = []
    for value in _list(data.get('cases', []), MAX_CASES):
        case = _case(value, main, finals)
        if case.name in {c.name for c in cases}: invalid('duplicate case name')
        cases.append(case)
    return replace(main, cases=tuple(cases))


def document_cases(scenario: ScenarioV1, catalog: OperationCatalog | None) -> tuple[OutcomeCase, ...] | None:
    """One case per other value of the documented status enum in the scenario's terminal poll reply.

    A failed value replaces the terminal reply's status and must end as target_error. A pending value is inserted,
    without effects, before the terminal reply and must not change the scenario's outcome. None means no single
    documented status applies, so nothing was derived."""
    polls = [op for op in scenario.operations if op.role == 'poll']
    if catalog is None or scenario.outcome != 'succeeded' or len(polls) != 1 or polls[0].minimum != polls[0].maximum:
        return None
    poll = polls[0]
    index = poll.maximum - 1
    terminal = poll.replies[index]
    documented = next((op for op in catalog.operations if op.id == poll.id), None)
    response = documented.data.get('responses', {}).get(str(terminal.status)) if documented else None
    content = response.get('content') if isinstance(response, dict) else None
    schema = content.get('application/json', {}).get('schema') if isinstance(content, dict) else None
    properties = schema.get('properties') if isinstance(schema, dict) else None
    if not isinstance(properties, dict) or not isinstance(terminal.body, dict):
        return None
    fields = [(name, field['enum']) for name, field in properties.items()
              if isinstance(field, dict) and isinstance(field.get('enum'), list) and all(isinstance(v, str) for v in field['enum'])
              and terminal.body.get(name) in field['enum']]
    if len(fields) != 1:
        return None
    name, values = fields[0]
    others = [value for value in dict.fromkeys(values) if value != terminal.body[name]]
    if len(others) > MAX_DOCUMENTED_STATUSES:
        return None
    cases = []
    for value in others:
        kind = STATUS_WORDS.get(value.lower())
        swapped = replace(terminal, body={**terminal.body, name: value})
        if kind == 'pending':
            replies = poll.replies[:index] + (replace(swapped, effects=()), terminal)
            variant = replace(scenario, cases=())
        elif kind == 'failed':
            replies = poll.replies[:index] + (swapped,)
            variant = replace(scenario, outcome='target_error', reply=None, cases=())
        else:
            cases.append(OutcomeCase(f'status:{value}', 'document', None, value, 'unclassified'))
            continue
        operations = tuple(replace(op, minimum=len(replies), maximum=len(replies), replies=replies) if op is poll else op
                           for op in scenario.operations)
        cases.append(OutcomeCase(f'status:{value}', 'document', replace(variant, operations=operations), value, kind))
    return tuple(cases)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result: invalid('duplicate JSON key')
        result[key] = value
    return result


def read_scenario(path: Path, *, catalog=None):
    path = Path(path)
    if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode) or path.stat().st_size > MAX_SCENARIO_BYTES:
        invalid('input must be a bounded regular JSON file')
    with path.open('rb') as handle:
        raw = handle.read(MAX_SCENARIO_BYTES + 1)
    if len(raw) > MAX_SCENARIO_BYTES: invalid('byte limit exceeded')
    try:
        data = json.loads(raw, object_pairs_hook=_unique)
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        invalid('cannot parse JSON')
    return parse_scenario(data, catalog=catalog)
