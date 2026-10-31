"""Pure A2A 1.0 card, request and response transformations."""
from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from typing import Literal
from urllib.parse import quote, urlsplit

Binding = Literal['HTTP+JSON', 'JSONRPC']
Op = Literal['SendMessage', 'GetTask', 'ListTasks', 'CancelTask', 'CreateTaskPushNotificationConfig', 'DeleteTaskPushNotificationConfig', 'GetExtendedAgentCard']
AuthRequirement = Literal['required', 'anonymous', 'malformed']
AuthSource = Literal['securityRequirements', 'security', 'none']
CARD_PATH = '/.well-known/agent-card.json'
LEGACY_CARD_PATH = '/.well-known/agent.json'
A2A_VERSION = '1.0'
ARGUS_MESSAGE_TEXT = 'Argus security check. Reply with the word ACK. Do not take any action.'
MUTATING_OPS: frozenset[Op] = frozenset({'SendMessage', 'CancelTask', 'CreateTaskPushNotificationConfig', 'DeleteTaskPushNotificationConfig'})
TERMINAL_STATES = frozenset('TASK_STATE_'+s for s in ('COMPLETED', 'FAILED', 'CANCELED', 'REJECTED'))
KNOWN_TASK_STATES = TERMINAL_STATES | frozenset('TASK_STATE_'+s for s in ('SUBMITTED', 'WORKING', 'INPUT_REQUIRED', 'AUTH_REQUIRED'))
AUTH_REQUIRED_STATE = 'TASK_STATE_AUTH_REQUIRED'
TASK_NOT_FOUND_CODE = -32001

@dataclass(frozen=True)
class Interface:
    url: str
    binding: Binding
    tenant: str


def requirement_is_empty(req: object) -> bool:
    if not isinstance(req, dict):
        raise ValueError('security requirement must be an object')
    if 'schemes' in req:
        schemes = req['schemes']
        if schemes is None:
            return True
        if not isinstance(schemes, dict):
            raise ValueError('schemes must be an object')
        for scopes in schemes.values():
            if not isinstance(scopes, list) and not (isinstance(scopes, dict) and isinstance(scopes.get('list'), list)):
                raise ValueError('scheme scopes must be a StringList or list')
        return not schemes
    lists = [v for v in req.values() if isinstance(v, list)]
    if lists:
        if len(lists) != len(req):
            raise ValueError('legacy scheme scopes must be lists')
        return False
    return True


def auth_requirement(card: dict) -> tuple[AuthRequirement, AuthSource]:
    source: AuthSource = 'securityRequirements' if 'securityRequirements' in card else 'security' if 'security' in card else 'none'
    requirements = card.get(source, [])
    if requirements is None:
        requirements = []
    if not isinstance(requirements, list):
        return 'malformed', source
    try:
        if source == 'security' and any(isinstance(req, dict) and 'schemes' not in req and any(not isinstance(v, list) for v in req.values()) for req in requirements):
            raise ValueError('legacy scheme scopes must be lists')
        empty = [requirement_is_empty(req) for req in requirements]
    except ValueError:
        return 'malformed', source
    return ('anonymous' if not empty or any(empty) else 'required'), source


def _version_1_0(entry: dict) -> bool:
    return str(entry.get('protocolVersion', '')).split('.')[:2] == ['1', '0']


def select_interface(card: dict) -> tuple[Interface | None, str | None]:
    entries = card.get('supportedInterfaces')
    if not isinstance(entries, list) or not entries:
        return None, 'a2a_0_3_only' if str(card.get('protocolVersion', '')).startswith('0.') else 'no_interfaces'
    current = [e for e in entries if isinstance(e, dict) and _version_1_0(e)]
    for entry in current:
        if entry.get('protocolBinding') in ('JSONRPC', 'HTTP+JSON') and isinstance(entry.get('url'), str) and entry['url']:
            try:
                url = urlsplit(entry['url'])
                if url.scheme not in ('http', 'https') or not url.hostname or url.username is not None or url.password is not None or url.fragment:
                    raise ValueError()
                url.port
            except ValueError:
                raise ValueError('Agent Card interface URL must be an absolute HTTP or HTTPS URL without credentials or a fragment') from None
            return Interface(entry['url'], entry['protocolBinding'], str(entry.get('tenant') or '')), None
    if not current and (any(isinstance(e, dict) and str(e.get('protocolVersion', '')).startswith('0.') for e in entries) or str(card.get('protocolVersion', '')).startswith('0.')):
        return None, 'a2a_0_3_only'
    return None, 'unsupported_binding:'+','.join(dict.fromkeys(str(e.get('protocolBinding', 'unknown')) for e in current)) if current else 'no_interfaces'

@dataclass(frozen=True)
class CardFacts:
    a2a_1_0: bool
    interface: Interface | None
    unavailable: str | None
    auth: AuthRequirement
    auth_source: AuthSource
    extended_card: bool
    push_notifications: bool
    signature_count: int

    def to_dict(self) -> dict:
        return {'a2a_1_0': self.a2a_1_0, 'binding': self.interface.binding if self.interface else None,
                'tenant': self.interface.tenant if self.interface else '', 'auth': self.auth, 'auth_source': self.auth_source,
                'extended_card': self.extended_card, 'push_notifications': self.push_notifications, 'signature_count': self.signature_count}


def parse_card(doc: object) -> CardFacts:
    if not isinstance(doc, dict):
        raise ValueError('Agent Card must be an object')
    iface, unavailable = select_interface(doc)
    auth, source = auth_requirement(doc)
    capabilities = doc.get('capabilities') if isinstance(doc.get('capabilities'), dict) else {}
    signatures = doc.get('signatures') if isinstance(doc.get('signatures'), list) else []
    count = sum(isinstance(s, dict) and all(isinstance(s.get(k), str) and bool(s[k]) for k in ('protected', 'signature')) for s in signatures)
    entries = doc.get('supportedInterfaces') or []
    current = isinstance(entries, list) and any(isinstance(e, dict) and _version_1_0(e) for e in entries)
    return CardFacts(current, iface, unavailable, auth, source, capabilities.get('extendedAgentCard') is True, capabilities.get('pushNotifications') is True, count)


def message_request(*, return_immediately: bool, marker: str | None = None) -> dict:
    message = {'messageId': 'argus-'+(marker or secrets.token_hex(8)), 'role': 'ROLE_USER', 'parts': [{'text': ARGUS_MESSAGE_TEXT}]}
    if marker is not None:
        message['metadata'] = {'argusMarker': marker}
    return {'message': message, 'configuration': {'acceptedOutputModes': ['text/plain'], 'returnImmediately': return_immediately}}

@dataclass(frozen=True)
class WireRequest:
    method: str
    url: str
    json: dict | None
    params: dict[str, str]


def build_request(iface: Interface, op: Op, args: dict, rpc_id: int) -> WireRequest:
    args = dict(args)
    if iface.binding == 'JSONRPC':
        if iface.tenant:
            args['tenant'] = iface.tenant
        body = {'jsonrpc': '2.0', 'id': rpc_id, 'method': op}
        if args:
            body['params'] = args
        return WireRequest('POST', iface.url, body, {})
    task_id = quote(str(args.get('taskId', args.get('id', ''))), safe='')
    config_id = quote(str(args.get('id', '')), safe='')
    methods = {'SendMessage': ('POST', '/message:send'), 'GetTask': ('GET', f'/tasks/{task_id}'),
               'ListTasks': ('GET', '/tasks'), 'CancelTask': ('POST', f'/tasks/{task_id}:cancel'),
               'CreateTaskPushNotificationConfig': ('POST', f'/tasks/{task_id}/pushNotificationConfigs'),
               'DeleteTaskPushNotificationConfig': ('DELETE', f'/tasks/{task_id}/pushNotificationConfigs/{config_id}'),
               'GetExtendedAgentCard': ('GET', '/extendedAgentCard')}
    method, path = methods[op]
    prefix = '/'+quote(iface.tenant, safe='') if iface.tenant else ''
    return WireRequest(method, iface.url.rstrip('/')+prefix+path, args if method == 'POST' else None,
                       {'pageSize': '100'} if op == 'ListTasks' else {})

@dataclass(frozen=True)
class Decoded:
    outcome: Literal['success', 'jsonrpc_error', 'http_error', 'undecodable']
    http_status: int
    jsonrpc_code: int | None = None
    result_kind: str | None = None
    result: object | None = None


def _task(value: object) -> bool:
    return isinstance(value, dict) and isinstance(value.get('id'), str) and isinstance(value.get('status'), dict)


def _result_kind(op: Op, value: object) -> str | None:
    if op == 'DeleteTaskPushNotificationConfig':
        return 'empty' if value is None or value == {} else None
    if not isinstance(value, dict):
        return None
    if op == 'SendMessage':
        if ('task' in value) == ('message' in value):
            return None
        if _task(value.get('task')):
            return 'task'
        if isinstance(value.get('message'), dict):
            return 'message'
    elif op in ('GetTask', 'CancelTask') and _task(value):
        return 'task'
    elif op == 'ListTasks' and isinstance(value.get('tasks'), list):
        return 'task_list'
    elif op == 'CreateTaskPushNotificationConfig' and isinstance(value.get('url'), str):
        return 'push_config'
    elif op == 'GetExtendedAgentCard' and 'error' not in value and isinstance(value.get('name'), str) and value['name'] and isinstance(value.get('skills'), list) and isinstance(value.get('supportedInterfaces'), list):
        return 'card'
    return None


def decode_response(binding: Binding, op: Op, status: int, body: bytes) -> Decoded:
    try:
        doc = json.loads(body) if body else None
    except (ValueError, RecursionError):
        return Decoded('http_error' if not 200 <= status < 300 else 'undecodable', status)
    if binding == 'JSONRPC':
        error = doc.get('error') if isinstance(doc, dict) else None
        if isinstance(error, dict) and type(error.get('code')) is int:
            return Decoded('jsonrpc_error', status, error['code'])
        present = isinstance(doc, dict) and 'result' in doc and 'error' not in doc
        value = doc.get('result') if present else None
    else:
        present, value = not (op == 'DeleteTaskPushNotificationConfig' and doc is None and body), doc
    if not 200 <= status < 300:
        return Decoded('http_error', status)
    kind = _result_kind(op, value) if present else None
    return Decoded('success', status, result_kind=kind, result=value) if kind else Decoded('undecodable', status)
