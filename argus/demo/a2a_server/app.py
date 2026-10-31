"""Independent A2A 1.0 server fixtures without model or outbound calls."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Literal
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from argus.a2a.protocol import Binding, MUTATING_OPS, TASK_NOT_FOUND_CODE

Variant = Literal['naive', 'safe', 'message_ack', 'auth_required_state', 'optional_auth', 'jsonrpc_custom_code', 'shared_workspace', 'sync_complete', 'cancel_anomaly', 'no_extended_card', 'push_jsonrpc_error_200', 'no_push', 'message_only']
DEMO_TOKENS = {'primary': 'Bearer demo-alice', 'second': 'Bearer demo-bob'}
JSONRPC_CUSTOM_AUTH_CODE = -31001
JSONRPC_ONLY_VARIANTS = frozenset({'jsonrpc_custom_code', 'push_jsonrpc_error_200'})

@dataclass
class DemoLedger:
    state_changing: int = 0
    sent_texts: list[str] = field(default_factory=list)

_VARIANTS = {
    'naive': {'authenticate': False, 'isolate': False, 'reject_private': False, 'signed': False},
    'safe': {}, 'message_ack': {'authenticate': False, 'isolate': False, 'reject_private': False, 'signed': False, 'message_only': True},
    'auth_required_state': {'auth_required': True}, 'optional_auth': {'anonymous': True},
    'jsonrpc_custom_code': {'custom_auth': True}, 'shared_workspace': {'isolate': False},
    'sync_complete': {'sync_complete': True}, 'cancel_anomaly': {'cancel_anomaly': True},
    'no_extended_card': {'extended_card': False}, 'push_jsonrpc_error_200': {'push_error_200': True},
    'no_push': {'push': False}, 'message_only': {'message_only': True},
}


def _private(url: str) -> bool:
    host = (urlsplit(url).hostname or '').lower().rstrip('.')
    if host == 'localhost':
        return True
    try:
        addr = ipaddress.ip_address(host)
        return addr.is_loopback or addr.is_private or addr.is_link_local
    except ValueError:
        return False


def create_app(variant: Variant, binding: Binding, *, anonymous_requirement: dict | None = None) -> FastAPI:
    if variant not in _VARIANTS or binding not in ('JSONRPC', 'HTTP+JSON'):
        raise ValueError('unknown demo variant or binding')
    if variant in JSONRPC_ONLY_VARIANTS and binding == 'HTTP+JSON':
        raise ValueError('variant requires JSONRPC')
    flags = {'authenticate': True, 'isolate': True, 'reject_private': True, 'signed': True, 'extended_card': True, 'push': True, **_VARIANTS[variant]}
    app = FastAPI()
    app.state.ledger = DemoLedger()
    app.state.tasks = {}
    app.state.push_configs = {}
    owners = {}

    def card(request):
        doc = {'name': 'Argus A2A demo', 'skills': [], 'supportedInterfaces': [{'url': str(request.base_url).rstrip('/')+('/a2a/rpc' if binding == 'JSONRPC' else '/a2a/rest'), 'protocolBinding': binding, 'protocolVersion': '1.0'}],
               'capabilities': {'pushNotifications': flags['push'], 'extendedAgentCard': flags['extended_card']},
               'securityRequirements': [{'schemes': {'bearer': {'list': []}}}],
               'securitySchemes': {'bearer': {'httpAuthSecurityScheme': {'scheme': 'Bearer'}}}}
        if flags.get('anonymous'):
            doc['securityRequirements'].append(anonymous_requirement if anonymous_requirement is not None else {'schemes': {}})
        if flags['signed']:
            doc['signatures'] = [{'protected': 'eyJhbGciOiJFUzI1NiJ9', 'signature': 'ZGVtby1zaWduYXR1cmU'}]
        return doc

    @app.get('/.well-known/agent-card.json')
    async def public_card(request: Request):
        return card(request)

    def error(code, status, rpc_id):
        if binding == 'JSONRPC':
            return JSONResponse({'jsonrpc': '2.0', 'id': rpc_id, 'error': {'code': code, 'message': 'Request rejected'}}, status_code=status)
        return JSONResponse({'error': {'code': status, 'details': [{'@type': 'type.googleapis.com/google.rpc.ErrorInfo', 'reason': 'TASK_NOT_FOUND' if code == TASK_NOT_FOUND_CODE else 'REQUEST_REJECTED'}]}}, status_code=status)

    def success(result, rpc_id):
        return JSONResponse({'jsonrpc': '2.0', 'id': rpc_id, 'result': result} if binding == 'JSONRPC' else result)

    def new_task(args, owner, state=None):
        task_id = f'task-{len(app.state.tasks)+1}'
        task = {'id': task_id, 'status': {'state': state or ('TASK_STATE_COMPLETED' if flags.get('sync_complete') or not args.get('configuration', {}).get('returnImmediately', False) else 'TASK_STATE_WORKING')}, 'history': [args.get('message', {})]}
        app.state.tasks[task_id] = task
        owners[task_id] = owner
        return task

    async def dispatch(request, op, args, rpc_id=None):
        if op in MUTATING_OPS:
            app.state.ledger.state_changing += 1
        if op == 'SendMessage':
            app.state.ledger.sent_texts.extend(part.get('text', '') for part in args.get('message', {}).get('parts', []) if isinstance(part, dict) and 'text' in part)
        token = request.headers.get('authorization')
        authenticated = token in DEMO_TOKENS.values()
        if flags['authenticate'] and not authenticated:
            if op == 'SendMessage' and flags.get('auth_required'):
                return success({'task': new_task(args, token, 'TASK_STATE_AUTH_REQUIRED')}, rpc_id)
            if flags.get('custom_auth'):
                return error(JSONRPC_CUSTOM_AUTH_CODE, 200, rpc_id)
            return error(-31001, 401, rpc_id)
        if op == 'GetExtendedAgentCard':
            return success(card(request), rpc_id) if flags['extended_card'] else error(-32004, 400, rpc_id)
        if op == 'SendMessage':
            if flags.get('message_only'):
                return success({'message': {'messageId': 'demo-ack', 'role': 'ROLE_AGENT', 'parts': [{'text': 'ACK'}]}}, rpc_id)
            return success({'task': new_task(args, token)}, rpc_id)
        if op == 'ListTasks':
            return success({'tasks': [t for task_id, t in app.state.tasks.items() if not flags['isolate'] or owners[task_id] == token]}, rpc_id)
        task_id = args.get('taskId', args.get('id'))
        task = app.state.tasks.get(task_id)
        if task is None or (flags['isolate'] and owners[task_id] != token):
            if task is not None and op == 'CancelTask' and flags.get('cancel_anomaly'):
                task['status']['state'] = 'TASK_STATE_CANCELED'
            return error(TASK_NOT_FOUND_CODE, 200 if binding == 'JSONRPC' else 404, rpc_id)
        if op == 'GetTask':
            return success(task, rpc_id)
        if op == 'CancelTask':
            task['status']['state'] = 'TASK_STATE_CANCELED'
            return success(task, rpc_id)
        if op in ('CreateTaskPushNotificationConfig', 'DeleteTaskPushNotificationConfig'):
            if not flags['push']:
                return error(-32003, 400, rpc_id)
            if op == 'CreateTaskPushNotificationConfig':
                if flags['reject_private'] and _private(args.get('url', '')):
                    return error(-32602, 200 if flags.get('push_error_200') else 400, rpc_id)
                config_id = args.get('id') or f'config-{len(app.state.push_configs)+1}'
                config = {**args, 'id': config_id}
                app.state.push_configs[(task_id, config_id)] = config
                return success(config, rpc_id)
            app.state.push_configs.pop((task_id, args.get('id')), None)
            return success({}, rpc_id)
        return error(-32601, 400, rpc_id)

    if binding == 'JSONRPC':
        @app.post('/a2a/rpc')
        async def rpc(request: Request):
            body = await request.json()
            return await dispatch(request, body.get('method'), body.get('params') or {}, body.get('id'))
    else:
        @app.post('/a2a/rest/message:send')
        async def send(request: Request):
            return await dispatch(request, 'SendMessage', await request.json())
        @app.get('/a2a/rest/extendedAgentCard')
        async def extended(request: Request):
            return await dispatch(request, 'GetExtendedAgentCard', {})
        @app.get('/a2a/rest/tasks')
        async def list_tasks(request: Request):
            return await dispatch(request, 'ListTasks', {})
        @app.get('/a2a/rest/tasks/{task_id}')
        async def get_task(task_id: str, request: Request):
            return await dispatch(request, 'GetTask', {'id': task_id})
        @app.post('/a2a/rest/tasks/{task_id}:cancel')
        async def cancel(task_id: str, request: Request):
            return await dispatch(request, 'CancelTask', {'id': task_id})
        @app.post('/a2a/rest/tasks/{task_id}/pushNotificationConfigs')
        async def create_push(task_id: str, request: Request):
            return await dispatch(request, 'CreateTaskPushNotificationConfig', {**await request.json(), 'taskId': task_id})
        @app.delete('/a2a/rest/tasks/{task_id}/pushNotificationConfigs/{config_id}')
        async def delete_push(task_id: str, config_id: str, request: Request):
            return await dispatch(request, 'DeleteTaskPushNotificationConfig', {'taskId': task_id, 'id': config_id})
    return app
