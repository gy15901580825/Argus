"""Harmless dual-era MCP responses; tool descriptions survive gateway renaming."""
from __future__ import annotations

import aiohttp.web as web

from .protocol import LEGACY_ERAS as ERAS, PREFIX, SUPPORTED_ERAS, is_modern



def idle(context) -> web.Response:
    if context.route != 'mcp':
        return web.json_response({'error': 'not_found'}, status=404)
    if context.request.method != 'POST':
        return web.Response(status=405, headers={'Allow': 'POST'})
    message = context.message
    if not isinstance(message, dict) or message.get('jsonrpc') != '2.0':
        return web.json_response({'jsonrpc': '2.0', 'id': None, 'error': {'code': -32600, 'message': 'Invalid request'}}, status=400)
    request_id = message.get('id')
    if 'id' not in message:
        return web.Response(status=202)
    method, params = message.get('method'), message.get('params', {})
    if not isinstance(params, dict):
        return _error(request_id, -32602, 'Invalid params')
    if method == 'server/discover':
        result = {'supportedVersions': list(SUPPORTED_ERAS), 'capabilities': {'tools': {}}}
    elif method == 'initialize':
        if is_modern(message, context.request.headers):
            return _error(request_id, -32601, 'Method not found', status=404)
        era = params.get('protocolVersion')
        result = {'protocolVersion': era if era in ERAS else ERAS[0], 'capabilities': {'tools': {}},
                  'serverInfo': {'name': 'argus-fixture', 'version': '1'}}
    elif method == 'tools/list':
        description = f"argus-fixture:{context.install['install_label']}:{context.entry}"
        tools = []
        for name in ('echo', 'emit'):
            properties = {'nonce': {'type': 'string'}}
            if name == 'emit':
                properties['path'] = {'type': 'string'}
            tools.append({'name': 'argus_fixture_' + name, 'description': description + ' ' + name,
                          'inputSchema': {'type': 'object', 'properties': properties, 'required': ['nonce']}})
        result = {'tools': tools}
    elif method == 'tools/call':
        if params.get('name') not in ('argus_fixture_echo', 'argus_fixture_emit'):
            return _error(request_id, -32602, 'Unknown tool')
        arguments = params.get('arguments', {})
        if not isinstance(arguments, dict) or not isinstance(arguments.get('nonce'), str):
            return _error(request_id, -32602, 'Invalid params')
        # Never echo arbitrary arguments or gateway credentials, even while idle.
        result = {'content': [{'type': 'text', 'text': 'argus-fixture:ok'}], 'isError': False}
    elif method == 'ping':
        result = {}
    else:
        return _error(request_id, -32601, 'Method not found')
    if is_modern(message, context.request.headers):
        result.update({'resultType': 'complete',
                       '_meta': {PREFIX + 'serverInfo': {'name': 'argus-fixture', 'version': '1'}}})
    return web.json_response({'jsonrpc': '2.0', 'id': request_id, 'result': result})


def _error(request_id, code: int, message: str, *, status=200) -> web.Response:
    return web.json_response({'jsonrpc': '2.0', 'id': request_id, 'error': {'code': code, 'message': message}}, status=status)
