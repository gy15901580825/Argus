"""Per-request version metadata and its Streamable HTTP header mirrors."""
import base64
import binascii

import aiohttp.web as web

MODERN = '2026-07-28'
LEGACY_ERAS = ('2025-11-25', '2025-06-18')
SUPPORTED_ERAS = (MODERN, *LEGACY_ERAS)
PREFIX = 'io.modelcontextprotocol/'
MODERN_ERRORS = frozenset((-32020, -32021, -32022))


def metadata(version=MODERN):
    return {PREFIX + 'protocolVersion': version,
            PREFIX + 'clientInfo': {'name': 'argus-probe', 'version': '1'},
            PREFIX + 'clientCapabilities': {'elicitation': {'form': {}}}}


def header_value(value):
    if (value != value.strip() or any(ord(c) < 32 and c != '\t' or ord(c) > 126 for c in value)
            or value.startswith('=?base64?') and value.endswith('?=')):
        return '=?base64?' + base64.b64encode(value.encode()).decode() + '?='
    return value


def decode_header(value):
    if value.startswith('=?base64?') and value.endswith('?='):
        try:
            return base64.b64decode(value[9:-2], validate=True).decode()
        except (ValueError, UnicodeError, binascii.Error):
            return None
    return value


def mirrored_headers(message):
    params = message.get('params', {})
    headers = {'MCP-Protocol-Version': params['_meta'][PREFIX + 'protocolVersion'],
               'Mcp-Method': message['method']}
    if message['method'] in ('tools/call', 'prompts/get', 'resources/read'):
        headers['Mcp-Name'] = header_value(params.get('name', params.get('uri', '')))
    return headers


def is_modern(message, headers):
    params = message.get('params', {}) if isinstance(message, dict) else {}
    meta = params.get('_meta', {}) if isinstance(params, dict) else {}
    return (isinstance(meta, dict) and PREFIX + 'protocolVersion' in meta
            or headers.get('MCP-Protocol-Version') == MODERN)


def error(request_id, code, message, *, data=None, status=400):
    value = {'code': code, 'message': message}
    if data is not None:
        value['data'] = data
    return web.json_response({'jsonrpc': '2.0', 'id': request_id, 'error': value}, status=status)


def validate(message, headers, supported=SUPPORTED_ERAS):
    if not isinstance(message, dict) or message.get('jsonrpc') != '2.0' or not isinstance(message.get('method'), str):
        return error(None, -32600, 'Invalid request')
    request_id = message.get('id')
    params = message.get('params', {})
    meta = params.get('_meta') if isinstance(params, dict) else None
    if (not isinstance(meta, dict) or not isinstance(meta.get(PREFIX + 'protocolVersion'), str)
            or not isinstance(meta.get(PREFIX + 'clientCapabilities'), dict)):
        return error(request_id, -32602, 'Missing required request metadata')
    version = meta[PREFIX + 'protocolVersion']
    required = {'MCP-Protocol-Version': version, 'Mcp-Method': message['method']}
    if message['method'] in ('tools/call', 'prompts/get', 'resources/read'):
        source = params.get('uri') if message['method'] == 'resources/read' else params.get('name')
        if not isinstance(source, str):
            return error(request_id, -32602, 'Invalid params')
        required['Mcp-Name'] = source
    for name, expected in required.items():
        actual = headers.get(name)
        if name == 'Mcp-Name' and actual is not None:
            actual = decode_header(actual)
        if actual != expected:
            return error(request_id, -32020, 'Header mismatch')
    if version not in supported:
        return error(request_id, -32022, 'Unsupported protocol version',
                     data={'supported': list(supported), 'requested': version})
    return None
