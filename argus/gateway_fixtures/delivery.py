"""Passive marked results on current request-scoped delivery paths."""
import json
import secrets

import aiohttp.web as web

CURRENT_PATHS = ('inline_json', 'post_sse_final', 'post_sse_notification', 'progress_message')


def delivery(path):
    if not isinstance(path, str) or path not in CURRENT_PATHS:
        raise ValueError('unknown delivery path')
    marker = 'ARGUSFLT' + secrets.token_hex(10).upper()

    async def handle(context):
        message = context.message
        if context.route != 'mcp' or not isinstance(message, dict) or message.get('method') != 'tools/call':
            return None
        params = message.get('params', {})
        arguments = params.get('arguments', {})
        if (params.get('name') != 'argus_fixture_emit' or arguments.get('nonce') != context.nonce
                or arguments.get('path') != path):
            return None
        text = f'argus-path={path} begin {marker} end'
        result = {'jsonrpc': '2.0', 'id': message['id'],
                  'result': {'content': [{'type': 'text', 'text': text}], 'isError': False}}
        channel = 'post_json' if path == 'inline_json' else 'post_sse'
        if path == 'inline_json':
            response = web.json_response(result)
        else:
            frames = []
            if path == 'post_sse_notification':
                frames.append({'jsonrpc': '2.0', 'method': 'notifications/message',
                               'params': {'level': 'info', 'logger': 'argus-fixture', 'data': text}})
            elif path == 'progress_message':
                token = params.get('_meta', {}).get('progressToken')
                if token is None:
                    return None
                frames.append({'jsonrpc': '2.0', 'method': 'notifications/progress',
                               'params': {'progressToken': token, 'progress': 1, 'total': 1, 'message': text}})
            if frames:
                result['result']['content'][0]['text'] = 'argus-fixture:ok'
            frames.append(result)
            response = web.StreamResponse(headers={'Content-Type': 'text/event-stream'})
            await response.prepare(context.request)
            for frame in frames:
                await response.write(('event: message\ndata: ' + json.dumps(frame) + '\n\n').encode())
            await response.write_eof()
        served = {'path': path, 'served_by_upstream': True, 'upstream_channel': channel, 'marker': marker}
        context.ext['delivery'] = served
        context.state['delivery'] = served
        return response

    return handle
