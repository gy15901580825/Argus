"""Passive marked results and notifications on bounded legacy streams."""
import asyncio
import json
import secrets

import aiohttp.web as web

from .record import REQUESTS_MAX

CURRENT_PATHS = ('inline_json', 'post_sse_final', 'post_sse_notification', 'progress_message')
LEGACY_PATHS = ('post_sse_resumed', 'get_stream_notification')


def delivery(path):
    if not isinstance(path, str) or path not in (*CURRENT_PATHS, *LEGACY_PATHS):
        raise ValueError('unknown delivery path')
    marker = 'ARGUSFLT' + secrets.token_hex(10).upper()

    pending, listeners = {}, {}

    def witness(context, channel, nonce):
        served = {'path': path, 'served_by_upstream': True, 'upstream_channel': channel,
                  'marker': marker, 'nonce': nonce}
        context.ext['delivery'] = served
        context.state['delivery'] = served

    async def handle(context):
        if context.route == 'mcp' and context.request.method == 'GET' and path in LEGACY_PATHS:
            cursor = context.request.headers.get('Last-Event-ID')
            key = (context.entry, context.request.headers.get('Mcp-Session-Id'))
            if path == 'post_sse_resumed':
                stored = pending.pop((key, cursor), None)
                if stored is None:
                    return web.Response(status=404)
                frame, nonce = stored
                channel = 'resumed_sse'
            else:
                if cursor or key in listeners:
                    return web.Response(status=405)
                if len(listeners) >= REQUESTS_MAX:
                    return web.Response(status=429)
                future = asyncio.get_running_loop().create_future()
                listeners[key] = future
                frame, nonce = None, None
                channel = 'get_sse'
            response = web.StreamResponse(headers={'Content-Type': 'text/event-stream'})
            await response.prepare(context.request)
            try:
                if frame is None:
                    try:
                        # A finite listener lets unrelated entries finish without a synthetic delivery.
                        frame, nonce = await asyncio.wait_for(future, timeout=1)
                    except TimeoutError:
                        await response.write_eof()
                        return response
                await response.write(('id: ' + secrets.token_hex(16) + '\nevent: message\ndata: '
                                      + json.dumps(frame) + '\n\n').encode())
                witness(context, channel, nonce)
                await response.write_eof()
            finally:
                if path == 'get_stream_notification':
                    listeners.pop(key, None)
            return response
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
        if path == 'post_sse_resumed':
            # Recording caps do not stop request handling, so pending streams need their own cap.
            if len(pending) >= REQUESTS_MAX:
                return web.Response(status=429)
            key = (context.entry, context.request.headers.get('Mcp-Session-Id'))
            cursor = secrets.token_hex(16)
            pending[(key, cursor)] = (result, context.nonce)
            response = web.StreamResponse(headers={'Content-Type': 'text/event-stream'})
            await response.prepare(context.request)
            await response.write(f'id: {cursor}\nretry: 100\ndata:\n\n'.encode())
            await response.write_eof()
            return response
        if path == 'get_stream_notification':
            key = (context.entry, context.request.headers.get('Mcp-Session-Id'))
            future = listeners.get(key)
            if future is not None and not future.done():
                future.set_result(({'jsonrpc': '2.0', 'method': 'notifications/message',
                                    'params': {'level': 'info', 'logger': 'argus-fixture', 'data': text}}, context.nonce))
            result['result']['content'][0]['text'] = 'argus-fixture:ok'
            return web.json_response(result)
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
        witness(context, channel, context.nonce)
        return response

    return handle
