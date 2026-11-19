"""Case behaviors used only to exercise the reference proxy."""
import json

from aiohttp import web


def behavior(config):
    async def handle(context):
        message = context.message or {}
        if context.request.path == context.install['webhook']['path'].replace('{path_token}', context.install['path_token']):
            context.route = 'webhook'
            body = config.get('hook_body', {'decision': 'allow'})
            return web.Response(status=config.get('hook_status', 200), body=b'' if body is None else json.dumps(body).encode(), content_type='application/json')
        if context.origin == 'foreign':
            context.route = 'redirect_target'
            return web.json_response({'jsonrpc': '2.0', 'id': message.get('id'), 'result': {'content': []}})
        if context.request.method == 'GET':
            mode = 'resumed_sse' if context.request.headers.get('Last-Event-ID') else 'get_sse'
        elif message.get('method') == 'tools/call' and message.get('params', {}).get('arguments', {}).get('nonce') == context.nonce:
            mode = config.get('delivery')
            if config.get('redirect') and context.route == 'mcp':
                return web.Response(status=config.get('redirect_status', 307), headers={'Location': config['redirect']})
        else:
            return None
        if mode is None or 'receipt' in message.get('params', {}).get('arguments', {}):
            return None
        context.state.setdefault('served', []).append(mode)
        text = 'argus-path=' + mode + ' begin ' + config['marker'] + ' end'
        result = {'jsonrpc': '2.0', 'id': message.get('id'), 'result': {'content': [{'type': 'text', 'text': text}]}}
        if mode == 'post_json':
            return web.json_response(result)
        if mode == 'priming':
            events = ['id: event-1\nretry: 100\ndata: {}\n\n']
        else:
            if mode in ('post_notification', 'get_sse'):
                payload = {'jsonrpc': '2.0', 'method': 'notifications/message', 'params': {'data': text}}
            elif mode == 'progress':
                payload = {'jsonrpc': '2.0', 'method': 'notifications/progress', 'params': {'progressToken': 'p', 'progress': 1, 'message': text}}
            else:
                payload = result
            events = ['id: event-1\nevent: message\ndata: ' + json.dumps(payload) + '\n\n']
            if mode in ('post_notification', 'progress'):
                events.append('data: ' + json.dumps({'jsonrpc': '2.0', 'id': message.get('id'), 'result': {'content': []}}) + '\n\n')
        response = web.StreamResponse(headers={'Content-Type': 'text/event-stream'})
        await response.prepare(context.request)
        for event in events:
            # Exercise incremental SSE parsing rather than buffering one whole response.
            cut = len(event) // 2
            await response.write(event[:cut].encode())
            await response.write(event[cut:].encode())
        await response.write_eof()
        return response
    return handle
