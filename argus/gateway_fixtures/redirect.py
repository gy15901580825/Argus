"""Passive redirect destinations and strict per-case upstream redirects."""
import aiohttp.web as web

from .upstream import idle


def target(context):
    for entry, info in context.install['entries'].items():
        path = info['path'].replace('{path_token}', context.install['path_token']) + '/moved'
        if context.request.path == path:
            context.entry, context.route = entry, 'mcp'
            response = (web.json_response({'jsonrpc': '2.0', 'id': context.message.get('id') if isinstance(context.message, dict) else None,
                                           'error': {'code': -32000, 'message': 'Foreign redirect target'}})
                        if context.origin == 'foreign' else idle(context))
            context.route = 'redirect_target'
            return response
    return None


def redirect(config):
    if (not isinstance(config, dict) or set(config) != {'status', 'to', 'on'}
            or type(config['status']) is not int or config['status'] not in (307, 308)
            or config['to'] not in ('same_origin', 'foreign') or config['on'] != 'tools/call'):
        raise ValueError('invalid redirect configuration')

    async def handle(context):
        moved = target(context)
        if moved is not None:
            return moved
        if (context.route != 'mcp' or not isinstance(context.message, dict)
                or context.message.get('method') != config['on']
                or context.message.get('params', {}).get('arguments', {}).get('nonce') != context.nonce):
            return None
        origin = 'upstream' if config['to'] == 'same_origin' else 'foreign'
        path = context.install['entries'][context.entry]['path'].replace('{path_token}', context.install['path_token'])
        context.ext['redirect'] = dict(config)
        return web.Response(status=config['status'], headers={
            'Location': context.install['origins'][origin]['public'].rstrip('/') + path + '/moved'})

    return handle


def redirect_target(config):
    if config != {}:
        raise ValueError('redirect target has no configuration')

    async def handle(context):
        return target(context)

    return handle
