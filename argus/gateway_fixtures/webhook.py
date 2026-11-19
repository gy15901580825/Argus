"""Passive pre-call decisions; webhook identity payloads stay out of evidence."""
from __future__ import annotations

import copy
import json

import aiohttp.web as web

DEFAULT_CONTRACT = {'allow': {'status': 200, 'body': {'decision': 'allow'}},
                    'deny': {'status': 200, 'body': {'decision': 'deny'}}}


def resolve_decision(config, contract):
    if not isinstance(config, dict) or config.keys() - {'status', 'body', 'documented', 'responses'}:
        raise ValueError('invalid webhook decision')
    if 'responses' in config:
        if config.keys() != {'responses'} or not isinstance(config['responses'], list) or not 1 <= len(config['responses']) <= 20:
            raise ValueError('invalid webhook response sequence')
        if any(not isinstance(item, dict) or 'responses' in item for item in config['responses']):
            raise ValueError('nested webhook response sequences are invalid')
        return {'responses': [resolve_decision(item, contract) for item in config['responses']]}
    if 'documented' in config:
        if config['documented'] not in ('allow', 'deny', 'deny_2xx') or 'body' in config:
            raise ValueError('invalid documented webhook decision')
        name = 'deny' if config['documented'] == 'deny_2xx' else config['documented']
        response = copy.deepcopy(contract[name])
        if config['documented'] == 'deny_2xx' and not 200 <= response['status'] < 300:
            response['status'] = 200
        response['status'] = config.get('status', response['status'])
    else:
        if 'status' not in config:
            raise ValueError('webhook status required')
        response = {'status': config['status'], 'body': config.get('body')}
    if type(response['status']) is not int or not 200 <= response['status'] <= 599:
        raise ValueError('invalid webhook status')
    encoded = json.dumps(response['body'], allow_nan=False).encode()
    if len(encoded) > 65536:
        raise ValueError('webhook body too large')
    return response


def decision(config):
    resolved = resolve_decision(config, DEFAULT_CONTRACT)
    responses = resolved.get('responses', [resolved])
    index = 0

    async def handle(context):
        nonlocal index
        if context.route != 'webhook':
            return None
        correlated = context.nonce is not None and context.nonce.encode() in context.body
        response = responses[min(index, len(responses) - 1)]
        if correlated:
            index += 1
        context.ext['webhook'] = {'nonce_correlated': correlated}
        return web.Response(status=response['status'], content_type='application/json',
                            body=b'' if response['body'] is None else json.dumps(response['body']).encode())

    return handle


async def idle(context):
    if context.route != 'webhook':
        return None
    return web.json_response(DEFAULT_CONTRACT['allow']['body'])
