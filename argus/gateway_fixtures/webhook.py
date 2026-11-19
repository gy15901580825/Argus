"""Passive pre-call decisions; webhook identity payloads stay out of evidence."""
from __future__ import annotations

import copy
import json

import aiohttp.web as web

DEFAULT_CONTRACT = {'allow': {'status': 200, 'body': {'decision': 'allow'}},
                    'deny': {'status': 200, 'body': {'decision': 'deny'}}}


class NoDocumentedDeny(ValueError):
    """The documented contract has no 2xx denial to exercise."""


def status_sets(contract):
    allow = set(contract['allow'].get('statuses', [contract['allow']['status']]))
    deny = set(contract['deny'].get('statuses', set(range(200, 600)) - allow))
    return {'allow': allow, 'deny': deny}


def validate_contract(contract):
    mode = contract.get('decision', 'body')
    if mode not in ('status', 'body'):
        raise ValueError('features.webhook.decision must be status or body')
    for name in ('allow', 'deny'):
        response = contract[name]
        fields = {'status', 'body', 'statuses'} if mode == 'status' else {'status', 'body'}
        required = {'status'} if mode == 'status' else {'status', 'body'}
        if not isinstance(response, dict) or response.keys() - fields or required - response.keys():
            raise ValueError(f'invalid features.webhook.{name} response')
        try:
            resolve_decision({'status': response['status'], 'body': response.get('body')}, DEFAULT_CONTRACT)
        except (ValueError, TypeError):
            raise ValueError(f'invalid features.webhook.{name} status or JSON body') from None
        if 'statuses' in response:
            statuses = response['statuses']
            if (not isinstance(statuses, list) or not statuses
                    or any(type(status) is not int or not 200 <= status <= 599 for status in statuses)
                    or len(set(statuses)) != len(statuses) or response['status'] not in statuses):
                raise ValueError(f'features.webhook.{name}.statuses must contain distinct HTTP statuses including status')
    if mode == 'status':
        sets = status_sets(contract)
        if sets['allow'] & sets['deny'] or any(contract[name]['status'] not in sets[name] for name in sets):
            raise ValueError('features.webhook allow/deny status sets must be disjoint and include their response status')


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
        response = {'status': contract[name]['status'], 'body': copy.deepcopy(contract[name].get('body'))}
        if config['documented'] == 'deny_2xx':
            if contract.get('decision', 'body') == 'status':
                statuses = status_sets(contract)['deny'] & set(range(200, 300))
                if not statuses:
                    raise NoDocumentedDeny('deny_2xx_documented: no documented 2xx deny status outside the allow set')
                response['status'] = next((status for status in (response['status'], 204, 202) if status in statuses), min(statuses))
            elif not 200 <= response['status'] < 300:
                response['status'] = 200
        response['status'] = config.get('status', response['status'])
        if (contract.get('decision', 'body') == 'status' and config['documented'] == 'deny_2xx'
                and (type(response['status']) is not int or not 200 <= response['status'] < 300)):
            raise ValueError('documented 2xx webhook deny must use a 2xx status')
        if contract.get('decision', 'body') == 'status' and response['status'] not in status_sets(contract)[name]:
            raise ValueError('documented webhook response status contradicts its decision set')
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
