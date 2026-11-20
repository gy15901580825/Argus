"""Passive foreign authorization server for OAuth issuer-binding conformance."""
from __future__ import annotations

import base64
import hmac
from urllib.parse import unquote_plus

import aiohttp.web as web

from .oauth import SCOPE, _digest, _error, _params, issuer_url


def handle(runtime, context):
    if context.route in ('as_metadata', 'authorize', 'token'):
        context.state.setdefault('oauth', {})['foreign_as_mode'] = runtime.foreign_as_mode
    if context.route == 'as_metadata':
        if context.request.method != 'GET':
            return _error('invalid_request', 405)
        runtime._event(context, 'as_metadata_fetched', {'at': 'foreign'})
        issuer = issuer_url(runtime.install, 'foreign')
        authorize = issuer_url(runtime.install) if runtime.foreign_as_mode == 'mirror_authorize' else issuer
        return web.json_response({'issuer': issuer, 'authorization_endpoint': authorize + '/authorize',
            'token_endpoint': issuer + '/token', 'response_types_supported': ['code'],
            'grant_types_supported': ['client_credentials', 'authorization_code'],
            'token_endpoint_auth_methods_supported': ['client_secret_basic', 'client_secret_post'],
            'code_challenge_methods_supported': ['S256'], 'scopes_supported': [SCOPE],
            'authorization_response_iss_parameter_supported': runtime.send_iss
                if runtime.foreign_as_mode == 'mirror_authorize' else False})
    if context.route not in ('authorize', 'token'):
        return None
    try:
        params = _params(context)
    except (ValueError, UnicodeError):
        params = {}
    if context.route == 'authorize':
        if runtime.foreign_as_mode == 'own':
            if context.request.method != 'GET':
                return _error('invalid_request', 405)
            return runtime._authorize(context, params)
        runtime._event(context, 'authorize', {
            'at': 'foreign', 'client_id_hit': params.get('client_id') == runtime.client['client_id'],
            'resource': runtime._resource_observation(context, params.get('resource', '')),
            'state_present': 'state' in params,
            'code_challenge_method': 'S256' if params.get('code_challenge_method') == 'S256' else 'other',
            'redirect_uri_corr': context.recorder.oauth_observation(params.get('redirect_uri', ''))['corr'],
            'challenge': context.recorder.oauth_observation(params.get('code_challenge', ''), challenge=True)})
    else:
        _record_token(runtime, context, params)
    # Token exchanges are observed but never yield a usable token.
    return _error('invalid_grant')


def _record_token(runtime, context, params):
    client_id, client_secret = params.get('client_id', ''), params.get('client_secret', '')
    client_auth = 'client_secret_post' if 'client_secret' in params else 'none'
    authorization = context.request.headers.get('Authorization', '')
    if authorization.startswith('Basic '):
        client_auth = 'client_secret_basic'
        try:
            decoded = base64.b64decode(authorization[6:], validate=True).decode('utf-8')
            client_id, client_secret = map(unquote_plus, decoded.split(':', 1))
        except (ValueError, UnicodeError):
            client_id, client_secret = '', ''
    code = context.recorder.oauth_observation(params.get('code', ''))
    verifier = context.recorder.oauth_observation(params.get('code_verifier', ''), verifier=True)
    issued = next((event for event in context.state.get('oauth', {}).get('codes_issued', [])
                   if event['corr'] == code['corr']), None)
    if issued is not None and issued['by'] == 'foreign':
        stored = runtime.codes.pop(_digest(params.get('code', '')), None)
        if stored is None or stored.origin != 'foreign':
            issued = None
    matches = (issued is not None and verifier.get('verifier_s256') is not None
               and verifier['verifier_s256'] == issued.get('verifier_s256'))
    grant = params.get('grant_type', '')
    runtime._event(context, 'token', {
        'at': 'foreign', 'actor': 'argus_user_agent'
            if context.nonce and context.request.headers.get('X-Argus-Consent-Agent') == context.nonce else 'gateway',
        'grant_type': grant if grant in ('client_credentials', 'authorization_code') else 'other',
        'client_auth': client_auth,
        'client_id_hit': hmac.compare_digest(client_id.encode(), runtime.client['client_id'].encode()),
        'client_secret_hit': hmac.compare_digest(client_secret.encode(), runtime.client['client_secret'].encode()),
        'resource': runtime._resource_observation(context, params.get('resource', '')),
        'code': code, 'code_issued_by': issued['by'] if issued else None,
        'verifier_s256': verifier.get('verifier_s256'), 'verifier_corr': verifier['corr'],
        'verifier_matches_challenge_from': issued['by'] if matches else None})
