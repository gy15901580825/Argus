"""Passive, loopback OAuth fixtures for RFC discovery and PKCE conformance."""
from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import time
from dataclasses import dataclass
from urllib.parse import parse_qsl, unquote_plus, urlencode, urlsplit, urlunsplit

import aiohttp.web as web

from .registry import DefinitionError

SCOPE = 'argus.fixture'
TTL_S = 60
STATE_MAX = 200


def issuer_url(install, origin='issuer'):
    return install['origins'][origin]['public'].rstrip('/') + '/a/' + install['path_token']


def discovery_paths(install):
    path = '/a/' + install['path_token']
    return ('/.well-known/oauth-authorization-server' + path,
            '/.well-known/openid-configuration' + path,
            path + '/.well-known/openid-configuration')


def prm_paths(install):
    path = install['entries']['oauth']['path'].replace('{path_token}', install['path_token'])
    return ('/.well-known/oauth-protected-resource' + path,
            '/.well-known/oauth-protected-resource')


def classify(install, origin, path):
    if 'oauth' not in install['entries']:
        return None
    if origin == 'upstream' and path in prm_paths(install):
        return 'prm', 'oauth'
    if origin in ('issuer', 'foreign'):
        if path in discovery_paths(install):
            return 'as_metadata', 'oauth'
        prefix = '/a/' + install['path_token']
        if path in (prefix + '/authorize', prefix + '/token'):
            return path.rsplit('/', 1)[1], 'oauth'
    return None


def _toggle(config, values):
    if config not in values:
        raise DefinitionError('invalid OAuth toggle')
    async def handler(context):
        return None
    return handler


def prm(config):
    if (not isinstance(config, dict) or set(config) != {'authorization_servers'}
            or config['authorization_servers'] not in (['issuer'], ['foreign'])):
        raise DefinitionError('prm must select one fixture authorization server')
    return _toggle(config['authorization_servers'][0], ('issuer', 'foreign'))


def challenge(config):
    return _toggle(config, ('invalid_token',))


def iss(config):
    return _toggle(config, ('always', 'never'))


def as_mode(config):
    return _toggle(config, ('own', 'mirror_authorize'))


def oauth_entry(install):
    client_id = 'argus-canary-client-' + secrets.token_hex(16)
    client_secret = 'argus-canary-secret-' + secrets.token_hex(16)
    return {'auth': 'oauth', 'client_id': client_id, 'client_secret': client_secret,
            'sheet': ['Issuer: ' + issuer_url(install), 'Client ID: ' + client_id,
                      'Client secret: ' + client_secret,
                      'Scope: ' + SCOPE]}


def register(registry):
    registry.add_origin('issuer', {'symmetric_with': 'foreign'})
    registry.add_entry('oauth', '/u/{path_token}/oauth/mcp', oauth_entry)
    registry.add_behavior('upstream', 'prm', prm)
    registry.add_behavior('upstream', 'challenge', challenge)
    registry.add_behavior('issuer', 'iss', iss)
    registry.add_behavior('foreign', 'as_mode', as_mode)


def _digest(value):
    return hashlib.sha256(value.encode('utf-8')).digest()


def _params(context):
    if context.route == 'authorize':
        pairs = list(context.request.query.items())
    else:
        if context.request.content_type != 'application/x-www-form-urlencoded':
            raise ValueError
        pairs = parse_qsl(context.body.decode('utf-8'), keep_blank_values=True, strict_parsing=True)
    if len(pairs) > 128 or len({name for name, _ in pairs}) != len(pairs):
        raise ValueError
    return dict(pairs)


def _error(name, status=400):
    return web.json_response({'error': name}, status=status,
                             headers={'Cache-Control': 'no-store', 'Pragma': 'no-cache'})


@dataclass
class _Code:
    client_id: str
    redirect_uri: str
    challenge: str
    expires: float


class OAuthRuntime:
    """Protocol state stays outside the exported case state; codes are keyed by hash."""

    def __init__(self, install):
        self.install = install
        self.client = install['entries']['oauth']
        self.redirect_uri = None
        self.codes: dict[bytes, _Code] = {}
        self.tokens: dict[bytes, float] = {}
        self.authorization_server = 'issuer'
        self.send_iss = True
        self.foreign_as_mode = 'own'

    def begin_case(self, toggles):
        self.codes.clear()
        upstream = toggles.get('upstream', {})
        self.authorization_server = upstream.get('prm', {}).get('authorization_servers', ['issuer'])[0]
        self.send_iss = toggles.get('issuer', {}).get('iss', 'always') == 'always'
        self.foreign_as_mode = toggles.get('foreign', {}).get('as_mode', 'own')
        if upstream.get('challenge') == 'invalid_token':
            self.tokens.clear()

    def end_case(self):
        self.codes.clear()
        self.authorization_server = 'issuer'
        self.send_iss = True
        self.foreign_as_mode = 'own'

    def close(self):
        self.end_case()
        self.tokens.clear()
        self.redirect_uri = None

    def _resource(self):
        from .install import entry_url
        return entry_url(self.install, 'oauth')

    def _resource_observation(self, context, value):
        observation = context.recorder.oauth_observation(value)
        observation['matches_expected'] = value == self._resource()
        return observation

    def _event(self, context, name, event):
        context.ext['oauth'] = {name: event}
        if context.case_id is not None:
            events = context.state.setdefault('oauth', {}).setdefault(name, [])
            if len(events) < STATE_MAX:
                events.append(event)

    async def handle(self, context):
        if context.route == 'prm':
            if context.request.method != 'GET':
                return _error('invalid_request', 405)
            self._event(context, 'prm_served', {'as': self.authorization_server})
            return web.json_response({'resource': self._resource(),
                'authorization_servers': [issuer_url(self.install, self.authorization_server)],
                'scopes_supported': [SCOPE], 'bearer_methods_supported': ['header']})
        if context.origin == 'upstream' and context.entry == 'oauth' and context.route == 'mcp':
            authorization = context.request.headers.get('Authorization', '')
            token = authorization[7:] if authorization.startswith('Bearer ') else ''
            valid = self.tokens.get(_digest(token), 0) > time.monotonic()
            context.ext['oauth'] = {'token_valid': valid}
            if valid:
                return None
            metadata = self.install['origins']['upstream']['public'].rstrip('/') + prm_paths(self.install)[0]
            challenge_value = f'Bearer resource_metadata="{metadata}", scope="{SCOPE}"'
            if token or self.authorization_server != 'issuer':
                challenge_value += ', error="invalid_token"'
            return web.json_response({'error': 'unauthorized'}, status=401,
                                     headers={'WWW-Authenticate': challenge_value})
        if context.origin == 'foreign':
            from .foreign_oauth import handle
            return handle(self, context)
        if context.origin != 'issuer':
            return None
        if context.route == 'as_metadata':
            if context.request.method != 'GET':
                return _error('invalid_request', 405)
            self._event(context, 'as_metadata_fetched', {'at': 'issuer'})
            issuer = issuer_url(self.install)
            return web.json_response({'issuer': issuer, 'authorization_endpoint': issuer + '/authorize',
                'token_endpoint': issuer + '/token', 'response_types_supported': ['code'],
                'grant_types_supported': ['client_credentials', 'authorization_code'],
                'token_endpoint_auth_methods_supported': ['client_secret_basic', 'client_secret_post'],
                'code_challenge_methods_supported': ['S256'], 'scopes_supported': [SCOPE],
                'authorization_response_iss_parameter_supported': self.send_iss})
        if context.route not in ('authorize', 'token'):
            return None
        if context.request.method != ('GET' if context.route == 'authorize' else 'POST'):
            return _error('invalid_request', 405)
        try:
            params = _params(context)
        except (ValueError, UnicodeError):
            return _error('invalid_request')
        return self._authorize(context, params) if context.route == 'authorize' else self._token(context, params)

    def _authorize(self, context, params):
        challenge_value = params.get('code_challenge', '')
        event = {'at': 'issuer', 'client_id_hit': params.get('client_id') == self.client['client_id'],
                 'resource': self._resource_observation(context, params.get('resource', '')),
                 'state_present': 'state' in params,
                 'code_challenge_method': 'S256' if params.get('code_challenge_method') == 'S256' else 'other',
                 'redirect_uri_corr': context.recorder.oauth_observation(params.get('redirect_uri', ''))['corr'],
                 'challenge': context.recorder.oauth_observation(challenge_value, challenge=True)}
        self._event(context, 'authorize', event)
        if not event['client_id_hit']:
            return _error('unauthorized_client')
        redirect = params.get('redirect_uri', '')
        parsed = urlsplit(redirect)
        try:
            valid_redirect = (parsed.scheme in ('http', 'https') and parsed.hostname and not parsed.fragment
                              and not parsed.username and not parsed.password and parsed.port != 0)
        except ValueError:
            valid_redirect = False
        if not valid_redirect or self.redirect_uri is not None and redirect != self.redirect_uri:
            return _error('invalid_request')
        def authorization_error(name):
            return self._redirect(params, parsed, [('error', name)])

        # First successful request pins the exact callback for this install's lifetime.
        if params.get('response_type') != 'code':
            return authorization_error('unsupported_response_type')
        if params.get('code_challenge_method') != 'S256' or not re.fullmatch(r'[A-Za-z0-9_-]{43}', challenge_value):
            return authorization_error('invalid_request')
        if not event['resource']['matches_expected']:
            return authorization_error('invalid_target')
        if params.get('scope', SCOPE) != SCOPE:
            return authorization_error('invalid_scope')
        self.codes = {key: value for key, value in self.codes.items() if value.expires > time.monotonic()}
        if len(self.codes) >= STATE_MAX:
            return authorization_error('temporarily_unavailable')
        self.redirect_uri = redirect
        code = secrets.token_urlsafe(32)
        self.codes[_digest(code)] = _Code(self.client['client_id'], redirect, challenge_value, time.monotonic() + TTL_S)
        self._event(context, 'codes_issued', {'by': 'issuer', **context.recorder.oauth_observation(code),
                                           'h_sent_iss': self.send_iss,
                                           'verifier_s256': event['challenge'].get('verifier_s256')})
        return self._redirect(params, parsed, [('code', code)])

    def _redirect(self, params, parsed, response):
        pairs = list(parse_qsl(parsed.query, keep_blank_values=True)) + response
        if 'state' in params:
            pairs.append(('state', params['state']))
        if self.send_iss:
            pairs.append(('iss', issuer_url(self.install)))
        location = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(pairs), ''))
        return web.Response(status=302, headers={'Location': location, 'Cache-Control': 'no-store'})

    def _token(self, context, params):
        client_id, client_secret = params.get('client_id', ''), params.get('client_secret', '')
        client_auth = 'client_secret_post' if 'client_secret' in params else 'none'
        authorization = context.request.headers.get('Authorization', '')
        if authorization:
            if not authorization.startswith('Basic ') or 'client_secret' in params or 'client_id' in params:
                return _error('invalid_request')
            try:
                decoded = base64.b64decode(authorization[6:], validate=True).decode('utf-8')
                client_id, client_secret = map(unquote_plus, decoded.split(':', 1))
                client_auth = 'client_secret_basic'
            except (ValueError, UnicodeError):
                return _error('invalid_client', 401)
        verifier = params.get('code_verifier', '')
        code = params.get('code', '')
        grant = params.get('grant_type', '')
        verifier_observation = context.recorder.oauth_observation(verifier, verifier=True)
        event = {'at': 'issuer', 'client_auth': client_auth,
                 'grant_type': grant if grant in ('client_credentials', 'authorization_code') else 'other',
                 'client_id_hit': hmac.compare_digest(client_id.encode(), self.client['client_id'].encode()),
                 'client_secret_hit': hmac.compare_digest(client_secret.encode(), self.client['client_secret'].encode()),
                 'resource': self._resource_observation(context, params.get('resource', '')),
                 'actor': 'argus_user_agent' if context.nonce and context.request.headers.get('X-Argus-Consent-Agent') == context.nonce else 'gateway',
                 'code': context.recorder.oauth_observation(code),
                 'verifier_s256': verifier_observation.get('verifier_s256'),
                 'verifier_corr': verifier_observation['corr'],
                 'verifier_matches_challenge_from': None}
        self._event(context, 'token', event)
        if not event['client_id_hit'] or not event['client_secret_hit']:
            response = _error('invalid_client', 401)
            response.headers['WWW-Authenticate'] = 'Basic realm="argus.fixture"'
            return response
        if not event['resource']['matches_expected']:
            return _error('invalid_target')
        if params.get('scope', SCOPE) != SCOPE:
            return _error('invalid_scope')
        if grant == 'authorization_code':
            issued = self.codes.pop(_digest(code), None)
            if (issued is None or issued.expires <= time.monotonic()
                    or issued.client_id != client_id or issued.redirect_uri != params.get('redirect_uri')
                    or not re.fullmatch(r'[A-Za-z0-9._~-]{43,128}', verifier)
                    or base64.urlsafe_b64encode(hashlib.sha256(verifier.encode('ascii')).digest()).decode().rstrip('=') != issued.challenge):
                return _error('invalid_grant')
            event['code_issued_by'] = 'issuer'
            event['verifier_matches_challenge_from'] = 'issuer'
        elif grant != 'client_credentials':
            return _error('unsupported_grant_type')
        self.tokens = {key: expiry for key, expiry in self.tokens.items() if expiry > time.monotonic()}
        if len(self.tokens) >= STATE_MAX:
            return _error('temporarily_unavailable', 503)
        token = secrets.token_urlsafe(32)
        self.tokens[_digest(token)] = time.monotonic() + TTL_S
        return web.json_response({'access_token': token, 'token_type': 'Bearer', 'expires_in': TTL_S,
                                  'scope': SCOPE}, headers={'Cache-Control': 'no-store', 'Pragma': 'no-cache'})
