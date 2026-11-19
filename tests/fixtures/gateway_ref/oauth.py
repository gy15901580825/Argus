"""Static upstream OAuth strategies for loopback conformance tests."""
from __future__ import annotations

import base64
import hashlib
import re
import secrets
import time
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlsplit, urlunsplit

from .proxy import ReferenceGateway, loopback_url


class OAuthError(RuntimeError):
    pass


@dataclass(frozen=True)
class StaticClient:
    issuer: str
    client_id: str = field(repr=False)
    client_secret: str = field(repr=False)
    grant: str = 'client_credentials'

    def __post_init__(self):
        loopback_url(self.issuer)
        if self.grant not in ('client_credentials', 'authorization_code'):
            raise ValueError('unknown upstream OAuth grant')


class OAuthReferenceGateway(ReferenceGateway):
    def __init__(self, entries, *, clients: dict[str, StaticClient], strategy='issuer', validate_iss=None, **kwargs):
        super().__init__(entries, **kwargs)
        if strategy not in ('entry', 'issuer') or not clients or not set(clients) <= set(entries):
            raise ValueError('unknown upstream OAuth strategy or entry')
        self.strategy = strategy
        if validate_iss is not None and type(validate_iss) is not bool:
            raise ValueError('validate_iss must be a boolean')
        self.validate_iss = strategy == 'issuer' if validate_iss is None else validate_iss
        self.registrations = {}
        for name, client in clients.items():
            key = name if strategy == 'entry' else client.issuer
            if key in self.registrations and self.registrations[key] != client:
                raise ValueError('conflicting registration for authorization server')
            self.registrations[key] = client
        self.oauth_entries = set(clients)
        self.tokens = {}
        self.token_keys = {}

    async def __aexit__(self, *args):
        try:
            await super().__aexit__(*args)
        finally:
            self.tokens.clear()
            self.token_keys.clear()

    async def upstream_headers(self, name):
        headers = await super().upstream_headers(name)
        token, expires = self.tokens.get(self.token_keys.get(name), ('', 0))
        if expires > time.monotonic():
            headers['Authorization'] = 'Bearer ' + token
        return headers

    async def _request(self, name, request, **kwargs):
        response = await super()._request(name, request, **kwargs)
        if name not in self.oauth_entries or response.status_code != 401:
            return response
        challenge = response.headers.get('WWW-Authenticate', '')
        await response.aclose()
        self.tokens.pop(self.token_keys.get(name), None)
        await self._authenticate(name, challenge)
        response = await super()._request(name, request, **kwargs)
        if response.status_code == 401:
            await response.aclose()
            raise OAuthError('Upstream rejected the authorization server token')
        return response

    async def _document(self, url):
        loopback_url(url)
        response = await self.client.get(url, follow_redirects=False)
        if response.status_code != 200:
            raise OAuthError('OAuth metadata unavailable')
        document = response.json()
        if not isinstance(document, dict):
            raise OAuthError('Invalid OAuth metadata')
        return document

    async def _authenticate(self, name, challenge):
        match = re.search(r'\bresource_metadata="([^"]+)"', challenge)
        if not match:
            raise OAuthError('Protected resource metadata unavailable')
        resource = self.entries[name].url
        prm = await self._document(match[1])
        if prm.get('resource') != resource:
            raise OAuthError('Protected resource metadata mismatch')
        servers = prm.get('authorization_servers')
        if not isinstance(servers, list) or len(servers) != 1 or not isinstance(servers[0], str):
            raise OAuthError('Expected one authorization server')
        issuer = servers[0]
        loopback_url(issuer)
        parsed = urlsplit(issuer)
        metadata_url = urlunsplit((parsed.scheme, parsed.netloc,
                                  '/.well-known/oauth-authorization-server' + parsed.path, '', ''))
        metadata = await self._document(metadata_url)
        if metadata.get('issuer') != issuer:
            raise OAuthError('Authorization server metadata issuer mismatch')
        key = name if self.strategy == 'entry' else issuer
        client = self.registrations.get(key)
        if client is None:
            raise OAuthError('Authorization server changed; static credentials are bound to their issuer')
        token_url = metadata['token_endpoint']
        loopback_url(token_url)
        params = {'grant_type': client.grant, 'resource': resource, 'scope': 'argus.fixture'}
        if client.grant == 'authorization_code':
            params.update(await self._authorization_code(issuer, metadata, client, resource))
        params.update(client_id=client.client_id, client_secret=client.client_secret)
        response = await self.client.post(token_url, data=params, follow_redirects=False)
        if response.status_code != 200:
            raise OAuthError('Upstream OAuth token request rejected')
        token = response.json()
        if token.get('token_type', '').lower() != 'bearer' or not isinstance(token.get('access_token'), str):
            raise OAuthError('Invalid upstream OAuth token response')
        token_key = name if self.strategy == 'entry' else (issuer, resource)
        self.tokens[token_key] = (token['access_token'], time.monotonic() + token['expires_in'])
        self.token_keys[name] = token_key

    async def _authorization_code(self, issuer, metadata, client, resource):
        if 'S256' not in metadata.get('code_challenge_methods_supported', []):
            raise OAuthError('Authorization server does not support S256')
        authorize_url = metadata['authorization_endpoint']
        loopback_url(authorize_url)
        verifier, state = secrets.token_urlsafe(48), secrets.token_urlsafe(32)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode('ascii')).digest()).decode().rstrip('=')
        callback = self.url.removesuffix('/mcp') + '/oauth/callback'
        response = await self.client.get(authorize_url, params={
            'client_id': client.client_id, 'response_type': 'code', 'redirect_uri': callback,
            'resource': resource, 'scope': 'argus.fixture', 'state': state,
            'code_challenge': challenge, 'code_challenge_method': 'S256'}, follow_redirects=False)
        if response.status_code != 302:
            raise OAuthError('Upstream OAuth authorization rejected')
        location = urlsplit(response.headers['Location'])
        loopback_url(response.headers['Location'])
        if urlunsplit((location.scheme, location.netloc, location.path, '', '')) != callback:
            raise OAuthError('OAuth callback mismatch')
        values = parse_qs(location.query, keep_blank_values=True)
        if values.get('state') != [state]:
            raise OAuthError('OAuth state mismatch')
        if self.validate_iss:
            # RFC 9207 requires comparison whenever iss is present, even without advertisement.
            if ('iss' in values and values['iss'] != [issuer]
                    or metadata.get('authorization_response_iss_parameter_supported') is True and 'iss' not in values):
                raise OAuthError('Authorization response issuer mismatch')
        if 'error' in values or len(values.get('code', [])) != 1:
            raise OAuthError('Upstream OAuth authorization rejected')
        return {'code': values['code'][0], 'code_verifier': verifier, 'redirect_uri': callback}

    async def _handle(self, request):
        try:
            return await super()._handle(request)
        except OAuthError as exc:
            message = await request.json() if request.method == 'POST' else {}
            return self._error(message.get('id'), -32000, str(exc))
