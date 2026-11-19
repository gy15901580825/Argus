"""Operator-authorized URL consent for gateway conformance cases."""
from __future__ import annotations

import asyncio
import select
import sys
from urllib.parse import parse_qsl, urljoin, urlsplit

import httpx

from argus.targets._base import ProbeNotApplicable, TargetTransportError


def validate_static_oauth(value):
    allowed = {'grant': ('client_credentials', 'authorization_code'),
               'consent': ('none', 'follow_url', 'manual'), 'trigger': ('challenge', 'manual_restart')}
    if not isinstance(value, dict) or set(value) != set(allowed):
        raise ValueError('static_oauth_client requires grant, consent and trigger')
    for name, choices in allowed.items():
        if value[name] not in choices:
            raise ValueError(f'invalid static_oauth_client.{name}')


def _origin(url):
    try:
        parsed = urlsplit(url)
        if (parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or parsed.fragment):
            raise ValueError
        port = parsed.port
        return parsed.scheme, parsed.hostname.lower(), port if port is not None else (443 if parsed.scheme == 'https' else 80)
    except (ValueError, TypeError, AttributeError):
        raise TargetTransportError('consent URL requires an HTTP(S) origin without userinfo or fragment') from None


class ConsentDriver:
    def __init__(self, gateway, install, mode, timeout_s):
        self.gateway, self.mode, self.timeout_s = gateway, mode, timeout_s
        self.allowed = {_origin(value['public']): name for name, value in install['origins'].items()}
        self.allowed[_origin(gateway.gateway['url'])] = 'gateway'
        self.nonce = None
        self.hops = []
        self.completed = set()

    def begin_case(self, nonce):
        self.nonce, self.hops, self.completed = nonce, [], set()

    def validate(self, elicitation):
        if (not isinstance(elicitation, dict) or elicitation.get('mode') != 'url'
                or not isinstance(elicitation.get('elicitationId'), str) or not elicitation['elicitationId']
                or not isinstance(elicitation.get('message'), str) or not isinstance(elicitation.get('url'), str)):
            raise TargetTransportError('gateway returned a malformed URL elicitation')
        self.destination(elicitation['url'])

    def destination(self, url):
        origin = _origin(url)
        if origin not in self.allowed:
            raise TargetTransportError('consent URL origin is outside the fixture and gateway allowlist')
        return self.allowed[origin]

    async def open(self, elicitation):
        self.validate(elicitation)
        key = (elicitation['elicitationId'], elicitation['url'])
        if key in self.completed:
            raise ProbeNotApplicable('consent completed but gateway requested the same authorization again')
        if len(self.completed) >= 10:
            raise ProbeNotApplicable('consent exceeds 10 elicitations per case')
        if self.mode == 'none':
            raise ProbeNotApplicable('gateway requires consent; configure follow_url or manual')
        if self.mode == 'manual':
            print(elicitation['url'], flush=True)
            print(elicitation['message'] + '\nComplete authorization, then press Enter to retry.', flush=True)
            if not sys.stdin.isatty():
                raise ProbeNotApplicable('manual consent requires a TTY; skipped in a non-interactive run')
            deadline = asyncio.get_running_loop().time() + self.timeout_s
            while asyncio.get_running_loop().time() < deadline:
                if select.select([sys.stdin], [], [], 0)[0]:
                    if not sys.stdin.readline():
                        raise ProbeNotApplicable('manual consent cancelled')
                    self.completed.add(key)
                    return
                await asyncio.sleep(0.1)
            raise ProbeNotApplicable('manual consent timed out')
        try:
            await asyncio.wait_for(self.follow(elicitation['url']), self.timeout_s)
        except (TimeoutError, httpx.TimeoutException):
            if self.gateway.last_failure is not None:
                raise TargetTransportError('consent error response body timed out') from None
            raise ProbeNotApplicable('consent navigation timed out') from None
        except httpx.HTTPError:
            raise TargetTransportError('consent navigation failed') from None
        self.completed.add(key)

    async def follow(self, url):
        for redirects in range(11):
            origin = self.destination(url)
            headers = {'X-Argus-Consent-Agent': self.nonce}
            if origin == 'gateway':
                headers.update(self.gateway.gateway.get('auth', {}).get('headers', {}))
                headers['X-Argus-Consent-Agent'] = self.nonce
            # Construct each request without the client's gateway credential defaults.
            for name, value in parse_qsl(urlsplit(url).query):
                if name not in ('response_type', 'code_challenge_method', 'scope'):
                    self.gateway.redactor.add(value)
            outgoing = httpx.Request('GET', url, headers=headers)
            if origin == 'gateway':
                self.gateway.client.cookies.set_cookie_header(outgoing)
            try:
                response = await self.gateway.client.send(outgoing, stream=True, follow_redirects=False)
            except httpx.HTTPError:
                self.gateway.last_failure = {**self.gateway.failure_context('GET', url), 'path_class': 'auth'}
                raise
            self.gateway.exchanges += 1
            try:
                parsed = urlsplit(str(outgoing.url))
                route = 'authorize' if parsed.path.rstrip('/').endswith('/authorize') else 'callback' if origin == 'gateway' and any(k == 'code' or k == 'error' for k, _ in parse_qsl(parsed.query)) else 'other'
                self.hops.append({'origin': origin, 'route': route, 'status': response.status_code,
                                  'query': sorted({name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)})})
                if response.status_code in (301, 302, 303, 307, 308):
                    if redirects == 10:
                        raise TargetTransportError('consent redirect chain exceeds 10 hops')
                    location = response.headers.get('Location')
                    if not location:
                        raise TargetTransportError('consent redirect has no location')
                    url = urljoin(str(outgoing.url), location)
                    self.destination(url)
                elif response.is_success:
                    return
                else:
                    await self.gateway.record_failure(response, path_class='auth')
                    if response.status_code in (401, 403):
                        reason = f'consent navigation returned HTTP {response.status_code}'
                        if origin == 'gateway' and not outgoing.headers.get('Cookie'):
                            reason += ('; follow_url may require a browser cookie session; '
                                       'configure gateway.auth.cookies or use consent: manual')
                        raise TargetTransportError(reason)
                    raise ProbeNotApplicable('consent navigation did not complete authorization')
            finally:
                await response.aclose()
