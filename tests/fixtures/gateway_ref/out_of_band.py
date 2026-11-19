"""A gateway whose upstream authorization is available only out of band."""
from aiohttp import web

from .oauth import OAuthError, OAuthReferenceGateway


class ReauthorizationRequired(Exception):
    pass


class OutOfBandOAuthReferenceGateway(OAuthReferenceGateway):
    def __init__(self, *args, refusal_status=403, **kwargs):
        super().__init__(*args, **kwargs)
        self.refusal_status = refusal_status
        self.pending = {}
        self.authorization_errors = {}
        self.blocked_calls = 0
        self.reauthorizations = 0

    async def _authenticate(self, name, challenge):
        if name in self.token_keys:
            self.pending[name] = challenge
            self.blocked_calls += 1
            raise ReauthorizationRequired
        await super()._authenticate(name, challenge)

    async def reauthorize(self, name):
        self.reauthorizations += 1
        try:
            await super()._authenticate(name, self.pending.pop(name))
        except OAuthError as exc:
            self.authorization_errors[name] = str(exc)

    async def _request(self, name, request, **kwargs):
        if name in self.authorization_errors:
            raise OAuthError(self.authorization_errors[name])
        return await super()._request(name, request, **kwargs)

    async def _handle(self, request):
        try:
            return await super()._handle(request)
        except ReauthorizationRequired:
            return web.Response(status=self.refusal_status, text='Upstream authorization is required.\n')
