import jwt

from .service import Rejected


class OwnerVerifier:
    def __init__(self, tenant, audience, *, key_resolver=None):
        self.tenant = tenant
        self.audience = audience
        self.issuer = f"https://login.microsoftonline.com/{tenant}/v2.0"
        self.key_resolver = key_resolver
        self.jwks = None

    def verify(self, token, role):
        try:
            if len(token) > 16384:
                raise ValueError
            if self.key_resolver is None:
                if self.jwks is None:
                    self.jwks = jwt.PyJWKClient(f"https://login.microsoftonline.com/{self.tenant}/discovery/v2.0/keys", timeout=5)
                key = self.jwks.get_signing_key_from_jwt(token).key
            else:
                key = self.key_resolver(token)
            claims = jwt.decode(token, key, algorithms=["RS256"], audience=self.audience, issuer=self.issuer,
                                options={"require": ["exp", "iss", "aud", "tid", "oid"]})
            if claims["tid"] != self.tenant or not isinstance(claims["oid"], str) or not claims["oid"]:
                raise ValueError
        except (jwt.PyJWTError, ValueError, TypeError):
            raise Rejected(401, "invalid_owner_token") from None
        roles = claims.get("roles", [])
        if not isinstance(roles, list) or any(not isinstance(item, str) for item in roles) or role not in roles:
            raise Rejected(403, "missing_role")
        return self.tenant + "/" + claims["oid"]
