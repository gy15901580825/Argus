from __future__ import annotations

import json
import os
from datetime import datetime
from importlib.metadata import entry_points
from pathlib import Path
from typing import Protocol

from pydantic import BaseModel, Field, SecretStr


class CredentialUnavailable(RuntimeError):
    pass


class ConnRef(BaseModel):
    connection_id: str
    role: str


class AccessToken(BaseModel):
    value: SecretStr = Field(min_length=1)
    expires_at: datetime
    scopes: frozenset[str]


class CredentialProvider(Protocol):
    async def access_token(self, ref: ConnRef, scopes: set[str]) -> AccessToken: ...


class EnvironmentCredentialProvider:
    def __init__(self, config: dict, run_token: SecretStr, connections: dict[str, str]):
        self.config = config

    async def access_token(self, ref: ConnRef, scopes: set[str]) -> AccessToken:
        name = self.config.get("variables", {}).get(ref.connection_id)
        if not name or not isinstance(name, str) or not name.startswith("ARGUS_TEST_CREDENTIAL_"):
            raise CredentialUnavailable("test credential environment variable is not configured")
        raw = os.getenv(name)
        if not raw:
            raise CredentialUnavailable("test connection needs reauthorization")
        try:
            token = AccessToken.model_validate_json(raw)
        except Exception as exc:
            raise CredentialUnavailable("test credential is invalid") from exc
        _check_token(token, scopes)
        return token


class FileCredentialProvider:
    def __init__(self, config: dict, run_token: SecretStr, connections: dict[str, str]):
        self.directory = Path(config.get("directory", "~/.config/argus/credentials")).expanduser()

    async def access_token(self, ref: ConnRef, scopes: set[str]) -> AccessToken:
        if not ref.connection_id.replace("-", "").replace("_", "").isalnum():
            raise CredentialUnavailable("invalid connection reference")
        path = self.directory / (ref.connection_id + ".json")
        try:
            if path.stat().st_mode & 0o077:
                raise CredentialUnavailable("credential file must have mode 0600")
            token = AccessToken.model_validate(json.loads(path.read_text()))
        except CredentialUnavailable:
            raise
        except Exception as exc:
            raise CredentialUnavailable("test connection needs reauthorization") from exc
        _check_token(token, scopes)
        return token


def _check_token(token: AccessToken, scopes: set[str]):
    from argus.scenarios.models import now
    if token.expires_at.tzinfo is None or token.expires_at <= now():
        raise CredentialUnavailable("connection needs reauthorization")
    if not scopes.issubset(token.scopes):
        raise CredentialUnavailable("connection is missing required scopes")


def build_credential_provider(kind: str, config: dict, run_token: SecretStr, connections: dict[str, str]) -> CredentialProvider:
    factories = {"environment": EnvironmentCredentialProvider, "file": FileCredentialProvider}
    if kind in factories:
        return factories[kind](config, run_token, connections)
    matches = sorted((ep for ep in entry_points(group="argus.credential_providers") if ep.name == kind), key=lambda ep: ep.value)
    if len(matches) != 1:
        raise ValueError("credential provider is not installed or is ambiguous")
    return matches[0].load()(config, run_token, connections)
