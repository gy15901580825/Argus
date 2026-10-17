"""database.get_database_url: DATABASE_URL takes precedence over flyway.toml."""
from __future__ import annotations

import database


def test_env_var_wins_over_flyway_toml(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://u:p@db.example:5432/x")
    monkeypatch.setattr(database.os.path, "exists", lambda p: True)
    monkeypatch.setattr(database.toml, "load", lambda p: {"environments": {"default": {
        "url": "jdbc:postgresql://other:5432/y", "user": "a", "password": "b"}}})
    assert database.get_database_url() == "postgresql+asyncpg://u:p@db.example:5432/x"


def test_flyway_toml_used_when_env_unset(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setattr(database.os.path, "exists", lambda p: True)
    monkeypatch.setattr(database.toml, "load", lambda p: {"environments": {"default": {
        "url": "jdbc:postgresql://other:5432/y", "user": "a", "password": "b"}}})
    assert database.get_database_url() == "postgresql+asyncpg://a:b@other:5432/y"
