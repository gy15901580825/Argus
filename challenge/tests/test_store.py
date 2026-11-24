import sqlite3

import pytest

from store import Store


@pytest.mark.parametrize("existing_wal", [False, True])
def test_store_opens_in_delete_journal_mode(tmp_path, existing_wal):
    path = tmp_path / "challenge.sqlite3"
    if existing_wal:
        with sqlite3.connect(path) as db:
            assert db.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
    store = Store(str(path))
    with store.connect() as db:
        assert db.execute("PRAGMA journal_mode").fetchone()[0] == "delete"
        assert db.execute("PRAGMA busy_timeout").fetchone()[0] == 10_000
    assert store.reserve(0.5, 1) is not None
    store.count(3, "submissions")
    reopened = Store(str(path))
    assert reopened.spent() == 0.5
    assert reopened.counts(3)["submissions"] == 1
