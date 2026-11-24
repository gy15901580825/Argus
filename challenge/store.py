from contextlib import contextmanager
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import time


class Store:
    def __init__(self, path: str):
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS budget(day TEXT PRIMARY KEY, spent REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS counters(level INTEGER PRIMARY KEY, starts INTEGER NOT NULL DEFAULT 0, submissions INTEGER NOT NULL DEFAULT 0, wins INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS wins(id INTEGER PRIMARY KEY, level INTEGER NOT NULL, input TEXT NOT NULL, trace TEXT NOT NULL, created_at REAL NOT NULL);
            """)
            db.execute("DELETE FROM wins WHERE created_at < ?", (time.time() - 90 * 86400,))

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def today(self) -> str:
        return datetime.now(timezone.utc).date().isoformat()

    def spent(self) -> float:
        with self.connect() as db:
            row = db.execute("SELECT spent FROM budget WHERE day = ?", (self.today(),)).fetchone()
            return row[0] if row else 0.0

    def reserve(self, amount: float, limit: float) -> str | None:
        day = self.today()
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("INSERT OR IGNORE INTO budget VALUES (?, 0)", (day,))
            spent = db.execute("SELECT spent FROM budget WHERE day = ?", (day,)).fetchone()[0]
            if spent + amount > limit + 1e-12:
                return None
            db.execute("UPDATE budget SET spent = spent + ? WHERE day = ?", (amount, day))
        return day

    def reconcile(self, day: str, reservation: float, actual: float):
        with self.connect() as db:
            db.execute("UPDATE budget SET spent = MAX(0, spent + ?) WHERE day = ?", (actual - reservation, day))

    def count(self, level: int, kind: str):
        if kind not in ("starts", "submissions", "wins"):
            raise ValueError("Unknown counter")
        with self.connect() as db:
            db.execute("INSERT OR IGNORE INTO counters(level) VALUES (?)", (level,))
            db.execute(f"UPDATE counters SET {kind} = {kind} + 1 WHERE level = ?", (level,))

    def counts(self, level: int) -> dict:
        with self.connect() as db:
            row = db.execute("SELECT starts, submissions, wins FROM counters WHERE level = ?", (level,)).fetchone()
            return dict(row) if row else {"starts": 0, "submissions": 0, "wins": 0}

    def share(self, level: int, player_input: str, trace: list[dict]):
        with self.connect() as db:
            db.execute("INSERT INTO wins(level, input, trace, created_at) VALUES (?, ?, ?, ?)", (level, player_input, json.dumps(trace), time.time()))

    def wins(self) -> list[dict]:
        with self.connect() as db:
            rows = db.execute("SELECT level, input, trace FROM wins ORDER BY id").fetchall()
            return [{"level": row["level"], "input": row["input"], "trace": json.loads(row["trace"])} for row in rows]
