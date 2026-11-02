from copy import deepcopy
from dataclasses import replace
from threading import RLock

from .models import Run


class MemoryStore:
    def __init__(self):
        self.lock = RLock()
        self.runs: dict[str, Run] = {}
        self.limits: dict[str, dict] = {}

    def create(self, run):
        with self.lock:
            if run.run_id in self.runs:
                return False
            self.runs[run.run_id] = deepcopy(run)
            return True

    def get(self, run_id, now, *, include_expired=False):
        with self.lock:
            value = self.runs.get(run_id)
            if value is not None and (include_expired or value.expires_at > now):
                return deepcopy(value)
            return None

    def get_auth(self, run_id, now, *, include_expired=False):
        with self.lock:
            run = self.runs.get(run_id)
            if run is None or not include_expired and run.expires_at <= now:
                return None
            return deepcopy(replace(run, probes={}))

    def list_auth(self, now, *, include_expired=False):
        with self.lock:
            return [deepcopy(replace(run, probes={})) for run in self.runs.values() if include_expired or run.expires_at > now]

    def update(self, run, expected_version):
        with self.lock:
            current = self.runs.get(run.run_id)
            if current is None or current.version != expected_version:
                return False
            replacement = deepcopy(run)
            replacement.version = expected_version + 1
            self.runs[run.run_id] = replacement
            return True

    def list_runs(self, now, *, include_expired=False):
        with self.lock:
            return [deepcopy(value) for value in self.runs.values() if include_expired or value.expires_at > now]

    def purge(self, now):
        with self.lock:
            keys = [key for key, value in self.runs.items() if value.expires_at <= now]
            for key in keys:
                self.runs.pop(key)
            expired_limits = [key for key, value in self.limits.items() if value.get("expires_at", float("inf")) <= now]
            for key in expired_limits:
                self.limits.pop(key)
            return len(keys)

    def atomic_limit(self, key, change):
        with self.lock:
            replacement, result = change(deepcopy(self.limits.get(key, {})))
            self.limits[key] = deepcopy(replacement)
            return result
