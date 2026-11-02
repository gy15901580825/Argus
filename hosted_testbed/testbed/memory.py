import copy
import threading

from .models import Run


class MemoryStore:
    def __init__(self):
        self.runs: dict[str, Run] = {}
        self.limits: dict[str, dict] = {}
        self.lock = threading.RLock()

    def create(self, run):
        with self.lock:
            if run.run_id in self.runs:
                return False
            self.runs[run.run_id] = copy.deepcopy(run)
            return True

    def get(self, run_id, now, *, include_expired=False):
        with self.lock:
            run = self.runs.get(run_id)
            if run is None or not include_expired and run.expires_at <= now:
                return None
            return copy.deepcopy(run)

    def update(self, run, expected_version):
        with self.lock:
            old = self.runs.get(run.run_id)
            if old is None or old.version != expected_version:
                return False
            updated = copy.deepcopy(run)
            updated.version = expected_version + 1
            self.runs[run.run_id] = updated
            return True

    def list_runs(self, now, *, include_expired=False):
        with self.lock:
            return [copy.deepcopy(run) for run in self.runs.values() if include_expired or run.expires_at > now]

    def purge(self, now):
        with self.lock:
            expired = [key for key, run in self.runs.items() if run.expires_at <= now]
            for key in expired:
                del self.runs[key]
            return len(expired)

    def atomic_limit(self, key, change):
        with self.lock:
            value, result = change(copy.deepcopy(self.limits.get(key, {})))
            self.limits[key] = copy.deepcopy(value)
            return result
