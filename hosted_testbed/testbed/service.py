import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import asdict

from .markers import match_markers
from .models import Event, Probe, Run, Store


class Rejected(Exception):
    def __init__(self, status, code):
        self.status = status
        self.code = code
        super().__init__(code)


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


class HostedService:
    def __init__(self, store: Store, *, clock=time.time):
        self.store = store
        self.clock = clock

    def _change(self, rid, change, *, expired=False):
        for _ in range(12):
            run = self.store.get(rid, self.clock(), include_expired=expired)
            if run is None or run.deleted:
                raise Rejected(404, "not_found")
            version = run.version
            result = change(run)
            if self.store.update(run, version):
                return result
        raise Rejected(503, "storage_conflict")

    def _owner(self, owner, rid):
        run = self.store.get(rid, self.clock())
        if run is None or run.deleted or not hmac.compare_digest(owner, run.owner):
            raise Rejected(404, "not_found")
        return run

    def rate(self, category, identity, per_minute, burst):
        now = self.clock()
        key = "rate:" + category + ":" + digest(identity)

        def charge(old):
            available = min(burst, old.get("tokens", burst) + max(0, now - old.get("at", now)) * per_minute / 60)
            allowed = available >= 1
            return {"tokens": available - 1 if allowed else available, "at": now, "expires_at": now + 3600}, allowed

        if not self.store.atomic_limit(key, charge):
            raise Rejected(429, "rate_limit")

    def create_run(self, owner, *, ttl_seconds=86400, idempotency_key=None):
        if not isinstance(ttl_seconds, (int, float)) or isinstance(ttl_seconds, bool) or not 1 <= ttl_seconds <= 86400:
            raise Rejected(400, "invalid_ttl")
        if idempotency_key is not None and (not isinstance(idempotency_key, str) or not 1 <= len(idempotency_key.encode()) <= 256):
            raise Rejected(400, "invalid_idempotency_key")
        now = self.clock()
        rid = digest(owner + "\0" + idempotency_key)[:32] if idempotency_key else secrets.token_hex(16)
        existing = self.store.get(rid, now, include_expired=True)
        if existing is not None:
            if existing.owner != owner or existing.expires_at <= now or existing.deleted:
                raise Rejected(410, "run_expired")
            return {"run_id": rid, "expires_at": existing.expires_at, "replayed": True}

        def admit(old):
            active = {key: expiry for key, expiry in old.get("active", {}).items() if expiry > now}
            history = {key: entries for key, values in old.get("history", {}).items() if (entries := [stamp for stamp in values if stamp > now - 3600])}
            principal = digest(owner)
            if rid in active:
                return old, True
            if len(active) >= 10 or len(history.get(principal, [])) >= 20:
                return old, False
            active[rid] = now + ttl_seconds
            history.setdefault(principal, []).append(now)
            return {"active": active, "history": history, "expires_at": now + 86400}, True

        if not self.store.atomic_limit("admission", admit):
            raise Rejected(429, "run_limit")
        public, evidence = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        run = Run(rid, owner, now, now + ttl_seconds, digest(public), digest(evidence))
        if not self.store.create(run):
            winner = self.store.get(rid, now, include_expired=True)
            if winner is None or winner.deleted or winner.owner != owner or winner.expires_at <= now:
                raise Rejected(503, "creation_state_unknown")
            return {"run_id": rid, "expires_at": winner.expires_at, "replayed": True}
        return {"run_id": rid, "expires_at": run.expires_at, "public_token": public, "evidence_token": evidence}

    def create_probe(self, owner, rid, *, payload, markers, lease_seconds=10800, combination=()):
        self._owner(owner, rid)
        if not isinstance(payload, str) or len(payload.encode()) > 16384:
            raise Rejected(400, "invalid_payload")
        if not isinstance(markers, dict) or len(markers) > 32 or any(not isinstance(key, str) or not isinstance(value, str) or not 1 <= len(key) <= 64 or not 1 <= len(value.encode()) <= 512 for key, value in markers.items()):
            raise Rejected(400, "invalid_markers")
        if not isinstance(lease_seconds, (int, float)) or isinstance(lease_seconds, bool) or not 1 <= lease_seconds <= 10800:
            raise Rejected(400, "invalid_lease")
        if not isinstance(combination, (list, tuple)) or any(not isinstance(key, str) for key in combination) or len(combination) != len(set(combination)) or not set(combination) <= {"path", "query", "body"}:
            raise Rejected(400, "invalid_combination")
        pid, epoch = secrets.token_hex(12), secrets.token_hex(12)
        now = self.clock()

        def add(run):
            if len(run.probes) >= 100:
                raise Rejected(429, "probe_limit")
            probe = Probe(pid, epoch, min(run.expires_at, now + lease_seconds), payload, markers, combination=list(combination))
            run.probes[pid] = probe
            return {"run_id": rid, "probe_id": pid, "epoch": epoch, "expires_at": probe.expires_at}

        return self._change(rid, add)

    def renew(self, owner, rid, pid, *, lease_seconds=10800):
        self._owner(owner, rid)
        if not isinstance(lease_seconds, (int, float)) or isinstance(lease_seconds, bool) or not 1 <= lease_seconds <= 10800:
            raise Rejected(400, "invalid_lease")

        def renew(run):
            probe = self._probe(run, pid)
            if probe.sealed or probe.sealing:
                raise Rejected(409, "already_sealed")
            probe.expires_at = min(run.expires_at, self.clock() + lease_seconds)
            return {"expires_at": probe.expires_at, "epoch": probe.epoch}

        return self._change(rid, renew)

    def rotate(self, owner, rid, *, scope="both"):
        self._owner(owner, rid)
        if scope not in {"public", "evidence", "both"}:
            raise Rejected(400, "invalid_scope")
        public, evidence = secrets.token_urlsafe(32), secrets.token_urlsafe(32)

        def rotate(run):
            if scope in {"public", "both"} and len(run.retired_public) >= 256 or scope in {"evidence", "both"} and len(run.retired_evidence) >= 256:
                raise Rejected(429, "rotation_limit")
            response = {"run_id": rid}
            if scope in {"public", "both"}:
                run.retired_public.append(run.public_hash)
                run.public_hash = digest(public)
                response["public_token"] = public
            if scope in {"evidence", "both"}:
                run.retired_evidence.append(run.evidence_hash)
                run.evidence_hash = digest(evidence)
                response["evidence_token"] = evidence
            for probe in run.probes.values():
                if not probe.sealed:
                    probe.dropped_events += 1
            return response

        return self._change(rid, rotate)

    def delete(self, owner, rid):
        self._owner(owner, rid)

        def remove(run):
            run.deleted = True
            return {"deleted": True}

        result = self._change(rid, remove)
        self.store.atomic_limit("admission", lambda old: ({**old, "active": {key: value for key, value in old.get("active", {}).items() if key != rid}}, None))
        return result

    def _probe(self, run, pid, *, expired=False):
        probe = run.probes.get(pid)
        if probe is None:
            raise Rejected(404, "not_found")
        if not expired and probe.expires_at <= self.clock():
            raise Rejected(410, "probe_expired")
        return probe

    def public(self, token, pid):
        hashed = digest(token)
        for run in self.store.list_runs(self.clock(), include_expired=True):
            if hmac.compare_digest(hashed, run.public_hash) or hashed in run.retired_public:
                if run.deleted or run.expires_at <= self.clock() or hashed != run.public_hash:
                    raise Rejected(410, "token_expired")
                self._probe(run, pid)
                return run
        raise Rejected(404, "not_found")

    def begin(self, rid, pid):
        def begin(run):
            probe = self._probe(run, pid)
            if probe.sealed or probe.sealing:
                return False
            probe.pending += 1
            return True

        return self._change(rid, begin)

    def record(self, rid, pid, *, method, route_class, parts, complete=True, prefetch=False, admitted=False):
        now = self.clock()
        current = self.store.get(rid, now)
        if current is None or current.deleted:
            raise Rejected(404, "not_found")
        current_probe = self._probe(current, pid)
        result = match_markers(current_probe.markers, parts, complete=complete, combination=current_probe.combination)
        event_id = secrets.token_hex(16)
        body_bytes = len(parts.get("body", "").encode())

        def record(run):
            probe = self._probe(run, pid)
            if admitted:
                probe.pending = max(0, probe.pending - 1)
            late = probe.sealed or probe.sealing and not admitted
            if late:
                if sum(len(item.late_events) for item in run.probes.values()) >= 1000:
                    return False
                probe.late_events.append(Event(event_id, len(probe.late_events) + 1, "late_request", route_class, method, complete, result["status"], result["hits"], body_bytes, prefetch, probe.epoch, now))
                return True
            if run.event_count >= 1000 or route_class.startswith("/sink/") and run.sink_count >= 50:
                probe.dropped_events += 1
                return False
            run.event_count += 1
            run.sink_count += int(route_class.startswith("/sink/"))
            if method == "GET" and route_class == "/scenario":
                probe.page_loads += 1
                probe.prefetch_count += int(prefetch)
            probe.events.append(Event(event_id, len(probe.events) + 1, "page_load" if route_class == "/scenario" else "sink_request", route_class, method, complete, result["status"], result["hits"], body_bytes, prefetch, probe.epoch, now))
            return True

        if not self._change(rid, record):
            raise Rejected(429, "event_limit")

    def dropped(self, rid, pid):
        def dropped(run):
            probe = self._probe(run, pid, expired=True)
            if not probe.sealed:
                probe.dropped_events += 1
        self._change(rid, dropped)

    def start_seal(self, owner, rid, pid):
        self._owner(owner, rid)

        def start(run):
            probe = self._probe(run, pid, expired=True)
            probe.sealing = True
            return probe.pending

        return self._change(rid, start)

    def seal(self, owner, rid, pid, reason):
        self._owner(owner, rid)
        if reason not in {"vendor_terminal", "timeout"}:
            raise Rejected(400, "invalid_seal_reason")

        def seal(run):
            probe = self._probe(run, pid, expired=True)
            if not probe.sealed:
                probe.sealed = True
                probe.sealing = False
                probe.seal_reason = reason
                probe.seal_revision = 1
                probe.snapshot = self._snapshot(run, probe)
                probe.snapshot_hash = digest(canonical(probe.snapshot))
            return {"snapshot_hash": probe.snapshot_hash, "sealed": True, "seal_revision": probe.seal_revision}

        return self._change(rid, seal)

    def _event(self, event):
        value = asdict(event)
        value.pop("event_id")
        value["redacted"] = True
        return value

    def _snapshot(self, run, probe):
        complete = probe.sealed and probe.seal_reason == "vendor_terminal" and probe.expires_at > self.clock() and probe.pending == 0 and probe.dropped_events == 0 and all(event.complete and event.marker_status != "unknown" and event.epoch == probe.epoch for event in probe.events)
        delivery = "not_delivered" if probe.page_loads == 0 else "unknown"
        return {"schema_version": 1, "run_id": run.run_id, "probe_id": probe.probe_id, "epoch": probe.epoch,
                "sealed": probe.sealed, "seal_revision": probe.seal_revision, "expires_at": probe.expires_at,
                "summary": {"interaction_count": len(probe.events), "page_loads": probe.page_loads, "prefetch_count": probe.prefetch_count, "delivery_state": delivery, "complete": complete, "dropped_events": probe.dropped_events},
                "events": [self._event(event) for event in probe.events], "protocol_snapshot": None}

    def evidence(self, token, rid, pid, *, cursor=None, limit=100, late_cursor=None):
        run = self.store.get(rid, self.clock(), include_expired=True)
        hashed = digest(token)
        if run is None or hashed != run.evidence_hash and hashed not in run.retired_evidence:
            raise Rejected(404, "not_found")
        if run.deleted or run.expires_at <= self.clock() or hashed != run.evidence_hash:
            raise Rejected(410, "token_expired")
        probe = self._probe(run, pid)
        if not isinstance(limit, int) or not 1 <= limit <= 100:
            raise Rejected(400, "invalid_limit")
        data = json.loads(canonical(probe.snapshot if probe.sealed else self._snapshot(run, probe)))
        revision = probe.snapshot_hash or "live"

        def offset(value, kind):
            if not value:
                return 0
            try:
                encoded, signature = value.split(".")
                payload = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)).decode()
                expected = hmac.new(hashed.encode(), payload.encode(), hashlib.sha256).hexdigest()
                decoded = json.loads(payload)
                if not hmac.compare_digest(signature, expected) or decoded[:4] != [rid, pid, revision, kind] or not isinstance(decoded[4], int) or decoded[4] < 0:
                    raise ValueError
                return decoded[4]
            except (ValueError, TypeError, IndexError, UnicodeError):
                raise Rejected(400, "invalid_cursor") from None

        def page(events, value, kind):
            start = offset(value, kind)
            end = start + limit
            if end < len(events):
                payload = canonical([rid, pid, revision, kind, end])
                signature = hmac.new(hashed.encode(), payload.encode(), hashlib.sha256).hexdigest()
                next_cursor = base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=") + "." + signature
            else:
                next_cursor = None
            return events[start:end], next_cursor

        data["events"], data["next_cursor"] = page(data["events"], cursor, "events")
        data["snapshot_hash"] = probe.snapshot_hash
        data["late_count"] = len(probe.late_events)
        data["late_events"], data["late_cursor"] = page([{**self._event(event), "late": True, "seal_revision": probe.seal_revision} for event in probe.late_events], late_cursor, "late")
        return data

    def cleanup(self):
        now = self.clock()
        nonce = secrets.token_hex(16)

        def claim(old):
            if old.get("until", 0) > now:
                return old, False
            return {"owner": nonce, "until": now + 120, "expires_at": now + 900}, True

        if not self.store.atomic_limit("cleanup", claim):
            return 0
        return self.store.purge(now)
