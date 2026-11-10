from __future__ import annotations

import asyncio
import os
import re
import uuid
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import httpx

from ._base import TargetDeliveryError
from argus.browser_runner.scenarios import dom_injection, os_cmd, ui_phishing, visual_injection
from argus_transport.security import Redactor, redacted_transport_logs


class HostedTrapError(TargetDeliveryError):
    def __init__(self, message: str, *, status: int | None = None):
        super().__init__(message)
        self.status = status


class UnsupportedHostedScenario(HostedTrapError):
    pass


@dataclass(frozen=True)
class HostedRun:
    run_id: str
    public_token: str = field(repr=False)
    evidence_token: str = field(repr=False)
    expires_at: float


class HostedClient:
    def __init__(self, spec):
        self.spec = spec
        self.redactor = Redactor()
        self._http = httpx.AsyncClient(timeout=10.0, trust_env=False)

    def _owner_token(self) -> str:
        token = os.environ.get(self.spec.owner_token_env)
        if not token:
            raise HostedTrapError(
                f"set {self.spec.owner_token_env} to an Entra access token for the hosted service"
            )
        self.redactor.add(token)
        return token

    def _register(self, run: HostedRun) -> None:
        self.redactor.add(run.public_token)
        self.redactor.add(run.evidence_token)

    async def _request(self, method, path, *, run=None, evidence=False, _return_status=False, **kwargs):
        if run is not None:
            self._register(run)
        token = run.evidence_token if evidence else self._owner_token()
        headers = {"Authorization": f"Bearer {token}", **kwargs.pop("headers", {})}
        try:
            with redacted_transport_logs(self.redactor):
                response = await self._http.request(
                    method, self.spec.service_url + path, headers=headers, **kwargs
                )
            try:
                data = response.json()
            except ValueError:
                data = None
            if not response.is_success:
                if evidence:
                    return self.unreadable()
                code = data.get("code", data.get("error")) if isinstance(data, dict) else None
                code = self.redactor.clean(code)
                if not isinstance(code, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", code):
                    code = "hosted_request_failed"
                raise HostedTrapError(
                    f"hosted service returned {response.status_code} {code}",
                    status=response.status_code,
                )
            if _return_status:
                return response.status_code
            if not isinstance(data, dict):
                if evidence:
                    return self.unreadable()
                raise HostedTrapError("hosted service returned an invalid response")
            return data
        except httpx.HTTPError:
            if evidence:
                return self.unreadable()
        raise HostedTrapError("hosted service request failed")

    @staticmethod
    def unreadable() -> dict:
        return {
            "summary": {"complete": False}, "events": [], "late_events": [],
            "next_cursor": None, "late_cursor": None,
            "unreadable": True, "reason": "evidence_unreadable",
        }

    async def create_run(self) -> HostedRun:
        data = await self._request(
            "POST", "/v1/runs", json={"schema_version": 1, "ttl_seconds": self.spec.run_ttl_s},
            headers={"Idempotency-Key": str(uuid.uuid4())},
        )
        for key in ("public_token", "evidence_token"):
            value = data.get(key)
            if isinstance(value, str):
                self.redactor.add(value)
        if not all(isinstance(data.get(key), str) and data[key] for key in ("run_id", "public_token", "evidence_token")) or not isinstance(data.get("expires_at"), (int, float)):
            raise HostedTrapError("hosted service returned an invalid run")
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", data["run_id"]):
            raise HostedTrapError("hosted service returned an invalid run")
        return HostedRun(data["run_id"], data["public_token"], data["evidence_token"], data["expires_at"])

    async def create_probe(self, run: HostedRun, *, payload, markers, lease_s, scenario_id="synthetic-page"):
        scenario_id = re.sub(r"[^A-Za-z0-9_-]", "", scenario_id)[:64] or "synthetic-page"
        data = await self._request(
            "POST", f"/v1/runs/{run.run_id}/probes", run=run,
            json={
                "kind": "browser", "scenario_id": scenario_id,
                "page_format": "html", "payload": payload, "public_token": run.public_token,
                "synthetic_markers": [{"marker_id": key, "value": value} for key, value in markers.items()],
                "ttl_seconds": lease_s,
            },
        )
        if not isinstance(data.get("probe_id"), str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", data["probe_id"]) or not isinstance(data.get("scenario_url"), str):
            raise HostedTrapError("hosted service returned an invalid probe")
        if "\\" in data["scenario_url"] or any(
            char.isspace() or ord(char) < 32 or ord(char) == 127 for char in data["scenario_url"]
        ):
            raise HostedTrapError("hosted service returned an invalid scenario URL")
        try:
            scenario = urlsplit(data["scenario_url"])
            service = urlsplit(self.spec.service_url)
            ports = {"http": 80, "https": 443}
            same_origin = (
                (scenario.scheme, scenario.hostname, scenario.port if scenario.port is not None else ports.get(scenario.scheme))
                == (service.scheme, service.hostname, service.port if service.port is not None else ports.get(service.scheme))
                and scenario.username is None and scenario.password is None
            )
        except ValueError:
            same_origin = False
        if not same_origin:
            raise HostedTrapError("hosted service returned a scenario URL outside its origin")
        return data["probe_id"], data["scenario_url"]

    async def seal(self, run: HostedRun, probe_id: str, reason: str) -> dict:
        return await self._request(
            "POST", f"/v1/runs/{run.run_id}/probes/{probe_id}/seal", run=run, json={"reason": reason}
        )

    async def evidence(self, run: HostedRun, probe_id: str, *, cursor=None, late_cursor=None) -> dict:
        params = {"probe_id": probe_id, "limit": 100}
        if cursor is not None:
            params["cursor"] = cursor
        if late_cursor is not None:
            params["late_cursor"] = late_cursor
        return await self._request("GET", f"/v1/runs/{run.run_id}/evidence", run=run, evidence=True, params=params)

    async def delete_run(self, run: HostedRun) -> int:
        return await self._request("DELETE", f"/v1/runs/{run.run_id}", run=run, _return_status=True)

    async def aclose(self) -> None:
        await self._http.aclose()

_SCENARIOS = {
    "dom_injection": dom_injection,
    "ui_phishing": ui_phishing,
    "visual_injection": visual_injection,
    "os_cmd": os_cmd,
}


def render_hosted_scenario(scenario_kind: str, payload: str, **options) -> str:
    if scenario_kind == "visual_injection":
        raise UnsupportedHostedScenario("visual_injection is unsupported with trap_mode=hosted")
    from argus.browser_runner.scenarios._options import validate_options

    options = dict(validate_options(scenario_kind, options))
    # Hosted HTML has a 16 KiB limit and a CSP that disallows downloadable fonts.
    if scenario_kind == "os_cmd":
        options["_include_font"] = False
    content, _ = _SCENARIOS[scenario_kind].render(payload, **options)
    if not isinstance(content, str):
        raise UnsupportedHostedScenario("hosted scenarios require HTML")
    return content

def _count(value):
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def _valid_page(page):
    summary = page.get("summary")
    return (
        isinstance(summary, dict)
        and isinstance(summary.get("complete"), bool)
        and all(isinstance(summary.get(key), int) and not isinstance(summary[key], bool) and summary[key] >= 0
                for key in ("page_loads", "prefetch_count", "dropped_events"))
        and all(isinstance(page.get(key), list) and all(isinstance(event, dict) for event in page[key])
                for key in ("events", "late_events"))
        and all(page.get(key) is None or isinstance(page[key], str) for key in ("next_cursor", "late_cursor"))
    )


class HostedTrap:
    def __init__(self, client: HostedClient, run: HostedRun, markers: dict, lease_s: int, *, scenario_id="synthetic-page", html: str | None = None):
        self.client = client
        self.redactor = client.redactor
        self.html = html
        self.run = run
        self.markers = markers
        self.lease_s = lease_s
        self.scenario_id = scenario_id
        self.probe_id = None
        self._evidence = None
        self._url = ""

    async def open(self, html_or_render) -> str:
        source = self.html if html_or_render is None else html_or_render
        content = source() if callable(source) else source
        if not isinstance(content, str):
            raise UnsupportedHostedScenario("visual_injection is unsupported with trap_mode=hosted")
        self.probe_id, self._url = await self.client.create_probe(
            self.run, payload=content, markers=self.markers, lease_s=self.lease_s, scenario_id=self.scenario_id
        )
        return self._url

    def public_url(self) -> str:
        return self.client.redactor.clean(self._url)

    async def close(self, *, terminal: bool) -> dict:
        if self._evidence is not None:
            return self._evidence
        if self.probe_id is None:
            return {}
        await self.client.seal(self.run, self.probe_id, "vendor_terminal" if terminal else "timeout")
        normal_events = []
        late_events = []
        cursor = late_cursor = None
        normal_pending = late_pending = True
        first = None
        unreadable = False
        for _ in range(10):
            page = await self.client.evidence(self.run, self.probe_id, cursor=cursor, late_cursor=late_cursor)
            if page.get("unreadable") or not _valid_page(page):
                unreadable = True
                break
            if first is None:
                first = page
            elif page.get("snapshot_hash") != first.get("snapshot_hash"):
                unreadable = True
            if normal_pending:
                normal_events.extend(page["events"])
                cursor = page.get("next_cursor")
                normal_pending = cursor is not None
            if late_pending:
                late_events.extend(page["late_events"])
                late_cursor = page.get("late_cursor")
                late_pending = late_cursor is not None
            if not normal_pending and not late_pending:
                break
        else:
            unreadable = normal_pending or late_pending
        summary = (first or {}).get("summary", {})
        requests = []
        for event in normal_events:
            route = event.get("route_class", "")
            if isinstance(route, str) and route.startswith("/sink/"):
                hits = event.get("canary_hits", [])
                valid_hits = isinstance(hits, list) and all(isinstance(hit, dict) and isinstance(hit.get("marker_id"), str) and isinstance(hit.get("location"), str) for hit in hits)
                requests.append({
                    "method": event.get("method") if isinstance(event.get("method"), str) else "UNKNOWN",
                    "path": route, "query": "", "body": "", "complete": event.get("complete") is True and valid_hits,
                    "redacted": True, "marker_hits": hits if valid_hits else [],
                    "body_bytes": event.get("body_bytes"),
                })
        loads = _count(summary.get("page_loads"))
        late_hits = sum(len(event.get("canary_hits", [])) for event in late_events if isinstance(event.get("canary_hits"), list))
        self._evidence = self.client.redactor.clean({
            "interaction_count": loads + len(requests), "page_loads": loads, "trap_requests": requests,
            "hosted": {"markers": self.markers, "rounds": [{
                "probe_id": self.probe_id, "seal_revision": _count((first or {}).get("seal_revision")),
                "snapshot_hash": (first or {}).get("snapshot_hash") or "",
                "complete": terminal and summary.get("complete") is True and not unreadable,
                "page_loads": loads, "prefetch_count": _count(summary.get("prefetch_count")),
                "dropped_events": _count(summary.get("dropped_events")),
                "late_count": _count((first or {}).get("late_count")),
                "late_marker_hits": late_hits, "unreadable": unreadable,
            }]},
        })
        return self._evidence
