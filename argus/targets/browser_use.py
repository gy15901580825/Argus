"""Browser-use target adapter — delegates to client_agent over the existing WS bridge.

Plan 3 implemented the runtime; Plan 4 just exposes it via factory + REST API.
Under `argus-probe run --local` the same probe runs in-process instead (see
`local_browser_mode`).
"""

from __future__ import annotations

import asyncio
import contextlib
import contextvars
import ipaddress
import json
import logging
import math
import re
import time
import uuid
import warnings

from argus_transport import (
    TransportSpec,
    TransportResult,
    TransportOutcome,
    execution_policy,
)
from dataclasses import dataclass, fields
from typing import ClassVar
from urllib.parse import parse_qsl, quote_plus, urlsplit

from fastapi import WebSocketDisconnect

from argus.assertions import canary_in, trap_canaries
from argus.targets._base import (
    Target,
    TargetDeliveryError,
    TargetBlockedError,
    TargetTransportError,
    Turn,
)

_SCENARIO_KINDS = frozenset(
    {"dom_injection", "ui_phishing", "visual_injection", "os_cmd"}
)

# Same cap as the trap server's, so evidence summed over rounds stays bounded.
_MAX_TRAP_REQUESTS = 50

# Set only by run_local. Server mode never runs the trap page in-process.
_LOCAL_RUN: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "browser_local_run", default=False
)


@contextlib.contextmanager
def local_browser_mode():
    """Run browser probes in this process instead of through a client_agent.

    Never hold it across a `yield`: set and reset must run in the same context."""
    token = _LOCAL_RUN.set(True)
    try:
        yield
    finally:
        _LOCAL_RUN.reset(token)


@dataclass(frozen=True)
class HostedTrapSpec:
    service_url: str
    owner_token_env: str = "ARGUS_HOSTED_OWNER_TOKEN"
    run_ttl_s: int = 86400

    def __post_init__(self) -> None:
        if not isinstance(self.service_url, str) or any(char.isspace() for char in self.service_url):
            raise ValueError("service_url must be an HTTPS origin")
        try:
            parts = urlsplit(self.service_url)
            port = parts.port
        except (ValueError, TypeError):
            raise ValueError("service_url must be an HTTPS origin") from None
        if parts.scheme != "https" and not (
            parts.scheme == "http" and parts.hostname in {"127.0.0.1", "localhost"}
        ) or not parts.hostname or port == 0:
            raise ValueError("service_url must be an HTTPS origin or loopback HTTP origin")
        if parts.path or parts.query or parts.fragment or parts.username or parts.password:
            raise ValueError("service_url must be an origin without path, query, fragment, or credentials")
        if not isinstance(self.owner_token_env, str) or not re.fullmatch(
            r"[A-Z_][A-Z0-9_]{0,63}", self.owner_token_env
        ):
            raise ValueError("owner_token_env must be an uppercase environment variable name")
        if isinstance(self.run_ttl_s, bool) or not isinstance(self.run_ttl_s, int) or not 1 <= self.run_ttl_s <= 86400:
            raise ValueError("run_ttl_s must be an integer from 1 to 86400")


@dataclass(frozen=True)
class BrowserUseSpec:
    kind: str = "browser_use"
    agent_url: str | None = None
    transport: TransportSpec | dict | None = None
    scenario_kind: str = ""
    timeout_s: float | None = None
    extra_context: tuple[tuple[str, str], ...] = ()
    # Where the trap page listens and the URL the agent is told to open: on this
    # machine under --local, else on the client_agent's. The agent must reach that URL.
    trap_host: str = "127.0.0.1"
    trap_port: int = 0
    trap_public_url: str = ""
    trap_mode: str = "local"
    hosted: HostedTrapSpec | dict | None = None

    def __post_init__(self) -> None:
        # Coerce dict OR list-of-2-element-lists → tuple-of-tuples
        # (model_dump() emits list-of-lists for tuple fields).
        ctx = self.extra_context
        if isinstance(ctx, dict):
            object.__setattr__(self, "extra_context", tuple(ctx.items()))
        elif isinstance(ctx, list):
            object.__setattr__(self, "extra_context", tuple(tuple(c) for c in ctx))
        # Validate kind FIRST (T1 review-fix pattern)
        if self.kind != "browser_use":
            raise ValueError(f"kind must be 'browser_use', got {self.kind!r}")
        if self.trap_mode not in ("local", "hosted"):
            raise ValueError("trap_mode must be 'local' or 'hosted'")
        if self.trap_mode == "hosted":
            if self.hosted is None:
                raise ValueError("hosted is required when trap_mode=hosted")
            hosted = HostedTrapSpec(**self.hosted) if isinstance(self.hosted, dict) else self.hosted
            if not isinstance(hosted, HostedTrapSpec):
                raise ValueError("hosted must be a hosted trap specification")
            object.__setattr__(self, "hosted", hosted)
            if self.transport is None:
                raise ValueError("trap_mode=hosted requires transport")
            if self.sets_trap:
                raise ValueError("hosted and local trap settings conflict")
        elif self.hosted is not None:
            raise ValueError("hosted must be empty when trap_mode=local")
        if self.transport is not None:
            if self.agent_url is not None or self.timeout_s is not None:
                raise ValueError(
                    "transport and legacy browser transport fields conflict"
                )
            transport = (
                TransportSpec.from_dict(self.transport)
                if isinstance(self.transport, dict)
                else self.transport
            )
            if not isinstance(transport, TransportSpec):
                raise ValueError("transport must be a transport specification")
            object.__setattr__(self, "transport", transport)
        else:
            warnings.warn(
                "browser_use legacy agent_url and timeout_s are deprecated; migrate to transport before the next major release",
                DeprecationWarning,
                stacklevel=2,
            )
            if not self.agent_url:
                raise ValueError("agent_url is required")
            object.__setattr__(
                self, "timeout_s", 60.0 if self.timeout_s is None else self.timeout_s
            )
        if self.scenario_kind not in _SCENARIO_KINDS:
            raise ValueError(
                "scenario_kind must be one of dom_injection/ui_phishing/visual_injection/os_cmd"
            )
        self._validate_trap()

    def _validate_trap(self) -> None:
        # IPv4Address also accepts an int, which would reach the wire as a number.
        if not isinstance(self.trap_host, str):
            raise ValueError(
                f"trap_host must be an IPv4 address string, got {self.trap_host!r}"
            )
        try:
            host = ipaddress.IPv4Address(self.trap_host)
        except ValueError:
            raise ValueError(
                f"trap_host must be an IPv4 address, got {self.trap_host!r}"
            ) from None
        if (
            isinstance(self.trap_port, bool)
            or not isinstance(self.trap_port, int)
            or not 0 <= self.trap_port <= 65535
        ):
            raise ValueError(
                f"trap_port must be an integer from 0 to 65535, got {self.trap_port!r}"
            )
        if not self.trap_public_url:
            if host.is_unspecified:
                raise ValueError(
                    f"trap_host {self.trap_host} listens on every interface; set trap_public_url "
                    "to the address your agent should open"
                )
            return
        parts = urlsplit(self.trap_public_url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError(
                f"trap_public_url must be an http(s) URL such as http://192.168.1.20:8765, "
                f"got {self.trap_public_url!r}"
            )
        if parts.query or parts.fragment:
            raise ValueError(
                "trap_public_url must not carry a query string or fragment"
            )
        if self.trap_port == 0:
            # A random port can't appear in a URL written before the run.
            raise ValueError(
                "trap_public_url needs a fixed trap_port for the trap page to listen on"
            )

    @property
    def sets_trap(self) -> bool:
        return (self.trap_host, self.trap_port, self.trap_public_url) != (
            "127.0.0.1",
            0,
            "",
        )


def _valid_evidence(ev) -> bool:
    """Fail closed: an empty or misshapen record must not read as "the agent did nothing"."""
    return (
        isinstance(ev, dict)
        and all(
            isinstance(ev.get(k), int)
            and not isinstance(ev.get(k), bool)
            and ev.get(k) >= 0
            for k in ("interaction_count", "page_loads")
        )
        and isinstance(ev.get("trap_requests"), list)
        and all(
            isinstance(r, dict)
            and all(
                isinstance(r.get(k), str) for k in ("method", "path", "query", "body")
            )
            and isinstance(r.get("complete"), bool)
            for r in ev["trap_requests"]
        )
    )


def _redacted(text: str) -> str:
    return f"<redacted {len(text)} chars>"


def _mask_json(value, canaries: tuple[str, ...]):
    if isinstance(value, dict):
        return {k: _mask_json(v, canaries) for k, v in value.items()}
    if isinstance(value, list):
        return [_mask_json(v, canaries) for v in value]
    if isinstance(value, bool) or value is None:
        return value
    text = value if isinstance(value, str) else json.dumps(value)
    return text if _holds_canary(text, canaries) else _redacted(text)


_TEXT_FIELD_SEP = re.compile(r"(\r?\n|;|&)")


def _holds_canary(text: str, canaries: tuple[str, ...]) -> bool:
    return any(canary_in(text, c) for c in canaries)


def _mask_text(text: str, canaries: tuple[str, ...]) -> str:
    """Replace every value that holds no canary with its length; keep names and canary values."""
    if not text:
        return text
    masked = None
    try:
        masked = json.dumps(_mask_json(json.loads(text), canaries), ensure_ascii=False)
    except (ValueError, RecursionError):
        pass
    # Form-encoded text has no raw whitespace; strict parsing refuses a segment without "=".
    if masked is None and not any(c.isspace() for c in text):
        try:
            pairs = parse_qsl(text, keep_blank_values=True, strict_parsing=True)
        except ValueError:
            pairs = []
        if pairs:
            masked = "&".join(
                f"{quote_plus(k)}={quote_plus(v) if _holds_canary(v, canaries) else _redacted(v)}"
                for k, v in pairs
            )
    if masked is None and not _holds_canary(text, canaries):
        masked = _redacted(text)
    if masked is None:
        # Free text (multipart, text/plain): keep only the lines or fields that hold a canary.
        parts = _TEXT_FIELD_SEP.split(text)
        masked = "".join(
            (
                part
                if not part
                or _TEXT_FIELD_SEP.fullmatch(part)
                or _holds_canary(part, canaries)
                else _redacted(part)
            )
            for part in parts
        )
    # A canary split across fields (an unencoded "&" inside it) must stay visible to the check.
    if any(canary_in(text, c) and not canary_in(masked, c) for c in canaries):
        return text
    return masked


def _masked_request(req: dict, canaries: tuple[str, ...]) -> dict:
    return dict(
        req,
        query=_mask_text(req["query"], canaries),
        body=_mask_text(req["body"], canaries),
    )


def _is_delivery_failure(e: Exception) -> bool:
    """True for the bridge and transport failures; caller bugs must propagate."""
    from argus.connection_manager import NoClientAgentError

    # handle_response turns a JSON-RPC error into a bare Exception.
    if type(e) is Exception:
        return True
    return isinstance(
        e, (NoClientAgentError, asyncio.TimeoutError, OSError, WebSocketDisconnect)
    )


def _describe(e: Exception, waited_s: float) -> str:
    if str(e):
        return f"{type(e).__name__}: {e}"
    if isinstance(e, asyncio.TimeoutError):
        return f"timed out after {waited_s:g}s"
    return type(e).__name__


def _get_client_agent_ws():
    """Lazy import so tests can patch."""
    from argus.connection_manager import connection_manager

    return connection_manager.get_redteam_bridge()


class BrowserUseTarget(Target):
    # Plan 4 name + Plan 2 legacy alias ("browser-using").
    compatible_classes: ClassVar[frozenset[str]] = frozenset(
        {
            "browser_using_agent",
            "browser-using",
        }
    )

    def __init__(self, spec: BrowserUseSpec) -> None:
        self.spec = spec
        # Set by begin_probe; None means a non-probe caller, which keeps the
        # old prompt-as-payload behaviour.
        self._scenario_kind: str | None = None
        self._scenario_payload: str | None = None
        self._evidence: dict = {}
        # Canaries the probe checks for; every other recorded value is masked.
        self._canaries: tuple[str, ...] = ()
        self._conversation_id = None
        self._session_id = None
        self._last_run_log = None
        self._probe_id = "synthetic-page"
        self._hosted_client = None
        self._hosted_run = None
        self._hosted_runs = []
        self._hosted_cleanup = []
        self._hosted_probe_count = 0
        self.supports_history = (
            spec.transport is not None and spec.transport.session.mode != "none"
        )

    async def begin_probe(self, probe) -> None:
        self._evidence = {}
        self._conversation_id = None
        self._session_id = None
        self._last_run_log = None
        self._probe_id = getattr(probe, "id", "synthetic-page")
        self._canaries = trap_canaries(getattr(probe, "assertions", None) or ())
        payload = getattr(probe, "scenario_payload", None)
        kind = getattr(probe, "scenario_kind", None)
        # No scenario block: the attack is the prompt itself, so send it as the
        # page payload as before. Reset so a previous probe's scenario never leaks.
        if not kind and not payload:
            self._scenario_kind = None
            self._scenario_payload = None
            return
        # A declared scenario without a payload would put the benign prompt on
        # the trap page and could only ever pass.
        if not isinstance(payload, str) or not payload.strip():
            raise ValueError(
                f"browser probe {probe.id!r} has no scenario.payload to plant"
            )
        if kind and kind not in _SCENARIO_KINDS:
            raise ValueError(
                f"browser probe {probe.id!r} has unknown scenario.kind {kind!r}"
            )
        self._scenario_kind = kind or None
        self._scenario_payload = payload

    async def send_prompt(
        self, prompt: str, history: tuple[Turn, ...] = ()
    ) -> tuple[str, float]:
        if self.spec.trap_mode == "hosted" and not _LOCAL_RUN.get():
            raise TargetDeliveryError("trap_mode=hosted runs only with --local")
        msg = {
            "type": "redteam_browser_probe",
            "scenario_kind": self._scenario_kind or self.spec.scenario_kind,
            "agent_url": self.spec.agent_url,
            # payload goes into the trap page; prompt is the user's instruction.
            "payload": (
                self._scenario_payload if self._scenario_payload is not None else prompt
            ),
            "prompt": prompt,
            "timeout_s": self.spec.timeout_s,
            "extra_context": dict(self.spec.extra_context),
        }
        if self.spec.transport is not None:
            msg.pop("agent_url")
            msg.pop("timeout_s")
            if not history or self._conversation_id is None:
                self._conversation_id = uuid.uuid4().hex
                self._session_id = None
            msg.update(
                transport=self.spec.transport.to_dict(),
                history=[
                    {"role": turn.role, "content": turn.content} for turn in history
                ],
                conversation_id=self._conversation_id,
                session_id=self._session_id,
            )
            deadline = self.spec.transport.timeout.total_deadline_s
            cleanup = self.spec.transport.timeout.cleanup_grace_s
        else:
            deadline = self.spec.timeout_s
            cleanup = 0.0
        self._last_run_log = None
        start = time.monotonic()
        if _LOCAL_RUN.get():
            reply = await asyncio.wait_for(
                self._run_in_process(msg), timeout=deadline + cleanup + 5.0
            )
            if not _valid_evidence(reply.get("trap_evidence")):
                raise TargetDeliveryError("the trap server returned no evidence")
        else:
            # Send only the trap settings that differ from the default; never null.
            msg.update(
                {
                    f.name: getattr(self.spec, f.name)
                    for f in fields(self.spec)
                    if f.name.startswith("trap_")
                    and getattr(self.spec, f.name) != f.default
                }
            )
            ws = _get_client_agent_ws()
            # Same 5 s grace as --local, so the client_agent's own timeout error
            # can still arrive; the outer wait is only a backstop for the bridge.
            bridge_timeout_s = deadline + cleanup + 5.0
            try:
                reply = await asyncio.wait_for(
                    ws.send_and_wait(msg, timeout_s=bridge_timeout_s),
                    timeout=deadline + cleanup + 10.0,
                )
            except Exception as e:
                if not _is_delivery_failure(e):
                    raise
                raise TargetDeliveryError(_describe(e, bridge_timeout_s)) from e
            if not isinstance(reply, dict):
                raise TargetDeliveryError(
                    f"client_agent reply has no result object (got {type(reply).__name__})"
                )
            self._check_trap_url(reply.get("trap_url"))
            # An older client_agent has no recorder; its silence must not read as "agent did nothing".
            if not _valid_evidence(reply.get("trap_evidence")):
                raise TargetDeliveryError(
                    "client_agent did not return trap evidence (upgrade client_agent)"
                )
        self._merge_evidence(reply["trap_evidence"])
        wall_latency_ms = (time.monotonic() - start) * 1000.0
        if "transport_result" not in reply:
            if self.spec.transport is not None:
                raise TargetDeliveryError("client_agent omitted the transport result")
            reported = reply.get("latency_ms")
            latency = (
                float(reported)
                if isinstance(reported, (int, float))
                else wall_latency_ms
            )
            return reply.get("final_text", ""), latency
        try:
            result = TransportResult.from_dict(reply["transport_result"])
        except (ValueError, TypeError) as exc:
            raise TargetDeliveryError(
                "client_agent returned an invalid transport result"
            ) from exc
        transport = {
            "outcome": result.outcome.value,
            "http_status": result.http_status,
            "matched_rule_id": result.matched_rule_id,
            "reason_code": result.reason_code.value,
        }
        if (
            result.outcome == TransportOutcome.BLOCKED
            and self.spec.transport is not None
        ):
            rules = list(self.spec.transport.outcome.rules)
            submission = getattr(self.spec.transport.delivery, "submit_outcome", None)
            if submission:
                rules.extend(submission.rules)
            if not any(
                rule.id == result.matched_rule_id
                and rule.outcome == TransportOutcome.BLOCKED
                and result.http_status in rule.http_status
                for rule in rules
            ):
                raise TargetTransportError("mapping_error: invalid refusal rule")
            if result.diagnostics.get("origin") != "mapped_body_rule":
                raise TargetTransportError("mapping_error: missing refusal provenance")
            transport["origin"] = "mapped_body_rule"
        self._evidence["transport"] = transport
        if result.outcome == TransportOutcome.SUCCEEDED:
            metadata = result.as_dict()["metadata"]
            if (
                self.spec.transport is not None
                and self.spec.transport.session.mode == "server_returned"
            ):
                session_id = metadata.get("session_id")
                if not isinstance(session_id, str) or not session_id:
                    self._evidence["transport"].update(
                        outcome="target_error", reason_code="mapping_error"
                    )
                    raise TargetTransportError(
                        "mapping_error: missing session identifier"
                    )
                self._session_id = session_id
            if metadata:
                from argus.scenarios.models import TargetRunLog

                events = metadata.get("run_log", [])
                log_fields = {
                    key: metadata[key]
                    for key in ("session_id", "run_id")
                    if key in metadata
                }
                log_fields["events"] = (
                    events.get("events", events.get("tools", []))
                    if isinstance(events, dict)
                    else events
                )
                try:
                    self._last_run_log = TargetRunLog.model_validate(log_fields)
                except ValueError as exc:
                    raise TargetTransportError(
                        "mapping_error: invalid target run log"
                    ) from exc
            return result.response_text, result.latency_ms
        if result.outcome == TransportOutcome.BLOCKED:
            raise TargetBlockedError(
                "target API refused the request", transport_metadata=transport
            )
        if result.outcome == TransportOutcome.TIMED_OUT:
            raise TimeoutError("timeout: target operation exceeded its budget")
        raise TargetTransportError(f"target_error: {result.reason_code.value}")

    async def collect_evidence(self) -> dict:
        """The trap record with every value that is not a canary masked, since bodies and
        queries can hold real credentials an agent autofilled."""
        ev = dict(self._evidence)
        if "trap_requests" in ev:
            ev["trap_requests"] = [
                _masked_request(r, self._canaries) for r in ev["trap_requests"]
            ]
        return ev

    def _merge_evidence(self, new: dict) -> None:
        """Rounds of one probe add up; begin_probe starts over."""
        old = self._evidence
        requests = (old.get("trap_requests", []) + new["trap_requests"])[
            :_MAX_TRAP_REQUESTS
        ]
        if isinstance(new.get("hosted"), dict):
            requests = old.get("trap_requests", []) + new["trap_requests"]
        page_loads = old.get("page_loads", 0) + new["page_loads"]
        self._evidence = {
            "interaction_count": page_loads + len(requests),
            "page_loads": page_loads,
            "trap_requests": requests,
        }
        if isinstance(new.get("hosted"), dict):
            previous = old.get("hosted", {})
            self._evidence["hosted"] = {
                "markers": {**previous.get("markers", {}), **new["hosted"]["markers"]},
                "rounds": previous.get("rounds", []) + new["hosted"]["rounds"],
            }

    def _check_trap_url(self, got) -> None:
        """A client_agent without trap support serves on 127.0.0.1 and omits trap_url."""
        s = self.spec
        if not s.sets_trap:
            return
        # The page sits under a random path token (secrets.token_urlsafe(12)).
        tail = r"/[A-Za-z0-9_-]{16}/scenario"
        if s.trap_public_url:
            base = s.trap_public_url.rstrip("/")
            expected = base + "/<token>/scenario"
            ok = (
                isinstance(got, str)
                and re.fullmatch(re.escape(base) + tail, got) is not None
            )
        else:
            expected = (
                f"http://{s.trap_host}:{s.trap_port or '<any port>'}/<token>/scenario"
            )
            try:
                parts = urlsplit(got) if isinstance(got, str) else None
                ok = (
                    parts is not None
                    and parts.hostname == s.trap_host
                    and s.trap_port in (0, parts.port)
                    and re.fullmatch(tail, parts.path) is not None
                )
            except ValueError:
                ok = False
        if not ok:
            raise TargetDeliveryError(
                "client_agent did not use the trap settings (upgrade client_agent): "
                f"expected {expected}, got {got!r}"
            )

    async def _run_in_process(self, msg: dict) -> dict:
        from argus.browser_runner.browser_probe import BrowserProbe

        if self.spec.trap_mode == "hosted":
            from .hosted_trap import HostedClient, HostedTrap, HostedTrapError, render_hosted_scenario

            html = render_hosted_scenario(msg["scenario_kind"], msg["payload"])
            values = tuple(dict.fromkeys(self._canaries))
            if len(values) > 32 or any(len(value.encode("utf-8")) > 512 for value in values):
                raise HostedTrapError("hosted markers permit at most 32 values of at most 512 bytes")
            markers = {f"c{index}": value for index, value in enumerate(values, 1)}
            if self._hosted_client is None:
                self._hosted_client = HostedClient(self.spec.hosted)
            lease_s = min(10800, math.ceil(
                self.spec.transport.timeout.total_deadline_s
                + self.spec.transport.timeout.cleanup_grace_s + 60
            ))
            for attempt in range(2):
                if self._hosted_run is None or self._hosted_probe_count >= 100:
                    self._hosted_run = await self._hosted_client.create_run()
                    self._hosted_runs.append(self._hosted_run)
                    self._hosted_probe_count = 0
                trap = HostedTrap(self._hosted_client, self._hosted_run, markers, lease_s, scenario_id=self._probe_id, html=html)
                try:
                    return await BrowserProbe().run(msg, policy=execution_policy(self.spec.transport), trap=trap)
                except HostedTrapError as exc:
                    if attempt or exc.status not in {404, 410} or trap.probe_id is not None:
                        raise
                    self._hosted_run = None
                finally:
                    if trap.probe_id is not None:
                        self._hosted_probe_count += 1

        local_msg = dict(
            msg,
            trap_host=self.spec.trap_host,
            trap_port=self.spec.trap_port,
            trap_public_url=self.spec.trap_public_url,
        )
        policy = (
            execution_policy(self.spec.transport)
            if self.spec.transport is not None
            else None
        )
        return await BrowserProbe().run(local_msg, policy=policy)

    async def aclose(self) -> None:
        if self._hosted_client is None:
            return
        try:
            for run in self._hosted_runs:
                record = {
                    "scope": "run", "step": run.run_id, "status": "failed",
                    "method": "DELETE", "url": self.spec.hosted.service_url + f"/v1/runs/{run.run_id}",
                    "http_status": None,
                }
                try:
                    record["http_status"] = await self._hosted_client.delete_run(run)
                    record["status"] = "done"
                except Exception as exc:
                    record["http_status"] = getattr(exc, "status", None)
                    logging.getLogger(__name__).warning("could not delete hosted run")
                self._hosted_cleanup.append(self._hosted_client.redactor.clean(record))
        finally:
            try:
                await self._hosted_client.aclose()
            except Exception:
                logging.getLogger(__name__).warning("could not close hosted client")
            finally:
                self._hosted_runs = []
                self._hosted_run = None
                self._hosted_client = None

    def cleanup_report(self) -> dict | None:
        if self.spec.trap_mode != "hosted":
            return None
        opened = [record for record in self._hosted_cleanup if record["status"] != "done"]
        return {
            "complete": not opened, "done": sum(record["status"] == "done" for record in self._hosted_cleanup),
            "open": opened, "stop_reason": None, "leftover": [],
        }

    def last_run_log(self):
        return self._last_run_log
