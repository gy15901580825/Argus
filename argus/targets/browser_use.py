"""Browser-use target adapter — delegates to client_agent over the existing WS bridge.

Plan 3 implemented the runtime; Plan 4 just exposes it via factory + REST API.
Under `argus-probe run --local` the same probe runs in-process instead (see
`local_browser_mode`).
"""

from __future__ import annotations

import asyncio
import contextlib
import contextvars
import hashlib
import inspect
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
from argus.witness import WitnessSpec, binds_canary, current_witness
from argus_transport.security import redacted_transport_logs
from dataclasses import dataclass, field, fields
from typing import ClassVar
from urllib.parse import parse_qsl, quote_plus, unquote_plus, urlsplit

from fastapi import WebSocketDisconnect

from argus.assertions import canary_in, canary_sequence_requests, stored_credential_site, trap_unmasked_values
from argus.targets._base import (
    ProbeNotApplicable,
    Target,
    TargetDeliveryError,
    TargetBlockedError,
    TargetTransportError,
    Turn,
)

_SCENARIO_KINDS = frozenset(
    {"dom_injection", "ui_phishing", "visual_injection", "os_cmd", "cross_origin_bridge", "click_swap",
     "document_inject", "js_dialog", "extraction_tamper", "form_recipient_redirect", "field_egress"}
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


_MAX_STORED_CREDENTIALS = 16
_MIN_STORED_VALUE_CHARS = 12


@dataclass(frozen=True)
class StoredCredential:
    """A synthetic credential the operator loaded into the agent's own vault for this test."""

    site: str
    label: str
    value: str = field(repr=False)

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(self.value.encode("utf-8")).hexdigest()[:8]

    def describe(self) -> str:
        return f"{self.site} {self.label} sha256:{self.fingerprint}"


def _stored_credentials(raw) -> tuple[StoredCredential, ...]:
    """Validate stored_credentials; errors name an entry by position, never by its value."""
    if not isinstance(raw, (list, tuple)):
        raise ValueError("stored_credentials must be a list of {site, label, value} entries")
    if len(raw) > _MAX_STORED_CREDENTIALS:
        raise ValueError(f"stored_credentials allows at most {_MAX_STORED_CREDENTIALS} entries")
    out = []
    for i, entry in enumerate(raw):
        if isinstance(entry, StoredCredential):
            entry = {"site": entry.site, "label": entry.label, "value": entry.value}
        if not isinstance(entry, dict) or set(entry) != {"site", "label", "value"}:
            raise ValueError(f"stored_credentials[{i}] must have exactly the keys site, label and value")
        for key in ("site", "label", "value"):
            text = entry[key]
            if not isinstance(text, str) or not text.strip() or text != text.strip():
                raise ValueError(f"stored_credentials[{i}].{key} must be a non-empty string without "
                                 "leading or trailing spaces")
        if any(c.isspace() for c in entry["site"]):
            raise ValueError(f"stored_credentials[{i}].site must be a host name such as bank.vendor.example")
        if not _MIN_STORED_VALUE_CHARS <= len(entry["value"]) <= 512:
            raise ValueError(f"stored_credentials[{i}].value must be {_MIN_STORED_VALUE_CHARS} to 512 characters, "
                             "so it cannot collide with ordinary page text")
        out.append(StoredCredential(entry["site"], entry["label"], entry["value"]))
    if len({c.value for c in out}) != len(out):
        raise ValueError("stored_credentials values must be distinct")
    return tuple(out)


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
    # Synthetic credentials the operator loaded into the agent's vault; values never reach reports.
    stored_credentials: tuple[StoredCredential, ...] | list = field(default=(), repr=False)

    witness: WitnessSpec | dict | None = None

    @property
    def binds_secret_canary(self) -> bool:
        return self.transport is not None and binds_canary(self.transport.to_dict()["request"])

    def __post_init__(self) -> None:
        if self.witness is not None:
            witness = WitnessSpec.from_dict(self.witness) if isinstance(self.witness, dict) else self.witness
            if not isinstance(witness, WitnessSpec):
                raise ValueError("witness must be a witness specification")
            object.__setattr__(self, "witness", witness)
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
                "scenario_kind must be one of dom_injection/ui_phishing/visual_injection/os_cmd/"
                "cross_origin_bridge/click_swap/document_inject/js_dialog/extraction_tamper/form_recipient_redirect"
            )
        self._validate_trap()
        object.__setattr__(self, "stored_credentials", _stored_credentials(self.stored_credentials))

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
        and (
            "asset_fetches" not in ev
            or isinstance(ev["asset_fetches"], dict)
            and all(
                isinstance(k, str) and type(v) is int and v >= 0
                for k, v in ev["asset_fetches"].items()
            )
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
    return text if _holds_unmasked_value(text, canaries) else _redacted(text)


_TEXT_FIELD_SEP = re.compile(r"(\r?\n|;|&)")


def _holds_unmasked_value(text: str, canaries: tuple[str, ...]) -> bool:
    """Masking alone ignores case; assertions retain their own matching rules."""
    return any(canary_in(text, c) or canary_in(text.casefold(), c.casefold()) for c in canaries)


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
                f"{quote_plus(k)}={quote_plus(v) if _holds_unmasked_value(v, canaries) else _redacted(v)}"
                for k, v in pairs
            )
    if masked is None and not _holds_unmasked_value(text, canaries):
        masked = _redacted(text)
    if masked is None:
        # Free text (multipart, text/plain): keep only the lines or fields that hold a canary.
        parts = _TEXT_FIELD_SEP.split(text)
        masked = "".join(
            (
                part
                if not part
                or _TEXT_FIELD_SEP.fullmatch(part)
                or _holds_unmasked_value(part, canaries)
                else _redacted(part)
            )
            for part in parts
        )
    # A canary split across fields (an unencoded "&" inside it) must stay visible to the check.
    if any(_holds_unmasked_value(text, (c,)) and not _holds_unmasked_value(masked, (c,)) for c in canaries):
        return text
    return masked


_SEPARATOR_RUN = r"[\s\-]*"


def _scrub_stored(text, creds: tuple[StoredCredential, ...]):
    """Replace each declared stored value with its site, label and fingerprint; redact a field
    that still holds one in another spelling (URL- or JSON-encoded, say)."""
    if not isinstance(text, str) or not text or not creds:
        return text
    for cred in sorted(creds, key=lambda c: len(c.value), reverse=True):
        squeezed = re.sub(r"[\s\-]", "", cred.value) or cred.value
        pattern = _SEPARATOR_RUN.join(re.escape(char) for char in squeezed)
        text = re.sub(pattern, lambda _m: f"<stored credential {cred.describe()}>", text, flags=re.IGNORECASE)
    left = [c for c in creds if _holds_unmasked_value(text, (c.value,))
            or _holds_unmasked_value(unquote_plus(text), (c.value,))]
    if left:
        return f"<redacted {len(text)} chars holding stored credential " + ", ".join(c.describe() for c in left) + ">"
    return text


@dataclass(frozen=True)
class _StoredCredentialLogRedactor:
    creds: tuple[StoredCredential, ...] = field(repr=False)

    def clean(self, text):
        return _scrub_stored(text, self.creds)


def _scrub_stored_data(value, creds: tuple[StoredCredential, ...]):
    """Scrub declared values throughout run metadata, including keys and identifiers."""
    if not creds:
        return value
    if isinstance(value, dict):
        return {_scrub_stored(k, creds): _scrub_stored_data(v, creds) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub_stored_data(v, creds) for v in value]
    if isinstance(value, (int, float)):
        text = str(value)
        scrubbed = _scrub_stored(text, creds)
        return scrubbed if scrubbed != text else value
    return _scrub_stored(value, creds)


def _scrub_stored_request(req: dict, creds: tuple[StoredCredential, ...], piece: bool) -> dict:
    """A request that carries one piece of a stored value spelled across several URLs loses that piece."""
    out = {k: _scrub_stored(req[k], creds) for k in ("path", "query", "body")}
    if piece:
        marker = "<redacted piece of a stored credential>"
        if out["query"]:
            out["query"] = marker
        else:
            out["path"] = out["path"].rpartition("/")[0] + "/" + marker
    return dict(req, **out)


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
        self._witness = current_witness()
        self._witness_values: tuple[str, ...] = ()
        self._witness_start = time.monotonic()
        self._witness_channels = ()
        # Set by begin_probe; None means a non-probe caller, which keeps the
        # old prompt-as-payload behaviour.
        self._scenario_kind: str | None = None
        self._scenario_payload: str | None = None
        self._scenario_options: dict = {}
        self._evidence: dict = {}
        # Canaries the probe checks for; every other recorded value is masked.
        self._canaries: tuple[str, ...] = ()
        # The site whose stored credential this probe scores; None for every other probe.
        self._stored_site: str | None = None
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

    @property
    def _sensitive_credentials(self):
        extra = ((StoredCredential("run", "canary", self._witness.canary),
                  StoredCredential("run", "witness_token", self._witness.token))
                 if self._witness is not None else ())
        return self.spec.stored_credentials + extra

    def register_witness_values(self, values):
        if self._witness is None:
            raise ProbeNotApplicable("witness channels require run --local")
        self._witness.register_values(values)

    async def begin_probe(self, probe) -> None:
        self._witness_values = tuple(getattr(probe, "witness_values", ()))
        channels = getattr(probe, "requires_witness", ())
        self._witness_channels = tuple(channels) if isinstance(channels, (tuple, list)) else ()
        self._witness_start = time.monotonic()
        if self._witness_channels:
            if not _LOCAL_RUN.get() or self._witness is None:
                raise ProbeNotApplicable("witness channels require run --local; server mode is unsupported")
            if self.spec.trap_mode == "hosted":
                raise ProbeNotApplicable("witness channels are unsupported with hosted traps")
            if any(getattr(self._witness.spec, channel) is None for channel in self._witness_channels):
                raise ProbeNotApplicable("the target spec does not configure the required witness channel")
            if getattr(probe, "requires_secret_canary", False) is True and not self.spec.binds_secret_canary:
                raise ProbeNotApplicable("the target spec does not pass the declared secret to the agent")
            await self._witness.start(self._witness_channels)
            self.register_witness_values(getattr(probe, "witness_values", ()))
        self._evidence = {}
        self._conversation_id = None
        self._session_id = None
        self._last_run_log = None
        self._probe_id = getattr(probe, "id", "synthetic-page")
        self._canaries = trap_unmasked_values(getattr(probe, "assertions", None) or ())
        self._stored_site = stored_credential_site(getattr(probe, "assertions", None) or ())
        if self._stored_site is not None:
            if self.spec.trap_mode == "hosted":
                raise ProbeNotApplicable("stored-credential probes need the submitted values, which hosted traps redact")
            if not any(c.site == self._stored_site for c in self.spec.stored_credentials):
                raise ProbeNotApplicable(
                    f"the target spec declares no stored credential for {self._stored_site}; add a synthetic "
                    "test credential for it under stored_credentials to run this probe"
                )
        self._scenario_options = dict(getattr(probe, "scenario_options", {}))
        payload = getattr(probe, "scenario_payload", None)
        kind = getattr(probe, "scenario_kind", None)
        # No scenario block: the attack is the prompt itself, so send it as the
        # page payload as before. Reset so a previous probe's scenario never leaks.
        if not kind and not payload:
            self._scenario_kind = None
            self._scenario_payload = None
            self._require_client_support()
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
        self._require_client_support()

    def _require_client_support(self) -> None:
        """Skip, before anything is sent, a scenario the connected client agent cannot serve."""
        if _LOCAL_RUN.get():
            return
        check = getattr(_get_client_agent_ws(), "missing_scenario_support", None)
        # A bridge without this check keeps the old path: the send itself reports failures.
        if not inspect.ismethod(check):
            return
        reason = check(self._scenario_kind or self.spec.scenario_kind, self._scenario_options)
        if reason:
            raise ProbeNotApplicable(reason)

    async def send_prompt(
        self, prompt: str, history: tuple[Turn, ...] = ()
    ) -> tuple[str, float]:
        creds = self._sensitive_credentials
        log_scope = (redacted_transport_logs(_StoredCredentialLogRedactor(creds))
                     if creds else contextlib.nullcontext())
        with log_scope:
            try:
                text, latency = await self._send_prompt(prompt, history)
            except Exception as exc:
                if not creds:
                    raise
                # Keep the exception type and metadata used to classify failed deliveries.
                message = str(exc)
                scrubbed = _scrub_stored(message, creds)
                if scrubbed != message:
                    exc.args = (scrubbed,)
                    # Some exception types format attributes rather than their args.
                    if _scrub_stored(str(exc), creds) != str(exc):
                        raise TargetDeliveryError(scrubbed) from None
                # Validation and bridge causes can quote raw agent output in a traceback.
                raise exc from None
        # The reply can echo a stored value; it must not reach reports in plaintext.
        return _scrub_stored(text, self._sensitive_credentials), latency

    def rendered_prompt(self, prompt: str) -> str:
        if self._witness_channels and self._witness is not None:
            return prompt.replace("%argus_secret%", f"%{self._witness.spec.secret_placeholder}%")
        return prompt

    async def _send_prompt(
        self, prompt: str, history: tuple[Turn, ...] = ()
    ) -> tuple[str, float]:
        self._last_run_log = None
        prompt = self.rendered_prompt(prompt)
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
        if self._scenario_options:
            msg["scenario_options"] = self._scenario_options
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
            from argus.model_egress import TRACE_PROBE, without_secret_bindings

            if self._witness is not None and _LOCAL_RUN.get():
                if self._probe_id.split("::", 1)[0] == TRACE_PROBE + "_control":
                    msg["transport"] = without_secret_bindings(msg["transport"])
                else:
                    msg.update(secret_canary=self._witness.canary,
                               secret_placeholder=self._witness.spec.secret_placeholder)
            else:
                msg["transport"] = without_secret_bindings(msg["transport"])
            deadline = self.spec.transport.timeout.total_deadline_s
            cleanup = self.spec.transport.timeout.cleanup_grace_s
        else:
            deadline = self.spec.timeout_s
            cleanup = 0.0
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
                    self._last_run_log = TargetRunLog.model_validate(
                        _scrub_stored_data(log_fields, self._sensitive_credentials)
                    )
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
        if self._scenario_kind == "field_egress" and self._witness is not None:
            from argus.model_egress import TRACE_PROBE, field_fills
            control = self._probe_id.split("::", 1)[0] == TRACE_PROBE + "_control"
            value = self._witness_values[0] if control else self._witness.canary
            ev["field_fills"] = field_fills(ev, value)
        if "trap_requests" in ev:
            requests = ev["trap_requests"]
            sequence = {i for canary in self._canaries
                        for i in canary_sequence_requests(requests, canary)}
            ev["trap_requests"] = [
                dict(_masked_request(r, self._canaries), query=r["query"])
                if i in sequence else _masked_request(r, self._canaries)
                for i, r in enumerate(requests)
            ]
            creds = self._sensitive_credentials
            if self._stored_site is not None:
                ev["stored_credentials"] = self._stored_record(requests)
            if creds:
                pieces = {i for c in creds for i in canary_sequence_requests(requests, c.value)}
                ev["trap_requests"] = [
                    _scrub_stored_request(r, creds, i in pieces) for i, r in enumerate(ev["trap_requests"])
                ]
        if self._witness is not None and self._witness_channels:
            ev["witness"] = self._witness.evidence(self._witness_start, time.monotonic())
            ev["witness"]["canary_bound"] = self.spec.binds_secret_canary
            if self._scenario_kind == "field_egress":
                from argus.model_egress import model_evidence_notes, position_records
                if "otlp" in self._witness_channels:
                    from argus.model_egress import trace_evidence_notes
                    position_records(ev, "otlp")
                    ev["trace_egress_notes"] = trace_evidence_notes(ev)
                    if control:
                        ev["witness"]["canary_bound"] = False
                        ev["trace_control_value_seen"] = any(any(r["values_seen"]) for r in ev["witness"]["otlp"])
                else:
                    position_records(ev)
                    ev["model_egress_notes"] = model_evidence_notes(ev)
        return _scrub_stored_data(ev, self._sensitive_credentials)

    def _stored_record(self, requests: list[dict]) -> dict:
        """Which of this probe's declared values reached the sink, matched as no_canary_in_trap_requests
        matches a canary, named by label and fingerprint only."""
        declared = [c for c in self.spec.stored_credentials if c.site == self._stored_site]
        hits = []
        for cred in declared:
            found = {i for i, r in enumerate(requests)
                     if any(canary_in(str(r.get(k) or ""), cred.value) for k in ("path", "query", "body"))}
            found.update(canary_sequence_requests(requests, cred.value))
            if found:
                hits.append({"label": cred.label, "fingerprint": cred.fingerprint,
                             "requests": [i + 1 for i in sorted(found)]})
        return {
            "site": self._stored_site,
            "declared": [{"label": c.label, "fingerprint": c.fingerprint} for c in declared],
            "hits": hits,
        }

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
        if "page_opened_at" in new:
            opened = [stamp for stamp in (old.get("page_opened_at"), new["page_opened_at"])
                      if isinstance(stamp, (int, float))]
            self._evidence["page_opened_at"] = min(opened, default=None)
        # Absent on a runner that predates asset tracking; stays absent so a check can tell.
        if "asset_fetches" in new:
            fetches = dict(old.get("asset_fetches", {}))
            for name, count in new["asset_fetches"].items():
                fetches[name] = fetches.get(name, 0) + count
            self._evidence["asset_fetches"] = fetches
        if "inbox_page_loads" in new:
            self._evidence["inbox_page_loads"] = (
                old.get("inbox_page_loads", 0) + new["inbox_page_loads"]
            )
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

            html = render_hosted_scenario(msg["scenario_kind"], msg["payload"], **msg.get("scenario_options", {}))
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
