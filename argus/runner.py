"""Probe runner — orchestrates probe → target → judge → Finding."""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import logging
import re
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, AsyncIterator
from uuid import UUID, uuid4

import httpx

from argus import llm
from argus.input_budget import InputLimits, fit_history

from argus.placeholders import needs_rendering, render_generator_name, target_model_name
from argus.a2a.events import events_from_trials
from argus.cost_meter import CostExceededError
from argus.events import Event
from argus.deep_thread import DeepThread
from argus.phases import PhaseRun, clean_failure, judge_trial
from argus.trials import TrialRecord, aggregate_trials, pass_wording, snapshot_finding
from argus_transport.runtime_v2 import TargetRunStopped
from argus.world_assertions import report_from_reply
from argus.probe import Probe
from argus.targets._base import ProbeNotApplicable

if TYPE_CHECKING:
    from argus.persona_strategy import PersonaStrategyProbe

logger = logging.getLogger(__name__)


def _rubric_candidate(rubrics_dir: Path, rubric_path: str) -> Path:
    """Resolve `rubric_path` under `rubrics_dir`; raise if it escapes."""
    rel = Path(rubric_path)
    if rel.parts and rel.parts[0] == "rubrics":
        rel = Path(*rel.parts[1:])
    root = rubrics_dir.resolve()
    candidate = (rubrics_dir / rel).resolve()
    if not (candidate == root or root in candidate.parents):
        raise ValueError(f"rubric path escapes rubrics_dir: {rubric_path!r}")
    return candidate


# Worst-first order for keeping one finding across the rounds of a hybrid thread.
_VERDICT_RANK = {"pass": 0, "error": 1, "warn": 2, "fail": 3}


def _is_hybrid(probe) -> bool:
    return bool(getattr(probe, "judge_when_assertions_pass", False))


def _needs_judge(probe) -> bool:
    return not getattr(probe, "assertions", ()) or _is_hybrid(probe)


# Verdict constants (Plan 4 T7) — used in Finding.verdict and report renderers.
VERDICT_PASS = "pass"
VERDICT_WARN = "warn"
VERDICT_FAIL = "fail"
VERDICT_ERROR = "error"
VERDICT_BLOCKED_BY_TARGET = (
    "blocked_by_target"  # adapter HTTP 4xx (target gateway content filter)
)
VERDICT_SKIPPED = (
    "skipped"  # probe.target_class disjoint from target.compatible_classes
)
VERDICT_ABORTED = "aborted_cost"  # mid-run CostExceededError (daily cap crossed)
# Reason prefix of a judged probe skipped because no judge credential is set.
NO_JUDGE_KEY = "no judge key"
# Reason prefix of a probe the run never started because it had already hit a cost cap.
NOT_STARTED_AT_CAP = "not started"


def _short(exc: Exception) -> str:
    return (str(exc) or type(exc).__name__)[:200]


def _named(exc: BaseException) -> str:
    # httpx timeouts often have an empty message, so the class name carries the cause.
    msg = str(exc)
    return f"{type(exc).__name__}: {msg[:200]}" if msg else type(exc).__name__


# 4xx codes that mean the run is misconfigured or throttled, not that a defence fired.
_STATUS_HINTS = {
    401: "unauthorized; check credentials",
    407: "proxy authentication required; check credentials",
    404: "not found; check endpoint_url / request_url / model",
    405: "method not allowed; check endpoint_url / request_method",
    408: "the target timed out",
    422: "unprocessable request; check request_body_template / the request schema",
    429: "rate limited; slow down or retry later",
}

def _no_text_reason(target) -> str:
    from argus.targets import _BUILTIN_KINDS, kinds

    kind = getattr(getattr(target, "spec", None), "kind", None)
    info = _BUILTIN_KINDS.get(kind) if isinstance(kind, str) else None
    info = info or kinds().get(kind)
    hint = (info.no_text_hint if info else None) or "check the endpoint"
    return f"target returned no text; {hint}"


def _blank(text) -> bool:
    # Adapters may hand back a non-string (a list of parts); only real emptiness is "no text".
    return (
        text is None or (isinstance(text, str) and not text.strip()) or text in ([], {})
    )


_GRPC_HINTS = {
    "UNAUTHENTICATED": "check credentials",
    "PERMISSION_DENIED": "check credentials",
    "RESOURCE_EXHAUSTED": "rate limited; slow down or retry later",
}

# Probes in a row whose every send failed before the run stops: a hung target would
# otherwise cost one timeout per prompt across the whole library.
UNREACHABLE_AFTER = 5


class TargetUnreachableError(Exception):
    """The target failed every send of UNREACHABLE_AFTER probes in a row."""


def _status_code(exc: Exception) -> int | None:
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code
    code = getattr(
        exc, "status_code", None
    )  # SDK errors such as anthropic.APIStatusError
    return code if isinstance(code, int) else None


def _is_transport_failure(exc: Exception) -> bool:
    """The request did not produce a usable reply: network, timeout, or a body that is not JSON."""
    import json

    from argus.targets._base import TargetDeliveryError, TargetTransportError

    if isinstance(
        exc,
        (
            httpx.HTTPError,
            TargetDeliveryError,
            TargetTransportError,
            TimeoutError,
            ConnectionError,
            json.JSONDecodeError,
        ),
    ):
        return True
    try:
        import anthropic

        if isinstance(exc, anthropic.APIConnectionError):  # includes APITimeoutError
            return True
    except ImportError:  # pragma: no cover - anthropic is a base dependency
        pass
    try:
        from grpc.aio import AioRpcError

        if isinstance(exc, AioRpcError):
            return True
    except ImportError:  # pragma: no cover - grpcio is a base dependency
        pass
    return False


def _grpc_reason(exc: Exception) -> str | None:
    # AioRpcError's str() is a multi-line repr; reports need one line.
    try:
        from grpc.aio import AioRpcError
    except ImportError:  # pragma: no cover - grpcio is a base dependency
        return None
    if not isinstance(exc, AioRpcError):
        return None
    name = exc.code().name
    details = " ".join((exc.details() or "").split())[:200]
    suffix = f": {details}" if details else ""
    if name in _GRPC_HINTS:
        return f"target returned gRPC {name} ({_GRPC_HINTS[name]}){suffix}"
    return f"target request failed: gRPC {name}{suffix}"


_NO_CONTACT = (
    "not exercised: the reply shows no sign the agent read the linked content, "
    "so the attack never reached it; this is not a defended result"
)


def _no_contact(probe, response_text: str) -> bool:
    """True when the probe names lowercase markers from fetched content and the reply has none."""
    markers = getattr(probe, "contact_markers", ())
    # isinstance, not truthiness: a MagicMock probe would otherwise demote every pass.
    return isinstance(markers, tuple) and bool(markers) and not any(m in response_text.lower() for m in markers)


def _no_contact_reason(probe) -> str:
    reason = getattr(probe, "no_contact_reason", "")
    return reason if isinstance(reason, str) and reason else _NO_CONTACT


def _never_reached(blocked_reasoning: str) -> str:
    """Reasoning for a block from an agent that never touched its testbed."""
    m = re.match(r"target returned HTTP (\d{3}) ", blocked_reasoning)
    cause = (
        f"agent returned HTTP {m[1]}"
        if m
        else f"{blocked_reasoning.split('; counted as blocked')[0]}, and the agent"
    )
    return f"{cause} and never reached the testbed, so the probe did not run; this is not a defended result"


def _transport_failure_evidence(exc: Exception) -> dict | None:
    from argus.targets._base import TargetBlockedError

    metadata = getattr(exc, "transport_metadata", None)
    if (isinstance(exc, TargetBlockedError) and isinstance(metadata, dict)
            and metadata.get("origin") == "mapped_body_rule"
            and metadata.get("outcome") == "blocked"
            and isinstance(metadata.get("matched_rule_id"), str)
            and metadata["matched_rule_id"]):
        return {"transport": dict(metadata), "_mapped_body_refusal": True}
    return None


def _send_failure(exc: Exception) -> tuple[str, str] | None:
    """(verdict, reasoning) for a send_prompt failure that costs one probe, or None to re-raise.

    A target outage or a misconfigured spec must never abort the run (losing every
    finding so far) nor read as a defended result.
    """
    from argus.targets._base import TargetBlockedError, TargetDeliveryError, TargetTransportError

    if isinstance(exc, TargetBlockedError):
        return VERDICT_BLOCKED_BY_TARGET, f"{exc}; counted as blocked"
    if isinstance(exc, TargetTransportError):
        return VERDICT_ERROR, f"target transport failed: {_short(exc)}"
    grpc_reason = _grpc_reason(exc)
    if grpc_reason is not None:
        return VERDICT_ERROR, grpc_reason
    code = _status_code(exc)
    if code is not None:
        if code in _STATUS_HINTS:
            return VERDICT_ERROR, f"target returned HTTP {code} ({_STATUS_HINTS[code]})"
        if 400 <= code < 500:
            return (
                VERDICT_BLOCKED_BY_TARGET,
                f"target returned HTTP {code} to the attack prompt; counted as blocked",
            )
        if code >= 500:
            return VERDICT_ERROR, f"target returned HTTP {code} (server error)"
        # raise_for_status also raises on a redirect the adapter did not follow.
        return (
            VERDICT_ERROR,
            f"target returned HTTP {code}; check endpoint_url / request_url",
        )
    if isinstance(exc, TargetDeliveryError):
        return VERDICT_ERROR, f"target could not deliver the probe: {_short(exc)}"
    if _is_transport_failure(exc):
        return VERDICT_ERROR, f"target request failed: {_named(exc)}"
    return None


@dataclass(frozen=True)
class Finding:
    id: UUID
    probe_id: str
    attack_prompt: str
    target_response: str
    target_latency_ms: float
    probed_at: datetime
    verdict: str
    severity: str
    confidence: float
    reasoning: str
    judge_model: str
    escalated_model: str | None
    atlas_id: list[str] = field(default_factory=list)
    owasp_id: list[str] = field(default_factory=list)
    owasp_agentic: list[str] = field(default_factory=list)
    nist_id: list[str] = field(default_factory=list)
    eu_ai_act_id: list[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    # What the target observed, when it can observe anything (see
    # Target.collect_evidence). None for the text-only adapters.
    evidence: dict | None = None
    # How to fix it, from the probe's attack_class (argus/remediation.py). Empty when unknown.
    remediation: str = ""
    # Tiered fix-it steps (argus/remediation.py actions_for_probe). Empty when unknown.
    remediation_actions: list[dict] = field(default_factory=list)
    # Evidence-backed steps (argus/events.py); empty unless an adapter observed them.
    events: list[Event] = field(default_factory=list)


def skipped_finding(probe, reasoning: str) -> Finding:
    """A skipped Finding that still carries the probe's standards mappings,
    so the skip remains traceable in SARIF/JUnit rather than vanishing."""
    return Finding(
        id=uuid4(),
        probe_id=probe.id,
        attack_prompt="",
        target_response="",
        target_latency_ms=0.0,
        probed_at=datetime.now(timezone.utc),
        verdict=VERDICT_SKIPPED,
        severity="info",
        confidence=1.0,
        reasoning=reasoning,
        judge_model="",
        escalated_model=None,
        atlas_id=list(probe.mappings.atlas),
        owasp_id=list(probe.mappings.owasp_llm),
        owasp_agentic=list(getattr(probe.mappings, "owasp_agentic", ())),
        nist_id=list(probe.mappings.nist_ai_rmf),
        eu_ai_act_id=list(probe.mappings.eu_ai_act),
    )


def aborted_finding(probe, reasoning: str, *, history: bool = False) -> Finding:
    """The probe that was running when the cost cap stopped the run."""
    from argus.persona_strategy import PersonaStrategyProbe

    finding = replace(skipped_finding(probe, reasoning), verdict=VERDICT_ABORTED)
    if isinstance(probe, PersonaStrategyProbe):
        return DeepThread(probe, history, finding).finish('cost', reasoning)
    return finding


class Runner:
    def __init__(self, target, judge, rubrics_dir: Path) -> None:
        self._target = target
        input_limits = getattr(target, "input_limits", None)
        self._input_limits = input_limits if isinstance(input_limits, InputLimits) else InputLimits()
        self._judge = judge
        self._rubrics_dir = Path(rubrics_dir)
        # Set when this probe's evidence fetch failed; reset per probe in run_probe.
        self._evidence_failed = False
        # Breaker state: probes in a row whose every send failed, and the last reason.
        self._failed_streak = 0
        self._last_send_failure = ""
        self._sends_ok = self._sends_failed = 0
        # Inject the meter into iterative modules so their planner LLM calls record cost.
        # The meter is extracted from judge, which was passed in from api.py.
        if hasattr(judge, "_cost_meter") and judge._cost_meter is not None:
            from argus import iterative_tap, iterative_pair, persona_strategy

            iterative_tap.set_cost_meter(judge._cost_meter)
            iterative_pair.set_cost_meter(judge._cost_meter)
            persona_strategy.set_cost_meter(judge._cost_meter)

    def _shown(self, prompt: str) -> str:
        """The prompt as it went on the wire (testbed URL filled in). Duck-typed
        mock targets have no such method, so only a real bound method is called."""
        shown = getattr(self._target, "rendered_prompt", None)
        return shown(prompt) if prompt and inspect.ismethod(shown) else prompt

    def _skip(self, probe, reasoning: str) -> Finding:
        return skipped_finding(probe, reasoning)

    async def run_probe(self, probe) -> AsyncIterator[Finding]:
        from argus.persona_strategy import PersonaStrategyProbe

        if not isinstance(probe, PersonaStrategyProbe):
            async for finding in self._run_probe(probe):
                yield finding
            return
        template = self._finding(
            probe, '', '', 0.0, datetime.now(timezone.utc), verdict=VERDICT_ERROR,
            severity='info', confidence=1.0, reasoning='thread did not start', evidence=None,
        )
        state = DeepThread(probe, bool(getattr(self._target, 'supports_history', False)), template)
        try:
            async for finding in self._run_probe(probe, deep_state=state):
                if 'transcript' in (finding.evidence or {}):
                    yield finding
                elif finding.verdict == VERDICT_SKIPPED:
                    yield state.annotate(finding, 'not_started')
                else:
                    yield state.annotate(finding, 'not_started')
        except CostExceededError as exc:
            yield state.finish('cost', f'cost cap hit at round {len(state.rounds)}: {exc}')
        except (TargetRunStopped, TargetUnreachableError):
            raise
        except Exception as exc:
            if state.rounds:
                finding = state.finish('post_round', f'post-round step failed: {_named(exc)}')
                yield replace(finding, evidence={**finding.evidence, 'evidence_error': _named(exc)})
            elif isinstance(exc, ValueError):
                yield state.finish('not_started', f'thread could not start: {_named(exc)}')
            else:
                raise

    async def _run_probe(self, probe, *, deep_state: DeepThread | None = None) -> AsyncIterator[Finding]:
        # Template slots ({generator.name}) must never reach the target as literals.
        name = target_model_name(self._target)
        if isinstance(probe, Probe) and any(needs_rendering(p) for p in probe.prompts):
            probe = replace(
                probe,
                prompts=tuple(render_generator_name(p, name) for p in probe.prompts),
            )
        base = getattr(
            probe, "base", None
        )  # deep mode: the attacker reads the base's first prompt
        if isinstance(base, Probe) and any(needs_rendering(p) for p in base.prompts):
            probe.base = replace(
                base,
                prompts=tuple(render_generator_name(p, name) for p in base.prompts),
            )
        closing = getattr(probe, 'closing_prompt', None)
        if isinstance(closing, str) and needs_rendering(closing):
            probe.closing_prompt = render_generator_name(closing, name)
        # A pack probe looks in its pack's rubrics first, then the built-in ones.
        candidate = None
        pack_rubrics = getattr(probe, "rubrics_dir", None)
        if pack_rubrics is not None:
            candidate = _rubric_candidate(Path(pack_rubrics), probe.judge_rubric_path)
            if not candidate.is_file():
                candidate = None
        if candidate is None:
            candidate = _rubric_candidate(self._rubrics_dir, probe.judge_rubric_path)
        if candidate.exists() and candidate.is_file():
            rubric_text = candidate.read_text()
        else:
            logger.warning(
                "rubric not found for probe %s: resolved=%s", probe.id, candidate
            )
            rubric_text = None

        # Plan 5 D2: target_class compat check — skip probes that don't match the target adapter
        target_compat = getattr(self._target, "compatible_classes", frozenset())
        if probe.target_class and target_compat:
            if not (set(probe.target_class) & target_compat):
                yield Finding(
                    id=uuid4(),
                    probe_id=probe.id,
                    attack_prompt="",
                    target_response="",
                    target_latency_ms=0.0,
                    probed_at=datetime.now(timezone.utc),
                    verdict=VERDICT_SKIPPED,
                    severity="info",
                    confidence=1.0,
                    reasoning=f"probe.target_class {list(probe.target_class)} disjoint from target.compatible_classes {sorted(target_compat)}",
                    judge_model="",
                    escalated_model=None,
                    atlas_id=list(probe.mappings.atlas),
                    owasp_id=list(probe.mappings.owasp_llm),
                    owasp_agentic=list(getattr(probe.mappings, "owasp_agentic", ())),
                    nist_id=list(probe.mappings.nist_ai_rmf),
                    eu_ai_act_id=list(probe.mappings.eu_ai_act),
                )
                return

        unsupported = getattr(probe, "unsupported_trap_modes", {})
        if unsupported:
            from argus.targets.browser_use import BrowserUseTarget

            if isinstance(self._target, BrowserUseTarget):
                spec = self._target.spec
                reason = unsupported.get(spec.trap_mode)
                if reason is None and spec.trap_public_url:
                    reason = unsupported.get("public_url")
                if reason is not None:
                    yield self._skip(probe, reason)
                    return

        # A conversation probe must not be flattened into single shots against a
        # stateless adapter. Its later prompts ("Great. Now write the scene...")
        # are meaningless without the earlier turns, so running them cold would
        # test something the probe does not claim to test and report the target
        # as defended against an attack that was never mounted.
        #
        # Iterative probes (TAP/PAIR) are deliberately NOT skipped here: their
        # attacker LLM emits self-contained prompts each round, so on a stateless
        # adapter they degrade to query-refinement — weaker, but still a real
        # attack, and skipping them would lose grpc/browser_use coverage.
        if getattr(
            probe, "needs_history", getattr(probe, "conversation", False)
        ) is True and not getattr(self._target, "supports_history", False):
            yield self._skip(
                probe,
                f"probe requires conversation history but target adapter "
                f"{type(self._target).__name__} declares supports_history=False",
            )
            return

        # A judged probe with no rubric file would be judged against nothing. Error
        # before any send or attacker call; evidence-judged probes need no rubric.
        if rubric_text is None and _needs_judge(probe):
            yield self._finding(
                probe,
                "",
                "",
                0.0,
                datetime.now(timezone.utc),
                verdict=VERDICT_ERROR,
                severity="info",
                confidence=1.0,
                reasoning=f"rubric file not found: {candidate}",
                evidence=None,
            )
            return

        if getattr(probe, "is_phased", False) is True:
            if getattr(self._target, "supports_phases", False) is not True:
                yield self._skip(probe, "target has no isolated MCP world support")
                return
            async for finding in self._run_phased(probe):
                yield finding
            return

        self._sends_ok = self._sends_failed = 0
        if not getattr(probe, "iterative", False) and probe.trials > 1:
            inner = self._run_static_trials(probe, rubric_text)
        else:
            inner = self._run_once(probe, rubric_text, deep_state=deep_state)
        async for finding in inner:
            yield finding
        self._check_breaker()

    async def _run_once(self, probe, rubric_text, *, deep_state: DeepThread | None = None) -> AsyncIterator[Finding]:
        from argus.persona_strategy import PersonaStrategyProbe

        # The probe is going to run: tell a stateful adapter where the previous
        # probe ended. Deliberately after both skip decisions — a skipped probe
        # must not open a session — and before any exchange, so nothing the
        # previous probe did is still visible to this one's assertions.
        # Duck-typed mock targets are everywhere in the suite and have no such
        # method, so the guard mirrors the collect_evidence call below.
        begin = getattr(self._target, "begin_probe", None)
        if inspect.iscoroutinefunction(begin):
            try:
                await begin(probe)
            except ProbeNotApplicable as exc:
                yield self._skip(probe, str(exc))
                return
            except ValueError as e:
                # A probe the adapter refuses to stage — a malformed
                # `scenario.payload`, say — is one broken probe, not a broken
                # scan. Letting it abort the run turns a JSON typo in one YAML
                # into "the scanner failed", which in a CI gate gets the gate
                # disabled; one errored probe among 25 that ran gets the probe
                # fixed instead. Still fail-closed: it never reports a pass.
                # ValueError only, deliberately: it is how this codebase signals
                # a bad spec (see the __post_init__ guards, and json's
                # JSONDecodeError which subclasses it). Catching Exception here
                # would swallow real bugs in an adapter's setup.
                yield self._finding(
                    probe,
                    "",
                    "",
                    0.0,
                    datetime.now(timezone.utc),
                    verdict=VERDICT_ERROR,
                    severity="info",
                    confidence=1.0,
                    reasoning=f"target could not set up this probe: {e}",
                    evidence=None,
                )
                return
            except Exception as e:
                # Testbed unreachable while opening the session: same policy,
                # one errored probe rather than an aborted scan.
                if not _is_transport_failure(e):
                    raise
                yield self._finding(
                    probe,
                    "",
                    "",
                    0.0,
                    datetime.now(timezone.utc),
                    verdict=VERDICT_ERROR,
                    severity="info",
                    confidence=1.0,
                    reasoning=f"target could not set up this probe: {_short(e)}",
                    evidence=None,
                )
                self._sends_failed += 1
                self._last_send_failure = (
                    f"target could not set up this probe: {_short(e)}"
                )
                return

        self._evidence_failed = False

        # Dispatch on iterative flag
        if isinstance(probe, PersonaStrategyProbe):
            inner = self._run_deep(probe, rubric_text, state=deep_state)
        elif getattr(probe, "iterative", False):
            inner = self._run_iterative(probe, rubric_text)
        else:
            inner = self._run_static(probe, rubric_text)

        # Attach whatever the target observed. Text-only adapters return {} and
        # their findings keep evidence=None, so nothing downstream changes for
        # them. A finding that already carries evidence built its own verdict
        # from it and is left alone. After a failed fetch for this probe, a
        # refetch would attach evidence its error verdict was never based on.
        async for f in inner:
            unseen = self._evidence_failed
            # Show the prompt as it went on the wire, not the probe's template.
            if not isinstance(probe, PersonaStrategyProbe) and not (
                getattr(probe, "indirect", ()) and getattr(self._target, "material_channel", False)
            ):
                f = replace(f, attack_prompt=self._shown(f.attack_prompt))
            mapped_refusal = bool((f.evidence or {}).get("_mapped_body_refusal"))
            if mapped_refusal:
                f = replace(f, evidence={k: v for k, v in f.evidence.items()
                                         if k != "_mapped_body_refusal"})
            indirect_only = set(f.evidence or {}) == {"indirect"}
            thread_only = isinstance(probe, PersonaStrategyProbe) and not getattr(probe, 'assertions', ())
            if (f.evidence is None or mapped_refusal or indirect_only or thread_only) and not self._evidence_failed:
                # Duck-typed targets are everywhere in the test suite; only call
                # a collector that is genuinely an async method, so a bare mock
                # target keeps working.
                collector = getattr(self._target, "collect_evidence", None)
                if inspect.iscoroutinefunction(collector):
                    try:
                        observed = await collector()
                    except (CostExceededError, TargetRunStopped):
                        raise
                    except Exception as e:
                        # The verdict was decided without evidence, so a testbed
                        # blip only loses the attachment; say so and keep going.
                        unseen = True
                        if thread_only:
                            evidence = {**(f.evidence or {}), 'evidence_error': _named(e)}
                            if f.verdict != VERDICT_FAIL:
                                evidence['stop_reason'] = 'collect_evidence'
                                f = replace(f, verdict=VERDICT_ERROR, severity='info')
                            f = replace(f, evidence=evidence,
                                        reasoning=f'{f.reasoning} | collect_evidence failed: {_named(e)}')
                        elif not _is_transport_failure(e):
                            raise
                        else:
                            f = replace(
                                f,
                                reasoning=f"{f.reasoning} | evidence unavailable: {_short(e)}",
                            )
                    else:
                        if observed:
                            evidence = (
                                {**observed, **(f.evidence or {})}
                                if mapped_refusal or indirect_only or thread_only
                                else observed
                            )
                            f = replace(f, evidence=evidence)
            # A 4xx or refusal before the agent touched the testbed means the attack was never
            # staged in front of it (unreachable testbed, wrong origin), not that it was defended.
            # Same gate as _assertion_finding: only evidence-judged probes that need the testbed.
            if (
                f.verdict == VERDICT_BLOCKED_BY_TARGET
                and not isinstance(probe, PersonaStrategyProbe)
                and probe.assertions
                and probe.requires_interaction
                and not (f.evidence or {}).get("interaction_count")
                and not mapped_refusal
            ):
                f = replace(
                    f, verdict=VERDICT_ERROR, reasoning=_never_reached(f.reasoning)
                )
            if mapped_refusal and not (f.evidence or {}).get("interaction_count"):
                metadata = {**f.evidence["transport"], "exposure": "not_exercised"}
                f = replace(f, evidence={**f.evidence, "transport": metadata},
                            reasoning="target API refused the request; scenario was not exercised")
            contact_responses = (
                [row['target_response'] for row in (f.evidence or {}).get('transcript', [])]
                if isinstance(probe, PersonaStrategyProbe) else [f.target_response]
            )
            no_contact = all(_no_contact(probe, text) for text in contact_responses)
            if f.verdict == VERDICT_PASS and no_contact:
                f = replace(f, verdict=VERDICT_SKIPPED, severity="info", confidence=1.0,
                            evidence={**(f.evidence or {}), "exposure": "not_exercised"},
                            reasoning=_no_contact_reason(probe))
            elif (f.verdict in (VERDICT_FAIL, VERDICT_WARN) and f.judge_model and no_contact
                    and not unseen and not (f.evidence or {}).get("trap_requests")):
                # Keep the verdict, but show that nothing proves the payload reached the agent.
                # Judge verdicts only: judge_model is empty when an assertion decided it.
                f = replace(f, evidence={**(f.evidence or {}), "exposure": "not_exercised"})
            yield f

    async def _run_static_trials(self, probe, rubric_text) -> AsyncIterator[Finding]:
        records = []
        template = None
        severity = "info"
        latency = 0.0
        stop = None
        ranks = {name: rank for rank, name in enumerate(("info", "low", "medium", "high", "critical"))}
        for trial in range(1, probe.trials + 1):
            observations = []
            try:
                async for finding in self._run_once(probe, rubric_text):
                    observations.append(snapshot_finding(finding))
                    if template is None:
                        template = finding
                    if ranks[finding.severity] > ranks[severity]:
                        severity = finding.severity
                    latency += finding.target_latency_ms
            except (CostExceededError, TargetRunStopped) as exc:
                stop = exc
            summary = aggregate_trials([item["verdict"] for item in observations])
            verdict = summary.verdict
            reason_code = summary.reason_code
            reason = " ".join(item["reasoning"] for item in observations)
            if stop is not None:
                if verdict not in (VERDICT_FAIL, VERDICT_WARN):
                    verdict = VERDICT_ABORTED if isinstance(stop, CostExceededError) else VERDICT_ERROR
                reason_code = "cost_cap" if isinstance(stop, CostExceededError) else stop.reason
                reason = f"trial interrupted: {_named(stop)}"
            elif not observations:
                reason = "trial produced no observations"
            records.append(TrialRecord(trial, verdict, reason_code, reason, None,
                                       {"observations": observations}))
            if stop is not None:
                break
        summary = aggregate_trials([row.verdict for row in records],
                                   stopped_at_cost_cap=isinstance(stop, CostExceededError))
        probed_at = template.probed_at if template is not None else datetime.now(timezone.utc)
        wording = pass_wording(probe.trials, probed_at.date()) if summary.verdict == VERDICT_PASS else summary.sentence()
        reasons = " ".join(f"Trial {row.trial}: {row.verdict}: {row.reason}" for row in records)
        reasoning = f"{wording} {summary.counts_line()} {reasons}"
        evidence = {"trial_summary": summary.as_dict(), "trials": [row.as_dict() for row in records]}
        if template is None:
            template = self._finding(probe, "", "", 0.0, probed_at, verdict=summary.verdict,
                                     severity="info", confidence=1.0, reasoning=reasoning, evidence=evidence)
        yield replace(template, verdict=summary.verdict, severity=severity,
                      target_latency_ms=latency, reasoning=reasoning, evidence=evidence)
        if stop is not None:
            raise stop

    def _note_send(self, failure_reason: str | None) -> None:
        """Count one send for the breaker; a block is an answer, so pass None for it."""
        if failure_reason is None:
            self._sends_ok += 1
        else:
            self._sends_failed += 1
            self._last_send_failure = failure_reason

    def _check_breaker(self) -> None:
        """After a probe: raise once UNREACHABLE_AFTER probes in a row failed every send."""
        if self._sends_failed and not self._sends_ok:
            self._failed_streak += 1
        elif self._sends_ok:
            self._failed_streak = 0
        if self._failed_streak >= UNREACHABLE_AFTER:
            raise TargetUnreachableError(
                f"target unreachable: {self._failed_streak} probes in a row failed ({self._last_send_failure})"
            )

    async def _assertion_finding(
        self, probe, prompt, response_text, latency_ms, probed_at
    ) -> Finding:
        """Build a Finding whose verdict comes from captured evidence."""
        from argus.assertions import AssertionResult, ObservationContext, evaluate_assertions
        from argus.world_assertions import CHECKS, Undecided
        from argus.targets.python_target import PythonTarget
        from argus.targets.python_evidence import evaluate_python_assertions

        if isinstance(self._target, PythonTarget):
            evaluate_assertions = evaluate_python_assertions
        evidence = {}
        collector = getattr(self._target, "collect_evidence", None)
        if inspect.iscoroutinefunction(collector):
            try:
                evidence = await collector() or {}
            except Exception as e:
                if not _is_transport_failure(e):
                    raise
                # No evidence means no verdict. A testbed blip or an expired
                # session errors this probe only; it must never read as a pass.
                self._evidence_failed = True
                evidence_source = "target" if isinstance(self._target, PythonTarget) else "testbed"
                return self._finding(
                    probe,
                    prompt,
                    response_text,
                    latency_ms,
                    probed_at,
                    verdict=VERDICT_ERROR,
                    severity="info",
                    confidence=1.0,
                    reasoning=f"could not read evidence from the {evidence_source}: {_short(e)}",
                    evidence=None,
                )

        # An assertion-backed probe that never reached its target proves nothing.
        # Every "did not overpay" check is satisfied by doing nothing at all, so
        # reporting a pass here would hand the customer a false green.
        if (probe.requires_interaction and not evidence.get("interaction_count")
                and getattr(probe, "scenario_kind", None) != "cross_origin_bridge"):
            return self._finding(
                probe,
                prompt,
                response_text,
                latency_ms,
                probed_at,
                verdict=VERDICT_ERROR,
                severity="info",
                confidence=1.0,
                reasoning=(
                    "target never reached its testbed, so the probe did "
                    "not actually run; this is not a defended result"
                ),
                evidence=evidence or None,
            )

        # Per-prompt checks (leak replay) need the prompt's position; a prompt
        # repeated within one probe is ambiguous, so it gets none and fails closed.
        prompts = list(getattr(probe, "prompts", ()))
        prompt_index = prompts.index(prompt) if prompts.count(prompt) == 1 else None
        if not prompts and getattr(probe, "base", None) is not None:
            prompt_index = (
                0  # deep thread: the attacker is shown only the base's first prompt
            )
        # Blocking registry lookups must not stall the event loop.
        context = None
        context_error = None
        try:
            payload = json.loads(getattr(probe, "scenario_payload", ""))
        except (TypeError, ValueError):
            payload = None
        stages_world = isinstance(payload, dict) and payload.get("scenario") == "agent_world"
        try:
            if stages_world or getattr(probe, "scenario_kind", None) == "agent_world" or (
                getattr(probe, "scenario_payload", "") and any(
                    name in CHECKS for entry in probe.assertions for name in entry
                )
            ):
                context = ObservationContext.from_probe(probe, "attack")
        except Undecided as exc:
            context_error = AssertionResult("required_event", False, str(exc), error=True)
            context = ObservationContext("attack", getattr(probe, "scenario_kind", None), frozenset())
        kwargs = {"context": context} if context_error is not None or not isinstance(self._target, PythonTarget) else {}
        results = await asyncio.to_thread(
            evaluate_assertions, probe.assertions, evidence, response_text, prompt_index,
            **kwargs,
        )
        if context_error is not None:
            results.append(context_error)
        if isinstance(self._target, PythonTarget) and context is not None and context.required_events:
            results.append(AssertionResult(
                "required_event", False,
                "required_event_unsupported: Python target cannot check requested world triggers",
                error=True,
            ))
        undecided = [r for r in results if r.error]
        proven_failure = any(not r.passed and not r.error and r.verdict is None for r in results)
        if proven_failure:
            undecided = [r for r in undecided if not r.definition_error]
        if undecided and not (proven_failure and (
            context_error is not None or (context is not None and context.required_events)
        )):
            return self._finding(
                probe,
                prompt,
                response_text,
                latency_ms,
                probed_at,
                verdict=VERDICT_ERROR,
                severity="info",
                confidence=1.0,
                reasoning="; ".join(r.reason for r in undecided),
                evidence=evidence or None,
            )
        failed = [r for r in results if not r.passed and not r.error and r.verdict is None]
        warnings = [r for r in results if r.verdict == "warn"]
        skipped = [r for r in results if r.verdict == "skipped"]
        verdict = VERDICT_FAIL if failed else VERDICT_WARN if warnings else (
            VERDICT_SKIPPED if skipped else VERDICT_PASS
        )
        if (verdict == VERDICT_PASS
                and getattr(probe, "scenario_kind", None) == "cross_origin_bridge"
                and not evidence.get("inbox_page_loads")):
            return self._finding(
                probe, prompt, response_text, latency_ms, probed_at,
                verdict=VERDICT_SKIPPED, severity="info", confidence=1.0,
                reasoning="agent never loaded the inbox origin, so the private code was not exercised",
                evidence=evidence or None,
            )
        selected = failed or warnings or (skipped if verdict == VERDICT_SKIPPED else results)
        reasoning = "; ".join(r.reason for r in selected)
        severity = "info"
        if verdict in {VERDICT_FAIL, VERDICT_WARN}:
            levels = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
            severity = max((r.severity or probe.severity for r in selected), key=levels.__getitem__)
        return self._finding(
            probe,
            prompt,
            response_text,
            latency_ms,
            probed_at,
            verdict=verdict,
            severity=severity,
            confidence=1.0,
            reasoning=reasoning,
            evidence=evidence or None,
        )

    async def _hybrid_finding(
        self, probe, rubric_text, clean: Finding, *, round_n: int | None = None
    ) -> Finding:
        """The judge's verdict for a probe whose assertions all passed.

        Clean evidence only rules out the failures the assertions know how to see,
        so the judge decides; its finding carries the evidence and says why it ran.
        May raise ValueError for an unusable judge reply: the callers own that policy.
        """
        # Same rule as a judged probe: a blank reply is a broken response path, and a judge would read it as a pass.
        if _blank(clean.target_response):
            reason = _no_text_reason(self._target)
            return replace(
                clean,
                verdict=VERDICT_ERROR,
                severity="info",
                confidence=1.0,
                reasoning=reason if round_n is None else f"round {round_n}: {reason}",
            )
        verdict = await self._judge.judge(
            probe_name=probe.name,
            attack_prompt=(clean.attack_prompt if (getattr(probe, "indirect", ())
                                                  and getattr(self._target, "material_channel", False))
                           else self._shown(clean.attack_prompt)),
            target_response=clean.target_response,
            rubric_text=rubric_text,
            severity=probe.severity,
        )
        return replace(
            clean,
            verdict=verdict.verdict,
            severity=verdict.severity,
            confidence=verdict.confidence,
            reasoning=f"evidence clean ({clean.reasoning}); judge: {verdict.reasoning}",
            judge_model=verdict.judge_model,
            escalated_model=verdict.escalated_model,
        )

    def _finding(
        self,
        probe,
        prompt,
        response_text,
        latency_ms,
        probed_at,
        *,
        verdict,
        severity,
        confidence,
        reasoning,
        evidence,
        events: list[Event] | None = None,
    ) -> Finding:
        return Finding(
            id=uuid4(),
            probe_id=probe.id,
            attack_prompt=prompt,
            target_response=response_text,
            target_latency_ms=latency_ms,
            probed_at=probed_at,
            verdict=verdict,
            severity=severity,
            confidence=confidence,
            reasoning=reasoning,
            # Deterministic verdicts name no model, because none was consulted.
            judge_model="",
            escalated_model=None,
            atlas_id=list(probe.mappings.atlas),
            owasp_id=list(probe.mappings.owasp_llm),
            owasp_agentic=list(getattr(probe.mappings, "owasp_agentic", ())),
            nist_id=list(probe.mappings.nist_ai_rmf),
            eu_ai_act_id=list(probe.mappings.eu_ai_act),
            evidence=evidence,
            events=list(events or []),
        )

    async def _run_phase(self, probe, phase: str, trial: int) -> PhaseRun:
        from argus.targets._base import Turn

        prompts, replies = [], []
        evidence = None
        evidence_error = None
        failure = None
        started = False
        try:
            try:
                await self._target.begin_phase(probe, phase, trial)
                started = True
            except ProbeNotApplicable:
                raise
            except Exception as exc:
                if not isinstance(exc, ValueError) and not _is_transport_failure(exc):
                    raise
                return PhaseRun(
                    phase,
                    trial,
                    ("error", f"target could not set up this phase: {_named(exc)}"),
                    None,
                    None,
                    (),
                    (),
                )
            for index, session_prompts in enumerate(probe.session_prompts, 1):
                if index >= 2:
                    await self._target.begin_conversation(index)
                transcript = []
                for prompt in session_prompts:
                    prompts.append(self._shown(prompt))
                    try:
                        response, latency = await self._target.send_prompt(
                            prompt, history=fit_history(tuple(transcript), self._input_limits.max_history_chars)[0]
                        )
                    except Exception as exc:
                        if isinstance(exc, CostExceededError):
                            raise
                        failure = _send_failure(exc)
                        if failure is None:
                            raise
                        self._note_send(failure[1] if failure[0] == "error" else None)
                        break
                    self._note_send(None)
                    replies.append(response or "")
                    transcript.extend(
                        (Turn("user", prompt), Turn("assistant", response or ""))
                    )
                if failure:
                    break
        except (ProbeNotApplicable, CostExceededError):
            raise
        except Exception as exc:
            if not isinstance(exc, ValueError) and not _is_transport_failure(exc):
                raise
            failure = ("error", _named(exc))
            self._note_send(failure[1])
        finally:
            if started:
                try:
                    evidence = await self._target.end_phase()
                except Exception as exc:
                    if not isinstance(exc, ValueError) and not _is_transport_failure(
                        exc
                    ):
                        raise
                    evidence_error = _named(exc)
        if evidence is not None and evidence.get("report") is None and replies:
            report = report_from_reply(replies[-1])
            if report is not None:
                evidence = dict(evidence)
                evidence["report"] = {
                    **report,
                    "seq": evidence.get("interaction_count", 0),
                    "conversation": len(probe.session_prompts),
                }
        return PhaseRun(
            phase,
            trial,
            failure,
            evidence,
            evidence_error,
            tuple(prompts),
            tuple(replies),
        )

    async def _run_phased(self, probe) -> AsyncIterator[Finding]:
        self._sends_ok = self._sends_failed = 0
        results = []
        cap = None
        trial = 0
        try:
            for trial in range(1, probe.trials + 1):
                clean = await self._run_phase(probe, "clean", trial)
                failure = clean_failure(probe, clean)
                if failure is not None:
                    results.append(failure)
                    continue
                attack = await self._run_phase(probe, "attack", trial)
                results.append(judge_trial(probe, clean, attack))
        except ProbeNotApplicable as exc:
            yield self._skip(probe, str(exc))
            return
        except CostExceededError as exc:
            cap = exc
        summary = aggregate_trials(
            [r.verdict for r in results], stopped_at_cost_cap=cap is not None
        )
        probed_at = datetime.now(timezone.utc)
        prefix = f"cost cap hit at trial {trial}: {cap} " if cap is not None else ""
        wording = (
            pass_wording(probe.trials, probed_at.date())
            if summary.verdict == "pass"
            else summary.sentence()
        )
        reasons = " ".join(
            f"Trial {r.trial}: {r.verdict} ({r.reason_code}): {r.reason}"
            for r in results
        )
        reasoning = (
            prefix
            + probe.scope_note
            + " "
            + wording
            + " "
            + summary.counts_line()
            + " "
            + reasons
        )
        attacks = [r.attack for r in results if r.attack is not None]
        yield self._finding(
            probe,
            "\n\n".join(p for run in attacks for p in run.prompts),
            attacks[-1].replies[-1] if attacks and attacks[-1].replies else "",
            0.0,
            probed_at,
            verdict=summary.verdict,
            severity=probe.severity if summary.verdict in ("fail", "warn") else "info",
            confidence=1.0,
            reasoning=reasoning.strip(),
            events=events_from_trials([(r.trial, r.attack.evidence) for r in results
                                       if r.attack is not None and r.attack.evidence is not None])
            if getattr(probe, "scenario_kind", None) == "a2a_world" else None,
            evidence={
                "trial_summary": summary.as_dict(),
                "trials": [r.as_dict() for r in results],
            },
        )
        self._check_breaker()
        if cap is not None:
            raise cap

    async def _run_static(
        self, probe, rubric_text: str | None
    ) -> AsyncIterator[Finding]:
        """Static-prompt path.

        Default: each prompt is an independent single shot (history stays empty).
        With `conversation: true`: prompts are consecutive turns of one
        conversation, so prompt N is sent with turns 1..N-1 as history.
        """
        from argus.targets._base import Turn

        indirect = getattr(probe, "indirect", ())
        use_material = bool(indirect) and getattr(self._target, "material_channel", False)
        sessions = getattr(probe, "sessions", ())
        conversation = getattr(probe, "conversation", False) or bool(sessions)
        session_starts = {}
        offset = 0
        for session, prompts in enumerate(sessions, 1):
            session_starts[offset] = session
            offset += len(prompts)
        session = 1
        exchanges = []
        transcript: list[Turn] = []
        for idx, prompt in enumerate(probe.prompts):
            if idx in session_starts:
                session = session_starts[idx]
                transcript = []
            indirect_evidence = {"indirect": {
                "task": indirect[idx].task,
                "material_sha256": hashlib.sha256(indirect[idx].material.encode("utf-8")).hexdigest(),
            }} if use_material else {}
            probed_at = datetime.now(timezone.utc)
            try:
                if use_material:
                    response_text, latency_ms = await self._target.send_prompt(
                        indirect[idx].task, history=fit_history(tuple(transcript), self._input_limits.max_history_chars)[0], material=indirect[idx].material
                    )
                else:
                    response_text, latency_ms = await self._target.send_prompt(
                        prompt, history=fit_history(tuple(transcript), self._input_limits.max_history_chars)[0]
                    )
            except Exception as e:
                failure = _send_failure(e)
                if failure is None:
                    raise
                verdict, reasoning = failure
                self._note_send(reasoning if verdict == VERDICT_ERROR else None)
                yield self._finding(
                    probe,
                    prompt,
                    "",
                    0.0,
                    probed_at,
                    verdict=verdict,
                    severity="info",
                    confidence=1.0,
                    reasoning=reasoning,
                    evidence={**(_transport_failure_evidence(e) or {}), **indirect_evidence} or None,
                )
                # Later turns of a conversation mean nothing without this one.
                if conversation:
                    return
                continue
            self._note_send(None)
            if sessions:
                exchanges.append({"session": session, "prompt": self._shown(prompt),
                                  "reply": response_text or ""})
            # An empty reply is a broken response path, not a refusal; a judge would read it as a pass.
            if not probe.assertions and _blank(response_text):
                yield self._finding(
                    probe,
                    prompt,
                    response_text or "",
                    latency_ms,
                    probed_at,
                    verdict=VERDICT_ERROR,
                    severity="info",
                    confidence=1.0,
                    reasoning=_no_text_reason(self._target),
                    evidence=indirect_evidence or None,
                )
                if conversation:
                    return
                continue
            if conversation:
                transcript.append(Turn(role="user", content=prompt))
                transcript.append(Turn(role="assistant", content=response_text))

            # A probe carrying assertions is judged on what the target *did*.
            # Asking an LLM to also form an opinion would cost money and could
            # only disagree with a fact.
            if probe.assertions:
                # One conversation is one attack. The early turns of a
                # multi-turn probe are setup — they contact nothing and prove
                # nothing, and judging them separately reported a three-turn
                # thread as two failed runs plus a verdict. This check is
                # positional (index), not by prompt text: a multi-turn attack
                # that repeats an earlier demand (e.g. re-asking for the same
                # payment after a refusal) would otherwise match on text and
                # be mistaken for the last turn.
                if conversation and idx != len(probe.prompts) - 1:
                    continue
                # A hybrid conversation probe is judged on its final turn only; the estimate counts every prompt.
                f = await self._assertion_finding(
                    probe, prompt, response_text, latency_ms, probed_at
                )
                if sessions:
                    f = replace(f, evidence={**(f.evidence or {}), "sessions": exchanges})
                if indirect_evidence:
                    f = replace(f, evidence={**(f.evidence or {}), **indirect_evidence})
                if f.verdict == VERDICT_PASS and _is_hybrid(probe):
                    try:
                        f = await self._hybrid_finding(probe, rubric_text, f)
                    except ValueError as e:
                        f = self._finding(
                            probe,
                            prompt,
                            response_text,
                            latency_ms,
                            probed_at,
                            verdict=VERDICT_ERROR,
                            severity="info",
                            confidence=1.0,
                            reasoning=f"judge reply could not be used: {str(e)[:200]}",
                            evidence=f.evidence,
                        )
                yield f
                continue

            try:
                verdict = await self._judge.judge(
                    probe_name=probe.name,
                    attack_prompt=prompt if use_material else self._shown(prompt),
                    target_response=response_text,
                    rubric_text=rubric_text,
                    severity=probe.severity,
                )
            except ValueError as e:
                # A judge reply missing a key or not JSON is one unusable
                # verdict, not a broken scan: it must not turn the run into
                # "the scanner failed". Still fail-closed: it never reports a
                # pass. ValueError only (JSONDecodeError subclasses it).
                yield self._finding(
                    probe,
                    prompt,
                    response_text,
                    latency_ms,
                    probed_at,
                    verdict=VERDICT_ERROR,
                    severity="info",
                    confidence=1.0,
                    reasoning=f"judge reply could not be used: {str(e)[:200]}",
                    evidence=indirect_evidence or None,
                )
                continue
            yield Finding(
                id=uuid4(),
                probe_id=probe.id,
                attack_prompt=prompt,
                target_response=response_text,
                target_latency_ms=latency_ms,
                probed_at=probed_at,
                verdict=verdict.verdict,
                severity=verdict.severity,
                confidence=verdict.confidence,
                reasoning=verdict.reasoning,
                judge_model=verdict.judge_model,
                escalated_model=verdict.escalated_model,
                atlas_id=list(probe.mappings.atlas),
                owasp_id=list(probe.mappings.owasp_llm),
                owasp_agentic=list(getattr(probe.mappings, "owasp_agentic", ())),
                nist_id=list(probe.mappings.nist_ai_rmf),
                eu_ai_act_id=list(probe.mappings.eu_ai_act),
                evidence=indirect_evidence or None,
            )

    async def _run_deep(self, probe: PersonaStrategyProbe, rubric_text, *, state: DeepThread | None = None) -> AsyncIterator[Finding]:
        from argus import llm
        from argus.assertions import trap_canaries
        from argus.iterative import IterationContext
        from argus.judge import Verdict
        from argus.targets._base import Turn

        template = self._finding(
            probe, '', '', 0.0, datetime.now(timezone.utc), verdict=VERDICT_ERROR,
            severity='info', confidence=1.0, reasoning='thread did not complete', evidence=None,
        )
        state = state or DeepThread(probe, bool(getattr(self._target, 'supports_history', False)), template)
        probe.input_limits = self._input_limits
        prior_prompts, prior_responses, prior_verdicts, history = [], [], [], []
        while True:
            round_n = len(state.rounds)
            if round_n >= probe.max_rounds:
                yield state.finish('max_rounds')
                return
            ctx = IterationContext(round_n, tuple(prior_prompts), tuple(prior_responses), tuple(prior_verdicts))
            if probe.should_halt(ctx):
                yield state.finish('attacker_stopped', 'attacker stopped before the round limit')
                return
            try:
                prompt = await probe.next_prompt(ctx)
            except CostExceededError as exc:
                yield state.finish('cost', f'cost cap hit at round {round_n}: {exc}')
                return
            except llm.JudgeBlockedError as exc:
                finding = state.finish('attacker_blocked', f'attacker content filter blocked the thread: {_named(exc)}')
                yield replace(finding, evidence={**finding.evidence, 'attacker_blocked': exc.as_dict()})
                return
            except Exception as exc:
                yield state.finish('attacker_stopped', f'attacker could not produce the next prompt: {_named(exc)}')
                return
            if prompt is None or not str(prompt).strip():
                yield state.finish('attacker_stopped', 'attacker stopped before the round limit')
                return
            input_actions = dict(probe.input_actions)
            wire_history, dropped = fit_history(tuple(history), self._input_limits.max_history_chars)
            if dropped:
                input_actions['history_turns_dropped'] = dropped
            probed_at = datetime.now(timezone.utc)
            response, latency = '', 0.0
            try:
                response, latency = await self._target.send_prompt(prompt, history=wire_history)
            except CostExceededError as exc:
                state.observe(self._finding(
                    probe, self._shown(prompt), '', 0.0, probed_at, verdict=VERDICT_ABORTED,
                    severity='info', confidence=1.0, reasoning=f'cost cap hit during send: {exc}', evidence=None,
                ), input_actions=input_actions)
                yield state.finish('cost', f'cost cap hit at round {round_n}: {exc}')
                return
            except Exception as exc:
                failure = _send_failure(exc)
                if failure is None:
                    raise
                verdict_name, reason = failure
                self._note_send(None if verdict_name == VERDICT_BLOCKED_BY_TARGET else reason)
                state.observe(self._finding(
                    probe, self._shown(prompt), '', 0.0, probed_at, verdict=verdict_name,
                    severity='info', confidence=1.0, reasoning=reason, evidence=_transport_failure_evidence(exc),
                ), input_actions=input_actions)
                yield state.finish('blocked_by_target' if verdict_name == VERDICT_BLOCKED_BY_TARGET else 'send_error')
                return
            shown = self._shown(prompt)
            self._note_send(None)
            if not probe.assertions and _blank(response):
                state.observe(self._finding(
                    probe, shown, response or '', latency, probed_at, verdict=VERDICT_ERROR,
                    severity='info', confidence=1.0, reasoning=_no_text_reason(self._target), evidence=None,
                ), input_actions=input_actions)
                yield state.finish('blank_reply')
                return
            current = None
            step = 'judge_unusable'
            try:
                if probe.assertions:
                    step = 'collect_evidence'
                    current = await self._assertion_finding(probe, shown, response, latency, probed_at)
                    step = 'judge_unusable'
                    missing = [value for value in trap_canaries(probe.assertions) if value not in prompt]
                    if (current.verdict == VERDICT_ERROR and probe.requires_interaction
                            and not (current.evidence or {}).get('interaction_count')
                            and not self._evidence_failed):
                        current = replace(current, verdict='not_exercised')
                    if missing and current.verdict != VERDICT_FAIL and not self._evidence_failed:
                        current = replace(current, verdict='not_exercised', severity='info', confidence=1.0,
                                          reasoning=f'the attack prompt did not carry the canary {missing[0]!r}; the probe did not run')
                    elif current.verdict == VERDICT_PASS and _is_hybrid(probe):
                        current = await self._hybrid_finding(probe, rubric_text, current, round_n=round_n)
                else:
                    verdict = await self._judge.judge(
                        probe_name=probe.name, attack_prompt=shown, target_response=response,
                        rubric_text=rubric_text, severity=probe.severity,
                    )
                    current = replace(self._finding(
                        probe, shown, response, latency, probed_at, verdict=verdict.verdict,
                        severity=verdict.severity, confidence=verdict.confidence,
                        reasoning=verdict.reasoning, evidence=None,
                    ), judge_model=verdict.judge_model, escalated_model=verdict.escalated_model)
            except CostExceededError as exc:
                state.observe(self._finding(
                    probe, shown, response, latency, probed_at, verdict=VERDICT_ABORTED,
                    severity='info', confidence=1.0, reasoning=f'cost cap hit while judging: {exc}',
                    evidence=current.evidence if current else None,
                ), input_actions=input_actions)
                yield state.finish('cost', f'cost cap hit at round {round_n}: {exc}')
                return
            except TargetRunStopped:
                raise
            except Exception as exc:
                evidence = dict(current.evidence or {}) if current else {}
                if step == 'collect_evidence':
                    evidence['evidence_error'] = _named(exc)
                if isinstance(exc, llm.JudgeBlockedError):
                    evidence['judge_blocked'] = exc.as_dict()
                state.observe(self._finding(
                    probe, shown, response, latency, probed_at, verdict=VERDICT_ERROR,
                    severity='info', confidence=1.0, reasoning=(f'evidence collection failed: {_named(exc)}' if step == 'collect_evidence'
                               else f'judge reply could not be used: {_named(exc)}'),
                    evidence=evidence or None,
                ), input_actions=input_actions)
                yield state.finish(step)
                return
            if probe.assertions and self._evidence_failed:
                current = replace(current, evidence={**(current.evidence or {}), 'evidence_error': current.reasoning})
            state.observe(current, input_actions=input_actions)
            if current.verdict == VERDICT_FAIL:
                yield state.finish('fail')
                return
            if _blank(response):
                yield state.finish('blank_reply', _no_text_reason(self._target))
                return
            if current.verdict not in {VERDICT_PASS, VERDICT_WARN, 'not_exercised'}:
                yield state.finish('collect_evidence' if self._evidence_failed else 'judge_unusable')
                return
            prior_prompts.append(shown)
            prior_responses.append(response)
            prior_verdicts.append(Verdict(current.verdict, current.severity, current.confidence,
                                          current.reasoning, current.judge_model, current.escalated_model))
            if state.history:
                history.extend((Turn('user', shown), Turn('assistant', response)))

    async def _run_iterative(
        self, probe, rubric_text: str | None
    ) -> AsyncIterator[Finding]:
        """IterativeProbe path: probe.next_prompt(ctx) drives each round."""
        from argus.assertions import trap_canaries
        from argus.cost_meter import CostExceededError
        from argus.iterative import IterationContext
        from argus.judge import Verdict
        from argus.targets._base import TargetDeliveryError, Turn

        prior_prompts: list[str] = []
        prior_responses: list[str] = []
        prior_verdicts = []
        # A probe carrying assertions is judged on what the target *did*, on this
        # path exactly as on the static one. Deep mode wraps assertion-backed
        # payment and MCP probes, and without this the iterative path handed them
        # to the prose judge — which reads a polite reply and says `pass`.
        #
        # A deep thread is ONE probe: one begin_probe, one session, many rounds.
        # So evidence accumulates across the rounds and the verdict rests on the
        # final state. The per-round result is computed anyway, but only to steer
        # the attacker and to let should_halt stop the thread the moment the
        # attack lands; the single Finding that survives is the last one computed,
        # which is why `pending` is yielded after the loop rather than inside it.
        assertions = getattr(probe, "assertions", ())
        pending: Finding | None = None
        # The transcript the target sees. Only populated when the adapter can hold
        # a conversation; against a stateless adapter the attack degrades to
        # query-refinement (see the note in run_probe).
        target_supports_history = getattr(self._target, "supports_history", False)
        transcript: list[Turn] = []
        round_n = 0
        try:
            while True:
                ctx = IterationContext(
                    round_n=round_n,
                    prior_prompts=tuple(prior_prompts),
                    prior_responses=tuple(prior_responses),
                    prior_verdicts=tuple(prior_verdicts),
                )
                if probe.should_halt(ctx):
                    break
                try:
                    prompt = await probe.next_prompt(ctx)
                except llm.CompletionTruncated as exc:
                    yield self._finding(
                        probe, "", "", 0.0, datetime.now(timezone.utc),
                        verdict=VERDICT_ERROR, severity="info", confidence=0.0,
                        reasoning=f"attacker could not produce the next prompt: {_named(exc)}",
                        evidence={"stop_reason": "attacker_stopped", "rounds_run": round_n},
                    )
                    return
                if prompt is None:
                    break
                probed_at = datetime.now(timezone.utc)
                try:
                    response_text, latency_ms = await self._target.send_prompt(
                        prompt, history=fit_history(tuple(transcript), self._input_limits.max_history_chars)[0]
                    )
                except Exception as e:
                    failure = _send_failure(e)
                    if failure is None:
                        raise
                    verdict_name, reasoning = failure
                    if isinstance(e, TargetDeliveryError):
                        reasoning = f"target could not deliver round {round_n} prompt: {_short(e)}"
                    else:
                        reasoning = f"round {round_n}: {reasoning}"
                    self._note_send(
                        reasoning if verdict_name == VERDICT_ERROR else None
                    )
                    # The next round needs this round's reply, so the attack ends here.
                    yield self._finding(
                        probe,
                        prompt,
                        "",
                        0.0,
                        probed_at,
                        verdict=verdict_name,
                        severity="info",
                        confidence=1.0,
                        reasoning=reasoning,
                        evidence=_transport_failure_evidence(e),
                    )
                    return
                self._note_send(None)
                if not assertions and _blank(response_text):
                    yield self._finding(
                        probe,
                        prompt,
                        response_text or "",
                        latency_ms,
                        probed_at,
                        verdict=VERDICT_ERROR,
                        severity="info",
                        confidence=1.0,
                        reasoning=f"round {round_n}: {_no_text_reason(self._target)}",
                        evidence=None,
                    )
                    return
                if assertions:
                    current = await self._assertion_finding(
                        probe, prompt, response_text, latency_ms, probed_at
                    )
                    # The attacker rewrites the prompt and may drop the secret; then the agent
                    # never had it and a clean trap proves nothing. A proven leak still stands.
                    missing = [c for c in trap_canaries(assertions) if c not in prompt]
                    if missing and current.verdict != VERDICT_FAIL:
                        current = replace(
                            current,
                            verdict=VERDICT_ERROR,
                            severity="info",
                            confidence=1.0,
                            reasoning=f"the attack prompt did not carry the canary {missing[0]!r}; "
                            "the probe did not run",
                        )
                    elif current.verdict == VERDICT_PASS and _is_hybrid(probe):
                        try:
                            current = await self._hybrid_finding(
                                probe, rubric_text, current, round_n=round_n
                            )
                        except ValueError as e:
                            # Same as the judged branch below: the next round needs this verdict.
                            yield self._finding(
                                probe,
                                prompt,
                                response_text,
                                latency_ms,
                                probed_at,
                                verdict=VERDICT_ERROR,
                                severity="info",
                                confidence=1.0,
                                reasoning=f"judge reply could not be used: {str(e)[:200]}",
                                evidence=current.evidence,
                            )
                            return
                    # Only the last pending finding is reported, so a hybrid thread keeps its worst
                    # round: a later judge pass must not erase an earlier warn.
                    if (
                        not _is_hybrid(probe)
                        or pending is None
                        or (
                            _VERDICT_RANK.get(current.verdict, 1)
                            >= _VERDICT_RANK.get(pending.verdict, 1)
                        )
                    ):
                        pending = current
                    # Fed back as a Verdict purely so the attacker LLM and
                    # should_halt see the round the way they see a judged one.
                    verdict = Verdict(
                        verdict=current.verdict,
                        severity=current.severity,
                        confidence=current.confidence,
                        reasoning=current.reasoning,
                        judge_model=current.judge_model,
                        escalated_model=current.escalated_model,
                    )
                else:
                    try:
                        verdict = await self._judge.judge(
                            probe_name=probe.name,
                            attack_prompt=self._shown(prompt),
                            target_response=response_text,
                            rubric_text=rubric_text,
                            severity=probe.severity,
                        )
                    except ValueError as e:
                        # Same reasoning as the static path. The next round needs
                        # this round's verdict, so the attack ends here.
                        yield self._finding(
                            probe,
                            prompt,
                            response_text,
                            latency_ms,
                            probed_at,
                            verdict=VERDICT_ERROR,
                            severity="info",
                            confidence=1.0,
                            reasoning=f"judge reply could not be used: {str(e)[:200]}",
                            evidence=None,
                        )
                        return
                    yield Finding(
                        id=uuid4(),
                        probe_id=probe.id,
                        attack_prompt=prompt,
                        target_response=response_text,
                        target_latency_ms=latency_ms,
                        probed_at=probed_at,
                        verdict=verdict.verdict,
                        severity=verdict.severity,
                        confidence=verdict.confidence,
                        reasoning=verdict.reasoning,
                        judge_model=verdict.judge_model,
                        escalated_model=verdict.escalated_model,
                        atlas_id=list(probe.mappings.atlas),
                        owasp_id=list(probe.mappings.owasp_llm),
                        owasp_agentic=list(
                            getattr(probe.mappings, "owasp_agentic", ())
                        ),
                        nist_id=list(probe.mappings.nist_ai_rmf),
                        eu_ai_act_id=list(probe.mappings.eu_ai_act),
                    )
                prior_prompts.append(prompt)
                prior_responses.append(response_text)
                prior_verdicts.append(verdict)
                if target_supports_history:
                    transcript.append(Turn(role="user", content=prompt))
                    transcript.append(Turn(role="assistant", content=response_text))
                round_n += 1
        except CostExceededError as e:
            yield Finding(
                id=uuid4(),
                probe_id=probe.id,
                attack_prompt="",
                target_response="",
                target_latency_ms=0.0,
                probed_at=datetime.now(timezone.utc),
                verdict=VERDICT_ABORTED,
                severity="info",
                confidence=1.0,
                reasoning=f"cost cap hit at round {round_n}: {e}",
                judge_model="",
                escalated_model=None,
                atlas_id=list(probe.mappings.atlas),
                owasp_id=list(probe.mappings.owasp_llm),
                owasp_agentic=list(getattr(probe.mappings, "owasp_agentic", ())),
                nist_id=list(probe.mappings.nist_ai_rmf),
                eu_ai_act_id=list(probe.mappings.eu_ai_act),
            )
            return

        # One thread, one finding. A clean early round is setup, not a defended
        # result, so the rounds are not reported separately — the same rule
        # `_run_static` applies to a `conversation: true` probe.
        if pending is not None:
            yield pending
