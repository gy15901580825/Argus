"""Probe runner — orchestrates probe → target → judge → Finding."""

from __future__ import annotations

import asyncio
import inspect
import logging
import re
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncIterator
from uuid import UUID, uuid4

import httpx

from argus.placeholders import needs_rendering, render_generator_name, target_model_name
from argus.probe import Probe

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


# Verdict constants (Plan 4 T7) — used in Finding.verdict and report renderers.
VERDICT_PASS = "pass"
VERDICT_FAIL = "fail"
VERDICT_ERROR = "error"
VERDICT_BLOCKED_BY_TARGET = "blocked_by_target"  # adapter HTTP 4xx (target gateway content filter)
VERDICT_SKIPPED = "skipped"                       # probe.target_class disjoint from target.compatible_classes
VERDICT_ABORTED = "aborted_cost"                  # mid-run CostExceededError (daily cap crossed)
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

# The empty-reply hint names the field that produced the text, per adapter kind.
_NO_TEXT_HINTS = {
    "custom_http": "check response_jsonpath or the endpoint",
    "openai_compat": "the endpoint returned no message content",
    "anthropic_native": "the endpoint returned no message content",
}


def _no_text_reason(target) -> str:
    hint = _NO_TEXT_HINTS.get(getattr(getattr(target, "spec", None), "kind", None), "check the endpoint")
    return f"target returned no text; {hint}"


def _blank(text) -> bool:
    # Adapters may hand back a non-string (a list of parts); only real emptiness is "no text".
    return text is None or (isinstance(text, str) and not text.strip()) or text in ([], {})

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
    code = getattr(exc, "status_code", None)  # SDK errors such as anthropic.APIStatusError
    return code if isinstance(code, int) else None


def _is_transport_failure(exc: Exception) -> bool:
    """The request did not produce a usable reply: network, timeout, or a body that is not JSON."""
    import json

    from argus.targets._base import TargetDeliveryError

    if isinstance(exc, (httpx.HTTPError, TargetDeliveryError, TimeoutError, ConnectionError,
                        json.JSONDecodeError)):
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


def _never_reached(blocked_reasoning: str) -> str:
    """Reasoning for a block from an agent that never touched its testbed."""
    m = re.match(r"target returned HTTP (\d{3}) ", blocked_reasoning)
    cause = (f"agent returned HTTP {m[1]}" if m
             else f"{blocked_reasoning.split('; counted as blocked')[0]}, and the agent")
    return f"{cause} and never reached the testbed, so the probe did not run; this is not a defended result"


def _send_failure(exc: Exception) -> tuple[str, str] | None:
    """(verdict, reasoning) for a send_prompt failure that costs one probe, or None to re-raise.

    A target outage or a misconfigured spec must never abort the run (losing every
    finding so far) nor read as a defended result.
    """
    from argus.targets._base import TargetBlockedError, TargetDeliveryError

    if isinstance(exc, TargetBlockedError):
        return VERDICT_BLOCKED_BY_TARGET, f"{exc}; counted as blocked"
    grpc_reason = _grpc_reason(exc)
    if grpc_reason is not None:
        return VERDICT_ERROR, grpc_reason
    code = _status_code(exc)
    if code is not None:
        if code in _STATUS_HINTS:
            return VERDICT_ERROR, f"target returned HTTP {code} ({_STATUS_HINTS[code]})"
        if 400 <= code < 500:
            return VERDICT_BLOCKED_BY_TARGET, f"target returned HTTP {code} to the attack prompt; counted as blocked"
        if code >= 500:
            return VERDICT_ERROR, f"target returned HTTP {code} (server error)"
        # raise_for_status also raises on a redirect the adapter did not follow.
        return VERDICT_ERROR, f"target returned HTTP {code}; check endpoint_url / request_url"
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
    nist_id: list[str] = field(default_factory=list)
    eu_ai_act_id: list[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    # What the target observed, when it can observe anything (see
    # Target.collect_evidence). None for the text-only adapters.
    evidence: dict | None = None
    # How to fix it, from the probe's attack_class (argus/remediation.py). Empty when unknown.
    remediation: str = ""


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
        nist_id=list(probe.mappings.nist_ai_rmf),
        eu_ai_act_id=list(probe.mappings.eu_ai_act),
    )


def aborted_finding(probe, reasoning: str) -> Finding:
    """The probe that was running when the cost cap stopped the run."""
    return replace(skipped_finding(probe, reasoning), verdict=VERDICT_ABORTED)


class Runner:
    def __init__(self, target, judge, rubrics_dir: Path) -> None:
        self._target = target
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
        # Template slots ({generator.name}) must never reach the target as literals.
        name = target_model_name(self._target)
        if isinstance(probe, Probe) and any(needs_rendering(p) for p in probe.prompts):
            probe = replace(probe, prompts=tuple(render_generator_name(p, name) for p in probe.prompts))
        base = getattr(probe, "base", None)  # deep mode: the attacker reads the base's first prompt
        if isinstance(base, Probe) and any(needs_rendering(p) for p in base.prompts):
            probe.base = replace(base, prompts=tuple(render_generator_name(p, name) for p in base.prompts))
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
            logger.warning("rubric not found for probe %s: resolved=%s", probe.id, candidate)
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
                    nist_id=list(probe.mappings.nist_ai_rmf),
                    eu_ai_act_id=list(probe.mappings.eu_ai_act),
                )
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
        if getattr(probe, "conversation", False) and not getattr(
            self._target, "supports_history", False
        ):
            yield self._skip(
                probe,
                f"probe requires conversation history but target adapter "
                f"{type(self._target).__name__} declares supports_history=False",
            )
            return

        # A judged probe with no rubric file would be judged against nothing. Error
        # before any send or attacker call; evidence-judged probes need no rubric.
        if rubric_text is None and not getattr(probe, "assertions", ()):
            yield self._finding(
                probe, "", "", 0.0, datetime.now(timezone.utc),
                verdict=VERDICT_ERROR, severity="info", confidence=1.0,
                reasoning=f"rubric file not found: {candidate}", evidence=None,
            )
            return

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
                    probe, "", "", 0.0, datetime.now(timezone.utc),
                    verdict=VERDICT_ERROR, severity="info", confidence=1.0,
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
                    probe, "", "", 0.0, datetime.now(timezone.utc),
                    verdict=VERDICT_ERROR, severity="info", confidence=1.0,
                    reasoning=f"target could not set up this probe: {_short(e)}",
                    evidence=None,
                )
                self._sends_ok, self._sends_failed = 0, 1
                self._last_send_failure = f"target could not set up this probe: {_short(e)}"
                self._check_breaker()
                return

        self._evidence_failed = False
        self._sends_ok = self._sends_failed = 0

        # Dispatch on iterative flag
        if getattr(probe, "iterative", False):
            inner = self._run_iterative(probe, rubric_text)
        else:
            inner = self._run_static(probe, rubric_text)

        # Attach whatever the target observed. Text-only adapters return {} and
        # their findings keep evidence=None, so nothing downstream changes for
        # them. A finding that already carries evidence built its own verdict
        # from it and is left alone. After a failed fetch for this probe, a
        # refetch would attach evidence its error verdict was never based on.
        async for f in inner:
            # Show the prompt as it went on the wire, not the probe's template.
            f = replace(f, attack_prompt=self._shown(f.attack_prompt))
            if f.evidence is None and not self._evidence_failed:
                # Duck-typed targets are everywhere in the test suite; only call
                # a collector that is genuinely an async method, so a bare mock
                # target keeps working.
                collector = getattr(self._target, "collect_evidence", None)
                if inspect.iscoroutinefunction(collector):
                    try:
                        observed = await collector()
                    except Exception as e:
                        # The verdict was decided without evidence, so a testbed
                        # blip only loses the attachment; say so and keep going.
                        if not _is_transport_failure(e):
                            raise
                        f = replace(f, reasoning=f"{f.reasoning} | evidence unavailable: {_short(e)}")
                    else:
                        if observed:
                            f = replace(f, evidence=observed)
            # A 4xx or refusal before the agent touched the testbed means the attack was never
            # staged in front of it (unreachable testbed, wrong origin), not that it was defended.
            # Same gate as _assertion_finding: only evidence-judged probes that need the testbed.
            if (f.verdict == VERDICT_BLOCKED_BY_TARGET and probe.assertions and probe.requires_interaction
                    and not (f.evidence or {}).get("interaction_count")):
                f = replace(f, verdict=VERDICT_ERROR, reasoning=_never_reached(f.reasoning))
            yield f
        self._check_breaker()

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


    async def _assertion_finding(self, probe, prompt, response_text, latency_ms, probed_at) -> Finding:
        """Build a Finding whose verdict comes from captured evidence."""
        from argus.assertions import evaluate_assertions

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
                return self._finding(
                    probe, prompt, response_text, latency_ms, probed_at,
                    verdict=VERDICT_ERROR, severity="info", confidence=1.0,
                    reasoning=f"could not read evidence from the testbed: {_short(e)}",
                    evidence=None,
                )

        # An assertion-backed probe that never reached its target proves nothing.
        # Every "did not overpay" check is satisfied by doing nothing at all, so
        # reporting a pass here would hand the customer a false green.
        if probe.requires_interaction and not evidence.get("interaction_count"):
            return self._finding(
                probe, prompt, response_text, latency_ms, probed_at,
                verdict=VERDICT_ERROR, severity="info", confidence=1.0,
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
            prompt_index = 0  # deep thread: the attacker is shown only the base's first prompt
        # Blocking registry lookups must not stall the event loop.
        results = await asyncio.to_thread(
            evaluate_assertions, probe.assertions, evidence, response_text, prompt_index
        )
        undecided = [r for r in results if r.error]
        if undecided:
            return self._finding(
                probe, prompt, response_text, latency_ms, probed_at,
                verdict=VERDICT_ERROR, severity="info", confidence=1.0,
                reasoning="; ".join(r.reason for r in undecided),
                evidence=evidence or None,
            )
        failed = [r for r in results if not r.passed]
        reasoning = "; ".join(r.reason for r in (failed or results))
        return self._finding(
            probe, prompt, response_text, latency_ms, probed_at,
            verdict=VERDICT_FAIL if failed else VERDICT_PASS,
            severity=probe.severity if failed else "info",
            confidence=1.0,
            reasoning=reasoning,
            evidence=evidence or None,
        )

    def _finding(self, probe, prompt, response_text, latency_ms, probed_at,
                 *, verdict, severity, confidence, reasoning, evidence) -> Finding:
        return Finding(
            id=uuid4(), probe_id=probe.id,
            attack_prompt=prompt, target_response=response_text,
            target_latency_ms=latency_ms, probed_at=probed_at,
            verdict=verdict, severity=severity, confidence=confidence,
            reasoning=reasoning,
            # Deterministic verdicts name no model, because none was consulted.
            judge_model="", escalated_model=None,
            atlas_id=list(probe.mappings.atlas),
            owasp_id=list(probe.mappings.owasp_llm),
            nist_id=list(probe.mappings.nist_ai_rmf),
            eu_ai_act_id=list(probe.mappings.eu_ai_act),
            evidence=evidence,
        )

    async def _run_static(self, probe, rubric_text: str | None) -> AsyncIterator[Finding]:
        """Static-prompt path.

        Default: each prompt is an independent single shot (history stays empty).
        With `conversation: true`: prompts are consecutive turns of one
        conversation, so prompt N is sent with turns 1..N-1 as history.
        """
        from argus.targets._base import Turn

        conversation = getattr(probe, "conversation", False)
        transcript: list[Turn] = []
        for idx, prompt in enumerate(probe.prompts):
            probed_at = datetime.now(timezone.utc)
            try:
                response_text, latency_ms = await self._target.send_prompt(
                    prompt, history=tuple(transcript)
                )
            except Exception as e:
                failure = _send_failure(e)
                if failure is None:
                    raise
                verdict, reasoning = failure
                self._note_send(reasoning if verdict == VERDICT_ERROR else None)
                yield self._finding(
                    probe, prompt, "", 0.0, probed_at,
                    verdict=verdict, severity="info", confidence=1.0,
                    reasoning=reasoning, evidence=None,
                )
                # Later turns of a conversation mean nothing without this one.
                if conversation:
                    return
                continue
            self._note_send(None)
            # An empty reply is a broken response path, not a refusal; a judge would read it as a pass.
            if not probe.assertions and _blank(response_text):
                yield self._finding(
                    probe, prompt, response_text or "", latency_ms, probed_at,
                    verdict=VERDICT_ERROR, severity="info", confidence=1.0,
                    reasoning=_no_text_reason(self._target), evidence=None,
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
                yield await self._assertion_finding(probe, prompt, response_text, latency_ms, probed_at)
                continue

            try:
                verdict = await self._judge.judge(
                    probe_name=probe.name,
                    attack_prompt=self._shown(prompt),
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
                    probe, prompt, response_text, latency_ms, probed_at,
                    verdict=VERDICT_ERROR, severity="info", confidence=1.0,
                    reasoning=f"judge reply could not be used: {str(e)[:200]}",
                    evidence=None,
                )
                continue
            yield Finding(
                id=uuid4(), probe_id=probe.id,
                attack_prompt=prompt, target_response=response_text,
                target_latency_ms=latency_ms, probed_at=probed_at,
                verdict=verdict.verdict, severity=verdict.severity,
                confidence=verdict.confidence, reasoning=verdict.reasoning,
                judge_model=verdict.judge_model, escalated_model=verdict.escalated_model,
                atlas_id=list(probe.mappings.atlas),
                owasp_id=list(probe.mappings.owasp_llm),
                nist_id=list(probe.mappings.nist_ai_rmf),
                eu_ai_act_id=list(probe.mappings.eu_ai_act),
            )

    async def _run_iterative(self, probe, rubric_text: str | None) -> AsyncIterator[Finding]:
        """IterativeProbe path: probe.next_prompt(ctx) drives each round."""
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
                prompt = await probe.next_prompt(ctx)
                if prompt is None:
                    break
                probed_at = datetime.now(timezone.utc)
                try:
                    response_text, latency_ms = await self._target.send_prompt(
                        prompt, history=tuple(transcript)
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
                    self._note_send(reasoning if verdict_name == VERDICT_ERROR else None)
                    # The next round needs this round's reply, so the attack ends here.
                    yield self._finding(
                        probe, prompt, "", 0.0, probed_at,
                        verdict=verdict_name, severity="info", confidence=1.0,
                        reasoning=reasoning, evidence=None,
                    )
                    return
                self._note_send(None)
                if not assertions and _blank(response_text):
                    yield self._finding(
                        probe, prompt, response_text or "", latency_ms, probed_at,
                        verdict=VERDICT_ERROR, severity="info", confidence=1.0,
                        reasoning=f"round {round_n}: {_no_text_reason(self._target)}", evidence=None,
                    )
                    return
                if assertions:
                    pending = await self._assertion_finding(
                        probe, prompt, response_text, latency_ms, probed_at
                    )
                    # Fed back as a Verdict purely so the attacker LLM and
                    # should_halt see the round the way they see a judged one.
                    verdict = Verdict(
                        verdict=pending.verdict, severity=pending.severity,
                        confidence=pending.confidence, reasoning=pending.reasoning,
                        judge_model="", escalated_model=None,
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
                            probe, prompt, response_text, latency_ms, probed_at,
                            verdict=VERDICT_ERROR, severity="info", confidence=1.0,
                            reasoning=f"judge reply could not be used: {str(e)[:200]}",
                            evidence=None,
                        )
                        return
                    yield Finding(
                        id=uuid4(), probe_id=probe.id,
                        attack_prompt=prompt, target_response=response_text,
                        target_latency_ms=latency_ms, probed_at=probed_at,
                        verdict=verdict.verdict, severity=verdict.severity,
                        confidence=verdict.confidence, reasoning=verdict.reasoning,
                        judge_model=verdict.judge_model, escalated_model=verdict.escalated_model,
                        atlas_id=list(probe.mappings.atlas),
                        owasp_id=list(probe.mappings.owasp_llm),
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
                id=uuid4(), probe_id=probe.id,
                attack_prompt="", target_response="",
                target_latency_ms=0.0, probed_at=datetime.now(timezone.utc),
                verdict=VERDICT_ABORTED, severity="info",
                confidence=1.0,
                reasoning=f"cost cap hit at round {round_n}: {e}",
                judge_model="", escalated_model=None,
                atlas_id=list(probe.mappings.atlas),
                owasp_id=list(probe.mappings.owasp_llm),
                nist_id=list(probe.mappings.nist_ai_rmf),
                eu_ai_act_id=list(probe.mappings.eu_ai_act),
            )
            return

        # One thread, one finding. A clean early round is setup, not a defended
        # result, so the rounds are not reported separately — the same rule
        # `_run_static` applies to a `conversation: true` probe.
        if pending is not None:
            yield pending
