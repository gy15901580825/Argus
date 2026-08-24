"""Probe runner — orchestrates probe → target → judge → Finding."""

from __future__ import annotations

import inspect
import logging
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncIterator
from uuid import UUID, uuid4

from orchestrator.redteam.probe import Probe

logger = logging.getLogger(__name__)

# Verdict constants (Plan 4 T7) — used in Finding.verdict and report renderers.
VERDICT_PASS = "pass"
VERDICT_FAIL = "fail"
VERDICT_ERROR = "error"
VERDICT_BLOCKED_BY_TARGET = "blocked_by_target"  # adapter HTTP 4xx (target gateway content filter)
VERDICT_SKIPPED = "skipped"                       # probe.target_class disjoint from target.compatible_classes
VERDICT_ABORTED = "aborted_cost"                  # mid-run CostExceededError (daily cap crossed)


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


class Runner:
    def __init__(self, target, judge, rubrics_dir: Path) -> None:
        self._target = target
        self._judge = judge
        self._rubrics_dir = Path(rubrics_dir)
        # Inject the meter into iterative modules so their planner LLM calls record cost.
        # The meter is extracted from judge, which was passed in from api.py.
        if hasattr(judge, "_cost_meter") and judge._cost_meter is not None:
            from orchestrator.redteam import iterative_tap, iterative_pair, persona_strategy
            iterative_tap.set_cost_meter(judge._cost_meter)
            iterative_pair.set_cost_meter(judge._cost_meter)
            persona_strategy.set_cost_meter(judge._cost_meter)

    def _skip(self, probe, reasoning: str) -> Finding:
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

    async def run_probe(self, probe) -> AsyncIterator[Finding]:
        # Existing rubric resolution unchanged
        rel = Path(probe.judge_rubric_path)
        if rel.parts and rel.parts[0] == "rubrics":
            rel = Path(*rel.parts[1:])
        rubrics_root = self._rubrics_dir.resolve()
        candidate = (self._rubrics_dir / rel).resolve()
        if not (candidate == rubrics_root or rubrics_root in candidate.parents):
            raise ValueError(f"rubric path escapes rubrics_dir: {probe.judge_rubric_path!r}")
        if candidate.exists() and candidate.is_file():
            rubric_text = candidate.read_text()
        else:
            logger.warning("rubric not found for probe %s: resolved=%s", probe.id, candidate)
            rubric_text = ""

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

        # Dispatch on iterative flag
        if getattr(probe, "iterative", False):
            inner = self._run_iterative(probe, rubric_text)
        else:
            inner = self._run_static(probe, rubric_text)

        # Attach whatever the target observed. Text-only adapters return {} and
        # their findings keep evidence=None, so nothing downstream changes for
        # them. A finding that already carries evidence built its own verdict
        # from it and is left alone.
        async for f in inner:
            if f.evidence is None:
                # Duck-typed targets are everywhere in the test suite; only call
                # a collector that is genuinely an async method, so a bare mock
                # target keeps working.
                collector = getattr(self._target, "collect_evidence", None)
                if inspect.iscoroutinefunction(collector):
                    observed = await collector()
                    if observed:
                        f = replace(f, evidence=observed)
            yield f

    async def _assertion_finding(self, probe, prompt, response_text, latency_ms, probed_at) -> Finding:
        """Build a Finding whose verdict comes from captured evidence."""
        from orchestrator.redteam.assertions import evaluate_assertions

        evidence = {}
        collector = getattr(self._target, "collect_evidence", None)
        if inspect.iscoroutinefunction(collector):
            evidence = await collector() or {}

        # An assertion-backed probe that never reached its target proves nothing.
        # Every "did not overpay" check is satisfied by doing nothing at all, so
        # reporting a pass here would hand the customer a false green.
        if probe.requires_interaction and not evidence.get("interaction_count"):
            return self._finding(
                probe, prompt, response_text, latency_ms, probed_at,
                verdict=VERDICT_ERROR, severity="info", confidence=1.0,
                reasoning=(
                    "target never contacted the payment testbed, so the probe did "
                    "not actually run; this is not a defended result"
                ),
                evidence=evidence or None,
            )

        results = evaluate_assertions(probe.assertions, evidence, response_text)
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

    async def _run_static(self, probe, rubric_text: str) -> AsyncIterator[Finding]:
        """Static-prompt path.

        Default: each prompt is an independent single shot (history stays empty).
        With `conversation: true`: prompts are consecutive turns of one
        conversation, so prompt N is sent with turns 1..N-1 as history.
        """
        import httpx
        from orchestrator.redteam.targets._base import Turn

        conversation = getattr(probe, "conversation", False)
        transcript: list[Turn] = []
        for idx, prompt in enumerate(probe.prompts):
            probed_at = datetime.now(timezone.utc)
            try:
                response_text, latency_ms = await self._target.send_prompt(
                    prompt, history=tuple(transcript)
                )
            except httpx.HTTPStatusError as e:
                if 400 <= e.response.status_code < 500:
                    yield Finding(
                        id=uuid4(), probe_id=probe.id,
                        attack_prompt=prompt, target_response="",
                        target_latency_ms=0.0, probed_at=probed_at,
                        verdict=VERDICT_BLOCKED_BY_TARGET, severity="info",
                        confidence=1.0,
                        reasoning=f"target HTTP {e.response.status_code}: target gateway rejected adversarial prompt",
                        judge_model="", escalated_model=None,
                        atlas_id=list(probe.mappings.atlas),
                        owasp_id=list(probe.mappings.owasp_llm),
                        nist_id=list(probe.mappings.nist_ai_rmf),
                        eu_ai_act_id=list(probe.mappings.eu_ai_act),
                    )
                    continue
                raise
            except Exception as e:
                if hasattr(e, "status_code") and isinstance(getattr(e, "status_code", None), int):
                    if 400 <= e.status_code < 500:
                        yield Finding(
                            id=uuid4(), probe_id=probe.id,
                            attack_prompt=prompt, target_response="",
                            target_latency_ms=0.0, probed_at=probed_at,
                            verdict=VERDICT_BLOCKED_BY_TARGET, severity="info",
                            confidence=1.0,
                            reasoning=f"target API status {e.status_code}: target gateway rejected adversarial prompt",
                            judge_model="", escalated_model=None,
                            atlas_id=list(probe.mappings.atlas),
                            owasp_id=list(probe.mappings.owasp_llm),
                            nist_id=list(probe.mappings.nist_ai_rmf),
                            eu_ai_act_id=list(probe.mappings.eu_ai_act),
                        )
                        continue
                raise
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

            verdict = await self._judge.judge(
                probe_name=probe.name,
                attack_prompt=prompt,
                target_response=response_text,
                rubric_text=rubric_text,
            )
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

    async def _run_iterative(self, probe, rubric_text: str) -> AsyncIterator[Finding]:
        """IterativeProbe path: probe.next_prompt(ctx) drives each round."""
        import httpx
        from orchestrator.redteam.cost_meter import CostExceededError
        from orchestrator.redteam.iterative import IterationContext
        from orchestrator.redteam.targets._base import Turn
        prior_prompts: list[str] = []
        prior_responses: list[str] = []
        prior_verdicts = []
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
                    return
                prompt = await probe.next_prompt(ctx)
                if prompt is None:
                    return
                probed_at = datetime.now(timezone.utc)
                try:
                    response_text, latency_ms = await self._target.send_prompt(
                        prompt, history=tuple(transcript)
                    )
                except httpx.HTTPStatusError as e:
                    if 400 <= e.response.status_code < 500:
                        yield Finding(
                            id=uuid4(), probe_id=probe.id,
                            attack_prompt=prompt, target_response="",
                            target_latency_ms=0.0, probed_at=probed_at,
                            verdict=VERDICT_BLOCKED_BY_TARGET, severity="info",
                            confidence=1.0,
                            reasoning=f"target HTTP {e.response.status_code}: target gateway rejected round {round_n} prompt",
                            judge_model="", escalated_model=None,
                            atlas_id=list(probe.mappings.atlas),
                            owasp_id=list(probe.mappings.owasp_llm),
                            nist_id=list(probe.mappings.nist_ai_rmf),
                            eu_ai_act_id=list(probe.mappings.eu_ai_act),
                        )
                        return  # iterative attacks abort on 4xx — target won't engage
                    raise
                except Exception as e:
                    if hasattr(e, "status_code") and isinstance(getattr(e, "status_code", None), int):
                        if 400 <= e.status_code < 500:
                            yield Finding(
                                id=uuid4(), probe_id=probe.id,
                                attack_prompt=prompt, target_response="",
                                target_latency_ms=0.0, probed_at=probed_at,
                                verdict=VERDICT_BLOCKED_BY_TARGET, severity="info",
                                confidence=1.0,
                                reasoning=f"target API status {e.status_code}: target gateway rejected round {round_n} prompt",
                                judge_model="", escalated_model=None,
                                atlas_id=list(probe.mappings.atlas),
                                owasp_id=list(probe.mappings.owasp_llm),
                                nist_id=list(probe.mappings.nist_ai_rmf),
                                eu_ai_act_id=list(probe.mappings.eu_ai_act),
                            )
                            return  # iterative attacks abort on 4xx — target won't engage
                    raise
                verdict = await self._judge.judge(
                    probe_name=probe.name,
                    attack_prompt=prompt,
                    target_response=response_text,
                    rubric_text=rubric_text,
                )
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
