"""The scan-mcp judge gate: judges only rule-undecided candidates, once per text, priced before every call."""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, replace
from typing import Callable, Literal, Sequence

from argus import llm
from argus.judge_blocks import block_reason
from argus.cost_meter import CostExceededError, CostMeter, estimate_call_usd
from argus.judge import Judge, JUDGE_MAX_TOKENS
from argus.jev_judge import EXPLAIN_MAX_TOKENS
from argus.mcp_scan.calls import show_text
from argus.mcp_scan.models import Candidate, Hit

logger = logging.getLogger(__name__)

# Judge._call's fixed framing (system header, untrusted notice, output contract, user headings) is about 830 characters.
_PROMPT_FRAME_CHARS = 1000
CAP_REASON = "not judged: cost cap"
ERROR_REASON = "not judged: judge reply unusable"
BLOCKED_REASON = "not judged: the provider content filter blocked the judge prompt"
# A warn, such as a jev pass below its confidence floor: scan-mcp counts only pass and fail.
UNSURE_REASON = "not judged: judge unsure, needs human review"
OFF_REASON = "not judged: judge off"


@dataclass
class JudgeOutcome:
    candidate: Candidate
    status: Literal["judged", "cap", "off", "error"]
    verdict: str = ""
    confidence: float = 0.0
    reasoning: str = ""
    judge_model: str = ""
    escalated_model: str | None = None
    error_code: Literal["content_filter", "completion_truncated"] | None = None
    judge_blocked: dict | None = None


def default_judge_factory(meter: CostMeter, config: llm.LLMConfig) -> Judge:
    judge = Judge("", meter, config)
    # The decider's spend never reaches the cost meter and has no price to estimate, so the cap could not hold.
    judge._decider = None
    judge._explain_verdicts = ("fail",)  # a warn is dropped below, so its explanation would be paid for nothing
    return judge


def _role_usd(config: llm.LLMConfig, role: str, chars: int) -> float:
    models = [config.model_for(role)]
    fb = config.fallback_provider
    if config.fallback_enabled and fb is not None:
        models.append(config.fallback_model_for(role))  # the fallback may answer, at its rate
    return max(estimate_call_usd(m, chars, JUDGE_MAX_TOKENS) for m in models)


def call_estimate_usd(config: llm.LLMConfig, chars: int) -> float:
    """Worst-case price of one judge() call: the fast pass plus, when it can happen, the strong escalation."""
    usd = _role_usd(config, "fast", chars)
    usd += _role_usd(config, "strong", chars) if config.escalation_is_meaningful else 0.0
    text_cfg = llm.explain_config(config)  # a jev explain model writes a reason for a fail
    return usd + (estimate_call_usd(text_cfg.fast_model, chars, EXPLAIN_MAX_TOKENS) if text_cfg else 0.0)


class JudgeGate:
    def __init__(self, per_run_cap_usd: float, config: llm.LLMConfig | None, rubric_text: str,
                 judge_factory: Callable[[CostMeter, llm.LLMConfig], Judge] = default_judge_factory) -> None:
        self.per_run_cap_usd = per_run_cap_usd
        self.config = config
        self.rubric_text = rubric_text
        self.judge_factory = judge_factory

    async def judge_all(self, candidates: list[Candidate], mask: Callable[[str], str], *,
                        hits: Sequence[Hit] = ()) -> list[JudgeOutcome]:
        """Judge rule-hit calls first; return one outcome per candidate in input order. Duplicate texts share a call."""
        if self.config is None or not self.per_run_cap_usd > 0:  # a NaN cap means off, not unbounded
            return [JudgeOutcome(c, "off", reasoning=OFF_REASON) for c in candidates]
        if not candidates:
            return []
        cap = self.per_run_cap_usd
        # Its own meter: never the server's shared one, and an infinite daily cap keeps the alert email silent.
        meter = CostMeter(daily_cap_usd=float("inf"), per_run_cap_usd=cap)
        judge = self.judge_factory(meter, self.config)
        done: dict[str, JudgeOutcome] = {}
        capped = False
        rule_hits = {(h.tool, h.call_seq) for h in hits}
        ordered = sorted(enumerate(candidates), key=lambda pair:
                         (pair[1].tool, pair[1].call_seq) not in rule_hits)
        results: dict[int, JudgeOutcome] = {}
        with meter.run_scope("scan-mcp"):
            for index, cand in ordered:
                key = hashlib.sha256(cand.text.encode("utf-8", "surrogatepass")).hexdigest()
                if key not in done:
                    if capped:
                        results[index] = JudgeOutcome(cand, "cap", reasoning=CAP_REASON)
                        continue
                    done[key] = await self._judge_one(judge, meter, cand, mask)
                    capped = done[key].status == "cap"
                results[index] = replace(done[key], candidate=cand)
        return [results[i] for i in range(len(candidates))]

    async def _judge_one(self, judge: Judge, meter: CostMeter, cand: Candidate,
                         mask: Callable[[str], str]) -> JudgeOutcome:
        masked = mask(cand.text)
        # The tool name is server-controlled, so it stays out of the trusted attack-prompt slot.
        attack = mask(f"{cand.source} of an MCP tool")
        chars = len(self.rubric_text) + _PROMPT_FRAME_CHARS + len(cand.probe_id) + len(attack) + len(masked)
        if meter.spent_in_current_run() + call_estimate_usd(self.config, chars) > self.per_run_cap_usd:
            return JudgeOutcome(cand, "cap", reasoning=CAP_REASON)
        try:
            v = await judge.judge(cand.probe_id, attack, masked, self.rubric_text)
        except CostExceededError:
            return JudgeOutcome(cand, "cap", reasoning=CAP_REASON)
        except llm.JudgeBlockedError as exc:
            safe = llm.JudgeBlockedError("", provider=show_text(mask(exc.provider)), model=show_text(mask(exc.model)),
                                        categories=tuple(show_text(mask(c)) for c in exc.categories),
                                        fallback=show_text(mask(exc.fallback)) if exc.fallback is not None else None)
            safe.escalated_from = exc.escalated_from
            return JudgeOutcome(cand, "error", verdict="error", reasoning=BLOCKED_REASON + "; " + block_reason(safe),
                                judge_model=safe.model, error_code="content_filter", judge_blocked=safe.as_dict())
        except Exception as e:  # noqa: BLE001 — a provider failure or malformed reply leaves this text unjudged
            # The tool name is the server's text: shown safely, so it cannot drive the terminal.
            logger.warning("scan-mcp judge failed on %s %s: %s", cand.probe_id, show_text(cand.tool),
                           type(e).__name__)
            return JudgeOutcome(cand, "error", reasoning=ERROR_REASON)
        if v.verdict == "error" and "CompletionTruncated" in v.reasoning:
            return JudgeOutcome(cand, "error", reasoning=f"not judged: {v.reasoning}",
                                error_code="completion_truncated")
        if v.verdict == "warn":
            return JudgeOutcome(cand, "error", reasoning=UNSURE_REASON)
        if v.verdict not in ("pass", "fail"):
            return JudgeOutcome(cand, "error", reasoning=ERROR_REASON)
        return JudgeOutcome(cand, "judged", verdict=v.verdict, confidence=v.confidence, reasoning=v.reasoning,
                            judge_model=v.judge_model, escalated_model=v.escalated_model)
