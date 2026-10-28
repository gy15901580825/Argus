"""The scan-mcp judge gate: judges only rule-undecided candidates, once per text, priced before every call."""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, replace
from typing import Callable, Literal

from argus import llm
from argus.cost_meter import CostExceededError, CostMeter, estimate_call_usd
from argus.judge import Judge
from argus.mcp_scan.models import Candidate

logger = logging.getLogger(__name__)

JUDGE_MAX_TOKENS = 400  # what Judge._call asks for
# Judge._call's fixed framing (system header, output contract, user headings) is under 700 characters.
_PROMPT_FRAME_CHARS = 1000
CAP_REASON = "not judged: cost cap"
ERROR_REASON = "not judged: judge reply unusable"


@dataclass
class JudgeOutcome:
    candidate: Candidate
    status: Literal["judged", "cap", "off", "error"]
    verdict: str = ""
    confidence: float = 0.0
    reasoning: str = ""
    judge_model: str = ""
    escalated_model: str | None = None


def default_judge_factory(meter: CostMeter, config: llm.LLMConfig) -> Judge:
    judge = Judge("", meter, config)
    # The decider's spend never reaches the cost meter and has no price to estimate, so the cap could not hold.
    judge._decider = None
    return judge


def _role_usd(config: llm.LLMConfig, role: str, chars: int) -> float:
    models = [config.model_for(role)]
    fb = config.fallback_provider
    if config.fallback_enabled and fb is not None:
        models.append(llm._DEFAULTS[fb][role])  # llm.complete may answer from the fallback, at its rate
    return max(estimate_call_usd(m, chars, JUDGE_MAX_TOKENS) for m in models)


def call_estimate_usd(config: llm.LLMConfig, chars: int) -> float:
    """Worst-case price of one judge() call: the fast pass plus, when it can happen, the strong escalation."""
    usd = _role_usd(config, "fast", chars)
    return usd + (_role_usd(config, "strong", chars) if config.escalation_is_meaningful else 0.0)


class JudgeGate:
    def __init__(self, per_run_cap_usd: float, config: llm.LLMConfig | None, rubric_text: str,
                 judge_factory: Callable[[CostMeter, llm.LLMConfig], Judge] = default_judge_factory) -> None:
        self.per_run_cap_usd = per_run_cap_usd
        self.config = config
        self.rubric_text = rubric_text
        self.judge_factory = judge_factory

    async def judge_all(self, candidates: list[Candidate], mask: Callable[[str], str]) -> list[JudgeOutcome]:
        """One outcome per candidate, in order. Duplicate texts share one judge call."""
        if self.config is None or self.per_run_cap_usd <= 0:
            return [JudgeOutcome(c, "off") for c in candidates]
        if not candidates:
            return []
        cap = self.per_run_cap_usd
        # Its own meter: never the server's shared one, and an infinite daily cap keeps the alert email silent.
        meter = CostMeter(daily_cap_usd=float("inf"), per_run_cap_usd=cap)
        judge = self.judge_factory(meter, self.config)
        done: dict[str, JudgeOutcome] = {}
        out: list[JudgeOutcome] = []
        capped = False
        with meter.run_scope("scan-mcp"):
            for cand in candidates:
                key = hashlib.sha256(cand.text.encode("utf-8", "surrogatepass")).hexdigest()
                if key not in done:
                    if capped:
                        out.append(JudgeOutcome(cand, "cap", reasoning=CAP_REASON))
                        continue
                    done[key] = await self._judge_one(judge, meter, cand, mask)
                    capped = done[key].status == "cap"
                out.append(replace(done[key], candidate=cand))
        return out

    async def _judge_one(self, judge: Judge, meter: CostMeter, cand: Candidate,
                         mask: Callable[[str], str]) -> JudgeOutcome:
        masked = mask(cand.text)
        attack = mask(f"{cand.source} of MCP tool {cand.tool}")
        chars = len(self.rubric_text) + _PROMPT_FRAME_CHARS + len(cand.probe_id) + len(attack) + len(masked)
        if meter.spent_in_current_run() + call_estimate_usd(self.config, chars) > self.per_run_cap_usd:
            return JudgeOutcome(cand, "cap", reasoning=CAP_REASON)
        try:
            v = await judge.judge(cand.probe_id, attack, masked, self.rubric_text)
        except CostExceededError:
            return JudgeOutcome(cand, "cap", reasoning=CAP_REASON)
        except Exception as e:  # noqa: BLE001 — a provider failure or malformed reply leaves this text unjudged
            logger.warning("scan-mcp judge failed on %s %s: %s", cand.probe_id, cand.tool, type(e).__name__)
            return JudgeOutcome(cand, "error", reasoning=ERROR_REASON)
        if v.verdict not in ("pass", "fail"):
            return JudgeOutcome(cand, "error", reasoning=ERROR_REASON)
        return JudgeOutcome(cand, "judged", verdict=v.verdict, confidence=v.confidence, reasoning=v.reasoning,
                            judge_model=v.judge_model, escalated_model=v.escalated_model)
