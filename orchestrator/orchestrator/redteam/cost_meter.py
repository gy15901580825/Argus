"""Cost meter with daily cap, per-run cap, predictive abort, and email alerts.

Strategy C semantics (Plan 4):
- daily_cap_usd: global; > cap rejects all new runs and any further `record` calls
- per_run_cap_usd: per-run; record() raises CostExceededError when next call would exceed
- predictive abort: pre-run estimator refuses runs whose estimated cost > per_run_cap or > daily remaining
- alert_threshold: at this fraction of daily_cap, fire one email alert; cooldown to avoid flood
"""
from __future__ import annotations

import contextlib
import logging
import time as _time
from datetime import date
from typing import Optional

logger = logging.getLogger(__name__)

# USD per 1M tokens. Anthropic list prices; Azure entries are the operator's
# negotiated rates and MUST be confirmed against the Azure agreement — the values
# here are placeholders chosen so the cap errs high, not billing facts. Override
# per-deployment with REDTEAM_PRICE_<MODEL>_INPUT / _OUTPUT if they differ.
_PRICES_PER_M_TOKENS = {
    "claude-haiku-4-5-20251001": {"input": 1.0, "output": 5.0},
    "claude-sonnet-4-6": {"input": 3.0, "output": 15.0},
    "claude-opus-4-7": {"input": 15.0, "output": 75.0},
    # Azure OpenAI deployments (see redteam/llm.py).
    "gpt-5.4-mini": {"input": 1.0, "output": 5.0},
}


def _price_for(model: str) -> dict:
    """Price lookup for `model`, pessimistic on a miss.

    The previous behaviour fell back to the CHEAPEST entry, so an unregistered
    model was silently under-counted and the daily cap permitted real spend past
    its limit. For a safety limit the fallback must over-estimate: an unknown
    model is billed at the most expensive known rate, and says so.
    """
    known = _PRICES_PER_M_TOKENS.get(model)
    if known is not None:
        return known
    worst = {
        "input": max(p["input"] for p in _PRICES_PER_M_TOKENS.values()),
        "output": max(p["output"] for p in _PRICES_PER_M_TOKENS.values()),
    }
    logger.warning(
        "no price registered for model %r — billing at the most expensive known rate "
        "(in=$%.2f/out=$%.2f per 1M tokens) so the cap cannot be undershot. "
        "Add it to _PRICES_PER_M_TOKENS.",
        model, worst["input"], worst["output"],
    )
    return worst

# Predictive estimator constants — char-based with margin (no real tokenizer dep).
_AVG_PROMPT_CHARS = 1000        # typical probe prompt
_AVG_RESPONSE_CHARS = 2000      # typical model reply
_CHARS_PER_TOKEN = 4
_SAFETY_MARGIN = 1.2

_DEFAULT_ITERATIVE_ROUNDS = 1


# Half a cent: below this a remaining budget is float residue, not money.
_BUDGET_EPSILON_USD = 0.005


class CostExceededError(RuntimeError):
    """Raised when a daily or per-run cap would be exceeded."""
    pass


# Backward-compat alias — remove after all callers are updated.
CostCapExceeded = CostExceededError


def _send_alert(meter: "CostMeter") -> None:
    """Hook for email_alert.send_daily_alert; patched in tests."""
    try:
        from orchestrator.email_alert import send_daily_alert
        send_daily_alert(meter.spent_today(), meter.daily_cap_usd)
    except Exception as e:
        logger.warning("Cost alert email failed (non-fatal): %s", e)


class CostMeter:
    def __init__(
        self,
        daily_cap_usd: float,
        per_run_cap_usd: float = 0.50,
        alert_threshold: float = 0.80,
        alert_cooldown_s: float = 3600.0,
        deep_per_run_cap_usd: float = 5.00,
        deep_budget_fraction: float = 0.60,
    ) -> None:
        self.daily_cap_usd = daily_cap_usd
        self.per_run_cap_usd = per_run_cap_usd
        self.alert_threshold = alert_threshold
        self.alert_cooldown_s = alert_cooldown_s
        # Deep (persona x strategy) runs escalate for up to 20 rounds and cost far
        # more than a static scan, so they get their own per-run cap.
        self.deep_per_run_cap_usd = deep_per_run_cap_usd
        # ...and their own slice of the day. record() rejects ALL spend once the
        # daily cap is hit, so without a partition two $5 deep runs would exhaust a
        # $13.50 day and every subsequent static CI gate would fail with
        # aborted_cost. Deep runs may consume at most this fraction; the remainder
        # is reserved for the static path.
        self.deep_budget_fraction = deep_budget_fraction
        self._day = date.today()
        self._spent_today = 0.0
        self._spent_today_deep = 0.0
        self._spent_in_run: Optional[float] = None  # None when no run is active
        self._run_is_deep = False
        self._last_alert_ts = 0.0

    @property
    def deep_daily_cap_usd(self) -> float:
        return self.daily_cap_usd * self.deep_budget_fraction

    def _maybe_reset_day(self) -> None:
        today = date.today()
        if today != self._day:
            self._day = today
            self._spent_today = 0.0
            self._spent_today_deep = 0.0
            self._last_alert_ts = 0.0

    def spent_today(self) -> float:
        self._maybe_reset_day()
        return self._spent_today

    def spent_today_deep(self) -> float:
        self._maybe_reset_day()
        return self._spent_today_deep

    def deep_budget_remaining(self) -> float:
        remaining = self.deep_daily_cap_usd - self.spent_today_deep()
        # Accumulated float error leaves sub-picocent residue after a slice is
        # drained. Treating that as "budget available" would admit a run that
        # aborts on its first call — the partial report this partition exists to
        # prevent. Anything under half a cent is exhausted.
        return remaining if remaining >= _BUDGET_EPSILON_USD else 0.0

    def can_start_deep_run(self) -> bool:
        """Checked before a deep run is created, so exhaustion is an upfront refusal
        rather than a mid-run abort that yields a partial report."""
        return self.deep_budget_remaining() > 0.0 and self.spent_today() < self.daily_cap_usd

    def spent_in_current_run(self) -> float:
        return self._spent_in_run or 0.0

    @contextlib.contextmanager
    def run_scope(self, run_id: str, deep: bool = False):
        if self._spent_in_run is not None:
            raise RuntimeError(f"run_scope is non-reentrant; another run is active")
        if deep and not self.can_start_deep_run():
            raise CostExceededError(
                f"deep budget ${self.deep_daily_cap_usd:.2f}/day "
                f"(={self.deep_budget_fraction:.0%} of the ${self.daily_cap_usd:.2f} daily cap) "
                f"is exhausted; ${self.deep_budget_remaining():.2f} remains. "
                "Static runs are unaffected."
            )
        self._spent_in_run = 0.0
        self._run_is_deep = deep
        try:
            yield
        finally:
            self._spent_in_run = None
            self._run_is_deep = False

    def record(self, model: str, input_tokens: int, output_tokens: int) -> float:
        self._maybe_reset_day()
        if self._spent_today >= self.daily_cap_usd:
            raise CostExceededError(
                f"daily cap ${self.daily_cap_usd:.2f} already reached on {self._day}"
            )
        prices = _price_for(model)
        cost = (input_tokens / 1_000_000) * prices["input"] + (output_tokens / 1_000_000) * prices["output"]

        # Per-run check uses pre-call accounting (lookahead): the next call to
        # record cannot push the per-run total above the applicable cap.
        if self._spent_in_run is not None:
            cap = self.deep_per_run_cap_usd if self._run_is_deep else self.per_run_cap_usd
            label = "deep per_run" if self._run_is_deep else "per_run"
            if self._spent_in_run + cost > cap:
                raise CostExceededError(
                    f"{label} cap ${cap:.2f} would be exceeded by this call"
                )
            if self._run_is_deep and self._spent_today_deep + cost > self.deep_daily_cap_usd:
                raise CostExceededError(
                    f"deep daily budget ${self.deep_daily_cap_usd:.2f} would be exceeded "
                    "by this call; static runs are unaffected"
                )
            self._spent_in_run += cost
            if self._run_is_deep:
                self._spent_today_deep += cost

        self._spent_today += cost
        self._maybe_alert()
        return cost

    def _maybe_alert(self) -> None:
        if self._spent_today < self.daily_cap_usd * self.alert_threshold:
            return
        now = _time.time()
        if now - self._last_alert_ts < self.alert_cooldown_s:
            return
        self._last_alert_ts = now
        _send_alert(self)

    def alert_triggered(self) -> bool:
        """Legacy helper kept for backward compat."""
        return self.spent_today() >= self.daily_cap_usd * self.alert_threshold

    def check_or_abort_pre_run(
        self,
        probe_ids: list[str],
        target_kind: str,
        iterative_rounds: int = _DEFAULT_ITERATIVE_ROUNDS,
        per_run_cap_override: float | None = None,
        total_exchanges: int | None = None,
        deep: bool = False,
    ) -> float:
        """Estimate total cost for the proposed run; raise if > per_run_cap or > daily remaining.

        per_run_cap_override: when provided, use this cap instead of the applicable
        per-run cap. Callers supply this from RunRequest.per_run_cap_usd to honor
        client-side caps.

        total_exchanges: total attack exchanges (one prompt sent + judged) across
        the whole run. One probe is not one exchange — a static probe sends every
        prompt it declares, and a deep/iterative thread runs up to max_rounds of
        them — so the caller, which knows the run shape, supplies the real count.
        Falls back to `len(probe_ids) * iterative_rounds` when omitted.

        deep: budget this run against the deep caps (deep_per_run_cap_usd and the
        deep slice of the day) instead of the static ones, and count the attacker
        LLM that drives every deep round.
        """
        self._maybe_reset_day()
        # Per-exchange: target send + judge call ≈ 2 LLM calls; an attacker/planner
        # LLM adds ≈ 1 more — always in deep mode, and assumed for the chat kinds.
        calls_per_round = 3 if (deep or target_kind in {"openai_compat", "anthropic_native"}) else 2
        # Char-based heuristic with safety margin
        est_input_tokens = (_AVG_PROMPT_CHARS / _CHARS_PER_TOKEN) * _SAFETY_MARGIN
        est_output_tokens = (_AVG_RESPONSE_CHARS / _CHARS_PER_TOKEN) * _SAFETY_MARGIN
        # Use Haiku rates as the dominant judge model
        prices = _PRICES_PER_M_TOKENS["claude-haiku-4-5-20251001"]
        cost_per_call = (est_input_tokens / 1_000_000) * prices["input"] + (
            est_output_tokens / 1_000_000
        ) * prices["output"]
        exchanges = total_exchanges if total_exchanges is not None else len(probe_ids) * iterative_rounds
        estimated = cost_per_call * exchanges * calls_per_round

        default_cap = self.deep_per_run_cap_usd if deep else self.per_run_cap_usd
        cap = per_run_cap_override if per_run_cap_override is not None else default_cap
        if estimated > cap:
            raise CostExceededError(
                f"estimated cost ${estimated:.4f} > per_run_cap ${cap:.2f}"
            )
        remaining = self.daily_cap_usd - self._spent_today
        label = "daily"
        if deep:
            # A deep run may only draw on its slice of the day; the remainder is
            # reserved so deep scans cannot starve the static CI path.
            if self.deep_budget_remaining() < remaining:
                remaining = self.deep_budget_remaining()
                label = "deep daily"
        if estimated > remaining:
            raise CostExceededError(
                f"estimated cost ${estimated:.4f} would exceed remaining {label} budget "
                f"(${remaining:.4f})"
            )
        return estimated
