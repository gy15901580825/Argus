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

_PRICES_PER_M_TOKENS = {
    "claude-haiku-4-5-20251001": {"input": 1.0, "output": 5.0},
    "claude-sonnet-4-6": {"input": 3.0, "output": 15.0},
    "claude-opus-4-7": {"input": 15.0, "output": 75.0},
}

# Predictive estimator constants — char-based with margin (no real tokenizer dep).
_AVG_PROMPT_CHARS = 1000        # typical probe prompt
_AVG_RESPONSE_CHARS = 2000      # typical model reply
_CHARS_PER_TOKEN = 4
_SAFETY_MARGIN = 1.2

_DEFAULT_ITERATIVE_ROUNDS = 1


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
    ) -> None:
        self.daily_cap_usd = daily_cap_usd
        self.per_run_cap_usd = per_run_cap_usd
        self.alert_threshold = alert_threshold
        self.alert_cooldown_s = alert_cooldown_s
        self._day = date.today()
        self._spent_today = 0.0
        self._spent_in_run: Optional[float] = None  # None when no run is active
        self._last_alert_ts = 0.0

    def _maybe_reset_day(self) -> None:
        today = date.today()
        if today != self._day:
            self._day = today
            self._spent_today = 0.0
            self._last_alert_ts = 0.0

    def spent_today(self) -> float:
        self._maybe_reset_day()
        return self._spent_today

    def spent_in_current_run(self) -> float:
        return self._spent_in_run or 0.0

    @contextlib.contextmanager
    def run_scope(self, run_id: str):
        if self._spent_in_run is not None:
            raise RuntimeError(f"run_scope is non-reentrant; another run is active")
        self._spent_in_run = 0.0
        try:
            yield
        finally:
            self._spent_in_run = None

    def record(self, model: str, input_tokens: int, output_tokens: int) -> float:
        self._maybe_reset_day()
        if self._spent_today >= self.daily_cap_usd:
            raise CostExceededError(
                f"daily cap ${self.daily_cap_usd:.2f} already reached on {self._day}"
            )
        prices = _PRICES_PER_M_TOKENS.get(model, _PRICES_PER_M_TOKENS["claude-haiku-4-5-20251001"])
        cost = (input_tokens / 1_000_000) * prices["input"] + (output_tokens / 1_000_000) * prices["output"]

        # Per-run check uses pre-call accounting (lookahead): the next call to
        # record cannot push the per-run total above per_run_cap.
        if self._spent_in_run is not None:
            if self._spent_in_run + cost > self.per_run_cap_usd:
                raise CostExceededError(
                    f"per_run cap ${self.per_run_cap_usd:.2f} would be exceeded by this call"
                )
            self._spent_in_run += cost

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
    ) -> float:
        """Estimate total cost for the proposed run; raise if > per_run_cap or > daily remaining.

        per_run_cap_override: when provided, use this cap instead of self.per_run_cap_usd.
        Callers supply this from RunRequest.per_run_cap_usd to honor client-side caps.
        """
        self._maybe_reset_day()
        # Per-call: target send + judge call ≈ 2 LLM calls; iterative probes add planner ≈ 1 more
        calls_per_round = 3 if target_kind in {"openai_compat", "anthropic_native"} else 2
        # Char-based heuristic with safety margin
        est_input_tokens = (_AVG_PROMPT_CHARS / _CHARS_PER_TOKEN) * _SAFETY_MARGIN
        est_output_tokens = (_AVG_RESPONSE_CHARS / _CHARS_PER_TOKEN) * _SAFETY_MARGIN
        # Use Haiku rates as the dominant judge model
        prices = _PRICES_PER_M_TOKENS["claude-haiku-4-5-20251001"]
        cost_per_call = (est_input_tokens / 1_000_000) * prices["input"] + (
            est_output_tokens / 1_000_000
        ) * prices["output"]
        total_calls = len(probe_ids) * iterative_rounds * calls_per_round
        estimated = cost_per_call * total_calls

        cap = per_run_cap_override if per_run_cap_override is not None else self.per_run_cap_usd
        if estimated > cap:
            raise CostExceededError(
                f"estimated cost ${estimated:.4f} > per_run_cap ${cap:.2f}"
            )
        if self._spent_today + estimated > self.daily_cap_usd:
            raise CostExceededError(
                f"estimated cost ${estimated:.4f} would exceed remaining daily budget "
                f"(${self.daily_cap_usd - self._spent_today:.4f})"
            )
        return estimated
