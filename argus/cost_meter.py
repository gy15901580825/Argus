"""Cost meter with daily cap, per-run cap, predictive abort, and email alerts.

Strategy C semantics (Plan 4):
- daily_cap_usd: global; > cap rejects all new runs and any further `record` calls
- per_run_cap_usd: per-run; record() counts a finished call, then raises CostExceededError once spend is past the cap
- predictive abort: pre-run estimator refuses runs whose estimated cost > per_run_cap or > daily remaining
- alert_threshold: at this fraction of daily_cap, fire one email alert; cooldown to avoid flood
"""
from __future__ import annotations

import contextlib
import logging
import math
import os
import re
import time as _time
from datetime import date
from typing import Optional

logger = logging.getLogger(__name__)

# USD per 1M tokens. Anthropic list prices; Azure entries are the operator's
# negotiated rates and MUST be confirmed against the Azure agreement — the values
# here are placeholders chosen so the cap errs high, not billing facts. Override
# any model with REDTEAM_PRICE_<MODEL>_INPUT / _OUTPUT (see price_env_names).
_PRICES_PER_M_TOKENS = {
    "claude-haiku-4-5-20251001": {"input": 1.0, "output": 5.0},
    "claude-sonnet-4-6": {"input": 3.0, "output": 15.0},
    "claude-opus-4-7": {"input": 15.0, "output": 75.0},
    # Azure OpenAI deployments (see redteam/llm.py).
    "gpt-5.4-mini": {"input": 1.0, "output": 5.0},
    # OpenAI judge defaults.
    "gpt-5.6-luna": {"input": 0.20, "output": 1.20},
    "gpt-5.6-terra": {"input": 2.00, "output": 12.00},
    # TypeSafe Jev: $0.042 per 1M input tokens, output tokens free (docs.typesafe.ai/models, read 2026-10-30).
    "jev-latest": {"input": 0.042, "output": 0.0},
    "jev-preview": {"input": 0.042, "output": 0.0},
    "jev-1.14.0": {"input": 0.042, "output": 0.0},
    "jev-1.13.0": {"input": 0.042, "output": 0.0},
}


_WARNED_UNPRICED: set[str] = set()
_WARNED_BAD_PRICE: set[tuple] = set()


def price_env_names(model: str) -> tuple[str, str]:
    """The env vars that declare `model`'s price, USD per 1M tokens: (input, output).

    <MODEL> is the model string upper-cased, with every run of characters other than
    A-Z and 0-9 replaced by one underscore: gemini/gemini-2.5-flash ->
    REDTEAM_PRICE_GEMINI_GEMINI_2_5_FLASH_INPUT and ..._OUTPUT.
    """
    stem = re.sub(r"[^A-Z0-9]+", "_", model.upper()).strip("_")
    return f"REDTEAM_PRICE_{stem}_INPUT", f"REDTEAM_PRICE_{stem}_OUTPUT"


def _declared_price(model: str) -> dict | None:
    """The operator's price for `model` from the env, or None. A half or malformed declaration is ignored, loudly."""
    names = price_env_names(model)
    raw = [os.environ.get(n) for n in names]
    if raw == [None, None]:
        return None
    try:
        values = [float(v) for v in raw]  # float(None) raises TypeError: one side missing
    except (TypeError, ValueError):
        values = []
    if len(values) != 2 or not all(math.isfinite(v) and v >= 0 for v in values):
        # Once per declaration: an estimate or a run prices the same model hundreds of times.
        if (names, tuple(raw)) in _WARNED_BAD_PRICE:
            return None
        _WARNED_BAD_PRICE.add((names, tuple(raw)))
        logger.warning("ignoring the declared price for %r: set both %s and %s to a number >= 0 "
                       "(USD per 1M tokens)", model, *names)
        return None
    return {"input": values[0], "output": values[1]}


def _price_for(model: str) -> dict:
    """Price lookup for `model`: the declared price, else the table, else pessimistic.

    The previous behaviour fell back to the CHEAPEST entry, so an unregistered
    model was silently under-counted and the daily cap permitted real spend past
    its limit. For a safety limit the fallback must over-estimate: an unknown
    model is billed at the most expensive known rate, and says so.
    """
    declared = _declared_price(model)
    if declared is not None:
        return declared
    known = _PRICES_PER_M_TOKENS.get(model)
    if known is not None:
        return known
    if model.startswith(("ollama/", "ollama_chat/")):
        return {"input": 0.0, "output": 0.0}  # local model, no per-token bill
    worst = {
        "input": max(p["input"] for p in _PRICES_PER_M_TOKENS.values()),
        "output": max(p["output"] for p in _PRICES_PER_M_TOKENS.values()),
    }
    # Once per model: an estimate or a run prices the same model hundreds of times.
    if model in _WARNED_UNPRICED:
        return worst
    _WARNED_UNPRICED.add(model)
    logger.warning(
        "no price registered for model %r — billing at the most expensive known rate "
        "(in=$%.2f/out=$%.2f per 1M tokens) so the cap cannot be undershot. "
        "Declare its price with --judge-price INPUT,OUTPUT or %s and %s (USD per 1M tokens).",
        model, worst["input"], worst["output"], *price_env_names(model),
    )
    return worst

# Predictive estimator constants — char-based with margin (no real tokenizer dep).
_AVG_PROMPT_CHARS = 1000        # typical probe prompt
_AVG_RESPONSE_CHARS = 2000      # typical model reply
_CHARS_PER_TOKEN = 4
_SAFETY_MARGIN = 1.2

_DEFAULT_ITERATIVE_ROUNDS = 1


def estimate_call_usd(model: str, input_chars: int, output_tokens: int) -> float:
    """Pre-call price of one completion: char-based input tokens with the safety margin, at `model`'s rate."""
    prices = _price_for(model)
    input_tokens = input_chars / _CHARS_PER_TOKEN * _SAFETY_MARGIN
    return (input_tokens / 1_000_000) * prices["input"] + (output_tokens / 1_000_000) * prices["output"]


# Half a cent: below this a remaining budget is float residue, not money.
_BUDGET_EPSILON_USD = 0.005


class CostExceededError(RuntimeError):
    """Raised when a daily or per-run cap would be exceeded.

    `estimated_usd` is set only when the pre-run estimate exceeds the per-run cap,
    so a caller can name the cap that would fit.
    """

    def __init__(self, message: str, estimated_usd: float | None = None) -> None:
        super().__init__(message)
        self.estimated_usd = estimated_usd


# Backward-compat alias — remove after all callers are updated.
CostCapExceeded = CostExceededError


def _send_alert(meter: "CostMeter") -> None:
    """Hook for email_alert.send_daily_alert; patched in tests."""
    try:
        from argus.email_alert import send_daily_alert
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
        self._run_cap: Optional[float] = None
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
    def run_scope(self, run_id: str, deep: bool = False, per_run_cap_usd: float | None = None,
                  spent_usd: float = 0.0, resume: bool = False):
        """Meter one run: record() raises once a call takes the run's spend past the cap.

        per_run_cap_usd overrides the applicable per-run cap for this run (the CLI's --per-run-cap).
        spent_usd and resume=True continue a run metered in steps, so a scope never has to stay
        open across a yield. The deep budget is checked only when a run starts, not when it resumes.
        """
        if self._spent_in_run is not None:
            raise RuntimeError(f"run_scope is non-reentrant; another run is active")
        if deep and not resume and not self.can_start_deep_run():
            raise CostExceededError(
                f"deep budget ${self.deep_daily_cap_usd:.2f}/day "
                f"(={self.deep_budget_fraction:.0%} of the ${self.daily_cap_usd:.2f} daily cap) "
                f"is exhausted; ${self.deep_budget_remaining():.2f} remains. "
                "Static runs are unaffected."
            )
        self._spent_in_run = spent_usd
        self._run_is_deep = deep
        self._run_cap = per_run_cap_usd
        try:
            yield
        finally:
            self._spent_in_run = None
            self._run_is_deep = False
            self._run_cap = None

    def record(self, model: str, input_tokens: int, output_tokens: int) -> float:
        """Count one finished call, then raise if it took spend past a cap."""
        return self.record_many([(model, input_tokens, output_tokens)])

    def record_many(self, calls) -> float:
        """Count finished calls, then check the caps once; returns their cost.

        `calls` is (model, input_tokens, output_tokens) for each attempt of one
        completion: refused attempts and the answer. Callers record after the
        calls have returned, so their cost is real: all of it is counted, even
        when it crosses a cap, and the error stops the next call.
        """
        self._maybe_reset_day()
        cost = 0.0
        for model, input_tokens, output_tokens in calls:
            prices = _price_for(model)
            cost += (input_tokens / 1_000_000) * prices["input"] + (output_tokens / 1_000_000) * prices["output"]
        was_over_daily = self._spent_today >= self.daily_cap_usd
        self._spent_today += cost
        over: str | None = None
        if was_over_daily:
            over = f"daily cap ${self.daily_cap_usd:.2f} already reached on {self._day}"
        if self._spent_in_run is not None:
            cap = self.deep_per_run_cap_usd if self._run_is_deep else self.per_run_cap_usd
            if self._run_cap is not None:
                cap = self._run_cap
            label = "deep per_run" if self._run_is_deep else "per_run"
            self._spent_in_run += cost
            if self._run_is_deep:
                self._spent_today_deep += cost
            if over is None and self._spent_in_run > cap:
                over = f"{label} cap ${cap:.2f} exceeded: this run has spent ${self._spent_in_run:.4f}"
            if over is None and self._run_is_deep and self._spent_today_deep > self.deep_daily_cap_usd:
                over = (f"deep daily budget ${self.deep_daily_cap_usd:.2f} exceeded; "
                        "static runs are unaffected")
        self._maybe_alert()
        if over is not None:
            raise CostExceededError(over)
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
        # Only Argus's own LLM calls are counted: per judged exchange a fast judge
        # call and, as if every verdict escalated, a strong one; deep mode adds the
        # attacker (fast role). Sends to the target are the target's bill.
        est_input_tokens = (_AVG_PROMPT_CHARS / _CHARS_PER_TOKEN) * _SAFETY_MARGIN
        est_output_tokens = (_AVG_RESPONSE_CHARS / _CHARS_PER_TOKEN) * _SAFETY_MARGIN

        def _call_usd(prices: dict) -> float:
            return (est_input_tokens / 1_000_000) * prices["input"] + (
                est_output_tokens / 1_000_000
            ) * prices["output"]

        # Price at the configured judge models; a bad provider setting falls back
        # to the Anthropic defaults here and is reported by the credential check.
        from argus import llm
        explain = None
        try:
            cfg = llm.resolve_config()
            fast, strong = _price_for(cfg.fast_model), _price_for(cfg.strong_model)
            escalates = cfg.escalation_is_meaningful
            # A jev run's text model explains fail/warn findings and drives deep mode's attacker.
            text_cfg = llm.explain_config(cfg)
            explain = _price_for(text_cfg.fast_model) if text_cfg is not None else None
        except ValueError:
            fast = _PRICES_PER_M_TOKENS["claude-haiku-4-5-20251001"]
            strong = _PRICES_PER_M_TOKENS["claude-sonnet-4-6"]
            escalates = True
        per_exchange = _call_usd(fast) + (_call_usd(strong) if escalates else 0.0)
        if explain is not None:
            per_exchange += _call_usd(explain)  # as if every verdict were fail or warn
        if deep:
            per_exchange += _call_usd(explain or fast)
        exchanges = total_exchanges if total_exchanges is not None else len(probe_ids) * iterative_rounds
        estimated = per_exchange * exchanges

        default_cap = self.deep_per_run_cap_usd if deep else self.per_run_cap_usd
        cap = per_run_cap_override if per_run_cap_override is not None else default_cap
        if estimated > cap:
            raise CostExceededError(
                f"estimated cost ${estimated:.4f} > per_run_cap ${cap:.2f}",
                estimated_usd=estimated,
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
