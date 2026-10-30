"""`argus-probe judge-check`: measure the chosen judge on Argus's labelled fixture cases."""
from __future__ import annotations

import asyncio
import contextlib
import logging
import math
import re
import sys

import click

from argus import llm
from argus.cli.judge_options import judge_options

EXIT_COST_CAP = 4  # same as `run`
_CONCURRENCY = 4
_REASON_MAX = 120


# AllProvidersFailed's framing; dropped so the cut keeps the cause.
_ERROR_FRAME = re.compile(r"^\w+: all providers failed for role='\w+': ")


def _pct(n: int, d: int) -> str:
    return "n/a" if d == 0 else f"{n / d * 100:.1f}%"


class _Once(logging.Filter):
    """Pass each distinct message once: an unreachable judge fails every case the same way."""

    def __init__(self) -> None:
        super().__init__()
        self._seen: set[str] = set()

    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        if msg in self._seen:
            return False
        self._seen.add(msg)
        return True


@contextlib.contextmanager
def _deduplicated(*names: str):
    once = _Once()
    loggers = [logging.getLogger(n) for n in names]
    for log in loggers:
        log.addFilter(once)
    try:
        yield
    finally:
        for log in loggers:
            log.removeFilter(once)


@click.command("judge-check")
@click.option("--all", "all_cases", is_flag=True, default=False,
              help="Run every fixture case instead of the default sample.")
@click.option("--per-run-cap", "per_run_cap", type=click.FloatRange(min=0), default=0.50, show_default=True,
              metavar="USD", help="Judge spend limit. A check whose estimate is above it does not start; "
                                  "the check stops when spend reaches it.")
@judge_options
def cmd_judge_check(all_cases: bool, per_run_cap: float) -> None:
    """Check a judge on Argus's labelled cases before you trust its verdicts.

    Default sample: one pass and one fail case per rubric, plus the shared hard cases.
    """
    from argus import judge_bench

    try:
        cfg = llm.resolve_config()
    except ValueError as e:
        raise click.UsageError(str(e)) from None
    every = judge_bench.load_all_cases()
    cases = every if all_cases else judge_bench.sample_cases(every)
    click.echo(f"Judge: {llm.describe(cfg)}")
    click.echo(llm.disclosure(cfg, "The fixture cases (Argus's own text, no target data)"))
    scope = "" if all_cases else (f" (one pass and one fail case per rubric, plus the shared hard cases; "
                                  f"--all runs all {len(every)})")
    click.echo(f"Cases: {len(cases)}{scope}")
    estimate = judge_bench.estimate_usd(cfg, cases)
    click.echo(f"Estimated cost: ${estimate:.4f} against --per-run-cap ${per_run_cap:.2f}")

    problem = judge_bench.credential_problem(cfg)
    if problem:
        click.echo(f"Error: {problem}", err=True)
        sys.exit(1)
    if estimate > per_run_cap:
        fit = math.ceil(estimate * 100) / 100
        click.echo(f"Rejected for cost: estimate ${estimate:.4f} > --per-run-cap ${per_run_cap:.2f}; "
                   f"rerun with --per-run-cap {fit:.2f}", err=True)
        sys.exit(EXIT_COST_CAP)

    with _deduplicated("argus.llm", "argus.judge"):
        records, spent, capped = asyncio.run(judge_bench.run_benchmark(cfg, cases, per_run_cap, _CONCURRENCY))
    s = judge_bench.summarise(records)
    click.echo("")
    click.echo(f"Accuracy: {_pct(s['correct'], s['cases'])} ({s['correct']}/{s['cases']})")
    click.echo(f"False pass: {s['false_pass']} of {s['should_not_pass']} cases that should not pass (missed attacks)")
    click.echo(f"False fail: {s['false_fail']} of {s['should_pass']} cases that should pass (false alarms)")
    click.echo(f"Errors: {s['errors']}")
    wrong = [r for r in records if r["status"] != "skipped" and not r["correct"]]
    if wrong:
        click.echo(f"Wrong ({len(wrong)}):")
        for r in wrong:
            got = "error" if r["status"] == "error" or r["verdict"] == "error" else r["verdict"]
            reason = _ERROR_FRAME.sub("", " ".join(str(r["reasoning"] or "").split()))
            if len(reason) > _REASON_MAX:
                reason = reason[:_REASON_MAX - 3] + "..."
            click.echo(f"  {r['rubric']} {r['case_id']}: expected {r['expected']}, got {got}: {reason}")
    click.echo("These are Argus's own labelled cases, a check that this judge reads the rubrics as intended, "
               "not a population estimate of its accuracy.")
    click.echo(f"Spent ${spent:.4f}.")
    if s["cases"] and s["errors"] == s["cases"]:
        # Nothing was measured, so a CI step running the check must not pass.
        click.echo(f"All {s['cases']} cases errored: the judge was not reachable or rejected every call. "
                   "Nothing was measured.", err=True)
        sys.exit(1)
    if capped:
        click.echo(f"{s['skipped']} case(s) were not run: the check stopped at --per-run-cap ${per_run_cap:.2f}.",
                   err=True)
        sys.exit(EXIT_COST_CAP)
