"""`argus-probe judge-check`: measure the chosen judge on Argus's labelled fixture cases."""
from __future__ import annotations

import asyncio
import math
import sys

import click

from argus import llm
from argus.cli.judge_options import judge_options

EXIT_COST_CAP = 4  # same as `run`
_CONCURRENCY = 4
_REASON_MAX = 120


def _pct(n: int, d: int) -> str:
    return "n/a" if d == 0 else f"{n / d * 100:.1f}%"


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
            reason = " ".join(str(r["reasoning"] or "").split())
            if len(reason) > _REASON_MAX:
                reason = reason[:_REASON_MAX - 3] + "..."
            click.echo(f"  {r['rubric']} {r['case_id']}: expected {r['expected']}, got {got}: {reason}")
    click.echo("These are Argus's own labelled cases, a check that this judge reads the rubrics as intended, "
               "not a population estimate of its accuracy.")
    click.echo(f"Spent ${spent:.4f}.")
    if capped:
        click.echo(f"{s['skipped']} case(s) were not run: the check stopped at --per-run-cap ${per_run_cap:.2f}.",
                   err=True)
        sys.exit(EXIT_COST_CAP)
