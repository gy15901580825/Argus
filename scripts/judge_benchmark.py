#!/usr/bin/env python3
"""Measure judge accuracy: run every rubric fixture through the real judge.

    python scripts/judge_benchmark.py --out judge-benchmark.json [--per-run-cap 1.00]

Prints the estimated cost first, refuses to run without a judge key, stops at
--per-run-cap, prints accuracy / false-pass / false-fail per rubric and overall,
and writes the full result (including every case) as JSON to --out.
`--dry-run` prints the estimate only and needs no key.

Provider and models come from the usual env (REDTEAM_MODEL_PROVIDER, ANTHROPIC_API_KEY,
OPENAI_API_KEY, REDTEAM_FAST_MODEL, REDTEAM_STRONG_MODEL). Method: docs/judge-accuracy.md.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))  # fixture loader shared with the test suite

from argus import llm  # noqa: E402
from argus.cost_meter import CostExceededError, CostMeter, _price_for, estimate_call_usd  # noqa: E402
from argus.judge import ESCALATION_SEVERITIES, Judge, build_judge_prompts  # noqa: E402
from rubric_cases import Case, load_all_cases, rubric_text  # noqa: E402

_OUTPUT_TOKENS = 200  # judge replies are ~100 tokens; the estimate leans high
_AZURE_KEYS = ("AZURE_API_KEY", "AZURE_OPENAI_API_KEY")


def estimate_usd(cfg: llm.LLMConfig, cases: list[Case]) -> float:
    """Estimate: every case on the fast model, plus a strong-model pass on each case expected not to pass."""
    total = 0.0
    for c in cases:
        system, user = build_judge_prompts(c.probe_name, c.attack_prompt, c.target_response, rubric_text(c.rubric))
        chars = len(system) + len(user)
        total += estimate_call_usd(cfg.fast_model, chars, _OUTPUT_TOKENS)
        # Escalation fires on high/critical findings; the judge only ever escalates cases it flags,
        # which are the ones that are not expected to pass.
        if cfg.escalation_is_meaningful and c.expect_verdict != "pass":
            total += estimate_call_usd(cfg.strong_model, chars, _OUTPUT_TOKENS)
    return total


def credential_problem(cfg: llm.LLMConfig, env=os.environ) -> str | None:
    err = llm.credential_error(cfg)
    if err:
        return err
    if cfg.provider == llm.PROVIDER_AZURE and not any(env.get(k) for k in _AZURE_KEYS):
        return "AZURE_API_KEY (or AZURE_OPENAI_API_KEY) is not set (REDTEAM_MODEL_PROVIDER=azure)."
    return None


def _rate(n: int, d: int) -> float | None:
    return None if d == 0 else round(n / d, 4)


def summarise(records: list[dict]) -> dict:
    """Accuracy, false-pass and false-fail rates for a list of per-case records.

    false_pass: the case should not pass (a real compromise, or an empty reply) and the judge said pass.
    false_fail: the case should pass and the judge said fail or warn.
    Errors (no usable verdict) count against accuracy but are neither of the two.
    """
    judged = [r for r in records if r["status"] != "skipped"]
    should_not_pass = [r for r in judged if not r["expects_pass"]]
    should_pass = [r for r in judged if r["expects_pass"]]
    correct = sum(1 for r in judged if r["correct"])
    fp = sum(1 for r in should_not_pass if r["verdict"] == "pass")
    ff = sum(1 for r in should_pass if r["verdict"] in ("fail", "warn"))
    return {
        "cases": len(judged),
        "correct": correct,
        "accuracy": _rate(correct, len(judged)),
        "false_pass": fp,
        "should_not_pass": len(should_not_pass),
        "false_pass_rate": _rate(fp, len(should_not_pass)),
        "false_fail": ff,
        "should_pass": len(should_pass),
        "false_fail_rate": _rate(ff, len(should_pass)),
        "errors": sum(1 for r in judged if r["status"] == "error" or r["verdict"] == "error"),
        "skipped": len(records) - len(judged),
    }


def build_report(records: list[dict]) -> dict:
    by_rubric: dict[str, list[dict]] = defaultdict(list)
    for r in records:
        by_rubric[r["rubric"]].append(r)
    return {
        "per_rubric": {k: summarise(v) for k, v in sorted(by_rubric.items())},
        "overall": summarise(records),
    }


async def _run_case(judge: Judge, c: Case, sem: asyncio.Semaphore, stop: asyncio.Event) -> dict:
    rec = {
        "rubric": c.rubric, "case_id": c.case_id, "shared": c.shared,
        "expected": c.expect_verdict if c.expect_verdict else "not " + "/".join(c.expect_not),
        "expects_pass": c.expects_pass, "verdict": None, "severity": None, "confidence": None,
        "reasoning": None, "judge_model": None, "escalated_model": None, "correct": False, "status": "ok",
    }
    async with sem:
        if stop.is_set():
            rec["status"] = "skipped"
            return rec
        try:
            v = await judge.judge(c.probe_name, c.attack_prompt, c.target_response, rubric_text(c.rubric))
        except CostExceededError:
            stop.set()
            rec["status"] = "skipped"
            return rec
        except Exception as e:  # noqa: BLE001 - an unusable reply or provider error is a data point, not a crash
            rec["status"] = "error"
            rec["reasoning"] = f"{type(e).__name__}: {str(e)[:200]}"
            return rec
    rec.update(
        verdict=v.verdict, severity=v.severity, confidence=v.confidence, reasoning=v.reasoning,
        judge_model=v.judge_model, escalated_model=v.escalated_model, correct=c.is_correct(v.verdict),
    )
    return rec


class _BenchMeter(CostMeter):
    """Also counts the call that trips the cap: the provider already billed it."""

    def __init__(self, **kw) -> None:
        super().__init__(**kw)
        self.over_cap_usd = 0.0

    def record(self, model: str, input_tokens: int, output_tokens: int) -> float:
        try:
            return super().record(model, input_tokens, output_tokens)
        except CostExceededError:
            p = _price_for(model)
            self.over_cap_usd += (input_tokens * p["input"] + output_tokens * p["output"]) / 1_000_000
            raise


async def run_benchmark(cfg: llm.LLMConfig, cases: list[Case], cap: float, concurrency: int):
    # Infinite daily cap keeps the cost-alert email silent (same as scan-mcp); --per-run-cap is the limit.
    meter = _BenchMeter(daily_cap_usd=float("inf"), per_run_cap_usd=cap)
    judge = Judge("", meter, cfg)
    judge._decider = None  # no third-party decider: it is unmetered and would blend into the numbers
    sem, stop = asyncio.Semaphore(concurrency), asyncio.Event()
    with meter.run_scope("judge-benchmark"):
        records = await asyncio.gather(*(_run_case(judge, c, sem, stop) for c in cases))
        spent = meter.spent_in_current_run() + meter.over_cap_usd
    return records, spent, stop.is_set()


def _fmt(x) -> str:
    return "  n/a" if x is None else f"{x * 100:5.1f}%"


def print_table(report: dict) -> None:
    print(f"{'rubric':36} {'n':>4} {'acc':>7} {'false-pass':>11} {'false-fail':>11} {'err':>4}")
    rows = list(report["per_rubric"].items()) + [("OVERALL", report["overall"])]
    for name, s in rows:
        fp = f"{_fmt(s['false_pass_rate'])} ({s['false_pass']}/{s['should_not_pass']})"
        ff = f"{_fmt(s['false_fail_rate'])} ({s['false_fail']}/{s['should_pass']})"
        print(f"{name:36} {s['cases']:>4} {_fmt(s['accuracy']):>7} {fp:>11} {ff:>11} {s['errors']:>4}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out", type=Path, help="write the JSON result here (required unless --dry-run)")
    ap.add_argument("--per-run-cap", type=float, default=1.00, help="USD; refuse to start above it, stop when reached (default 1.00)")
    ap.add_argument("--rubric", action="append", help="only this rubric file, e.g. jailbreak.md (repeatable)")
    ap.add_argument("--concurrency", type=int, default=4)
    ap.add_argument("--dry-run", action="store_true", help="print the case count and estimated cost, then exit")
    args = ap.parse_args(argv)
    if not args.dry_run and not args.out:
        ap.error("--out is required (or use --dry-run)")

    try:
        cfg = llm.resolve_config()
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    cases = load_all_cases()
    if args.rubric:
        cases = [c for c in cases if c.rubric in set(args.rubric)]
        if not cases:
            print(f"error: no cases for {args.rubric}", file=sys.stderr)
            return 2

    est = estimate_usd(cfg, cases)
    print(f"Judge benchmark: {len(cases)} cases, provider={cfg.provider}, fast={cfg.fast_model}, strong={cfg.strong_model}")
    print(f"Estimated cost: ${est:.4f} against --per-run-cap ${args.per_run_cap:.2f}")
    print("Jev decider: off for this run (judge only, so the numbers measure the judge)")
    if args.dry_run:
        return 0
    problem = credential_problem(cfg)
    if problem:
        print(f"error: {problem} Refusing to run without a judge key.", file=sys.stderr)
        return 2
    if est > args.per_run_cap:
        print(f"error: estimate ${est:.4f} exceeds --per-run-cap ${args.per_run_cap:.2f}; rerun with --per-run-cap {est:.2f} or higher.", file=sys.stderr)
        return 2

    records, spent, capped = asyncio.run(run_benchmark(cfg, cases, args.per_run_cap, args.concurrency))
    report = build_report(records)
    report["meta"] = {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "provider": cfg.provider, "fast_model": cfg.fast_model, "strong_model": cfg.strong_model,
        "estimated_usd": round(est, 4), "spent_usd": round(spent, 4), "per_run_cap_usd": args.per_run_cap,
        "stopped_at_cap": capped, "decider": "off", "cases_total": len(cases),
    }
    report["cases"] = records
    args.out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print()
    print_table(report)
    print(f"\nSpent ${spent:.4f}. Wrote {args.out}")
    if capped:
        print("warning: stopped at the per-run cap; some cases were skipped.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
