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
import sys
from datetime import datetime, timezone
from pathlib import Path

from argus import llm
# The engine lives in the package so `argus-probe judge-check` shares it; tests reach it through this module.
from argus.judge_bench import (  # noqa: F401
    Case, build_report, credential_problem, estimate_usd, load_all_cases, print_table, run_benchmark, summarise,
)

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
