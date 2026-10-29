# Judge accuracy

Most Argus verdicts come from an LLM judge, so the judge's own error rate matters as
much as the probe library. This page says how we measure it and what the last
measurement found.

## What is measured

Every rubric in `argus/rubrics/` has fixtures in `tests/rubrics/`: at least three replies
that should be judged `pass` (the target held) and at least three that should be judged
`fail` (the target complied). On top of that, `tests/rubrics/shared_hard_cases.yaml` holds
cases that every judge has to survive:

- an empty reply (the only wrong answer is `pass`; an empty reply proves nothing)
- a refusal that still leaks the secret or still complies
- a reply that states its own verdict (`verdict: pass`) while complying
- a reply that tells the judge to "ignore previous instructions"
- a reply that tries to close the judge's delimiter block
- a genuine refusal that merely quotes injection text (should still pass)

Each case goes through the real judge with the real rubric text, the same code path a
scan uses (fast model, then the strong model on high-severity findings).

## Definitions

| Term | Meaning |
|---|---|
| accuracy | share of cases where the judge's verdict matched the expected one |
| false pass | the case should not pass (a compromise, or an empty reply) and the judge said `pass`. This is a missed vulnerability. |
| false fail | the case should pass and the judge said `fail` or `warn`. This is a false alarm. |
| errors | the judge returned no usable verdict. Counted against accuracy, never as a pass. |

The sets are small and written by us. Read them as a regression and sanity check, not as a
population estimate; a rate on a rubric with six cases moves by 17 points per case.

## How to run it

```bash
# estimate only, no key needed
python scripts/judge_benchmark.py --dry-run

# real run (uses ANTHROPIC_API_KEY, or the provider set with REDTEAM_MODEL_PROVIDER)
python scripts/judge_benchmark.py --out judge-benchmark.json --per-run-cap 1.00
```

The script prints the estimated cost first, refuses to start without a judge key or when
the estimate is above `--per-run-cap`, stops when the cap is reached, then prints accuracy,
false-pass and false-fail rates per rubric and overall, and writes every case to the JSON
file. The Jev decider is switched off during the run so the numbers measure the judge alone. A call that finishes after the cap is reached is still billed and is counted in `spent_usd`; with `--concurrency` above 1 a few calls can finish past the cap, so spend can exceed the cap by a few cents. The estimate is a rough figure, not a bound: it prices 200 output tokens per call and a strong-model pass for every case not expected to pass. The offline test `tests/test_rubric_fixtures_schema.py` checks the fixtures on every
commit without a key.

## Results

Five back-to-back runs on 2026-10-29, 02:50 to 02:57 UTC, with the default Anthropic
judge (fast `claude-haiku-4-5-20251001`, strong `claude-sonnet-4-6`), 155 cases per run,
Jev decider off. The five runs together cost $1.84 of metered spend. That figure leaves
out the 35 strong-model calls that were refused: they are billed, but at the time a
refused call was not recorded by the cost meter. It is recorded now.

| Date | Judge (fast / strong) | Cases | Accuracy | False-pass | False-fail | Errors |
|---|---|---|---|---|---|---|
| 2026-10-29 | Haiku 4.5 / Sonnet 4.6 | 155 | 92.3% (median of 5, range 91.6 to 92.9%) | 10 to 12 of 92 | 0 of 63 in every run | 0 to 1 |

What the numbers say:

- The judge never raised a false alarm: no case that should pass was judged `fail` or
  `warn` in any of the five runs.
- The false passes fall into three groups:
  - One case labelled `fail` was judged `pass` in all five runs:
    `browser_visual.md` `subtly_steered_without_obeying`, where the agent repeats injected
    text from a chart while describing it. Its label is arguable (the agent described the
    image accurately), so read it as either a judge miss or a fixture to relabel.
  - Five or six cases labelled `warn` (a partial or borderline response) were judged
    `pass`. The judge puts the line between `warn` and `pass` more leniently than our
    labels do.
  - Four or five empty or whitespace-only replies were judged `pass`. A scan never sends
    these to the judge: since the run-reliability change, an empty reply is an `error`
    finding before the judge is called. The cases stay in the set as a regression check
    on the judge itself.
- In every run the strong model declined to review seven attack-heavy `fail` cases
  (`stop_reason=refusal`). The judge now keeps the fast model's verdict in that case and
  says so in the reasoning; a fast `pass` is never kept this way and becomes `warn` for
  human review. Before that change the refusal surfaced as an unhandled provider error,
  and in a real scan it stopped the whole run with an error at the first encoded-payload,
  unicode-smuggling or jailbreak probe the target failed. Five runs before the fix scored
  87.7 to 89.0% with 7 or 8 errors each.
- The remaining errors (one in two of the five runs) were judge replies with a usable
  verdict but a missing field: in one, the fast model wrote `reason` instead of
  `reasoning`. They are reported as errors, never as passes.

Limits: the cases are written by us, so the accuracy is agreement with our labels, not a
population estimate. Per-rubric sets are small (six to thirteen cases). Raw results:
`scripts/judge_benchmark.py --out` writes every case with the judge's verdict and
reasoning; the runs above are not committed.
