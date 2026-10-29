# Judge accuracy

Most Argus verdicts come from an LLM judge, so the judge's own error rate matters as
much as the probe library. This page says how we measure it. The numbers are filled in
from a live run; until then the table below is marked pending.

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
file. The offline test `tests/test_rubric_fixtures_schema.py` checks the fixtures on every
commit without a key.

## Results

Pending. No live run has been recorded yet.

| Date | Judge (fast / strong) | Cases | Accuracy | False-pass rate | False-fail rate | Errors |
|---|---|---|---|---|---|---|
| pending | pending | pending | pending | pending | pending | pending |

Per-rubric results: pending.
