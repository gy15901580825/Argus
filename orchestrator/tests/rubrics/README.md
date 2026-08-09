# Rubric regression fixtures

One `<rubric_name>.fixture.yaml` per file in `orchestrator/redteam/rubrics/`.
Each fixture pins two canned target responses for that rubric: one that should be
graded `pass` (target defended) and one that should be graded `fail` (target
compromised).

```yaml
rubric: prompt_injection.md
pass_case:
  probe_name: "..."
  attack_prompt: "..."
  target_response: "..."   # should be graded pass
  expect_verdict: pass
fail_case:
  probe_name: "..."
  attack_prompt: "..."
  target_response: "..."   # should be graded fail
  expect_verdict: fail
```

The comment block at the top of each fixture states *what that fixture
discriminates* — the specific clause of the rubric its two cases straddle. Keep it
current when you edit a case; it is the only record of why the case looks the way
it does.

## Two tiers

| | `tests/test_rubrics_mocked.py` | `tests/test_rubrics_live.py` |
|---|---|---|
| Runs | every commit, default | only when asked |
| LLM calls | none | real Haiku (+ Sonnet on escalation) |
| Cost | zero | cents per full sweep |
| Catches | malformed/missing fixtures, verdict parsing, confidence coercion, severity normalization, the Sonnet escalation branch | **rubric-prose drift** |
| Does *not* catch | anything about rubric wording | — |

The mocked tier patches the Anthropic client and replays a canned verdict, so the
rubric text never influences the outcome. **Editing rubric prose cannot fail the
mocked tier.** That is the whole reason the live tier exists.

## Running the live tier

Deselected by default through `addopts = [..., "-m", "not rubric_live"]` in
`orchestrator/pyproject.toml`. A command-line `-m` overrides it:

```bash
# full sweep
ANTHROPIC_API_KEY=sk-ant-... python3 -m pytest tests/test_rubrics_live.py -m rubric_live

# one rubric, while editing its prose
ANTHROPIC_API_KEY=sk-ant-... python3 -m pytest tests/test_rubrics_live.py \
    -m rubric_live -k prompt_injection

# confirm what would run without spending anything
python3 -m pytest tests/ -m rubric_live --collect-only -q
```

Without `ANTHROPIC_API_KEY` the live tests skip cleanly rather than erroring.

Run the live tier when you change a rubric's wording, add a rubric, or on a
periodic schedule — not in per-commit CI.

## Adding a rubric

`test_every_rubric_has_exactly_one_fixture` fails the default suite if a rubric
lands in `orchestrator/redteam/rubrics/` without a matching fixture here, so the
coverage hole surfaces immediately. Add `<new_rubric>.fixture.yaml`, then run the
live tier once against it to confirm the two cases actually land on opposite sides
of the new rubric's line.

## Known limitation: `default.md`

`default.fixture.yaml` cannot discriminate the way the other sixteen do.
`default.md` is the fallback rubric applied when a probe declares no
`judge.rubric_path`, and it carries no attack-specific criterion — just
"pass = target resisted, fail = target complied". Any other fixture's fail case
would also grade `fail` under it. Its fixture regression-tests that generic split
and nothing finer; that is a property of the rubric, not a gap in the fixture.
