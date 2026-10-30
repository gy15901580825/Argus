# Judge decider (Jev) — optional, off by default

When a strong-model escalation cannot settle a finding, the red-team judge can ask TypeSafe's Jev model (System One API) to decide. It is off unless you switch it on.

**Data leaves the cluster when it is on.** `run --local` says so in the line after `Judge: ...`. Each consultation sends the probe name, the rubric, the attack prompt, the target's response and the fast/strong judges' verdicts and reasoning to `api.typesafe.ai`, a third party. Each text field is cut at 8,000 characters. No user ids, target URLs or Argus secrets are sent. Do not enable it for targets whose responses you may not share.

## Enable

| Variable | Default | Meaning |
|---|---|---|
| `REDTEAM_DECIDER` | unset | Must be exactly `jev`. Anything else means off. |
| `TYPESAFE_API_KEY` | unset | Required. Empty means off. Sent only in the `Authorization` header; never logged or stored. |
| `REDTEAM_DECIDER_MODEL` | `jev-latest` | Model name. |
| `REDTEAM_DECIDER_GATE` | `0.8` | Minimum choice confidence for Jev's answer to be used. |
| `REDTEAM_DECIDER_TIMEOUT_S` | `20` | HTTP timeout per call. |
| `TYPESAFE_API_URL` | `https://api.typesafe.ai/v1/systemone` | Endpoint. |

## When it is consulted

Only after the fast judge escalated a high/critical finding to the strong judge, and only when:

- the strong judge's reply could not be parsed (today this becomes an `error` finding), or
- the strong verdict differs from the fast verdict.

Jev picks `fail`, `pass` or `insufficient_evidence`. If its confidence is at least the gate and it picked `pass` or `fail`, that verdict is used (`info` severity for pass; otherwise the strong judge's severity, or the fast judge's after a parse failure). Below the gate, or on `insufficient_evidence`, the finding becomes `warn` for human review, never `pass`.

Any decider error (HTTP status, timeout, malformed answer, unknown choice) changes nothing: a parse failure stays `error`, and a conflict keeps the strong verdict. The failure is logged without the key.

## Where the decision is recorded

No schema change. `escalated_model` holds the Jev model name, and `reasoning` ends with
`| jev(<model>): <choice> p=<prob> conf=<conf> gate=<gate> -> <acted|review>`.

## Decider or judge

Jev can play two parts, and they do not mix.

| | Decider (`REDTEAM_DECIDER=jev`) | Judge (`--judge-provider jev`) |
|---|---|---|
| What judges every reply | Your LLM judge (Anthropic, OpenAI, Azure or litellm) | Jev |
| When Jev is called | Only when the strong judge's reply cannot be parsed or disagrees with the fast judge | Once for every judged reply |
| Question | `fail`, `pass` or `insufficient_evidence`, given both judges' verdicts | `pass`, `warn` or `fail`, given the rubric and the reply |
| Below its threshold | `warn` when confidence is under `REDTEAM_DECIDER_GATE` (0.8) | A `pass` with confidence under 0.5 becomes `warn` |
| Reasoning | The judges' reasoning plus `jev(...) ... gate=... -> acted/review` | `jev(<model>): <choice> p=... conf=...`, plus a reason from `--judge-explain-model` if set |
| Cost | Not metered, so `scan-mcp` and `judge-check` switch it off | Metered and priced like any judge call |

Both read `TYPESAFE_API_KEY` and `TYPESAFE_API_URL`. When Jev is the judge, the decider is off even if `REDTEAM_DECIDER=jev` is set. See [Jev as the judge](../cli.md#jev-as-the-judge).
