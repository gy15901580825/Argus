# Judge decider (Jev) — optional, off by default

When a strong-model escalation cannot settle a finding, the red-team judge can ask TypeSafe's Jev model (System One API) to decide. It is off unless you switch it on.

**Data leaves the cluster when it is on.** Each consultation sends the probe name, the rubric, the attack prompt, the target's response and the fast/strong judges' verdicts and reasoning to `api.typesafe.ai`, a third party. Each text field is cut at 8,000 characters. No user ids, target URLs or Argus secrets are sent. Do not enable it for targets whose responses you may not share.

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
