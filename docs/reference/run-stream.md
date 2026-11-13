# `POST /redteam/run` event stream

This page is the contract for API consumers of `POST /redteam/run`. It lists every frame the stream can send, the fields each frame carries, the order frames come in, and how a stream ends. The [machine-readable frame list](#machine-readable-frame-list) at the end is what `tests/test_run_stream_contract.py` checks the running server against. CI fails when the server sends a frame type, an `event:` name or a field that this page does not list, or when a required field is missing.

## Before the stream starts

Request errors are plain HTTP responses with FastAPI's `{"detail": ...}` body, not stream frames: 422 for a bad target, probe id, suite or mode, 402 when the run's estimated cost is over a cap, 500 for missing judge settings. A consumer only reads frames after a 200.

## Framing

A 200 response is a Server-Sent Events stream (`Content-Type: text/event-stream`). Each frame ends with a blank line. A frame is either one `data:` line, or an `event:` line followed by one `data:` line. Every `data:` line holds one JSON object.

Every stream payload masks registered target-spec secret values with the same function and `***` token as run.json. This includes findings, deep transcripts, `deep_run` metadata, coverage, error details, and cleanup reports. Payloads are normalized to JSON values, as run.json does, then masked at the stream boundary before the frame is encoded. This also masks tuples that JSON converts to arrays.

## Frames

| Frame | `event:` name | `type` field | Sent |
|-------|---------------|--------------|------|
| [Deep run metadata](#deep_run-frame) | none | `"deep_run"` | Deep mode only, once, first. |
| [Finding](#finding-frame) | none | no `type` key | Zero or more, one per finding. |
| [Coverage](#coverage-frame) | none | `"coverage"` | Once, after the last finding, on a run that finishes. |
| [End](#end-frame) | `end` | none (`data: {}`) | Once, last, on a run that finishes. |
| [Error](#error-frame) | `error` | the exception class name | Once, last, on a run that fails after the stream started. |

To classify a frame, read the `event:` name first. `end` and `error` are terminal frames. A frame with no `event:` name is a deep run metadata frame when `type` is `"deep_run"`, a coverage frame when `type` is `"coverage"`, and a finding when it has no `type` key.

### Order

1. In deep mode, one `deep_run` frame. Static runs never send it.
2. Zero or more finding frames.
3. Then exactly one of:
   - one coverage frame followed by `event: end`, when the run finished; or
   - `event: error`, when the run failed after the stream started.

The coverage frame is always sent immediately before `event: end`, and is never sent on a run that ends with `event: error`. An error frame can come at any point, including as the first frame (for example when the target cannot be built once the stream is open). Findings sent before an error stay valid.

### Terminal frames

`event: end` and `event: error` end the stream. Nothing follows either of them, and a stream has at most one of them.

A stream that closes without either frame is an incomplete run. That happens when the client disconnects or the server process stops: the server closes the target and stops starting probes, and sends nothing more. Treat the findings received so far as partial.

## What a consumer sees in common cases

**Cost cap during the run.** The probe whose judge or attacker call crossed the cap is sent as a finding with verdict `aborted_cost`. Every probe or deep thread not yet started is also sent as an `aborted_cost` finding, with reasoning starting `not started:`, without another paid call. The stream then ends with `event: error` whose `type` is `CostExceededError` and whose `cost` shows the spend, which can pass the cap by the one call that crossed it. No coverage frame is sent. A cost cap known before the run starts is the HTTP 402 described above, not a frame.

**Judge content-filter block.**

- Static mode: the provider's content filter refusing a judge prompt stops the run. The stream ends with `event: error` whose `type` is `JudgeBlockedError` and which carries `judge_blocked`. The probe being judged sends no finding.
- Deep mode, attacker blocked: the thread ends as a finding with verdict `error`, `evidence.stop_reason` `"attacker_blocked"` and `evidence.attacker_blocked` holding the same object as `judge_blocked`. The run continues, and the stream ends with coverage and `event: end`.
- Deep mode, judge blocked during a round: the thread ends as a finding with verdict `error`, `evidence.stop_reason` `"judge_unusable"` and `evidence.judge_blocked` holding the same object. The run continues to coverage and `event: end`.

**Client disconnect.** The server sends no terminal frame. See [Terminal frames](#terminal-frames).

## Forward compatibility

A consumer must:

- ignore an `event:` name it does not know;
- ignore a bare frame whose `type` value it does not know;
- ignore fields it does not know, in every frame and in nested objects;
- treat a stream that closes without `event: end` or `event: error` as incomplete.

A consumer must not treat every bare frame as a finding. Deep runs send a `deep_run` frame first, and future versions may add other bare frames with a `type` key. A finding never has a `type` key.

Within a major version of `argus-probe`, the frames on this page change only by addition: a new field, a new frame type, or a new `event:` name. The required fields in the [machine-readable frame list](#machine-readable-frame-list), their names and their types, are stable across minor versions, and so is the frame order above. Optional fields can be added in a minor version. Renaming or removing a required field, changing its type, or changing the frame order needs a new major version, and the release notes announce it. Values inside open objects (`coverage.standards`, `summary.by_verdict`, `evidence`) follow the formats linked from each section, and new keys can appear there in a minor version.

## Finding frame

One finding per probe result, or per thread in deep mode. The object has exactly the keys of a run.json finding, described in [the run.json format](../run-json.md#run-summary), and never a `type` key.

| Field | Type | Meaning |
|-------|------|---------|
| `id` | string | A UUID for this finding. |
| `probe_id` | string | The probe that ran. In deep mode, the thread id. |
| `attack_prompt` | string | The prompt sent, or `""` when nothing was sent. |
| `target_response` | string | The target's reply, or `""`. |
| `target_latency_ms` | number | Time the target took to reply. |
| `probed_at` | string | ISO 8601 timestamp of the probe. |
| `verdict` | string | `pass`, `warn`, `fail`, `error`, `blocked_by_target`, `skipped` or `aborted_cost`. Ignore a value you do not know. |
| `severity` | string | `info`, `low`, `medium`, `high` or `critical`. |
| `confidence` | number | The judge's confidence, 0 to 1. |
| `reasoning` | string | Why the verdict was given. |
| `judge_model` | string | The model that gave the verdict, or `""` when none did. |
| `escalated_model` | string or null | The stronger model, when the verdict was escalated. |
| `atlas_id` | array of strings | MITRE ATLAS ids. |
| `owasp_id` | array of strings | OWASP LLM Top 10 ids. |
| `owasp_agentic` | array of strings | OWASP Top 10 for Agentic Applications ids. |
| `nist_id` | array of strings | NIST AI RMF ids. |
| `eu_ai_act_id` | array of strings | EU AI Act ids. |
| `created_at` | string | ISO 8601 timestamp the finding was created. |
| `evidence` | object or null | What the target observed. Deep findings carry the thread transcript here; see [deep thread evidence](../run-json.md#deep-thread-evidence). |
| `remediation` | string | How to fix the weakness, or `""`. |
| `remediation_actions` | array of objects | Tiered fix-it steps. |
| `events` | array of objects | Evidence-backed steps; see [finding events](../run-json.md#finding-events). `[]` when none. |

## `deep_run` frame

```json
{"type": "deep_run", "deep": {"seed": "…", "deep_pairs": 3, "max_rounds": 20, "threads": [{"thread_id": "…", "base_probe_id": "…", "persona": "…", "strategy": "…"}], "static_material_probe_ids": [], "history": false}}
```

| Field | Type | Meaning |
|-------|------|---------|
| `type` | string | Always `"deep_run"`. |
| `deep` | object | The run's deep selection, the same object as run.json's `deep`; see [deep run metadata](../run-json.md#deep-run-metadata). |

`deep` holds `seed` (string), `deep_pairs` (integer), `max_rounds` (integer), `threads` (array of objects, each with string `thread_id`, `base_probe_id`, `persona` and `strategy`), `static_material_probe_ids` (array of strings) and `history` (boolean). `threads` is the planned set, not proof that each thread ran. Each thread that runs sends one finding whose `probe_id` is its `thread_id`. This frame is metadata: do not count it as a finding.

## Coverage frame

```json
{"type": "coverage", "coverage": {...}, "summary": {...}, "cost": {"spent_usd": 0.0412, "per_run_cap_usd": 0.5}}
```

| Field | Type | Meaning |
|-------|------|---------|
| `type` | string | Always `"coverage"`. |
| `coverage` | object | The per-standard coverage table, the same object `GET /redteam/coverage` returns, with this run's results filled in: `thin_threshold` (number), `totals` (object) and `standards` (object). |
| `summary` | object | Counts of this run's findings, described below. |
| `cost` | object | `spent_usd` and `per_run_cap_usd`, both numbers, described below. |
| `target_cleanup` | object | Optional target cleanup report, described below. Omitted when the target returns no report. |

`summary` counts this run's findings:

```json
{
  "total": 0,
  "evaluated": 0,
  "evaluated_verdicts": ["fail", "pass", "warn"],
  "by_verdict": {"fail": 0, "pass": 0, "warn": 0, "skipped": 0, "blocked_by_target": 0, "aborted_cost": 0, "error": 0},
  "failed_by_severity": {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
}
```

`total` counts findings. `evaluated` counts findings whose verdict is in `evaluated_verdicts`: the probe reached the target and came back with a verdict. This is the same rule coverage uses for `tested`. `blocked_by_target`, `skipped`, `aborted_cost` and `error` findings are not evaluated. `by_verdict` counts every finding and always lists all seven verdicts. `failed_by_severity` counts only `fail` findings and always lists all five severities. A verdict or severity outside these lists gets its own key. The summary has no score and no percentage. If you compute a rate, divide by `evaluated`, not `total`. `summary.total` counts findings, while `coverage.totals.probes_run` counts distinct probes that were evaluated, so the two numbers can differ. The `deep_run` frame is not counted.

`cost.spent_usd` is the cost of this run's model calls in US dollars, rounded to six decimals. It is the engine's own estimate from model token usage and its price table, not an invoice. `cost.per_run_cap_usd` is the per-run cap the run was held to. It is the request's `per_run_cap_usd` when set, otherwise the server's default for the mode (static or deep). It is always a number. A run stopped at the cap can show `spent_usd` above `per_run_cap_usd` by the one call that crossed it.

## `end` frame

`event: end` with `data: {}`. The run finished and every finding was sent. It always follows the coverage frame.

## `error` frame

```json
{"detail": "per_run cap $0.05 exceeded: this run has spent $0.0600", "type": "CostExceededError", "cost": {"spent_usd": 0.06, "per_run_cap_usd": 0.05}}
```

| Field | Type | Meaning |
|-------|------|---------|
| `detail` | string | The error message. |
| `type` | string | The exception class name, an open set. `CostExceededError` means the run stopped at a cost cap; probes that did not start are sent first as `aborted_cost` findings. `JudgeBlockedError` means a provider content filter refused a judge prompt. `CleanupStateUnknown` means the cleanup report could not be read or validated; its detail is "cleanup state unknown". Treat any other value as a generic run failure. |
| `cost` | object | The same shape as the coverage frame's `cost`. |
| `target_cleanup` | object | Optional target cleanup report, described below. Omitted when the target returns no report or its report is invalid. |
| `judge_blocked` | object | Only when `type` is `JudgeBlockedError`. It holds `provider` (string), `model` (string, the model or deployment), `categories` (array of strings, empty when the provider names none) and `fallback` (`"off"` when a fallback provider exists but a block does not use it, `"<provider>/<model>: <error type>"` when the other attempt failed too, or null). |

The error frame's `type` is not a frame discriminator like the bare frames' `type`. The `event: error` line identifies the frame; `type` names the exception.

## `target_cleanup`

The coverage frame on success and the error frame on failure can include this object. It adds no frame. Targets with no cleanup report omit the key; it is never null.

| Field | Type | Meaning |
|-------|------|---------|
| `complete` | boolean | True only when `open` is empty and every abort is `done` or `not_needed`. |
| `done` | integer | Completed undo intents and delivery aborts. |
| `open` | array of objects | Unfinished records with `scope`, `step`, `status`, `method`, `url` (string or null), and `http_status` (integer or null). Abort records also have `attempt` (integer) and optional `failure_reason` (string). |
| `stop_reason` | string or null | The transport stop reason, if any. |
| `leftover` | array of strings | Required list of resources for manual review, including resources with no undo. |
| `aborts` | array of objects | Optional delivery abort records with the same fields as an open abort record. |

See [target cleanup in run.json](../run-json.md#target-cleanup) for statuses and completion rules. An invalid report omits `target_cleanup` and produces the "cleanup state unknown" diagnostic. When another exception already stopped the run, its type and original detail remain, and the diagnostic is appended to `detail`.

## Machine-readable frame list

`tests/test_run_stream_contract.py` reads the JSON block below. It drives `POST /redteam/run` in static mode, deep mode, a cost-cap error, a judge content-filter error and runs with a cleanup report, and checks every frame against this list. A frame passes when its `event:` name, or its `type` for a bare frame, matches one entry, every `required` field is present with the listed type, and every other field is listed under `optional`. Nested objects with their own `required` list are checked the same way. A type is `string`, `integer`, `number`, `boolean`, `object`, `array` or `null`, and `a|b` allows either. When you change what the server sends, update this list and the tables above in the same change.

```json
{
  "frames": [
    {
      "name": "deep_run",
      "event": null,
      "type": "deep_run",
      "required": {
        "type": "string",
        "deep": {
          "type": "object",
          "required": {
            "seed": "string",
            "deep_pairs": "integer",
            "max_rounds": "integer",
            "threads": {
              "type": "array",
              "items": {
                "type": "object",
                "required": {
                  "thread_id": "string",
                  "base_probe_id": "string",
                  "persona": "string",
                  "strategy": "string"
                }
              }
            },
            "static_material_probe_ids": "array",
            "history": "boolean"
          }
        }
      }
    },
    {
      "name": "finding",
      "event": null,
      "type": null,
      "required": {
        "id": "string",
        "probe_id": "string",
        "attack_prompt": "string",
        "target_response": "string",
        "target_latency_ms": "number",
        "probed_at": "string",
        "verdict": "string",
        "severity": "string",
        "confidence": "number",
        "reasoning": "string",
        "judge_model": "string",
        "escalated_model": "string|null",
        "atlas_id": "array",
        "owasp_id": "array",
        "owasp_agentic": "array",
        "nist_id": "array",
        "eu_ai_act_id": "array",
        "created_at": "string",
        "evidence": "object|null",
        "remediation": "string",
        "remediation_actions": "array",
        "events": "array"
      }
    },
    {
      "name": "coverage",
      "event": null,
      "type": "coverage",
      "required": {
        "type": "string",
        "coverage": {
          "type": "object",
          "required": {"thin_threshold": "number", "totals": "object", "standards": "object"}
        },
        "summary": {
          "type": "object",
          "required": {
            "total": "integer",
            "evaluated": "integer",
            "evaluated_verdicts": "array",
            "by_verdict": "object",
            "failed_by_severity": "object"
          }
        },
        "cost": {
          "type": "object",
          "required": {"spent_usd": "number", "per_run_cap_usd": "number"}
        }
      },
      "optional": {
        "target_cleanup": "$target_cleanup"
      }
    },
    {
      "name": "end",
      "event": "end",
      "type": null,
      "required": {}
    },
    {
      "name": "error",
      "event": "error",
      "type": null,
      "required": {
        "detail": "string",
        "type": "string",
        "cost": {
          "type": "object",
          "required": {"spent_usd": "number", "per_run_cap_usd": "number"}
        }
      },
      "optional": {
        "target_cleanup": "$target_cleanup",
        "judge_blocked": {
          "type": "object",
          "required": {
            "provider": "string",
            "model": "string",
            "categories": "array",
            "fallback": "string|null"
          }
        }
      }
    }
  ],
  "shared": {
    "target_cleanup": {
      "type": "object",
      "required": {
        "complete": "boolean",
        "done": "integer",
        "open": "array",
        "stop_reason": "string|null",
        "leftover": "array"
      },
      "optional": {"aborts": "array"}
    }
  }
}
```
