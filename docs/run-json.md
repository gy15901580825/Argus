# run.json

`run.json` is a file that records one local run: the target, the coverage summary and every finding. It is meant for tools that read `run.json`, such as CI scripts, dashboards and diff tools. The file stays on your machine. Argus does not upload it anywhere.

Write it with:

```bash
argus-probe run --local --target target.json --probes all --format json --out run.json
```

`--format json` works only with `--local`. In server mode the CLI stops with a usage error, because the server's report endpoint has no json format yet.

If a run stops partway, for example when the daily cost cap is crossed, the target stops answering or the judge fails unexpectedly, the CLI still writes `run.json` with the findings gathered so far, sets `status` to `"incomplete"` and exits with a non-zero code. A run that never starts (no judge key, an unknown probe id, a target spec that cannot be built, an estimate above `--per-run-cap`) writes no file. Ctrl-C and SIGTERM write no file either.

## Fields

The top-level keys always appear in this order. `incomplete_reason`, `notes` and `judge` appear only when they apply:

| Key | Type | Meaning |
|---|---|---|
| `schema_version` | string | Always `"argus.run/1"` for this version of the format. |
| `id` | string | A UUID for this run. |
| `status` | string | `"completed"` when every probe reached a verdict. `"incomplete"` when at least one finding is `error` or `aborted_cost`, or the run stopped early; the CLI then exits 1 (4 for the cost cap). |
| `incomplete_reason` | string | `run` only, and only when `status` is `"incomplete"`. Why, in the console's words: for example `2 of 9 probes errored; run incomplete; target returned HTTP 401 (unauthorized; check credentials)`. |
| `started_at` | string | ISO 8601 timestamp, UTC. |
| `finished_at` | string | ISO 8601 timestamp, UTC. |
| `argus_version` | string | The installed `argus-probe` version. It is `"unknown"` when the CLI runs from a source tree that was never installed. |
| `target_spec` | object | The target spec after `${VAR}` expansion, with secrets masked (see below). |
| `coverage` | object or null | The coverage summary per standard, as the engine reports it. Null if the engine sent none. |
| `findings` | array | One object per probe result. |
| `notes` | array of strings | Only when there is something to say: the incomplete reasons, and the warning when almost every probe was blocked with one HTTP code. `run` writes it; `mcp-trap` and `scan-mcp` do not. |
| `judge` | object | Only when the run used the LLM judge (`run` with a judged probe, `scan-mcp` with the judge on). The judge it was configured with: `provider`, `fast_model`, `strong_model`, `api_base_host` (the host and port of a custom base URL, never the path or query, or null) and `fallback_provider` (the provider tried when a call fails, or null). With the `jev` judge, `api_base_host` is the TypeSafe host and `explain_model` names the text model set with `--judge-explain-model`; the key is absent otherwise. Each finding's `judge_model` says which model gave that verdict. |

Each finding has the same keys as the engine's `Finding` record: `id`, `probe_id`, `attack_prompt`, `target_response`, `target_latency_ms`, `probed_at`, `verdict`, `severity`, `confidence`, `reasoning`, `judge_model`, `escalated_model`, `atlas_id`, `owasp_id`, `owasp_agentic`, `nist_id`, `eu_ai_act_id`, `created_at`, `evidence` and `remediation`.

`owasp_agentic` is a list of direct-risk tags from the OWASP Top 10 for Agentic Applications, 2026 edition (`ASI01` through `ASI10`). Unmapped findings contain `[]`. Older records may omit this additive field; reports render those records with empty agentic mappings. Coverage uses the key `owasp-agentic-top10` and always lists all ten categories, including `absent` cells.

HTML shows agentic tags beside each finding. SARIF stores the exact array in rule and result `properties.owasp_agentic`, with namespaced strings such as `OWASP-Agentic:ASI01` in `properties.tags`. JUnit stores one suite property per finding, named `owasp_agentic.1`, `owasp_agentic.2`, and so on in testcase order. Each value is a JSON array, including `[]` when unmapped. Each testcase's `system-out` starts with JSON metadata such as `{"owasp_agentic": ["ASI01"]}`; any warning or target-blocked explanation follows on a new line. This uses elements supported by strict xUnit2 consumers.

`remediation` is how to fix the weakness the probe tests: the probe's own text when it has one, else a few sentences for each of the probe's attack classes, one class per line. It is the same for every finding of a probe, whatever the verdict, and it is an empty string when there is no text for the probe. Files written before this field existed do not have it.

`evidence` is whatever the target adapter observed, such as tool calls, or null for text-only adapters. Its contents are free-form. Values that are not plain JSON are written as strings: timestamps in ISO 8601, UUIDs in their usual form, bytes decoded as UTF-8 (invalid bytes become U+FFFD), and any other type through `str()`.

For a `browser_use` target, `evidence` is the record of what the agent did on the trap page. It has three keys. `page_loads` counts how often the agent opened the trap page. `trap_requests` lists every request the agent sent to the trap's sink, in arrival order. Each entry has `method`, `path`, `query`, `body` and `complete`. `path` leaves out the trap's random path token, so it reads `/sink/...` on every run. The sink keeps at most 50 requests and 4000 characters of each body. `complete` is true when `body` holds the whole body. It is false when the body was longer than 4000 characters, when it stalled for 5 seconds, or when it was still arriving 2 seconds after the agent returned. If any entry is incomplete and no entry contains the canary, `no_canary_in_trap_requests` cannot decide, and the finding is an `error`. Queries and bodies can hold real credentials, for example ones the browser autofilled, so the evidence masks them. Each form field value (in a query or a form body) and each JSON string or number that does not contain one of the probe's canaries becomes `<redacted N chars>`, where N is the length of the decoded value. A body or query that is neither form fields nor JSON keeps its text only if it contains a canary; otherwise it becomes `<redacted N chars>` as a whole. Field names, JSON keys, `method`, `path` and `complete` are kept. A probe without a `no_canary_in_trap_requests` assertion has no canary, so every value is masked. The assertions read the masked record and reach the same verdict they would on the raw one. `interaction_count` is `page_loads` plus the number of sink requests. For a browser probe with assertions, no sink request and no page load means the agent never touched the trap, and the finding is an `error`, not a pass. Every bundled browser probe with assertions works this way. The rule does not apply to a probe without assertions, such as the 6 shared probes that also run against chat targets (counted on 2026-10-30): the judge decides those from the reply, whether or not the agent opened the page. It also does not apply to a probe that sets `requires_interaction: false`.

## Redaction

People commit reports to CI artifacts and upload SARIF to GitHub code scanning, so in local mode (`--local`) Argus masks secrets before it writes any report. Every format (`json`, `html`, `sarif` and `junit`) goes through the same masking step, so a secret masked in one format is masked in all of them. Reports from a server implementing the `/api/v1/redteam` API are rendered by that server and are not covered here. A masked value is the string `***`. Three rules apply.

### Rule 1: substituted environment values

A target spec can reference environment variables as `$VAR` or `${VAR}` in any string (and `%VAR%` on Windows). Argus records every non-empty value it substitutes. Before writing, it replaces each of those values with `***` in every string in the report. That covers the target spec, `target_response`, `reasoning` and `evidence` at any depth, including dict keys inside `evidence`. If two `evidence` keys mask to the same text, both are kept, the second as `***#2`. Longer values are replaced first, so a value that contains another one is masked whole.

This rule does not know which variables are secret. A non-secret value such as a port number or a hostname is masked too, wherever its characters appear in free text. This over-redaction is deliberate. These fields are always written as the engine produced them, never masked:

- run: `schema_version`, `argus_version`, `id`, `status`, `started_at`, `finished_at`, `coverage` and `target_spec.kind`
- each finding: `id`, `probe_id`, `verdict`, `severity`, `probed_at`, `created_at`, `confidence`, `target_latency_ms`, `atlas_id`, `owasp_id`, `owasp_agentic`, `nist_id`, `eu_ai_act_id`, `judge_model`, `escalated_model` and `remediation`

### Rule 2: secret-looking key names

A secret written directly in the target file, without a `${VAR}` reference, is caught by key name. In `target_spec`, at any depth, each key is compared after lowercasing it and removing `_` and `-`. So `api_key`, `apiKey` and `API-KEY` are treated the same.

- A key ending in `key`, `token` or `authheader`, or containing `secret`, `password`, `authorization`, `credential` or `cookie`, has its whole value replaced with `***`. This catches `privateKey`, `accessKey`, `access_token`, `clientSecret` and `authHeader`. Counters such as `max_tokens` end in `tokens`, do not match, and are kept.
- A key named `headers`, or ending in `headers` (for example `extra_headers`), keeps every header name and masks every header value. This works for header lists such as `[["Authorization", "Bearer ..."]]` and for header objects such as `{"Authorization": "Bearer ..."}`.

### Rule 3: literal values found by rule 2

Every value that rule 2 masks is also added to the list from rule 1. So if the target echoes a literal API key or header value back in `target_response` or `evidence`, it is masked there too. For a header value with a scheme, such as `Bearer abc123`, both the full value and the part after the scheme (`abc123`) are masked.

### Limits

Masking matches exact text. A secret that the target changes before echoing it, for example base64-encoded, URL-encoded, split across lines or reversed, is not caught. A secret written literally under a key name that rule 2 does not match, and with no `${VAR}` reference, is not caught either. Pass secrets through environment variables so rule 1 covers them.

## Compatibility

`schema_version` is `"argus.run/1"`. Within version 1 the format only grows by adding optional fields. Removing or renaming a field changes the version to `"argus.run/2"`. Tools that read `run.json` should ignore keys they do not know and check `schema_version` before reading anything else.

### Paired runs and trials

Paired probes store each clean and attack world's sealed evidence in `evidence.trials`. Each entry includes `trial`, `verdict`, `reason_code`, `reason`, `clean`, and `attack`. An attack is null when the clean control failed.

`evidence.trial_summary` contains `attempted`, `pass`, `fail`, `warn`, `error`, `skipped`, `blocked_by_target`, `valid`, `verdict`, and `reason_code`. The valid denominator is pass plus fail plus warn. The finding's reasoning repeats all seven counts and the valid denominator so each report format retains them.

A failure takes precedence over warning. Only all-pass trials produce pass. Mixed incomplete trials produce error. A cost cap retains an observed fail or warn, otherwise the result is `aborted_cost`. A pass records only that the behavior was not observed in this environment on that date.
