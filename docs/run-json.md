# run.json

`run.json` is a file that records one local run: the target, the coverage summary and every finding. It is meant for tools that read `run.json`, such as CI scripts, dashboards and diff tools. The file stays on your machine. Argus does not upload it anywhere.

Write it with:

```bash
argus-probe run --local --target target.json --probes all --format json --out run.json
```

`--format json` works only with `--local`. In server mode the CLI stops with a usage error, because the server's report endpoint has no json format yet.

If a run stops partway, for example when the cost cap is crossed, the CLI exits with a non-zero code and writes no file. You never get a half-written `run.json`.

## Fields

The top-level keys always appear in this order:

| Key | Type | Meaning |
|---|---|---|
| `schema_version` | string | Always `"argus.run/1"` for this version of the format. |
| `id` | string | A UUID for this run. |
| `status` | string | `"completed"` for a run that finished. |
| `started_at` | string | ISO 8601 timestamp, UTC. |
| `finished_at` | string | ISO 8601 timestamp, UTC. |
| `argus_version` | string | The installed `argus-probe` version. It is `"unknown"` when the CLI runs from a source tree that was never installed. |
| `target_spec` | object | The target spec after `${VAR}` expansion, with secrets masked (see below). |
| `coverage` | object or null | The coverage summary per standard, as the engine reports it. Null if the engine sent none. |
| `findings` | array | One object per probe result. |

Each finding has the same keys as the engine's `Finding` record: `id`, `probe_id`, `attack_prompt`, `target_response`, `target_latency_ms`, `probed_at`, `verdict`, `severity`, `confidence`, `reasoning`, `judge_model`, `escalated_model`, `atlas_id`, `owasp_id`, `nist_id`, `eu_ai_act_id`, `created_at` and `evidence`.

`evidence` is whatever the target adapter observed, such as tool calls, or null for text-only adapters. Its contents are free-form. Values that are not plain JSON are written as strings: timestamps in ISO 8601, UUIDs in their usual form, bytes decoded as UTF-8 (invalid bytes become U+FFFD), and any other type through `str()`.

## Redaction

People commit reports to CI artifacts and upload SARIF to GitHub code scanning, so in local mode (`--local`) Argus masks secrets before it writes any report. Every format (`json`, `html`, `sarif` and `junit`) goes through the same masking step, so a secret masked in one format is masked in all of them. Reports from an Argus server are rendered by the server and are not covered here. A masked value is the string `***`. Three rules apply.

### Rule 1: substituted environment values

A target spec can reference environment variables as `$VAR` or `${VAR}` in any string (and `%VAR%` on Windows). Argus records every non-empty value it substitutes. Before writing, it replaces each of those values with `***` in every string in the report. That covers the target spec, `target_response`, `reasoning` and `evidence` at any depth, including dict keys inside `evidence`. Longer values are replaced first, so a value that contains another one is masked whole.

This rule does not know which variables are secret. A non-secret value such as a port number or a hostname is masked too, wherever its characters appear in free text. This over-redaction is deliberate. These fields are always written as the engine produced them, never masked:

- run: `schema_version`, `argus_version`, `id`, `status`, `started_at`, `finished_at`, and `target_spec.kind`
- each finding: `id`, `probe_id`, `verdict`, `severity`, `probed_at`, `created_at`, `confidence` and `target_latency_ms`

### Rule 2: secret-looking key names

A secret written directly in the target file, without a `${VAR}` reference, is caught by key name. In `target_spec`, at any depth, and ignoring case:

- A key named `api_key`, `apikey` or `token`, or ending in `_key`, `apikey` or `token`, or containing `secret`, `password`, `authorization`, `credential` or `cookie`, has its whole value replaced with `***`. Counters such as `max_tokens` do not match and are kept.
- A key named `headers`, or ending in `headers` (for example `extra_headers`), keeps every header name and masks every header value. This works for header lists such as `[["Authorization", "Bearer ..."]]` and for header objects such as `{"Authorization": "Bearer ..."}`.

### Rule 3: literal values found by rule 2

Every value that rule 2 masks is also added to the list from rule 1. So if the target echoes a literal API key or header value back in `target_response` or `evidence`, it is masked there too. For a header value with a scheme, such as `Bearer abc123`, both the full value and the part after the scheme (`abc123`) are masked.

### Limits

Masking matches exact text. A secret that the target changes before echoing it, for example base64-encoded, URL-encoded, split across lines or reversed, is not caught. A secret written literally under a key name that rule 2 does not match, and with no `${VAR}` reference, is not caught either. Pass secrets through environment variables so rule 1 covers them.

## Compatibility

`schema_version` is `"argus.run/1"`. Within version 1 the format only grows by adding optional fields. Removing or renaming a field changes the version to `"argus.run/2"`. Tools that read `run.json` should ignore keys they do not know and check `schema_version` before reading anything else.
