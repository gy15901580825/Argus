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
| `summary` | object | Counts of this run's findings: `total`, `evaluated`, `evaluated_verdicts`, `by_verdict` and `failed_by_severity`. Always present. See below. |
| `findings` | array | One object per probe result. |
| `notes` | array of strings | Only when there is something to say: the incomplete reasons, and the warning when almost every probe was blocked with one HTTP code. `run` writes it; `mcp-trap` and `scan-mcp` do not. |
| `judge` | object | Only when the run used the LLM judge (`run` with a judged probe, `scan-mcp` with the judge on). The judge it was configured with: `provider`, `fast_model`, `strong_model`, `api_base_host` (the host and port of a custom base URL, never the path or query, or null) and `fallback_provider` (the provider tried when a call fails, or null). With the `jev` judge, `api_base_host` is the TypeSafe host and `explain_model` names the text model set with `--judge-explain-model`; the key is absent otherwise. Each finding's `judge_model` says which model gave that verdict. |

### Run summary

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

`total` counts findings. `evaluated` counts findings whose verdict is in `evaluated_verdicts`: the probe reached the target and came back with a verdict. This is the same rule coverage uses for `tested`. `blocked_by_target`, `skipped`, `aborted_cost` and `error` findings are not evaluated. `by_verdict` counts every finding and always lists all seven verdicts. `failed_by_severity` counts only `fail` findings and always lists all five severities. A verdict or severity outside these lists gets its own key. The summary has no score and no percentage. If you compute a rate, divide by `evaluated`, not `total`. `summary.total` counts findings, while `coverage.totals.probes_run` counts distinct probes that were evaluated, so the two numbers can differ.

`run`, `mcp-trap` and `scan-mcp` all write `summary` in run.json. It is computed from the written findings, so an early-stopped run has one too. Files written before this field existed do not have it.

Each finding has the same keys as the engine's `Finding` record: `id`, `probe_id`, `attack_prompt`, `target_response`, `target_latency_ms`, `probed_at`, `verdict`, `severity`, `confidence`, `reasoning`, `judge_model`, `escalated_model`, `atlas_id`, `owasp_id`, `owasp_agentic`, `nist_id`, `eu_ai_act_id`, `created_at`, `evidence`, `remediation`, `remediation_actions` and `events`.

`owasp_agentic` is a list of direct-risk tags from the OWASP Top 10 for Agentic Applications, 2026 edition (`ASI01` through `ASI10`). Unmapped findings contain `[]`. Older records may omit this additive field; reports render those records with empty agentic mappings. Coverage uses the key `owasp-agentic-top10` and always lists all ten categories, including `absent` cells.

HTML shows agentic tags beside each finding. SARIF stores the exact array in rule and result `properties.owasp_agentic`, with namespaced strings such as `OWASP-Agentic:ASI01` in `properties.tags`. JUnit stores one suite property per finding, named `owasp_agentic.1`, `owasp_agentic.2`, and so on in testcase order. Each value is a JSON array, including `[]` when unmapped. Each testcase's `system-out` starts with JSON metadata such as `{"owasp_agentic": ["ASI01"]}`; any warning or target-blocked explanation follows on a new line. This uses elements supported by strict xUnit2 consumers.

`remediation` is how to fix the weakness the probe tests: the probe's own text when it has one, else a few sentences for each of the probe's attack classes, one class per line. It is the same for every finding of a probe, whatever the verdict, and it is an empty string when there is no text for the probe. Files written before this field existed do not have it.

`remediation_actions` splits the same advice into steps by how fast you can ship them. Each entry has `tier`, `text` and `atlas_mitigation`. `tier` is `mitigation` (a configuration change you can make today, such as an approval gate, a filter or an allowlist) or `fix` (the design change that removes the weakness). `atlas_mitigation` is a MITRE ATLAS mitigation id such as `AML.M0030`, used as a tag, or null. Every built-in probe has at least one entry of each tier: one of each for a single attack class or a probe with its own text, and one of each per attack class otherwise, in the probe's class order. The list is the same for every finding of a probe. It is `[]` for `scan-skill` findings, for integration scenarios without `attack_class`, and for a probe-pack probe that sets its own `remediation` without `remediation_actions`. `remediation` keeps its old text, so tools that read only that field see no change. Files written before this field existed do not have it.

### Finding events

`events` records steps backed by evidence that Argus observed or the target reported. Every new finding includes the key. Findings without a supported source of events contain `[]`, including plain chat, MCP `agent_world`, browser, payment, and direct `scan-skill` findings. Files written before this field existed do not have it. The format remains `argus.run/1`.

Each event has these fields in this order:

| Field | Type | Meaning |
|---|---|---|
| `event_id` | string | Nonempty identifier, unique within this finding. |
| `parent_event_ids` | array of strings | IDs of earlier evidence-backed steps in the same finding. Empty when no parent identifier resolves. |
| `ts` | string or null | UTC wall-clock time with milliseconds and a trailing `Z`, such as `2026-11-01T04:10:24.123Z`. Null when the source has no timezone-aware wall-clock time. |
| `actor` | string | Nonempty role name, such as `argus`, `target_agent`, `planner`, `reviewer`, `executor`, `entry`, or `worker:<peer>`. |
| `operation` | string | One of the six values below. |
| `tool_name` | string or null | Tool or action name when recorded. Corresponds to OTel `gen_ai.tool.name`. |
| `tool_call_id` | string or null | Tool-call identifier when recorded. Corresponds to OTel `gen_ai.tool.call.id`. |
| `object_ref` | string or null | `<kind>:<id>`, with a kind from the table below and a nonempty ID without whitespace. Null when no supported object identifier exists. |
| `basis` | string | `observed` when Argus, the testbed, or a third-party API observed the step. `reported` when the target supplied it in telemetry or a run log. |
| `atlas_technique` | string or null | ATLAS technique ID such as `AML.T0051` or `AML.T0051.001`. Both current adapters emit null. Finding-level mappings remain in `atlas_id`. |
| `source` | string | `a2a_world` or `integration_scenario`. |
| `summary` | string or null | At most 200 characters, assembled only from `actor`, `operation`, `tool_name`, and the object kind. Contains no object ID or payload. |
| `seq` | integer or null | source record order within a finding; does not guarantee event occurrence order; nullable. |

Non-null `seq` values are nonnegative and unique within a finding. They support layout ordering and are not comparable across findings. When both a parent and its child have `seq`, the parent's value is smaller. A2A uses the testbed row's `seq`, with a trial-index offset of 1,000,000 per trial when combining trials. Integration scenarios record planted objects in registry order, then retain each evidence row's position after those objects. Deduplicated events keep their first recorded position.

The operation set is closed:

| Operation | Meaning | Current source |
|---|---|---|
| `invoke_agent` | An actor hands a task or message to an agent. | The scenario trigger, A2A `agent_message`, or A2A `peer_message` when `peer_trusted` is not false. |
| `execute_tool` | An agent calls a tool or action interface. | An A2A action sink row. `tool_name` contains the recorded action name. |
| `deliver_message` | A message enters a channel that an agent can read. | An A2A `peer_reply` or a scenario seed email sent by Argus. |
| `read_object` | An actor reads an object. | A successful target run-log `read`, `retrieve`, `search`, `get`, or `fetch` operation that is not a dry run. |
| `write_object` | An actor creates or changes an object. | An Argus-planted document or a Gmail `draft_created` or `draft_changed` observation. |
| `send_external` | Data goes to a destination outside the target's trust boundary, with an observed boundary marker. | An A2A `peer_message` with `peer_trusted` false. |

`invoke_agent` and `execute_tool` reuse OTel names. Argus adds no OpenTelemetry dependency. Writing a draft is `write_object`, even if its recipient is unexpected. A draft is not an observed send.

The object-kind set is closed:

| Kind | Identifier |
|---|---|
| `a2a.message` | A2A message ID. |
| `a2a.task` | A2A task ID, preferred for a peer reply when available. |
| `acs.email` | ID returned for a seed email sent through ACS. |
| `gdrive.file` | Google Drive file ID. |
| `gmail.message` | Gmail message ID, including the message inside a draft. |

`gmail.draft` is not a kind because the Gmail observer records the draft's message ID, which differs from its draft ID. `mcp.tool` has no emitter in this version. An A2A action has no object reference because its business references are canaries, not object IDs.

Downstream consumers build edges from `parent_event_ids`. Argus defines no separate edge or node types. Every parent ID resolves within the finding, and the graph has no cycles. An invalid adapter graph produces a warning and `events: []`. The two supported bases are `observed` and `reported`. There is no `inferred` basis, and judge reasoning never creates an event or a parent edge.

Only A2A world attack phases and the `mail_policy_conflict_v1` integration scenario currently emit events. A2A event IDs have a `t<trial>:` prefix. Invalid trial evidence emits no events. Discovery reads (`bootstrap_read`, `card_read`, and `task_poll`) and clean-phase rows are excluded. A2A parents resolve only recorded `parent_event_ids` and `parent_message_ids` against earlier emitted rows' event, message, or task IDs. Unresolved and forward references are dropped. Shared business values alone never create a parent edge.

The mail scenario uses test-group evidence plus the planted objects that evidence references, including a baseline policy document when referenced. Only a runner-created `response` row with `TARGET_SELF_REPORT` provenance becomes the observed Argus trigger. That trigger links to objects whose markers or IDs Argus put in the prompt. A target run-log or third-party row named `response` does not become an Argus invocation. Successful run-log reads remain `reported` and link to the recorded call and the object identified by marker or ID. Target identity claims do not become observations through these links. A draft links to the seed object's marker, not to the trigger call. No recorded identifier ties the draft to that call. Repeated observations with the same draft operation and message ID produce one event. Control and baseline evidence rows, infrastructure folders, `baseline_poll`, `draft_snapshot`, `object_changed`, and failed, non-read, or dry-run run-log rows produce no events.

All A2A `ts` values are null because the testbed's monotonic offsets have no wall-clock anchor. Mail triggers use Argus's timezone-aware response timestamp. Planted objects have no timestamp, and mail draft and run-log observations have no occurrence time, so their `ts` values are null. Poll time is not occurrence time. Naive datetimes also become null. Parent links express the recorded relationships. Neither `seq` nor array position guarantees event occurrence order.

Events exclude prompts, replies, raw tool arguments and outputs, email bodies, field values, and A2A references or canaries. Those payloads remain only in `evidence`, under its existing redaction rules. Event text is masked as described below. SARIF does not include events or `codeFlows`.

`evidence` is whatever the target adapter observed, such as tool calls, or null for text-only adapters. Its contents are free-form. Values that are not plain JSON are written as strings: timestamps in ISO 8601, UUIDs in their usual form, bytes decoded as UTF-8 (invalid bytes become U+FFFD), and any other type through `str()`.

For a `browser_use` target, `evidence` is the record of what the agent did on the trap page. It has three keys. `page_loads` counts how often the agent opened the trap page. `trap_requests` lists every request the agent sent to the trap's sink, in arrival order. Each entry has `method`, `path`, `query`, `body` and `complete`. `path` leaves out the trap's random path token, so it reads `/sink/...` on every run. The sink keeps at most 50 requests and 4000 characters of each body. `complete` is true when `body` holds the whole body. It is false when the body was longer than 4000 characters, when it stalled for 5 seconds, or when it was still arriving 2 seconds after the agent returned. If any entry is incomplete and no entry contains the canary, `no_canary_in_trap_requests` cannot decide, and the finding is an `error`. Queries and bodies can hold real credentials, for example ones the browser autofilled, so the evidence masks them. Each form field value (in a query or a form body) and each JSON string or number that does not contain one of the probe's canaries becomes `<redacted N chars>`, where N is the length of the decoded value. A body or query that is neither form fields nor JSON keeps its text only if it contains a canary; otherwise it becomes `<redacted N chars>` as a whole. Field names, JSON keys, `method`, `path` and `complete` are kept. A probe without a `no_canary_in_trap_requests` assertion has no canary, so every value is masked. The assertions read the masked record and reach the same verdict they would on the raw one. `interaction_count` is `page_loads` plus the number of sink requests. For a browser probe with assertions, no sink request and no page load means the agent never touched the trap, and the finding is an `error`, not a pass. Every bundled browser probe with assertions works this way. The rule does not apply to a probe without assertions, such as the 6 shared probes that also run against chat targets (counted on 2026-10-30): the judge decides those from the reply, whether or not the agent opened the page. It also does not apply to a probe that sets `requires_interaction: false`.

## Redaction

People commit reports to CI artifacts and upload SARIF to GitHub code scanning, so in local mode (`--local`) Argus masks secrets before it writes any report. Every format (`json`, `html`, `sarif` and `junit`) goes through the same masking step, so a secret masked in one format is masked in all of them. Reports from a server implementing the `/api/v1/redteam` API are rendered by that server and are not covered here. A masked value is the string `***`. Three rules apply.

### Rule 1: substituted environment values

A target spec can reference environment variables as `$VAR` or `${VAR}` in any string (and `%VAR%` on Windows). Argus records every non-empty value it substitutes. Before writing, it replaces each of those values with `***` in every string in the report. That covers the target spec, `target_response`, `reasoning` and `evidence` at any depth, including dict keys inside `evidence`. If two `evidence` keys mask to the same text, both are kept, the second as `***#2`. Longer values are replaced first, so a value that contains another one is masked whole.

This rule does not know which variables are secret. A non-secret value such as a port number or a hostname is masked too, wherever its characters appear in free text. This over-redaction is deliberate. These fields are always written as the engine produced them, never masked:

- run: `schema_version`, `argus_version`, `id`, `status`, `started_at`, `finished_at`, `coverage`, `summary` and `target_spec.kind`
- each finding: `id`, `probe_id`, `verdict`, `severity`, `probed_at`, `created_at`, `confidence`, `target_latency_ms`, `atlas_id`, `owasp_id`, `owasp_agentic`, `nist_id`, `eu_ai_act_id`, `judge_model`, `escalated_model`, `remediation` and `remediation_actions`
- each `events` entry: `event_id`, `parent_event_ids`, `ts`, `operation`, `basis`, `source`, `atlas_technique` and `seq`

Only these event structure fields are restored after masking. `actor`, `tool_name`, `tool_call_id`, `object_ref`, and `summary` undergo normal text masking. If masking makes an object kind unknown, `object_ref` becomes null. `summary` is clipped to 200 characters after masking.

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


MCP world snapshots may also carry `resource_reads` for resource worlds and `tool_calls[].server: "second"` for second-endpoint calls. Both are additive.

## A2A paired-world evidence

`a2a_agent` retains the frozen Finding and run.json field contracts. Per-trial evidence lives in `evidence.trials`, with clean and attack snapshots, verdict and `reason_code`; aggregate counts remain in `evidence.trial_summary`.

Each snapshot uses `schema_version: argus-a2a-evidence-v1`, with `world`, `phase`, `session_id`, `sealed`, `seal_timeout`, `capabilities`, `deployment`, fresh `canaries`, trusted-peer `registry`, value `claims`, `approvals_issued`, `events`, passive `actions`, optional `ingress`, `attack_delivered`, `rejected_requests`, `counters`, `budget` and `task_completed`. Events retain sequence, identity assurance, matching digest, current references, parent references, transport/version and response state. Actions separately record `request_received`, `accepted`, `applied`, verified caller, operation and business fields.

Agent identities are verified by distinct configured credentials. Matching sent/received digests establish an observed edge; caller-supplied adoption flags do not. Current-world attribution requires fresh business references, not a reused message or parent ID. Unassociated authenticated actions cause an evidence error. Single-agent budget symptoms can warn; observed cross-agent violations fail, even when a later hard budget truncates observation. Missing evidence or clean capability proof cannot become a pass.

The controller masks full and bare auth credentials from business text and fields in live and sealed snapshots. Public structural metadata, such as role, schema/version, recognized capability, claim/delivery and transport enums, remains unchanged when a credential happens to equal a public label. Message IDs, parent IDs and arbitrary business strings inside these evidence snapshots are never restored. Normalized finding event IDs follow the separate restoration rule above. CLI report redaction applies again to target credentials and receiver headers.
