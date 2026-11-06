# Verify a draft locally

`draft-target --verify-local` executes one transport v2 attempt per outcome case on a temporary copy. Every configured request origin becomes the same randomly assigned `http://127.0.0.1:PORT`, including provision, setup, polling, abort, undo and confirmation. Authentication is removed. Original secret references and process environment values are not resolved; only a version 2 scenario's synthetic values are used. The fake and copy are discarded when verification ends. The delivered target file remains unchanged.

```bash
argus-probe draft-target --openapi api.json --out target.json \
  --no-model --verify-local --scenario scenario.json
```

`--scenario` requires `--verify-local`. Without a scenario, bounded schema samples check supported request and response shapes. The result is `schema_mock_only`, never business success. Unsupported schema keywords are reported, rather than ignored, and produce `schema_mock_unsupported`. A nullable field, written as `type: [T, "null"]`, `nullable: true`, or `anyOf` or `oneOf` of one schema and `{type: "null"}`, is sampled as its non-null type, and an `enum` sample is its first non-null value. A reply sampled as null, such as a `type: "null"` field, always fails. Format checks include UUID, date, date-time, base64 byte, int32 and int64; multipart binary values are decoded strings. The value constraints that `draft-target` lists in its `schema_constraints_unchecked` gap, such as `pattern`, other `format` values or `multipleOf`, are not checked here either. Values must still have the documented type.

A scenario is an independent oracle prepared from documentation or a reviewed configuration before generating a draft. Neither the model nor the draft creates it. It describes fixed replies, actual request expectations and resource transitions. It never repairs the draft. Local checks cannot prove real service behavior, billing, latency or model safety.

## Version 1

All objects reject unknown fields. The following synchronous example matches a documented `ask` operation whose request accepts `goal` and whose reply contains `status` and `result`.

```json
{
  "version": 1,
  "source": {"document": "api.json", "pointers": ["/paths/~1ask/post"]},
  "resources": [],
  "operations": [{
    "id": "ask", "method": "POST", "path": "/ask", "role": "invoke",
    "calls": {"min": 1, "max": 1},
    "request": [{
      "check": "prompt_bound", "at": {"kind": "json", "pointer": "/goal"},
      "equals": "ping"
    }],
    "replies": [{
      "status": 200, "body": {"status": "COMPLETED", "result": "done"}, "effects": []
    }]
  }],
  "expect": {"outcome": "succeeded", "reply": "done", "resources": [], "required_gaps": []}
}
```

`source` is provenance text. It does not authorize opening or fetching another file. Each operation ID, method and route must agree with the independently supplied OpenAPI catalog. Operation IDs are bounded printable strings and preserve documented spelling. Internal resource IDs use lowercase letters, digits and underscores, starting with a letter, with at most 64 characters. Route parameter names preserve documented case. Paths begin with `/` and may contain `{parameter}` for one segment. Schemes, authorities, query strings, fragments, encoded paths, backslashes and dot segments are rejected in route patterns.

Each operation has one fixed role: `invoke`, `poll`, `upload`, `setup`, `delete`, `confirm` or `pause`. Its `calls` range is independent of the draft. `replies` is a finite ordered list, with at least `max` entries. Each reply contains `status`, a JSON `body` and `effects`. An optional `headers` object accepts only `Location` and `Retry-After`, case-insensitively with no duplicate names. `Location` is a fixed slash-prefixed relative path, optionally with a literal query, without authority, fragment, template or control characters. `Retry-After` is an integer string from `0` to `10`. Absolute destinations cannot be emitted by a scenario.

Each request predicate contains `check`, `at` and scalar literal `equals`. The permitted check names are `prompt_bound`, `material_bound`, `poll_identity` and `resource_identity`. A prompt predicate must expect `ping`; a material predicate must expect `Argus validation sample.`. Every declared material predicate must actually match, including predicates on operations whose minimum call count is zero. Removing the draft's material binding does not remove this independent obligation. Material-bearing transport also cannot pass without an observed matching material predicate. An invoke must have a prompt predicate. An upload must have a material predicate and its invocation must check the independently issued file reference. Every poll path identity needs its own predicate.

Request JSON rejects duplicate object keys, non-finite numbers and nesting beyond sixteen levels. Invalid bodies report `request_body_invalid` before schema or business predicates are evaluated.

Request body checks use the actual media type and bytes. A missing optional body is allowed; a nonempty body with the wrong declared media type is rejected. JSON and multipart request bodies are supported. Other declared body media and non-JSON reply media report `schema_mock_unsupported`. An explicitly invalid null response schema fails validation. Enum and const comparisons use JSON value equality, including nested values. Booleans differ from numbers, while `1` and `1.0` are equal. Nullable extends the base type without bypassing composition or enum constraints. Converted numeric parameters must be finite.

| Selector `at` | Meaning |
|---|---|
| `{"kind":"json","pointer":"/question"}` | RFC 6901 field in the actual JSON request body |
| `{"kind":"query","name":"id"}` | Exactly one query value |
| `{"kind":"path","name":"runId"}` | The named documented route parameter |
| `{"kind":"multipart_text","name":"description"}` | One text part without a filename |
| `{"kind":"multipart_file","name":"file","filename":"sample.txt"}` | One file part with the exact filename and UTF-8 contents |
| `{"kind":"raw_utf8"}` | Actual UTF-8 request bytes |

Duplicate query values and multipart parts fail instead of selecting the first. The file selector reads uploaded bytes, never a local file path. For an upload flow, declare a literal full resource name such as `files/file-a` in the response body and require that same full name in the invocation predicate. Poll predicates independently check each issued identity across pending and completed replies.

Resources have `id`, `initial` and `cleanup`. States are `absent`, `live` and `paused`; cleanup policies are `delete`, `pause` and `documented_no_delete`. A reply effect has `resource`, `from` and `to`. State preconditions and request predicates must match before an effect applies. A setup that ingests material can create a resource, and an invocation's `live` to `live` precondition can require that independent ingestion without inventing an undocumented invocation field.

`expect.resources` contains exactly one `{ "id": "file", "final": "absent" }` row per resource. A declared delete must end absent. Query DELETE and optional confirmation GET are observed only when the transport sends them. Existing v2 confirmation is a fallback for an unexpected primary cleanup status, not an extra request after every successful DELETE. A pause is an exceptional branch and does not count as completed business or deletion.

For documented lack of deletion, use `cleanup: "documented_no_delete"`, record the expected live residue, and list the independently required gap code in `expect.required_gaps`. Verification requires that code in the draft's existing gap list. It reports `business_only` and incomplete cleanup, and never invents a DELETE. An unrelated transport leftover or undeleted resource with a declared delete fails `cleanup_left_resources`.

## Version 2

Version 2 accepts every version 1 field plus a required `environment` object. It maps non-secret input names to synthetic string values, so a draft that sends `TARGET_INPUT_*` environment bindings can run against the fake. Version 1 files keep working unchanged and still reject `environment`.

```json
{
  "version": 2,
  "environment": {"TARGET_INPUT_URL": "https://material.invalid/doc"},
  "source": {"document": "api.json", "pointers": ["/paths/~1ask/post"]},
  "resources": [],
  "operations": [{
    "id": "ask", "method": "POST", "path": "/ask", "role": "invoke",
    "calls": {"min": 1, "max": 1},
    "request": [{"check": "prompt_bound", "at": {"kind": "json", "pointer": "/goal"}, "equals": "ping"}],
    "replies": [{"status": 200, "body": {"status": "COMPLETED", "result": "done"}, "effects": []}]
  }],
  "expect": {"outcome": "succeeded", "reply": "done", "resources": [], "required_gaps": []}
}
```

Names must start with `TARGET_INPUT_`, use uppercase letters, digits and underscores, and contain none of `key`, `token`, `secret`, `password`, `auth`, `header` or `cookie`. Values are nonempty text up to 1024 bytes without control characters. At most 32 names are allowed. The fake admits only these names; the process environment is never read. Values are synthetic and should not be production data.

## Version 3

Version 3 accepts every version 2 field plus a required `cases` list. The top-level operations and `expect` stay the main sequence. Each case replays that sequence with other replies for the operations it names, and states the outcome that sequence must end in. Versions 1 and 2 keep loading unchanged and still reject `cases`.

```json
"cases": [{
  "name": "job_failed",
  "operations": {
    "get_job": {
      "calls": {"min": 1, "max": 1},
      "replies": [{"status": 200, "body": {"status": "FAILED"}, "effects": [], "headers": {"Retry-After": "0"}}]
    }
  },
  "expect": {"outcome": "target_error", "reply": null}
}]
```

A case name follows the internal name rule and is unique. `operations` maps at least one operation ID from the main sequence to a replacement `calls` range and `replies` list. Both follow the operation rules above. Other operations, resources, final resource states and required gaps come from the main sequence. `expect` holds `outcome` and `reply` with the same rules as the main `expect`. At most 8 cases are allowed, and each case keeps the 64-request and 64-reply limits.

## Outcome cases from the document

Every scenario version also gets cases derived from the OpenAPI document, so the failure and pending paths run even when the scenario describes only success. Derivation needs a main sequence that ends in `succeeded` and exactly one `poll` operation with equal `min` and `max` calls. The last of those poll replies is the terminal reply. Its documented response must have exactly one top-level property with a string `enum` that contains the terminal reply's value. That value is the success status.

Each other documented value is classified by the fixed word table that `draft-target` uses for its `poll_status_proposed` gap, ignoring case.

| Class | Words | Derived sequence | Must end in |
|---|---|---|---|
| Pending | `pending`, `queued`, `running`, `in_progress`, `processing`, `started` | The main sequence with one extra poll reply before the terminal reply. It is a copy of the terminal reply with this status and no effects. | The main outcome and reply |
| Failed | `failed`, `error`, `cancelled`, `canceled`, `expired`, `timed_out` | The main sequence with the terminal reply's status replaced by this value. Effects are kept. | `target_error` with no reply |
| Other | anything else | Not run | Not checked |

The oracle cannot know what other values mean, so it does not assert one. They appear in `cases` as not run, and `status_meaning` is listed as unverified. A document with more than 32 other values, or without a matching enum, derives nothing and lists `documented_status_cases` as unverified. Declare a version 3 case to cover such a value.

Every case is checked like the main sequence, including call counts, resource states and cleanup. A failing case fails the whole verification with one of these names:

| Check | Meaning |
|---|---|
| `failure_status_succeeded` | A documented failure status ended as `succeeded` |
| `failure_status_mismatch` | A documented failure status ended otherwise than `target_error` after its one reply, for example `blocked` or another poll |
| `pending_status_unrecognised` | A documented pending status did not lead to the main sequence's result |
| `scenario_case_failed` | A declared version 3 case did not pass |

Cases run concurrently, each with its own fake and its own deadline. A pending case adds one poll. With a fixed 5-second poll interval it takes 5 seconds longer than the main sequence.

## Not verified

The fake removes authentication and serves every configured origin itself. `validation.local.unverified` names what local verification therefore cannot show, and the command prints each one as `local.unverified: NAME`.

| Name | Listed when |
|---|---|
| `auth_headers` | The draft configures authentication |
| `server_origin` | Always |
| `documented_status_cases` | No outcome cases could be derived from the document |
| `status_meaning` | A documented status value is outside the word table |

## Evidence and limits

Local evidence is stored separately in `target.provenance.json` under `validation.local`. Its version is 2. It contains a layer, status, business and cleanup booleans, failed check names, final execution counts, resource states and a bounded operation trace for the main sequence. `cases` has one row per declared or derived case: name, origin (`scenario` or `document`), status value and class, expected and actual outcome, whether it passed (`null` when not run), its own failed checks and its submit and poll counts. `unverified` lists the names above. One actual v2 attempt is recorded as `execution.attempts: 1`, even when policy stops it before any HTTP request. A missing or invalid spec has no attempt. The original gap list and readiness state are retained.

Failed checks include `failure_status_succeeded`, `failure_status_mismatch`, `pending_status_unrecognised`, `scenario_case_failed`, `invoke_not_called`, `prompt_not_bound`, `material_not_bound`, `poll_identity_changed`, `terminal_outcome_mismatch`, `reply_mismatch`, `operation_call_count`, `cleanup_left_resources`, `cleanup_gap_missing`, `unsafe_location` and `verification_budget_exceeded`. A response status of 200 or a transport `blocked` result cannot prove business completion.

Limits are 256 KiB scenario input, 8 declared cases, nesting depth 16, 32 operations, 32 resources, 64 total replies, 32 predicates per operation, 64 dispatched HTTP requests and 64 KiB request/response bodies or literals. The complete fake lifetime has a 30-second deadline with reserved shutdown time; attempt and close share the active deadline. A drafted poll still waits its 5-second interval between polls, so a scenario with k polls spends 5 × (k - 1) seconds of that deadline asleep. A poll that follows `Retry-After` waits before every poll, including the first, for the previous reply's `Retry-After`, or 5 seconds when that reply has none, so give accepted and pending replies `Retry-After: 0`. Earlier transport budgets remain in force. No retries, cleanup or other phase can dispatch to another port or host. The strict policy admits only the assigned HTTP origin before DNS.
