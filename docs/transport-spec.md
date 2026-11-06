# Configure an HTTP target

A `custom_http` target can use a `transport` object to describe its request, authentication, response, and result classification. You can map fields and business status codes without writing a target adapter. The same package owns request validation, deadlines, and safe diagnostics.

This example sends `goal` and reads either a nested or a top-level `result`. Replace the endpoint and secret reference with values available on the machine that sends the request.

```json
{
  "kind": "custom_http",
  "transport": {
    "version": 1,
    "request": {
      "method": "POST",
      "url": "https://agent.example/run",
      "headers": {"Accept": "application/json"},
      "body": {"json": {"goal": {"context": "prompt"}}}
    },
    "auth": {
      "kind": "headers",
      "headers": [{"name": "X-Api-Key", "secret": {"source": "file", "path": "/run/secrets/agent-key", "strip_final_newline": true}}]
    },
    "response": {
      "format": "json",
      "text": {"paths": ["$.result.result", "$.result"], "cast": "string_or_json", "empty": "error"},
      "metadata": {}
    },
    "outcome": {
      "kind": "rules",
      "unmatched": "target_error",
      "rules": [
        {"id": "policy", "priority": 100, "http_status": [200], "when": {"path": "$.error.code", "equals": "POLICY_REFUSAL"}, "outcome": "blocked"},
        {"id": "failed", "priority": 50, "http_status": [200], "when": {"path": "$.status", "equals": "FAILED"}, "outcome": "target_error"},
        {"id": "completed", "priority": 10, "http_status": [200], "when": {"path": "$.status", "equals": "COMPLETED"}, "outcome": "succeeded"}
      ]
    },
    "delivery": {"kind": "sync"},
    "timeout": {"total_deadline_s": 300, "connect_s": 10, "read_s": 300, "write_s": 30, "pool_s": 10, "cleanup_grace_s": 2},
    "session": {"mode": "none"},
    "limits": {"response_bytes": 8388608, "event_bytes": 1048576, "max_events": 1024, "max_rules": 32}
  }
}
```

## Check the configuration

```bash
argus-probe validate-target --target target.json --offline
argus-probe validate-target --target target.json --offline --sample-response sample.json
argus-probe validate-target --target target.json --execute
argus-probe validate-target --target target.json --execute --endpoint-override http://127.0.0.1:8080/run
```

Offline checks send no requests and do not resolve secret references. A sample file checks result rules and answer paths without a network connection. New transport files default to an offline check when neither mode is specified. Existing target files retain their single-prompt validation behavior.

Execute mode sends the benign prompt `ping`. Version 1 synchronous delivery makes one target request, with no retries or preliminary HEAD/OPTIONS requests. Version 2 runs configured provision lookups, lifecycle setup, one attempt, and cleanup. When any material binding exists, it supplies `Argus validation sample.` through that channel. Provision may add read-only lookup requests and configured persistent creation requests. The agent may use its own model or tools and incur costs. Diagnostics show status, selected rule, response paths, safe top-level keys, and request counts. They omit secret values and returned answer text.

## Bind request values

Each value has one shape. Use `{"context": "prompt"}` for the current prompt, `{"literal": value}` for JSON data, `{"object": {...}}` for nested field bindings, or `{"array": [...]}` for arrays. `missing: "omit"` on a context value omits a missing optional field. Invalid context names fail before a request. Values are serialized as data and cannot execute templates or scripts.

The available context names are `prompt`, `history`, `conversation_id`, `session_id`, and `run_id`. Browser targets also have `scenario_url`. A custom HTTP target cannot bind `scenario_url`.

## Use version 2

Version 2 lets you describe a SaaS agent's documented HTTP API with one JSON configuration. It supports local `custom_http` runs and `validate-target`. Browser targets and remote clients still support version 1. The client advertises `transport_versions: [1]`. Server API authorization policy is unchanged.

Set `transport.version` to the integer `2`. The parser requires an explicit integer version and rejects unknown versions. The string `"2"` and decimal `2.0` are invalid. Version 1 files remain valid without changes. Changing a file from version 1 to version 2 changes its baseline identity. Collect a new baseline before comparing runs.

Custom HTTP version 2 rejects `scenario_url` context expressions at target construction. This includes optional bindings in `let.run`, `let.attempt`, and every submit or poll request body and query. Nested expressions follow the same rule. Literal contents and JSON field names remain ordinary data.

This example binds an automation ID from a nonsecret environment variable and generates a reference for each attempt.

```json
{
	"kind": "custom_http",
	"transport": {
		"version": 2,
		"let": {
			"run": {
				"automation_id": {"env": "AUTOMATION_ID"},
				"source_name": {"concat": [{"literal": "argus-"}, {"generate": "uuid4"}]}
			},
			"attempt": {"ref": {"generate": "uuid4"}}
		},
		"request": {
			"method": "POST",
			"url": "https://api.vendor-a.example.test/automations/{automation_id}:invoke",
			"query": {"page_size": {"literal": 10}},
			"body": {"json": {
				"goal": {"context": "prompt"},
				"source": {"var": "source_name"},
				"ref": {"var": "ref"}
			}}
		},
		"auth": {"kind": "none"},
		"response": {
			"format": "json",
			"text": {"paths": ["$.result"], "cast": "string_or_json", "empty": "error"},
			"metadata": {}
		},
		"outcome": {
			"kind": "rules",
			"unmatched": "target_error",
			"rules": [{"id": "completed", "priority": 10, "http_status": [200], "when": {"path": "$.status", "equals": "COMPLETED"}, "outcome": "succeeded"}]
		},
		"delivery": {"kind": "sync"},
		"timeout": {"total_deadline_s": 300, "read_s": 300},
		"session": {"mode": "none"},
		"limits": {"response_bytes": 8388608, "event_bytes": 1048576, "max_events": 1024, "max_rules": 32}
	}
}
```

Version 2 preserves the version 1 `literal`, `context`, `object`, and `array` expressions. Each expression has one variant. These additional variants are available.

| Expression | Value |
| --- | --- |
| `{"var": "ref"}` | A declared variable. `missing: "omit"` omits a missing optional value. |
| `{"concat": [{"literal": "item-"}, {"var": "ref"}]}` | Concatenates 2 to 16 strings or integers, up to 8192 UTF-8 bytes. |
| `{"generate": "uuid4"}` | A fresh UUID string. |
| `{"generate": "now_iso8601"}` | A UTC timestamp with millisecond precision and a `Z` suffix. |
| `{"generate": "now_unix_ms"}` | An integer Unix timestamp in milliseconds. |
| `{"base64": {"context": "prompt"}}` | Base64 of a bound string's UTF-8 bytes. |
| `{"env": "AUTOMATION_ID"}` | A nonsecret environment value, up to 1024 UTF-8 bytes. Missing values fail unless `missing: "omit"` is set. |

Use `auth` secret references for credentials. An `env` expression is for nonsecret data and is checked against the execution policy's permitted environment names. Every required reference is checked before submission, including references used only by polling.

`let.run` evaluates in declaration order at the first attempt. Its values and referenced nonsecret environment values remain fixed for that target run, including across probes. `let.attempt` evaluates again for each prompt. An attempt declaration can use run variables and earlier attempt declarations. A run declaration can use earlier run declarations. Forward references and duplicate declarations are invalid. Reuse a generated value through `var` when two fields must receive the same value.

Variable names match `[a-z][a-z0-9_]{0,31}` and cannot contain `key`, `token`, `secret`, `password`, `auth`, `header`, or `cookie`. Context names are reserved. Polling reserves `run_id` for the captured submission ID and its poll URL placeholder.

URL placeholders bind declared variables in path segments. Each segment accepts one placeholder, including forms such as `{automation_id}:invoke`. Values are percent-encoded as individual segments. Placeholders in the origin or URL query are invalid. Use `request.query` for scalar query bindings. The engine URL-encodes those values and omits optional missing entries. A `query` object cannot accompany a URL that already contains `?`. Credential-like query names are rejected.

`DELETE` defaults to no body. An explicit JSON or text body is also accepted for `DELETE`. Version 2 supports synchronous delivery, multiple captured polling IDs, configurable stop triggers, and lifecycle setup and undo operations. SSE and request retries remain unsupported. Provisioning and multipart bodies are available in version 2. HTTP 429 stops the entire version 2 run by default, including cleanup requests.

```sh
argus-probe validate-target --target target-v2.json --offline
argus-probe validate-target --target target-v2.json --execute
argus-probe validate-target --target target-v2.json --execute --endpoint-override http://127.0.0.1:8080
```

Offline validation lists the method, placeholder names, query names, and declaration names. It sends no requests and does not render the body or read environment values. Empty binding lists are omitted. Execute mode reports HTTP status, selected outcome, and submission, poll, and retry counts. When lifecycle steps are configured, it appends `requests.setup=N requests.cleanup=N`. Provision adds `requests.provision=N`. Counts include all requests through run close, including confirmation GETs. Offline provision validation prints the manual checklist without resolving values or sending requests. It omits response bodies and resolved bindings.

A version 2 endpoint override takes an origin, with an optional trailing slash. It retains the configured paths and query bindings for submission, polling, lifecycle steps, undo and confirmation requests, and provision requests. A path, query, or fragment in the override is invalid. `--sample-response`, `--with-scenario`, and `--scenario-url` support version 1 transports only.

## Bind task and material separately

Bind `{"context": "prompt"}` to the user's task and `{"context": "material"}` to the API field that accepts third-party content. A probe can supply `indirect` entries with exactly `task` and `material`, one entry per original prompt. Both strings must be nonempty. `indirect` cannot accompany sessions or `conversation: true`. Original prompts remain unchanged for judging and findings.

Any material expression makes the target declare a material channel. A material reference without `missing: "omit"`, outside a step guarded by `if_present: "material"`, makes material required. A required target skips probes without `indirect` before provision or setup sends any request. Its reasoning says `target requires material; probe has no indirect field`. Optional targets also accept prompt-only probes. Guards skip their entire step and undo. Omitted values propagate through base64 and concat and omit their JSON field, query entry, or multipart part. Nested objects and arrays omit absent members.

`{"base64": {"context": "material"}}` encodes the material's UTF-8 bytes. For APIs that require uploads, use a multipart request body in an attempt step:

```json
{
	"multipart": {
		"file": {
			"filename": {"literal": "sample.txt"},
			"content_type": "text/plain",
			"content": {"context": "material"}
		}
	}
}
```

Multipart accepts one to four parts on POST or PUT. Each part has `filename`, `content_type`, and `content`. Content is a UTF-8 string of at most 1 MiB per part. Media types are `text/plain`, `text/markdown`, `application/json`, and `text/csv`. Filename expressions must produce a nonempty string without quotes, CR, LF, or NUL characters. Argus generates the multipart boundary. A conflicting configured Content-Type is rejected. Multipart is forbidden during cleanup. Material is literal content, so a path-shaped string does not read a local file. Capture a returned full resource name with `expect_prefix` and pass it through `var` when the API requires a remote file reference.

A material target receives separate task and material values. Other targets receive the original prompt. Findings keep that original prompt and add `evidence.indirect.task` and `material_sha256`. Deep mode runs indirect probes statically on material targets. The library includes 34 built-in probes with `indirect` entries, and 33 support the `custom_http` material channel. The SVG upload probe requires an `http-upload` target.

promptfoo's `indirectInjectionVar: X` corresponds to binding the API's X field to `{"context": "material"}` in Argus. The context name is fixed as `material`.

## Find provisioned resources

`lifecycle.provision` runs once per target run, before `lifecycle.run`. Its ordered `find` steps use GET requests and capture exactly one item from a response array. An items capture has `items`, a `where` predicate, and `take`. It can also use `expect_prefix` and `last_segment`. An ambiguous match ends the run. Expectation checks can reject a paginated response so the configured first page cannot silently select an incomplete list.

A find step can provide `given` values for every declared capture. When all supplied values resolve, Argus skips that GET. Values already supplied as final segments bypass network extraction. Optional `env` bindings with `missing: "omit"` allow lookup when the ID is absent. A step's `hint` can explain missing prerequisites, such as building the selected automation.

If the final find matches nothing, optional `create` steps run and then the find sequence runs again. These created resources persist and never enter the undo stack. Without creation, Argus stops with `not_provisioned` and sends no submission or lifecycle setup request. The CLI prints the failed step, its hint, `manual.title` and `manual.steps`, and a checklist derived from the configured selectors. Compound filters get one checklist row for the complete filter. Offline validation prints the same preparation checklist with zero HTTP requests.

Provision lookup IDs and generated values do not enter baseline identity. Only the configuration does. Use unique generated names and avoid simultaneous creation runs that could introduce ambiguous matches.

## Set up and undo version 2 resources

`lifecycle.run` is an ordered list of steps executed once, before the first attempt. `lifecycle.attempt` runs before each submission. Run declarations and captured values persist across probes. Attempt declarations are evaluated again for each attempt.

Each step has a unique `id`, a `request`, and an `expect.http_status` list. Setup requests accept GET, POST, PUT, PATCH, and DELETE. An optional `if_present` names an already visible variable or context value. When that value is absent, Argus skips the step. A step can `capture` response fields into named variables for later steps, submission, or its own undo request.

For example, add this run step to an existing version 2 transport:

```json
{
	"lifecycle": {
		"run": [{
			"id": "source",
			"request": {
				"method": "POST",
				"url": "https://api.vendor-a.example.test/v1/sources",
				"body": {"none": true}
			},
			"expect": {"http_status": [201]},
			"capture": {"source_id": {"path": "$.id"}},
			"undo": {
				"request": {
					"method": "DELETE",
					"url": "https://api.vendor-a.example.test/v1/sources/{source_id}"
				},
				"expect": {"http_status": [204, 404]}
			}
		}]
	}
}
```

A capture may set `expect_prefix` to a value expression. Argus checks that exact, case sensitive prefix before publishing any captures from the response. With `last_segment: true`, it extracts the final slash-delimited segment and requires 1 through 256 characters containing only letters, digits, `.`, `_`, `~`, or `-`. Without segment extraction, it retains the full captured value. A mismatch fails the attempt with `id_prefix_mismatch`. A run setup failure ends the run, while an attempt setup failure affects that attempt.

A step can omit `undo`. Argus reports resources created by such steps as informational leftovers. A successful HTTP status on a mutating lifecycle step retains a redacted creation descriptor even when its response body is rejected or interrupted, or a stop suppresses cleanup. Only safely parsed prefix captures supply full resource names. Persistent provision creation is excluded. An undo requires `request` and `expect.http_status` and accepts only GET or DELETE. Include 404 when an already absent object should count as cleaned. Configure the URL and variables so the request addresses resources this run owns. Argus does not independently verify ownership or add a prefix to resource names. Prefixes and generated names come from the configuration.

An undo can add `confirm: {"request": {"method": "GET", "url": "https://api.vendor-a.example.test/files/{file_id}/metadata"}, "gone_status": [404]}`. Argus sends this GET only after a fully received primary response whose HTTP status is outside `expect.http_status`. An accepted primary status sends no confirmation. A primary network failure or a failed body predicate with an accepted status also sends no confirmation. A configured `gone_status` marks the intent done. Another confirmation status or an unresolved binding leaves it `unconfirmed`. Confirmation shares the cleanup deadline and consumes one extra available cleanup request without taking another intent's reserved slot. With no extra capacity, Argus sends no GET and reports `unconfirmed`. A configured absence response does not independently prove physical deletion.

The upload and deletion behavior in this design follows the coordinator's recorded live API checks. Automated tests use loopback fake services. This implementation does not independently verify a live account.

Argus records each undo intent before sending the corresponding setup request. If the response is lost, an undo that uses previously known values can still execute. An undo that needs an uncaptured response value remains `unbound` for manual cleanup. Attempt undo runs in reverse order before the attempt returns, fails, or propagates cancellation. Run undo runs in reverse order when the target closes, including after an early consumer close. If an unfinished inner undo depends on an outer resource, the outer undo remains `blocked_by_inner`.

### Request and cleanup budgets

`budget.max_requests` limits all provision, setup, submission, and poll requests across the entire run. Omit it for no business request limit. When the next request exceeds the limit, Argus stops the run with `request_budget`; undo requests can still use their separate reserve. `budget.cleanup_reserve` defaults to 100. Each undo intent reserves one request before its setup request can be sent. If no reserve remains, the run stops with `cleanup_reserve` before creating that resource.

Run setup has its own `timeout.total_deadline_s`. Each attempt then receives a fresh business deadline. Attempt cleanup shares one `timeout.cleanup_s` across delivery abort and step undos. Run close has its own cleanup deadline. The default is 60 seconds and the maximum is 300 seconds. Cleanup time does not consume the business deadline. Cleanup failures preserve the primary finding and appear in `evidence.transport.cleanup`. The final [run.json cleanup summary](run-json.md#target-cleanup) lists unresolved cleanup intents and tracked resource names. Unresolved intents make the run incomplete. Leftover names alone leave the run status and exit code unchanged.

### Polling with multiple IDs

Version 2 accepts `delivery.ids` with one to four named selectors. Each selector has a `path`, and each name must appear exactly once in the poll URL path. `delivery.run_id` remains shorthand for `ids: {"run_id": {"path": "$.run_id"}}`. Use either `ids` or `run_id`. Each ID is encoded as one path segment. A missing ID fails only the current attempt with `missing_id` and sends no poll request. If a poll reply includes the same selector path with a changed value, the attempt fails with `poll_identity_changed`. An omitted path retains its prior value. `metadata.run_id` is present only when an ID is named `run_id`.

Lifecycle captures and delivery ID selectors can also use `expect_prefix` and `last_segment`. `expect_prefix` is a value expression that must resolve to a nonempty string matching the beginning of the captured resource name. With `last_segment: true`, Argus extracts the final slash-separated segment. It must contain 1 to 256 characters from `[A-Za-z0-9._~-]`. For example, `{"path": "$.name", "expect_prefix": {"literal": "runs/"}, "last_segment": true}` extracts `job-one` from `runs/job-one`. A prefix mismatch or invalid segment fails the capture. Delivery capture errors affect only the current attempt.

Each `delivery.ids` selector may also declare a `poll` object to check identity at a different path in poll replies. Its required `path` selects the poll ID. Its optional `last_segment` defaults to false, and `expect_prefix` uses the same value expressions as the invoke selector. No other fields are accepted. The `delivery.run_id` shorthand does not accept `poll`. Without `poll`, the existing same-path check and omitted-path behavior remain unchanged.

With `poll`, Argus checks every decoded poll reply before outcome rules. Missing, null, wrong-type, prefix-mismatched, or changed IDs fail the attempt with `poll_identity_changed`. A selector without segment extraction must match the captured invoke ID in both value and type. With `last_segment: true`, `expect_prefix` is required, and the raw poll value must equal the resolved prefix plus the captured invoke ID exactly. For example, `"poll": {"path": "$.name", "last_segment": true, "expect_prefix": {"literal": "runs/"}}` accepts `runs/job-one` for captured ID `job-one`. It rejects `runs/other/job-one` and `runs/job-one/`.

The poll prefix may reference pre-submit variables, context, and permitted environment values. It cannot reference IDs captured from that submission. Required environment values are checked before requests are sent.

Replace `interval_s` with `wait: {"from": "Retry-After", "default_s": 2, "max_s": 30}` to honor the target's requested delay before polling. `Retry-After` accepts seconds or an HTTP date. Missing or invalid values use `default_s`. A delay above `max_s` fails the attempt with `poll_wait_limit` without another poll. If the remaining total deadline cannot cover the delay, the attempt times out without sleeping. HTTP 429 is never retried, even when status stopping is disabled.

`delivery.location` defaults to `"ignore"`. Set it to `"verify"` to check every HTTP 202 response's `Location`. Relative values resolve against the URL of that request. The result must match the rendered poll URL's scheme, origin, and exact path, and cannot contain a query, fragment, or user information. A missing Location fails only the attempt with `location_missing`. An unsafe Location stops the run with `unsafe_location`. Submit responses receive a structural header check before body handling. Exact path verification follows ID extraction once all IDs are available. Poll responses can use the already rendered poll URL for full verification before body handling. Malformed bodies or missing IDs cannot hide a structurally unsafe header, and unavailable IDs never imply a path mismatch. `"follow"` is rejected at validation.

### Aborting abnormal poll delivery

Poll delivery can declare `delivery.abort` to stop a remote run when delivery ends abnormally:

```json
"abort": {
  "request": {
    "method": "POST",
    "url": "https://api.vendor-a.example.test/runs/{run_id}:stop",
    "body": {"none": true}
  },
  "expect": {
    "http_status": [200],
    "when": {"path": "$.state.stopped", "exists": true}
  }
}
```

The method is required and must be POST, DELETE, or GET. GET has no body. Multipart is forbidden. `expect.http_status` is required. `expect.when` is optional and uses the lifecycle predicate format. The abort request must share the submit origin and follows the same endpoint pinning, auth, redaction, and no-redirect rules. Step undo still accepts only DELETE or GET.

Argus arms the abort after every invoke ID is captured and validated. It freezes those IDs, pre-submit bindings, context, and the auth headers resolved for submit. The abort uses its own public headers and body content type. It does not resolve auth again. An explicit matched submit or poll outcome suppresses abort before response mapping, including success, target error, and blocked outcomes.

An armed abort runs once after timeout, poll or wait limits, network, HTTP, parse, response-size, poll identity or mapping errors, unmatched state, request-budget exhaustion, or cancellation. It runs before attempt step undos and shares their cleanup deadline. It reserves one available cleanup request only when cleanup needs the abort, without taking an existing step undo's reserved slot. An empty reserve records `failed` with `failure_reason: "budget"` and sends no abort. There are no retries. Cleanup errors preserve the original attempt result or exception.

An allowed HTTP status and matching optional predicate record `done`. An allowed status with a false predicate records `unconfirmed`. Other responses or cleanup errors record `failed`. A security stop records `skipped_stopped` and prevents further requests. A cancellation during abort cleanup records `interrupted`. Attempts that never arm the abort or match a terminal outcome record `not_needed`. Declaring an abort adds an `aborts` list to the cleanup report. A done abort adds one to `done`. Any status except `done` or `not_needed` adds an open item and makes cleanup incomplete.

Abort state is in memory. Argus does not reserve a slot before submit or retain a recovery record when the submit response is lost. It does not verify abort response IDs, retain step-undo inputs until an abort is confirmed, or abort after a security stop.

### Stop triggers

Version 2 defaults to `budget.stop_on.http_status: [429]`, `alert_names: []`, and `credential_echo: true`, even when `budget` is absent. A matching status stops the run with `stop_on_status`. A configured alert header's presence stops it with `alert`, regardless of casing. Credential echo detection stops it with `credential_echo` when the raw response body contains an exact resolved credential value. Detection checks only the bounded `limits.response_bytes` prefix. A complete match within that prefix trips before a response-size error or another body read, including across chunks. Values crossing or beyond the cap retain the size error and do not cause extra reads.

Disable status stopping with `http_status: []` and credential echo stopping with `credential_echo: false`. Leave `alert_names` empty to disable alert triggers. To disable all three configurable triggers, use:

```json
{"budget": {"stop_on": {"http_status": [], "alert_names": [], "credential_echo": false}}}
```

Location verification remains active when selected. A stop trigger takes priority over request and cleanup budgets. After it trips, Argus sends no further request, including undo requests. Remaining intents become `skipped_stopped`. The local CLI writes an incomplete report with findings already produced, even if there are none, and exits 1. Probes that did not reach a finding receive no invented verdict. The console prints `Target stopped the run: <reason>. No further request was sent, cleanup included.` and any remaining DELETE or GET URLs for manual cleanup. Resolved credential values in these URLs are redacted. Version 1 behavior is unchanged.

### Graceful cancellation

Local runs handle SIGINT and SIGTERM by cancelling the active attempt, waiting for bounded configured delivery abort and undo requests, and exiting with 130 or 143 without writing a report. The console lists remaining cleanup intents for manual cleanup. A second signal can interrupt cleanup; an active abort records `interrupted`. The first signal still determines the exit code and remaining intents stay visible. Signal handlers are restored afterward.

Cleanup is in memory and cannot recover from SIGKILL or a process crash. Removing a setup resource does not necessarily cancel a hosted job. Configure undo requests for the service's documented cleanup behavior.

## Complete version 2 examples

These neutral configurations describe two API shapes without vendor adapter code. Their hosts use reserved example domains. Each complete JSON example also exists as a test fixture.

The automated checks invoke the same Click command as `argus-probe run --local` in process with `CliRunner`. This allows injection of synthetic probes with neutral task and material text and a stub judge. The HTTP requests reach fake services bound to `127.0.0.1`. These checks do not invoke a subprocess or call a live vendor account. The upload and deletion shapes follow the coordinator's recorded live API checks.

### Vendor A threads

The [vendor A fixture](../tests/fixtures/transport_v2/vendor_a_threads.json) creates one source per run. Each material attempt inserts a message, asks a question, polls with thread and run IDs, and deletes the message. Source deletion runs last. A prompt-only probe skips message ingestion and still sends its question. The fixture's budget covers the tested batch of three material probes and one prompt-only probe. A larger batch needs its own request and cleanup budgets.

```json
{
	"kind": "custom_http",
	"transport": {
		"version": 2,
		"request": {
			"method": "POST",
			"url": "https://api.vendor-a.example.test/v1/ask",
			"headers": {"Accept": "application/json"},
			"body": {"json": {"message": {"context": "prompt"}}}
		},
		"auth": {"kind": "bearer", "secret": {"source": "env", "name": "VENDOR_A_API_KEY"}},
		"let": {
			"run": {"source_name": {"concat": [{"literal": "argus-"}, {"generate": "uuid4"}]}},
			"attempt": {"ref": {"concat": [{"literal": "argus-msg-"}, {"generate": "uuid4"}]}}
		},
		"lifecycle": {
			"run": [
				{
					"id": "source",
					"request": {
						"method": "POST",
						"url": "https://api.vendor-a.example.test/v1/sources",
						"headers": {"Accept": "application/json"},
						"body": {
							"json": {
								"name": {"var": "source_name"},
								"displayName": {"literal": "Argus isolated synthetic test"}
							}
						}
					},
					"expect": {"http_status": [201], "when": {"path": "$.id", "exists": true}},
					"capture": {"source_id": {"path": "$.id"}},
					"undo": {
						"request": {"method": "DELETE", "url": "https://api.vendor-a.example.test/v1/sources/{source_id}"},
						"expect": {"http_status": [200, 404]}
					}
				}
			],
			"attempt": [
				{
					"id": "ingest",
					"if_present": "material",
					"request": {
						"method": "POST",
						"url": "https://api.vendor-a.example.test/v1/messages",
						"headers": {"Accept": "application/json"},
						"body": {
							"json": {
								"id": {"var": "ref"},
								"threadId": {"var": "ref"},
								"sourceId": {"var": "source_id"},
								"displayName": {"literal": "Synthetic customer email"},
								"createdAt": {"generate": "now_iso8601"},
								"body": {"context": "material"},
								"sender": {"object": {"id": {"concat": [{"literal": "synthetic-customer-"}, {"var": "ref"}]}}},
								"recipients": {"literal": [{"id": "synthetic-test-company"}]},
								"attachments": {"literal": []},
								"public": {"literal": true}
							}
						}
					},
					"expect": {"http_status": [201], "when": {"path": "$.recordId", "exists": true}},
					"undo": {
						"request": {
							"method": "DELETE",
							"url": "https://api.vendor-a.example.test/v1/messages",
							"query": {"remoteId": {"var": "ref"}, "sourceId": {"var": "source_id"}}
						},
						"expect": {"http_status": [200, 404]}
					}
				}
			]
		},
		"response": {"format": "json", "text": {"paths": ["$.output"], "cast": "string", "empty": "error"}, "metadata": {}},
		"outcome": {
			"kind": "rules",
			"unmatched": "target_error",
			"rules": [
				{
					"id": "failed",
					"priority": 100,
					"http_status": [200],
					"when": {"path": "$.status", "equals": "failed"},
					"outcome": "target_error"
				},
				{
					"id": "stopped",
					"priority": 90,
					"http_status": [200],
					"when": {"path": "$.status", "equals": "stopped"},
					"outcome": "target_error"
				},
				{
					"id": "completed",
					"priority": 10,
					"http_status": [200],
					"when": {"path": "$.status", "equals": "completed"},
					"outcome": "succeeded"
				}
			]
		},
		"delivery": {
			"kind": "poll",
			"ids": {"thread_id": {"path": "$.threadId"}, "run_id": {"path": "$.runId"}},
			"request": {
				"method": "GET",
				"url": "https://api.vendor-a.example.test/v1/ask/{thread_id}/{run_id}",
				"headers": {"Accept": "application/json"},
				"body": {"none": true}
			},
			"location": "verify",
			"wait": {"from": "Retry-After", "default_s": 5, "max_s": 60},
			"pending": {"path": "$.status", "equals": "running"},
			"max_polls": 12,
			"submit_http_status": [200, 202],
			"submit_outcome": {
				"kind": "rules",
				"unmatched": "accepted",
				"rules": [
					{
						"id": "submit_failed",
						"priority": 100,
						"http_status": [200],
						"when": {"path": "$.status", "one_of": ["failed", "stopped"]},
						"outcome": "target_error"
					},
					{
						"id": "submit_completed",
						"priority": 10,
						"http_status": [200],
						"when": {"path": "$.status", "equals": "completed"},
						"outcome": "succeeded"
					}
				]
			}
		},
		"budget": {
			"max_requests": 20,
			"cleanup_reserve": 5,
			"stop_on": {"http_status": [429], "alert_names": ["X-Security-Alert"], "credential_echo": true}
		},
		"timeout": {
			"total_deadline_s": 240,
			"connect_s": 5,
			"read_s": 65,
			"write_s": 15,
			"pool_s": 5,
			"cleanup_grace_s": 2,
			"cleanup_s": 60
		},
		"session": {"mode": "none"},
		"limits": {"response_bytes": 1048576, "event_bytes": 65536, "max_events": 128, "max_rules": 32}
	}
}
```

### Vendor B automation

The [vendor B fixture](../tests/fixtures/transport_v2/vendor_b_automation.json) looks up one organization, workspace, and automation per run. The automation display name comes from `VENDOR_B_AUTOMATION_NAME`. Setting `VENDOR_B_AUTOMATION_ID` supplies the final ID and skips only the automation list request. The earlier organization and workspace lookups still run. Empty automation results print the configured preparation checklist and stop before any upload or invocation.

Each material attempt uploads `invoice.txt` as multipart and invokes the automation with that upload's complete resource name. Prefix checks retain the full file name for the remote reference and extract safe suffixes for DELETE and run polling. Material is required, so a probe without `indirect` is skipped before any request. The fixture's budgets cover four material attempts. Successful cleanup leaves no live uploaded files or reported leftovers.

Primary DELETE accepts 200 or 204. An unexpected status permits one metadata GET when cleanup reserve remains. A configured 404 confirmation completes cleanup. A present response or unavailable reserve leaves the full resource name in `leftover`, keeps the intent `unconfirmed`, and makes the run incomplete with exit 1. Argus sends no DELETE retry. The fake models a first DELETE returning 200 with `{}`, a repeated DELETE returning empty 500, and metadata returning snake_case fields before deletion and 404 afterward.

```json
{
	"kind": "custom_http",
	"transport": {
		"version": 2,
		"lifecycle": {
			"provision": {
				"find": [
					{
						"id": "org",
						"request": {
							"method": "GET",
							"url": "https://app.vendor-b.example.test/api/v1/me/organizations",
							"query": {"page_size": {"literal": 1000}},
							"body": {"none": true}
						},
						"expect": {
							"http_status": [200],
							"when": {
								"any": [
									{"path": "$.next_page_token", "exists": false},
									{"path": "$.next_page_token", "equals": ""}
								]
							}
						},
						"capture": {
							"org_id": {
								"items": "$.user_organizations",
								"where": {"path": "$.name", "exists": true},
								"take": "$.name",
								"last_segment": true,
								"expect_prefix": {"literal": "organizations/"}
							}
						}
					},
					{
						"id": "workspace",
						"request": {
							"method": "GET",
							"url": "https://app.vendor-b.example.test/api/v1/me/organizations/{org_id}/workspaces",
							"query": {"page_size": {"literal": 1000}},
							"body": {"none": true}
						},
						"expect": {
							"http_status": [200],
							"when": {
								"any": [
									{"path": "$.next_page_token", "exists": false},
									{"path": "$.next_page_token", "equals": ""}
								]
							}
						},
						"capture": {
							"ws_id": {
								"items": "$.user_workspaces",
								"where": {"path": "$.name", "exists": true},
								"take": "$.name",
								"last_segment": true,
								"expect_prefix": {
									"concat": [{"literal": "organizations/"}, {"var": "org_id"}, {"literal": "/workspaces/"}]
								}
							}
						}
					},
					{
						"id": "automation",
						"request": {
							"method": "GET",
							"url": "https://app.vendor-b.example.test/api/v1/organizations/{org_id}/workspaces/{ws_id}/automations",
							"query": {"page_size": {"literal": 1000}},
							"body": {"none": true}
						},
						"expect": {
							"http_status": [200],
							"when": {
								"any": [
									{"path": "$.next_page_token", "exists": false},
									{"path": "$.next_page_token", "equals": ""}
								]
							}
						},
						"capture": {
							"automation_id": {
								"items": "$.automations",
								"where": {
									"path": "$.display_name",
									"equals": {"env": "VENDOR_B_AUTOMATION_NAME", "missing": "omit"}
								},
								"take": "$.name",
								"last_segment": true,
								"expect_prefix": {
									"concat": [
										{"literal": "organizations/"},
										{"var": "org_id"},
										{"literal": "/workspaces/"},
										{"var": "ws_id"},
										{"literal": "/automations/"}
									]
								}
							}
						},
						"given": {"automation_id": {"env": "VENDOR_B_AUTOMATION_ID", "missing": "omit"}},
						"hint": "The automations list omits drafts that were never built. Build the automation once, or set VENDOR_B_AUTOMATION_ID from its URL."
					}
				],
				"manual": {
					"title": "Prepare the automation that Argus tests",
					"steps": [
						"Sign in with the account whose personal access token is in VENDOR_B_PAT.",
						"Create an automation in the workspace under test and set VENDOR_B_AUTOMATION_NAME to its display name.",
						"Give it a file input named invoice_file and a text input named user_question, and have it answer the question from the file.",
						"Build the automation at least once.",
						"Or set VENDOR_B_AUTOMATION_ID to the ID in the automation URL to skip its list lookup.",
						"Leave it in the draft stage. Argus invokes AUTOMATION_STAGE_DRAFT.",
						"Run argus-probe validate-target --target vendor_b_automation.json --execute."
					]
				}
			},
			"attempt": [
				{
					"id": "upload",
					"request": {
						"method": "POST",
						"url": "https://app.vendor-b.example.test/api/v1/organizations/{org_id}/workspaces/{ws_id}/files:upload",
						"headers": {"Accept": "application/json"},
						"body": {
							"multipart": {
								"file": {
									"filename": {"literal": "invoice.txt"},
									"content_type": "text/plain",
									"content": {"context": "material"}
								}
							}
						}
					},
					"expect": {"http_status": [201], "when": {"path": "$.metadata.name", "exists": true}},
					"capture": {
						"file_name": {
							"path": "$.metadata.name",
							"expect_prefix": {
								"concat": [
									{"literal": "organizations/"},
									{"var": "org_id"},
									{"literal": "/workspaces/"},
									{"var": "ws_id"},
									{"literal": "/files/"}
								]
							}
						},
						"file_id": {
							"path": "$.metadata.name",
							"expect_prefix": {
								"concat": [
									{"literal": "organizations/"},
									{"var": "org_id"},
									{"literal": "/workspaces/"},
									{"var": "ws_id"},
									{"literal": "/files/"}
								]
							},
							"last_segment": true
						}
					},
					"undo": {
						"request": {
							"method": "DELETE",
							"url": "https://app.vendor-b.example.test/api/v1/organizations/{org_id}/workspaces/{ws_id}/files/{file_id}"
						},
						"expect": {"http_status": [200, 204]},
						"confirm": {
							"request": {
								"method": "GET",
								"url": "https://app.vendor-b.example.test/api/v1/organizations/{org_id}/workspaces/{ws_id}/files/{file_id}/metadata"
							},
							"gone_status": [404]
						}
					}
				}
			]
		},
		"request": {
			"method": "POST",
			"url": "https://app.vendor-b.example.test/api/v1/organizations/{org_id}/workspaces/{ws_id}/automations/{automation_id}:invoke",
			"headers": {"Accept": "application/json"},
			"body": {
				"json": {
					"stage": {"literal": "AUTOMATION_STAGE_DRAFT"},
					"inputs": {
						"object": {
							"invoice_file": {"object": {"file": {"object": {"remote": {"var": "file_name"}}}}},
							"user_question": {"object": {"text": {"context": "prompt"}}}
						}
					}
				}
			}
		},
		"auth": {"kind": "bearer", "secret": {"source": "env", "name": "VENDOR_B_PAT"}},
		"response": {
			"format": "json",
			"text": {"paths": ["$.state.completed.outputs"], "cast": "string_or_json", "empty": "error"},
			"metadata": {}
		},
		"outcome": {
			"kind": "rules",
			"unmatched": "target_error",
			"rules": [
				{
					"id": "failed",
					"priority": 100,
					"http_status": [200],
					"when": {"path": "$.state.failed", "exists": true},
					"outcome": "target_error"
				},
				{
					"id": "awaiting_guidance",
					"priority": 90,
					"http_status": [200],
					"when": {"path": "$.state.awaiting_guidance", "exists": true},
					"outcome": "target_error"
				},
				{
					"id": "stopped",
					"priority": 80,
					"http_status": [200],
					"when": {"path": "$.state.stopped", "exists": true},
					"outcome": "target_error"
				},
				{
					"id": "stopping",
					"priority": 70,
					"http_status": [200],
					"when": {"path": "$.state.stopping", "exists": true},
					"outcome": "target_error"
				},
				{
					"id": "completed",
					"priority": 10,
					"http_status": [200],
					"when": {"path": "$.state.completed", "exists": true},
					"outcome": "succeeded"
				}
			]
		},
		"delivery": {
			"kind": "poll",
			"request": {
				"method": "GET",
				"url": "https://app.vendor-b.example.test/api/v1/organizations/{org_id}/workspaces/{ws_id}/automations/{automation_id}/runs/{run_id}",
				"body": {"none": true}
			},
			"pending": {"any": [{"path": "$.state.pending", "exists": true}, {"path": "$.state.executing", "exists": true}]},
			"interval_s": 1,
			"max_polls": 4,
			"submit_http_status": [200],
			"submit_outcome": {"kind": "rules", "unmatched": "accepted", "rules": []},
			"ids": {
				"run_id": {
					"path": "$.run_id",
					"last_segment": true,
					"expect_prefix": {
						"concat": [
							{"literal": "organizations/"},
							{"var": "org_id"},
							{"literal": "/workspaces/"},
							{"var": "ws_id"},
							{"literal": "/automations/"},
							{"var": "automation_id"},
							{"literal": "/runs/"}
						]
					}
				}
			}
		},
		"budget": {
			"max_requests": 23,
			"cleanup_reserve": 4,
			"stop_on": {"http_status": [429], "alert_names": [], "credential_echo": true}
		},
		"timeout": {
			"total_deadline_s": 240,
			"connect_s": 5,
			"read_s": 65,
			"write_s": 15,
			"pool_s": 5,
			"cleanup_grace_s": 2,
			"cleanup_s": 60
		},
		"session": {"mode": "none"},
		"limits": {"response_bytes": 1048576, "event_bytes": 65536, "max_events": 128, "max_rules": 32}
	}
}
```

## Map replies and outcomes

JSON paths support the root, fields, and array indexes, written as `$.name`, `$[0]` or `$['name']`. Use the bracket form for a field name that the dot form cannot express, such as `job state` or the reserved word `where`. A bracket name cannot be empty or contain a quote, a backslash or a line break. A quote would end the name, and the path evaluator reads a backslash as an escape, so `$['a\b']` would read the field `ab` instead. Wildcards, filters, and recursive descent are rejected. The first existing answer path wins. Only a missing path tries the next path. A wrong type or an empty value is a mapping error.

Rule IDs and priorities must be unique. The highest matching priority wins. A refusal or failed business status is classified before answer extraction. An unknown status is an error. Explicit refusal rules can allow HTTP 400 or 403. Authentication, configuration, rate-limit, and server errors cannot be changed into a success by a body rule.

A mapped refusal produces `blocked_by_target`. If an evidence-backed probe never reached its scenario, it remains untested and contributes nothing to the tested denominator. An API refusal does not prove that the scenario was defended. Ordinary HTTP failures and generic target refusal exceptions retain the existing interaction requirement.

Optional response metadata selects `session_id`, `run_id`, `run_log`, and provider `latency_ms`. Run logs use the existing event model. Invalid logs produce a mapping error. Provider latency does not reset or replace the operation deadline.

## Use sessions and secrets

`session.mode: "none"` declares no conversation support. `client_generated` supports client-provided history and conversation IDs. `server_returned` requires `id_path`; bind the later request to `session_id` with `missing: "omit"`. Each new probe resets session state.

Authentication takes an environment variable name or a file path, never a literal secret. For an environment reference use `{"source": "env", "name": "AGENT_API_KEY"}`. File references reject symlinks, nonregular files, empty contents, invalid encoding, and contents larger than 64 KiB. The optional newline rule removes at most one final newline.

Local execution permits only the endpoint origins configured in that transport and resolves references on the local machine. Server execution denies private target addresses and secret references by default. An operator must configure authorized origins, environment names, and file roots for a remote executor. References are preserved through configuration loading and are not expanded into messages.

Redirects are disabled. Header names cannot override HTTP framing, authentication headers cannot conflict with public headers, and values cannot contain line breaks. Response reads have a byte limit and share one operation deadline. New requests require identity content encoding and reject compressed responses before decompression. Streaming delivery is reserved for a later version and currently reports unsupported delivery.

## Migrate older target files

Old `request_url`, Jinja request template, header, JSONPath, and timeout fields remain accepted through a deprecated input boundary. They use the shared request engine. Their per-request timeout and response extraction behavior are preserved. Do not put old fields and `transport` in the same target object.

An unchanged old file retains its baseline identity. An offline legacy check prints its current identity and warns that migration changes identity. Simple templates can also produce a candidate new identity. Complex templates require manual migration. A new-format target needs a newly collected baseline; comparisons across target identities remain rejected. Baseline collection is a separate target operation and needs the operator's approval.


## Browser agents

A `browser_use` target accepts the same `transport` object. Replace the legacy `agent_url` and `timeout_s` fields when migrating. Bind the current page with `{"context": "scenario_url"}` and the user's instruction with `{"context": "prompt"}`. For an endpoint that calls the instruction `goal`, use this request body:

```json
{"json": {"url": {"context": "scenario_url"}, "goal": {"context": "prompt"}}}
```

Each probe starts its actual scenario page before rendering the request. Success, mapped refusal, target error, and timeout return a typed transport result together with the page URL and recorded page and sink requests. Cleanup has a bounded grace period. Configured authentication values are masked before the client sends this evidence. A successful answer without the interaction required by a probe remains an error.

`timeout.total_deadline_s` controls the whole operation. The bridge allows the configured `cleanup_grace_s` and delivery overhead after that deadline. A legacy browser target keeps its 60-second default request timeout.

A remote client must advertise `transport_versions: [1]` on the same connection that executes the probe. Older clients are rejected before dispatch. Remote operators authorize exact endpoint origins, environment names, and file roots in the client configuration; absent authorization denies secret access. See [client setup](../client_agent/README.md).

Offline browser validation renders a placeholder scenario URL and starts no server. For execution, provide `--with-scenario` to serve a neutral page, or `--scenario-url` to supply an existing neutral page. These options require `--execute`. Validation never runs a phishing scenario or a complete probe suite.

```sh
argus-probe validate-target --target browser.json --offline
argus-probe validate-target --target browser.json --execute --with-scenario
```

## Poll asynchronous jobs

Use `delivery.kind: "poll"` when submission returns a job ID. The following `delivery` object replaces the synchronous delivery object in the example above. Its GET origin must match the submission origin. Keep the top-level response selectors and outcome rules for terminal GET replies.

```json
{
  "kind": "poll",
  "run_id": {"path": "$.run_id"},
  "request": {
    "method": "GET",
    "url": "https://agent.example.invalid/runs/{run_id}",
    "body": {"none": true}
  },
  "pending": {"path": "$.status", "one_of": ["PENDING", "RUNNING"]},
  "interval_s": 2,
  "max_polls": 100,
  "submit_http_status": [200, 202],
  "submit_outcome": {
    "kind": "rules",
    "unmatched": "accepted",
    "rules": [
      {"id": "submit_refusal", "priority": 100, "http_status": [200, 202], "when": {"path": "$.error.code", "equals": "POLICY_REFUSAL"}, "outcome": "blocked"},
      {"id": "submit_failed", "priority": 50, "http_status": [200, 202], "when": {"path": "$.status", "equals": "FAILED"}, "outcome": "target_error"},
      {"id": "submit_completed", "priority": 10, "http_status": [200, 202], "when": {"path": "$.status", "equals": "COMPLETED"}, "outcome": "succeeded"}
    ]
  }
}
```

Submission happens once. A mapped refusal or failure stops before ID extraction. An explicit submission success rule returns a valid answer directly, including on HTTP 202. Otherwise an accepted submission needs one nonempty string or integer ID. The engine encodes that ID as one path segment and sends an immediate GET. It checks explicit terminal rules before the pending predicate and waits only for configured pending states. Unknown states, HTTP failures, and the exact poll limit produce errors. Requests are never retried or resubmitted.

The same resolved authentication is used for every request. Each request rechecks its endpoint address and uses only the remaining total deadline. The deadline includes submission, sleeps, and all response reads. Poll replies that omit their ID retain the submission ID; a new probe resets it.

`validate-target --execute` reports one submission and the actual GET count, at most `max_polls` and never more than 100. Offline validation makes no requests. An endpoint override changes the origin for both submission and polling while retaining the configured poll path.

Cancellation closes the local HTTP client and browser trap. The propagated cancellation carries safe `transport_diagnostics` with `job_detached` and the captured ID; browser cancellation also seals trap evidence. Version 1 sends no remote cancellation request. Version 2 runs configured GET or DELETE undo requests during graceful cancellation unless a stop trigger already suppressed all requests. A hosted job can continue unless those requests stop it. SSE delivery remains unsupported.
