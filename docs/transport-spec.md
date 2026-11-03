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

Execute mode sends the benign prompt `ping`. Synchronous delivery makes one target request, with no retries or preliminary HEAD/OPTIONS requests. The agent may use its own model or tools and incur costs. Diagnostics show status, selected rule, response paths, safe top-level keys, and request counts. They omit secret values and returned answer text.

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

`DELETE` defaults to no body. An explicit JSON or text body is also accepted for `DELETE`. The synchronous and single-ID polling behavior described on this page is available in version 2. SSE remains unsupported. Lifecycle operations, request retries, and multiple captured delivery IDs are not implemented in this version.

```sh
argus-probe validate-target --target target-v2.json --offline
argus-probe validate-target --target target-v2.json --execute
argus-probe validate-target --target target-v2.json --execute --endpoint-override http://127.0.0.1:8080
```

Offline validation lists the method, placeholder names, query names, and declaration names. It sends no requests and does not render the body or read environment values. Empty binding lists are omitted. Execute mode reports HTTP status, selected outcome, and submission, poll, and retry counts. It omits response bodies and resolved bindings.

A version 2 endpoint override takes an origin, with an optional trailing slash. It retains the configured paths and query bindings for submission and polling. A path, query, or fragment in the override is invalid. `--sample-response`, `--with-scenario`, and `--scenario-url` support version 1 transports only.

## Map replies and outcomes

JSON paths support the root, fields, and array indexes. Wildcards, filters, and recursive descent are rejected. The first existing answer path wins. Only a missing path tries the next path. A wrong type or an empty value is a mapping error.

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

Cancellation closes the local HTTP client and browser trap. The propagated cancellation carries safe `transport_diagnostics` with `job_detached` and the captured ID; browser cancellation also seals trap evidence. Argus sends no remote cancellation request. The hosted job can continue after local cancellation. SSE delivery remains unsupported.
