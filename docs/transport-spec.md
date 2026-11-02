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
