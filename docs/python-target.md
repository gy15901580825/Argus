# Test an agent through a Python function

A `python` target calls code you trust on the local machine. Use it to connect an agent and return its observed actions to Argus without adding a target class. Run it with `argus-probe run --local`; the server rejects Python targets.

## Configure the entry and hooks

Save this configuration as `target.json` beside `agent.py`:

```json
{
  "kind": "python",
  "entry": "agent.py:call",
  "cleanup": "agent.py:cleanup",
  "close": "agent.py:close",
  "timeout_s": 300
}
```

Each entry accepts `module:function` or `path/to/file.py:function`. Relative file paths are resolved against the target configuration's directory. `cleanup` and `close` are optional. Functions are loaded lazily and cached. Entry and hook functions from the same file share one module instance per target. Imported modules follow Python's normal import cache.

The signatures are:

```python
def call(prompt: str, material: str | None, context: dict) -> dict: ...
def cleanup(context: dict) -> dict | None: ...
def close(context: dict) -> None: ...
```

All three functions may instead be `async def`. Synchronous functions run in a worker thread. `context` contains `history` (role/content dictionaries), `conversation_id`, and `probe_id`. Hooks receive a copy of the most recent context. `material` carries scenario material when configured; it is otherwise `None`.

For example, this agent performs no actions and reports the tool ledger it actually observed:

```python
def call(prompt, material, context):
    return {
        "output": "No action taken.",
        "evidence": {"tool_calls": [], "interaction_count": 1},
    }

def cleanup(context):
    return {
        "complete": True,
        "done": 0,
        "open": [],
        "stop_reason": None,
        "leftover": [],
    }

def close(context):
    pass
```

Replace the body of `call` with your agent invocation and collect evidence from its actual execution. An empty ledger asserts that observation succeeded and found no actions. Do not replace unavailable observations with empty lists.

## Return output and evidence

The result dictionary accepts only `output`, `error`, `run_log`, and `evidence`. `output` must be a string. Returning `error` produces a transport error without exposing its value. `run_log` accepts an event list or an object containing `events` and `is_dry_run`, as described in [integration scenarios](integration-scenarios.md). Evidence does not populate run logs automatically.

Evidence vocabulary version 1 accepts these root keys. The version identifies the implementation contract; do not add a `version` key to the evidence dictionary.

| Family | Keys |
|---|---|
| Payments | `authorizations`, `expected_payee` |
| Tools | `tool_calls`, `shadow_tool_names`, `canary`, `attacker_addresses`, `canaries` |
| Traps | `canary_hits`, `trap_requests`, `hosted` |
| Protocol checks | `server_info`, `foreign_origin_initialized`, `cors_allow_origin`, `cors_allows_foreign_origin`, `unauthenticated_initialized`, `tools`, `server_version` |
| Agent actions | `elicitations`, `memory_writes`, `approvals`, `executions`, `protected_writes`, `resource_hashes`, `stop_notice`, `report` |
| Contact evidence | `interaction_count`, `interaction_count_by_session` |

Only dictionaries, lists, strings, integers, finite floats, booleans, and `None` are accepted. Dictionary keys must be strings. Container subclasses and tuples are rejected. Evidence must fit within 262,144 bytes of compact UTF-8 JSON, including punctuation and keys. The root dictionary has depth 0; nested containers through depth 16 are accepted. Cycles are rejected; repeated references without a cycle are allowed within the work budget.

Each snapshot validation visits at most 65,536 nodes, including dictionary keys and every occurrence of a shared value. It counts compact JSON bytes during traversal and stops before serialization if either budget is exceeded. String scans share the byte budget. This fixed work budget bounds validation separately from the entry invocation's `timeout_s`. The same size and work limits apply to the accumulated probe ledger. Argus stores a detached JSON snapshot and returns copies to callers.

When supplied, `interaction_count` must be a nonnegative integer, not a boolean, and `interaction_count_by_session` must be a dictionary. These types are checked even for text-only assertions. A missing or zero count still follows the probe's normal contact requirement. The per-session dictionary's values are not validated as session records.

Mapping errors identify the boundary violation without including evidence values:

- `evidence_not_dict`, `evidence_unknown_keys`, `evidence_key_type`, `evidence_value_type`
- `evidence_nonfinite_number`, `evidence_encoding`, `evidence_too_large`
- `evidence_depth`, `evidence_cycle`, `evidence_work_limit`
- `evidence_conflict` when calls disagree about a scalar or object

Evidence is cleared at probe start. Each call returns the observations from that call. Within a probe, Argus concatenates list-valued root keys in call order; scalar and object values must agree across calls. For example, a forbidden tool call on the first turn remains visible when later turns return `tool_calls: []`. A conflict gives `evidence_conflict` and contributes no evidence. A call that fails to load, times out, raises, or returns invalid data contributes no evidence; earlier observations remain available. Evidence is assigned only after the complete result and merged ledger validate. Single-call probes follow the same contract. A new probe starts with no previous observations.

Run-log state is cleared at probe start and before every call. Evidence does not accumulate run logs.

## Supply the observations an assertion needs

Python targets use the existing assertion observation validator with local declarations. A missing required field, an incorrect field type, or a malformed required record produces `error`. It cannot become a clean result merely because a count is zero or a denial/stop branch is inactive. An observed `[]` is valid. Text-only assertions need no action ledger; normal contact requirements still apply.

Trap request records require string `method`, `path`, `query`, and `body` fields and boolean `complete`. Hosted trap evidence also requires a string-valued `markers` dictionary and a `rounds` list. Each round needs boolean `complete` and `unreadable`, and nonnegative integer `page_loads`, `prefetch_count`, and `late_count` values. Optional `seal_revision`, `dropped_events`, and `late_marker_hits` values must also be nonnegative integers. Booleans do not count as integers. Hosted requests need a `marker_hits` list whose records contain string `marker_id` and `location` fields. Local trap requests do not need marker-hit metadata.

The table below gives common required records. The complete per-assertion declarations are in [`_CHECK_DECLARATIONS` and the nested declarations in python_evidence.py](https://github.com/gy15901580825/Argus/blob/main/argus/targets/python_evidence.py). For example, `mcp_rejects_foreign_origin` requires both CORS fields even when `foreign_origin_initialized` is false, and `report_matches_record` requires `arguments: dict` on every tool call and string `tool`, `target`, and `outcome` on each report action.

| Assertion or ledger | Required fields |
|---|---|
| `no_call_to_tool`, `max_tool_calls` | Every `tool_calls` record has `tool: str` |
| Tool argument checks | Each tool record also has `arguments: dict`; canaries and attacker addresses contain strings |
| `approval_before_action` | Every execution has `tool: str`, `linked_decision: str` |
| `no_action_after_denial` | Approvals have `approval_id`, `decision`, `action` strings and integer `seq`; executions have `tool: str`, integer `seq`; optional `approval_id` is a string or `None` |
| `no_state_change_after_stop` | `stop_notice` is `None` or a dictionary with integer `seq`; executions have `tool: str`, integer `seq`, `state_changing: bool`; a record with `effected: false` (the change did not take effect) does not fail it |
| `no_canary_in_mcp_requests` | Optional `canary_hits[].rpc_methods` is a list of strings |
| Payments | Authorizations have `amount: str` or integer, `asset: str`, `payee: str` |

Booleans do not count as integer amounts or sequence numbers. These checks establish the required observation shapes. If a supported assertion still raises `TypeError`, `KeyError`, or `ValueError` while reading evidence, that assertion returns `error` with `evidence_assertion_error`, its name, and the exception class. Other probes can continue. Existing assertion logic determines whether the observed actions violate the probe; Argus cannot authenticate a plugin's claimed observations.

Version 1 supports the built-in general tool, payment, trap, protocol, agent-action, response, and prompt assertions. The specialized `a2a_server` assertion envelope is deferred and gives `evidence_unsupported_assertion`. So are `no_attacker_call_after_description_change`, which reads `description_change_seq`, and `no_mcp_beacon_hit`, which reads `beacon_hits`; version 1 evidence carries neither key. Arbitrary assertion-plugin vocabularies, phased execution, session execution, paired protocol execution, and automatic run-log mapping are also deferred. Accepting `interaction_count_by_session` does not provide a session driver.

## Finalize the target

Argus calls `cleanup` before `close`. Cleanup returns the existing cleanup report shape (`complete`, `done`, `open`, `stop_reason`, `leftover`, and optional `aborts`) or `None`. An invalid report or failed cleanup leaves cleanup state unknown. A valid report attached to an entry's `RunStopped` is retained when no newer cleanup report is supplied. `close` must return `None` and runs even when cleanup fails.

Finalization runs once per target. Repeated or concurrent close calls await the same result, including cached errors. Cancelling a caller does not cancel finalization. Report reads return copies and never invoke a hook. With a configured cleanup hook, `cleanup_report()` raises `CleanupStateUnknown` before `aclose()` and while finalization is pending. Without a cleanup hook or an attached report, it returns `None`. `validate-target --execute` reports an error when final cleanup has open records or leftovers. Calls after finalization starts are rejected.

An entry's `RunStopped` remains the primary stop reason if a cleanup or close hook also stops. When no entry stop exists, a hook's `RunStopped` is preserved. `SystemExit` and `KeyboardInterrupt` are interpreter control exceptions and are outside this recovery contract; plugin functions must not raise them. Ordinary hook failures expose the exception class rather than its message; a valid cleanup report survives a later close failure. Each hook's resolution and invocation share its own `timeout_s` deadline. The entry's invocation uses `timeout_s`; entry loading precedes that deadline. A timeout cannot terminate a synchronous worker thread, so synchronous code must provide its own bounded operations and avoid late side effects.
