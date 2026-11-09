# Write a target plugin

A target plugin owns how Argus talks to a product. It sends tasks, waits for
results, reads evidence and releases resources. Install it alongside Argus.
You do not need to edit the engine to register a new kind.

Use Python 3.11 or later. This guide describes the current target contract.
The [CLI guide](cli.md#installed-target-plugins) explains the commands that
use it.

## Register a kind

An entry point in the `argus.targets` group loads a `(SpecClass, TargetClass)`
pair. Its name is the value of `kind` in the target JSON. The spec constructor
receives the fields in that JSON. The target constructor receives the spec.

This example is the generic adapter used by the registry acceptance tests.
It records a send count in a local file. Its `token` is a filename, not a
credential. It makes no network requests.

Create a new directory. Save the package definition below as `pyproject.toml`.
The docs test installs this package and runs every Python fence.

<!-- example: pyproject.toml -->
```toml
[build-system]
requires = ["setuptools>=68", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "generic-registry-fixture"
version = "0.0.0"
requires-python = ">=3.11"

[project.entry-points."argus.targets"]
registry_fixture = "generic_plugin:adapter"

[tool.setuptools.packages.find]
include = ["generic_plugin*"]
```

Save the adapter as `generic_plugin/__init__.py`.

<!-- example: generic_plugin/__init__.py -->
```python
from dataclasses import dataclass, field
from pathlib import Path

from argus.targets import Target


@dataclass(frozen=True)
class GenericSpec:
    token: str
    kind: str = "registry_fixture"
    transport: str = "plugin-owned"
    reply: str = "Observed a neutral response."
    derived: str = field(init=False)
    labels: list[str] = field(default_factory=list)

    def __post_init__(self):
        object.__setattr__(self, "derived", "computed")


class GenericTarget(Target):
    compatible_classes = frozenset({"registry_fixture", "mcp_server"})

    def __init__(self, spec):
        self.spec = spec
        self.compatible_classes = frozenset({"registry_fixture"})
        self.sent = 0

    async def send_prompt(self, prompt, history=(), *, material=None):
        self.sent += 1
        Path(self.spec.token).write_text(str(self.sent))
        return self.spec.reply, 0.0

    async def collect_evidence(self):
        return {"interaction_count": self.sent, "canary": "GENERIC_CANARY"}


adapter = (GenericSpec, GenericTarget)
```

Install the directory with `python -m pip install .`. This next file runs after
installation. It checks discovery, builds the target and reads its evidence.
Run it with `python check_plugin.py`.

<!-- example: check_plugin.py -->
```python
import asyncio
from pathlib import Path
from tempfile import TemporaryDirectory

from argus.targets import build_target, kinds


async def check():
    assert kinds()["registry_fixture"].required == frozenset({"token"})
    with TemporaryDirectory() as scratch:
        count = Path(scratch) / "count"
        target = build_target({"kind": "registry_fixture", "token": str(count)})
        text, latency = await target.send_prompt("Hello")
        assert text == "Observed a neutral response."
        assert latency >= 0
        assert count.read_text() == "1"
        assert (await target.collect_evidence())["interaction_count"] == 1
        await target.aclose()


if __name__ == "__main__":
    asyncio.run(check())
```

For CLI use, write `{"kind": "registry_fixture", "token": "count"}` to
`target.json`. Run `argus-probe validate-target --offline --target target.json`
to check the required field without sending a task. `argus-probe init --kind
registry_fixture --no-workflow` asks for `token`.

The acceptance fixture also supplies a probe pack. This guide's package only
registers the target. To use `run --local` or `list-probes --target`, provide
probes whose `target_class` matches the target instance. See the
[target-spec cookbook](onboarding/target-spec-cookbook.md).

### Optional kind metadata

Set `TargetClass.kind_info` to a frozen `argus.targets.KindInfo` record when
required fields have rules beyond the spec constructor.

| Field | Meaning |
| --- | --- |
| `kind` | Must match the entry-point name. |
| `required` | A `frozenset` of field names that must be present. |
| `description` | Text shown when choosing a kind. |
| `chat` | Enables chat validation and chat suggestions in init. Defaults to `False`. |
| `no_text_hint` | A hint added when a reply has no text. |
| `sandbox_reason` | Requires exactly `sandbox: true`; init inserts it. |
| `init_questions` | A tuple of `(field, question, default)` tuples. Defaults may be strings or `None`. |
| `validate` | An offline callable taking the spec dict. Raise `ValueError` for invalid values. |

The required check tests presence, not the meaning of a value. Use `validate`
for semantic rules. Plugin fields receive environment-variable expansion,
including a field called `transport`. That field belongs to your plugin.

Without `kind_info`, required fields come from non-defaulted dataclass init
fields, including `InitVar`. Argus excludes `kind` and fields with `init=False`.
A default or default factory makes a field optional. Other spec types get no
inferred required fields. Init asks generic questions for inferred fields.

Built-ins win name collisions. Duplicate entry points are sorted by name and
value; the first successfully loaded plugin wins. Broken entry points and
invalid kind metadata are skipped with warnings. Discovery is cached.
Restart the process after installing or removing a plugin.

### Probe compatibility

Declare a precise, non-empty `compatible_classes` set. Selection uses the
target instance. The fixture deliberately narrows its instance set to
`registry_fixture`, so `mcp_server` probes do not run against that instance.
New class names used by probe packs must also appear on the target class,
because the probe loader reads class metadata to validate them.

Set `supports_history = True` only if you preserve conversation history.
Set `material_channel = True` only if you accept separate third-party material.
These capabilities default to `False`. The runner skips probes that require
unsupported capabilities. `chat` in `KindInfo` does not set these flags.
The `--target-class` choices and `mcp-trap` admission list have their own scope.

## Target methods

Only `send_prompt` is abstract. Implement the other methods when the product
needs them. Calls to `send_prompt` are sequential within a run.

| Method | Contract |
| --- | --- |
| `send_prompt(prompt, history=(), *, material=None)` | Async. Return `(response_text, latency_ms)` as a string and a number. History is a tuple of `Turn` records with `role` and `content`. An empty history starts a fresh conversation. |
| `begin_probe(probe)` | Async. Reset probe evidence and stage any probe-specific state. Defaults to a no-op. |
| `collect_evidence()` | Async. Return a dict of observations for the current probe. Defaults to `{}`. |
| `aclose()` | Async. Release resources after the run, including a stopped run. Finalization calls it once. Defaults to a no-op. |
| `cleanup_report()` | Sync, optional. After closing, return a cleanup dict or `None`. The base class does not define this method. |
| `last_run_log()` | Sync. Return the latest `TargetRunLog`, or `None`. Defaults to `None`. |

The small registry fixture has a run-wide send counter. A product adapter must
reset observations at `begin_probe` so one probe cannot borrow another's
contact or side effects. Preserve observations across turns of the same probe.

`last_run_log` supplies a run trace for scenario reporting. It does not replace
`collect_evidence` for ordinary probe assertions. Return explicit observations
for the checks you want to run.

### Stop a run

Raise `argus.targets.RunStopped(reason, detail="")` when the run must stop,
for example when a quota is exhausted. The runner stops dispatching business
requests and finalizes the target. `TargetRunStopped` is an alias of the same
exception class.

The exception exposes `reason`, `detail`, `checklist`, `cleanup`,
`target_cleanup` and `transport_diagnostics`. `set_cleanup(report)` attaches a
report under the cleanup attributes and transport diagnostics. Preserve the
original reason when cleanup also fails. An invalid report produces the
`cleanup state unknown` diagnostic.

### Cleanup report

Return `None` if there is nothing to clean. Otherwise return a dict with these
fields. Extra fields are rejected.

| Field | Type |
| --- | --- |
| `complete` | `bool` |
| `done` | `int` |
| `open` | List of cleanup or abort records still open. |
| `stop_reason` | `str` or `None` |
| `leftover` | List of strings naming leftovers. |
| `aborts` | Optional list of abort records. |

A cleanup record has `scope` (`run` or `attempt`), `step` (string), `status`,
`method` (string), `url` (string or `None`) and `http_status` (integer or `None`).
Cleanup statuses are `pending`, `done`, `failed`, `skipped_stopped`,
`blocked_by_inner`, `unbound` and `unconfirmed`.

An abort record has the same fields, but `scope` must be `attempt`. It also has
`attempt` (integer) and optional `failure_reason` (string). Abort statuses are
`not_needed`, `armed`, `done`, `failed`, `unconfirmed`, `skipped_stopped` and
`interrupted`.

`complete` is true only when `open` is empty and every record in `aborts`, if
present, has status `done` or `not_needed`. Argus validates and caches the
report during finalization. Invalid reports cannot claim complete cleanup.

## Evidence and observation types

Map product records to the existing evidence keys. A missing or malformed
required observation gives an assertion error. An observed empty list is valid
for a list check. Emit `[]` only after observing that no matching events occurred.

The Python target uses evidence allowlist version 1. Its full key set and the
types declared by enabled checks are below. Being allowed does not make a key
required for every probe. Requirements depend on the assertion and its value.

| Evidence keys | Declared observation types |
| --- | --- |
| `tool_calls` | List of dicts. `tool` is a string. Argument checks also require `arguments` as a dict. Description-change checks require `after_description_change` as a bool. |
| `executions` | List of dicts. Required fields depend on the assertion; see below. |
| `approvals` | List of dicts with string `approval_id`, `decision`, `action`; denial checks need integer `seq`, and matching checks need dict `params`. |
| `protected_writes` | List of dicts with string `resource`. |
| `memory_writes` | List of dicts with string `note`. |
| `canaries` | Dict whose values are strings for world canary checks. |
| `elicitations` | List of dicts with string `tool` and JSON-valued `content`. |
| `stop_notice` | Dict with integer `seq`, or an observed `None`. |
| `report` | Dict containing an `actions` list of dicts with string `tool`, `target`, `outcome`. |
| `authorizations` | List of dicts with `amount` as string or integer, and string `asset` and `payee`. |
| `expected_payee`, `canary` | Strings. |
| `shadow_tool_names`, `attacker_addresses` | Lists of strings. |
| `trap_requests` | List of dicts with string `method`, `path`, `query`, `body` and bool `complete`. Hosted trap checks also require `marker_hits`. |
| `canary_hits` | List of dicts; optional `rpc_methods` is a list of strings. |
| `hosted` | Optional dict for trap checks; requires `markers` (dict of strings) and `rounds` (list of records). |
| `server_info` | Dict with string `name` and `version`. |
| `foreign_origin_initialized`, `cors_allows_foreign_origin`, `unauthenticated_initialized` | Bools. |
| `cors_allow_origin` | List of strings. |
| `tools` | List of dicts with string `name` and `description`. |
| `server_version` | String. |
| `resource_hashes` | Dict with dict `before` and `after`. |
| `interaction_count` | Non-negative integer; optional context observation. |
| `interaction_count_by_session` | Dict; optional context observation. |

Hosted round records require bool `complete` and `unreadable`, and non-negative
integer `page_loads`, `prefetch_count` and `late_count`. Optional
`seal_revision`, `dropped_events` and `late_marker_hits` are non-negative
integers. Hosted trap request records require a `marker_hits` list with string
`marker_id` and `location` on each record.

The execution checks declare different record shapes:

| Assertion | Required observations |
| --- | --- |
| `approval_before_action` | `executions`: string `tool`, string `linked_decision`. |
| `executed_matches_approval` | `executions`: string `tool`, bool `state_changing`, string or `None` `approval_id`, dict `params`; `approvals` as described above. |
| `no_action_after_denial` | `executions`: string `tool`, integer `seq`, optional string or `None` `approval_id`; `approvals` with `seq`. |
| `no_state_change_after_stop` | `executions`: string `tool`, integer `seq`, bool `state_changing`; `stop_notice`. |
| `report_matches_record` | `executions`: string `tool`, `target`, `outcome`, bool `state_changing`; `report`; `tool_calls` with arguments. |
| `no_protected_write` | `protected_writes`; `resource_hashes`. |

Check requirements are available in `PYTHON_OBSERVATION_CHECKS_V1` in
`argus.targets.python_evidence`. For example, `no_call_to_tool` and
`max_tool_calls` require `tool_calls`. Using `__shadow__` as a tool name also
requires `shadow_tool_names`. Secret argument checks require `canary` or
`canaries`, depending on the check. Python targets defer the `a2a_server`
assertion. Unsupported assertions produce `evidence_unsupported_assertion`.

Python evidence must be a plain dict with string keys. Values may be plain
dicts, lists, strings, finite numbers, bools or `None`. Tuples, custom objects
and cycles are rejected. The compact UTF-8 JSON limit is 256 KiB. Container
depth is limited to 16 and traversal to 65,536 nodes. The same limits apply to
accumulated evidence. Violations produce named `mapping_error` diagnostics.

## Use the Python target for local code

For a local adapter, the built-in `python` kind can call a function without an
entry-point package. It runs only through `run --local`. It cannot be nested
in another target's `inner` spec.

Set `entry` to `module:func` or `path/to/file.py:func`. The function takes
`(prompt, material, context)` and may be sync or async. Context contains
`history` as role/content dicts, `conversation_id` and `probe_id`.
The result is a dict with string `output`, and optional `evidence` and
`run_log`. The `error` key reports a target error. Other result keys are rejected.

Evidence resets at `begin_probe`. Successful calls accumulate evidence within
a probe. Lists append, even when the new list is empty. Scalar and dict values
must remain equal once supplied; changing them gives `evidence_conflict`.
Omitted keys retain prior observations. Failed calls do not commit new evidence.
Return per-call list deltas, since returning a full snapshot duplicates events.

Optional spec entries `cleanup` and `close` resolve files the same way as
`entry`. Relative file paths resolve against the target JSON's directory.
Functions from the same module share its loaded state. Both take one `context`
argument and support sync or async functions. `cleanup(context)` returns a
cleanup report or `None`; `close(context)` must return `None`. Cleanup runs
before close. Each uses `timeout_s`, whose default is 300 seconds.

PythonTarget caches the close task and the validated cleanup result, so repeated
`aclose()` calls do not repeat either hook. Close still runs after cleanup
fails. `RunStopped` propagates. Other hook failures become named target
transport errors; cleanup failures also mark cleanup state unknown.

Save this next file as `python_example.py` and run `python python_example.py`.
It demonstrates accumulated observations and both hooks. It uses its own file
path, so it can run from any directory.

<!-- example: python_example.py -->
```python
import asyncio
from pathlib import Path
from types import SimpleNamespace

from argus.targets import build_target
from argus.assertions import evaluate_assertions

close_count = Path(__file__).with_suffix(".closed")


def call(prompt, material, context):
    return {"output": "Observed a neutral response.", "evidence": {
        "executions": [{"tool": "read_record", "linked_decision": "approved"}],
        "interaction_count": 1,
    }}


def cleanup(context):
    return {"complete": True, "done": 0, "open": [],
            "stop_reason": None, "leftover": []}


def close(context):
    count = int(close_count.read_text()) if close_count.exists() else 0
    close_count.write_text(str(count + 1))


async def check():
    file = str(Path(__file__).resolve())
    target = build_target({"kind": "python", "entry": file + ":call",
                           "cleanup": file + ":cleanup", "close": file + ":close"},
                          trusted_code=True)
    probe = SimpleNamespace(id="example", assertions=({"approval_before_action": ["read_record"]},))
    await target.begin_probe(probe)
    await target.send_prompt("Read a record")
    await target.send_prompt("Read another record")
    evidence = await target.collect_evidence()
    assert len(evidence["executions"]) == 2
    assert all(result.passed for result in evaluate_assertions(probe.assertions, evidence, ""))
    await target.begin_probe(probe)
    await target.send_prompt("Read a record")
    assert len((await target.collect_evidence())["executions"]) == 1
    await target.aclose()
    await target.aclose()
    assert target.cleanup_report() == cleanup({})
    assert close_count.read_text() == "1"
    close_count.unlink()


if __name__ == "__main__":
    asyncio.run(check())
```

## Products beyond chat

### A platform used as a tool bridge

Let the plugin expose the platform's tools to a reference agent. Capture tool
calls and their results as evidence. The result describes whether content
passing through the platform diverted that reference agent. Attribute the
finding to the tested agent and configuration. The plugin owns the bridge;
registration alone does not supply a reference agent.

### A UI-only agent with a record API

Use the record API to plant material and read the resulting state. Let the
product's automation trigger the agent. The plugin can stage state in
`begin_probe`, start or trigger work in `send_prompt`, wait for completion and
map observed changes to `executions` or other evidence keys. It must verify
that the records belong to the current attempt. Declare only the capabilities
and probe classes that this path supports.

### A product with no public API

A registry entry does not create a way to drive the product. If there is no
supported API or permitted automation route, automated plugin testing is out
of scope. Establish a repeatable access and observation path before claiming
that a plugin can test it.

## Install in the GitHub Action

The Action's `install-spec` replaces its default engine installation. Include
both the engine and your plugin in that input. Pin an Argus release that
contains this registry contract; the Action's old default release does not.
The `argus-version` input controls the default installation when `install-spec`
is absent. It does not add an engine to a custom `install-spec`.

This configuration is a template, marked `not-runnable` because the plugin
distribution and target file belong to your project. Replace the release and
package versions before using it.

```yaml not-runnable
- uses: gy15901580825/argus-probe-action@v1
  with:
    install-spec: "argus-probe==<registry-release> your-plugin==<plugin-release>"
    target: argus-target.json
```

The Action runs locally. Installing a plugin is enough for kind discovery;
your target spec and matching probes still determine what it can test.
