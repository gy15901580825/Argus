# Integration scenarios

Integration scenarios test an agent through its existing mail and document connectors.
Drivers prepare marked objects, query independent state and clean only objects owned by the run.
They do not replace the target's connectors or use the instrumented testbed target.

The core implements the protocols and runner. Provider packages supply credentials.
Google and local ACS drivers are separately installable packages in `drivers/google` and `drivers/acs`.
argus-probe 0.9.0 ships the scenario runner and server API. The driver packages are not on PyPI; install them from this checkout.

## Installation

For development from this checkout:

```bash
python -m pip install -e '.[dev]' -e drivers/google -e drivers/acs
```

The package groups are `argus.drivers` and `argus.credential_providers`.
A driver entry point loads a factory accepting `(config, credential_provider)`.
A credential entry point loads a factory accepting `(config, run_token, connections)`.

`CredentialProvider.access_token(ConnRef, scopes)` returns `AccessToken` with a `SecretStr` value,
an aware expiration timestamp and the granted scopes. The core never reads OAuth refresh tokens.
The development providers read short-lived credentials from a configured environment variable or a mode-0600 file.
Environment variable names must start with `ARGUS_TEST_CREDENTIAL_`.
File connection references must be simple alphanumeric IDs with hyphens or underscores.

## Server API

All scenario endpoints require `Authorization: Bearer <ARGUS_SERVER_TOKEN>`.
An unset server token returns 503, including when the app is imported by uvicorn directly.
The run token is a separate credential capability, not server authentication.

`GET /redteam/scenarios` returns `{id, name, description, scenario}` entries.
The built-in scenario is `mail_policy_conflict_v1`. A scenario may set `attack_class`, a list of the same attack classes probes use; the built-in scenario uses `indirect-injection` and `data-exfil`.
A catalog response includes resolved template content so a trusted broker can freeze the exact seed content with the run.
Template files must stay within the catalog's `templates` directory and are limited to 64 KiB.
A trusted server should select the catalog scenario and supply the connection IDs and declared target account.
Do not let an untrusted browser choose credential-provider configuration, operation permissions or budgets.

`POST /redteam/scenario/run` takes:

```json
{
  "run_id": "00000000-0000-0000-0000-000000000001",
  "organization_id": "00000000-0000-0000-0000-000000000002",
  "scenario": {"id": "a-catalog-scenario", "kind": "integration_scenario"},
  "target": {"kind": "custom_http"},
  "connections": {"operator": "operator-id", "observer": "observer-id"},
  "credential_provider": {"kind": "a-provider", "config": {}, "drivers": {}},
  "run_token": "a-run-bound-capability"
}
```

The abbreviated scenario and target above show the transport shape. Use complete validated catalog and target specifications.
SSE events are `phase`, `object`, `heartbeat`, `finding` and `end`; unexpected execution failures use `error`.
Each event has `type`, `run_id` and `organization_id`.
Object events contain `object`. Finding events contain `finding` in the existing Finding format.
Named controls also carry `control_name` and use distinct `argus:<run>:control:<name>:<key>` markers.
Heartbeats are emitted while a phase waits, with an idle interval of 30 seconds.

`POST /redteam/scenario/cleanup` accepts the same run identity, scenario, connections and provider,
plus an `objects` list. It returns JSON with `run_id`, `organization_id`, `complete`, `gaps` and `objects`.
The target is optional and no target call runs during cleanup.
A hosted provider must require a cleanup-only capability restricted to reads and deletion of owned objects.
The driver operation guard also rejects sends and creates during cleanup.

## Evidence and outcomes

Phases are `prepare`, `readiness`, `baseline`, `test`, `observe`, `judge`, `cleanup`.
All terminal paths attempt cleanup, including the wall deadline and caller cancellation.
Test calls have separate target-call, third-party-call, judge-cost and wall budgets.
Cleanup has a separate bounded reserve of 100 calls and 60 seconds.
The deterministic scenarios do not call a judge model and report zero judge cost.

`defended` requires confirmed target contact, a complete observation window and no evidence gaps.
Target prose, echoed markers, dry-run tool intentions and an empty log cannot establish contact.
The baseline also requires successful structured retrieval of the expected marked object.
Targets that cannot expose this proof finish `not_ready` or `inconclusive`.
An empty collector response cannot establish a complete observation window. A driver must provide an independent checkpoint, and pagination, truncation or collection gaps make the result inconclusive.

Structured run events used as proof must contain a successful `read`, `get`, `retrieve`, `search` or `fetch`,
with the matching object ID or marker. Supplied run/group/version fields must match.
Conflicting IDs and markers are rejected. Citation prose is not a successful retrieval record.

For a custom HTTP target, configure `session_id_jsonpath`, `run_id_jsonpath` and `run_log_jsonpath`.
The run-log path may select an event list or an object containing `events` and `is_dry_run`.
The endpoint must provide real execution records. Do not manufacture records from response prose.
Scenario targets reject URL user information, credential query parameters and known credential values in query strings before making requests. Supply credentials through target headers instead.

Findings carry `remediation` and `remediation_actions` for the scenario's `attack_class`, or an empty string and `[]` when it has none.

Scenario results remain regular findings under `evidence.scenario`:

| Outcome | Finding verdict |
| --- | --- |
| defended | pass |
| violated | fail |
| not_ready, not_exercised | skipped |
| inconclusive, execution_error | error |

Reports distinguish target self-report, target run records and third-party API state.
Mail bodies and raw tool arguments are omitted from exported findings.
Raw target records live in mode-0600 local files referenced by `raw_ref`; known credentials are removed before writing.
Mail addresses in exported strings are masked. Object ownership is a hash of the normalized account address.

## Google and ACS boundaries

The operator uses `drive.file`. An observer uses `gmail.readonly`.
Optional `gmail.modify` permits moving received seed messages to trash; its absence is reported as retained cleanup.
Local Gmail sending uses operator `gmail.send` and observer reads for reconciliation.
It does not request operator read access just to check delivery.
An uncertain send leaves a durable pending intent and is not blindly repeated.

Google API list operations follow all pages within the call budget.
Draft differences are correlated with the exact run/group marker. Unrelated new drafts are ignored.
The Gmail driver needs a trusted `expected_seed_sender` setting or a registered sender artifact to clean received seeds.
It verifies the actual sender, recipient mailbox and marker before moving the message to trash.

Drive objects carry `appProperties.argus_marker`.
The driver reads Google Docs through `files.export` and plain-text files through `alt=media`, with a bounded response size. Evidence includes content hashes and private raw-file references, rather than document bodies.
The driver records the version after intentional sharing, and retains objects with changed markers, owners or versions.
On recovery, a modified object with no known original version is retained.
Folders are deleted only after their contents are safely cleaned.

The local ACS driver accepts only configured Azure-managed test senders and limits sends to 5 per minute and 10 per hour.
Hosted deployments should register their own broker driver so ACS credentials remain in the server.
ACS has no sender mailbox. Its immutable delivery ledger is marked `not_applicable`, and the Google observer handles received-message cleanup.
An accepted delivery whose receiver copy is not yet visible leaves cleanup incomplete for a later retry.
The local driver can use a separate credential connection through its `connection` setting.

## Verification

`tests/test_scenario_*` cover deadlines, cancellation, missing evidence, expired credentials,
negative baseline responses, control isolation, budgets, retries, ownership checks, REST payloads and SSE transport.
The fixtures use deterministic targets and HTTP stubs. They do not prove live Google or target connector behavior.
Live-account acceptance must verify actual object IDs, indexing, target retrieval and cleanup before production use.
