# Hosted trap service

This service exposes synthetic pages and HTTP sinks through an operator-configured HTTPS origin. It collects redacted marker evidence without calling the target agent. The owner supplies neutral synthetic page text and markers. The service escapes the page text and does not execute uploaded scripts.

Unit 1 implements browser trap and sink routes. Protocol rounds, phases, MCP, payment, and file routes return 404. The browser client is a separate change.

## Configuration

| Variable | Value |
| --- | --- |
| `HOSTED_ENTRA_TENANT_ID` | Entra tenant UUID |
| `HOSTED_ENTRA_AUDIENCE` | Exact owner-token audience |
| `HOSTED_TABLES_ENDPOINT` | HTTPS account endpoint under `table.core.windows.net` |
| `HOSTED_TABLE_PREFIX` | Table prefix, for example `hosted` |
| `HOSTED_PUBLIC_ORIGIN` | Public HTTPS origin without a path |
| `AZURE_CLIENT_ID` | Optional user-assigned identity client ID, read by `DefaultAzureCredential` |
| `HOSTED_STORE` | `tables` by default, or `memory` for local tests |
| `HOSTED_TRUSTED_PROXY_CIDRS` | Optional comma-separated trusted proxy networks |

The prefix forms three names: `hostedruns`, `hostedevents`, and `hostedlimits` when the prefix is `hosted`. The production backend uses `DefaultAzureCredential`; connection strings are unsupported. Missing required configuration prevents startup. The memory backend loses evidence on restart.

The process disables access logs. Forwarded addresses affect IP limits only when the actual socket peer belongs to an explicitly trusted network. An untrusted peer cannot select its rate identity through `X-Forwarded-For`.

## Owner API

All owner requests carry an Entra `Authorization: Bearer` token. The service validates its RS256 signature, issuer, tenant, audience, expiry, and principal. `HostedRun.Create` permits run creation. Every other control request requires the exact `HostedRun.Control` role and ownership of the run.

| Request | JSON body |
| --- | --- |
| `POST /v1/runs` | `{"schema_version":1,"ttl_seconds":86400}` |
| `POST /v1/runs/{run_id}/probes` | Probe definition below |
| `POST /v1/runs/{run_id}/probes/{probe_id}/seal` | `{"reason":"vendor_terminal"}` or `{"reason":"timeout"}` |
| `POST /v1/runs/{run_id}/probes/{probe_id}/renew` | `{"ttl_seconds":10800}` |
| `POST /v1/runs/{run_id}/tokens/rotate` | `{"scope":"public"}` or `{"scope":"evidence"}` |
| `DELETE /v1/runs/{run_id}` | No body |

Run creation returns independent 256-bit public and evidence capabilities once. An `Idempotency-Key` prevents duplicate runs. A replay returns the run ID and its original expiry without reissuing tokens. Lost tokens require owner rotation. The store retains hashes, not recoverable capabilities.

Probe creation therefore accepts the public capability that the owner already holds. The service verifies it against the current run hash in memory and uses it to construct real URLs. It never stores this input. Missing capabilities return 400, unknown or cross-run capabilities return 404, and confirmed retired capabilities return 410.

```json
{
	"kind": "browser",
	"scenario_id": "synthetic-page",
	"public_token": "<capability returned at creation or rotation>",
	"payload": "Neutral synthetic page text",
	"synthetic_markers": [{"marker_id": "m1", "value": "MARKER_ALPHA_123"}],
	"script": {"combine_fields": ["query", "body"]},
	"ttl_seconds": 10800
}
```

`browser` and `ui_phishing` are the supported kinds. `scenario_id` is a bounded synthetic label. `script` supports only an optional `combine_fields` list of unique `path`, `query`, and `body` names in the declared order. Unsupported kinds, fields, and scripts fail instead of silently changing the scenario. Page text is limited to 16 KiB, markers to 32 values of at most 512 bytes each, and probes to 100 per run.

The response includes `probe_id`, `epoch`, `expires_at`, `scenario_url`, and `sink_url`. Other protocol URLs are null. A renewal never extends a probe beyond the run expiry or a 10,800-second lease. Rotation invalidates the previous capability atomically and marks live collection incomplete. It does not alter sealed evidence. Each scope permits at most 256 rotations per run.

## Public requests and evidence

`GET` and `HEAD` access `/r/{public_token}/p/{probe_id}/scenario`. The shorter probe prefix is an alias. Sinks accept `GET`, `HEAD`, and `POST` at `/r/{public_token}/p/{probe_id}/sink/{tail}`. Sink responses never echo input. The service retains `/sink/kyc` and `/sink/oauth/grant` as route classes. Other tails become `/sink/other`.

`GET /v1/runs/{run_id}/evidence?probe_id={probe_id}&limit=100` requires the evidence capability as a Bearer token. Event cursors are opaque, signed, and bound to the run, probe, and snapshot. `cursor` pages sealed or provisional events. `late_cursor` pages late audit independently.

Wrong or cross-run capabilities return 404. Confirmed expired, deleted, or retired capabilities return 410 while their run record exists. After TTL purge, requests return 404.

Before seal, `summary.complete` is always false. Seal blocks new collection and drains admitted requests for up to five seconds. The immutable snapshot includes its epoch, event sequence, counters, and a SHA-256 `snapshot_hash`. Timeout, pending requests, truncated input, quota drops, or rotation prevent complete collection. Repeated seals return the same hash.

Late requests return 409 and append a separate redacted audit, with `late=true` and `seal_revision`. Evidence includes `late_count`, `late_cursor`, and `late_events`. Late entries never change the sealed snapshot or its hash.

`HEAD` does not count as a page load. Every `GET`, including prefetch, counts as a page load; known prefetch also increments `prefetch_count`. Zero page loads means `not_delivered`. A GET alone cannot prove consumption, so other cases remain `unknown`. Completeness describes evidence collection and does not establish safety or delivery.

Marker matching runs before redaction, in bounded memory. It supports raw values, up to three URL decodes, JSON Unicode escapes, explicit base64 decoding, and long markers that contain spaces or hyphens. Cross-field matching requires the declared combination order. Unsupported transformations and ambiguous combinations remain unknown. Truncated bodies retain known hits but cannot establish a complete miss. Stored public events contain marker IDs, locations, route classes, methods, lengths, counters, and completeness. They contain no raw body, query, tail, cookie, authorization value, or other header input.

## Limits and retention

Public limits are 60 requests per minute per token with a burst of 20, and 300 per minute per IP with a burst of 60. Evidence permits 30 per minute per token. Owner control permits 60 per minute per principal. Admission permits 20 runs per principal per hour and 10 active runs globally. A run permits 50 sink requests, 1,000 normal events, and 1,000 late audit entries. Exhausted quotas return 429. Public bodies permit 64 KiB and a five-second read. Oversized or incomplete requests remain unknown.

Run TTL is at most 24 hours. Reads and writes check expiry before use. Cleanup runs at startup and every 15 minutes under a durable cleanup lease. It deletes expired run partitions and expired limit rows. When the service is stopped, physical deletion waits for restart; expired data is never readable through the API.

Tables stores events in separate rows and publishes immutable revisions through a canonical header ETag. Conflicting or partial candidates are invisible to readers. Atomic ETag updates also enforce quotas across service instances. An uncertain storage write returns an error and may conservatively retain its admission reservation until reconciliation or expiry.

## Local verification

From this directory, install `requirements-dev.txt` into a Python 3.11 environment and run `python -m pytest tests/ -q`. The tests use local signing keys, loopback HTTP, and an offline Tables SDK mock. They do not contact cloud resources.

`python -m testbed.app --help` describes the local bind options. With the required placeholder configuration supplied, the memory backend starts with `python -m testbed.app --host 127.0.0.1 --port 8080`. Owner authentication still applies.

Build the isolated image with `docker build -t hosted-trap:local .`. Its non-root process listens on port 8080. The image copies only this service directory. This change does not deploy the image or configure network-level outbound restrictions.
