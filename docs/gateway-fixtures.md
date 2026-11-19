# Gateway fixture host

Keep the fixtures online while registering their entries in a gateway you operate.
Use a non-production gateway or an isolated tenant. The install contains synthetic
canaries; never add real gateway credentials to it.

```sh
argus-probe gateway-fixtures init
argus-probe gateway-fixtures sheet
ARGUS_FIXTURE_TOKEN=<generated-control-token> argus-probe gateway-fixtures serve
```

`init` creates `argus-gateway-install.json` with mode 0600 and refuses to replace an
existing file. `sheet` prints the same registration values without generating new
ones. Every command accepts `--install-file`.

The default `local-hosts` mode uses `127.0.0.1:8471` for upstream and
`127.0.0.2:8473` for foreign. Loopback aliases work on Linux; other systems may
need an alias configured first. `--mode local-ports` uses `127.0.0.1` for both
origins and warns that host-distinct redirect cases cannot run. `--mode compose`
uses `r.argus.test` and `e.argus.test` with listeners on `0.0.0.0`; configure those
aliases on the gateway's container network.

Override an origin with `--origin NAME=PUBLIC_URL,LISTEN,HOST`. `--mode public`
requires an explicit upstream and foreign origin. Origins sharing a listen
address share one listener and route by the exact configured Host authority.
Configure a reverse proxy to preserve that authority. Fixture URLs always come
from the install's public origins. An unknown Host or missing path token gets a
fixed 404 and does not add records.

`init --tls-cert CERT --tls-key KEY` stores paths to a certificate covering every
fixture hostname. The host serves TLS on the fixture listeners; the default
loopback control listener remains HTTP.
The control listener defaults to `127.0.0.1:8470`; `serve --control-bind IP:PORT`
changes it. A non-loopback control listener requires `--allow-remote-control`
and install TLS. Control routes never appear on fixture listeners. Prefer the
`ARGUS_FIXTURE_TOKEN` environment variable over `--control-token`.

## Control API

Every route requires `Authorization: Bearer <control-token>`, including health.
Missing or changed tokens get 401. The API accepts JSON bodies up to 64 KiB.

| Request | Body | Response |
| --- | --- | --- |
| `GET /v1/health` | None | Install label, origins, plugins, `eras` |
| `GET /v1/seen` | None | Entry summaries with first/last contact, methods and canary hits |
| `POST /v1/lease` | `{"ttl_s": 60}` | `{"lease_id": "..."}`; a second lease gets 409 |
| `POST /v1/cases` | Case definition below | `{"case_seq": 1}` |
| `POST /v1/cases/1/seal` | None | Sealed evidence; repeated seal returns the same evidence |
| `DELETE /v1/lease/<lease_id>` | None | Release, clear evidence and return to idle |

A case definition contains `lease_id`, `probe_id`, `case_id`, `nonce`, `toggles`
and `watch`. Toggles map each origin to named behaviour configurations. Unknown
origins or behaviours get a 400 `definition_error`, leaving the active case intact.
The watch object has `canaries`, `secrets`, `watch_key` and `case_key`.
Both keys are 32-byte values encoded as 64 hex characters. `secrets` maps labels
to HMAC-SHA256 hex digests, never raw credentials. `canaries` can be a list of
install header labels such as `upstream_header:X-API-Key`, or a map of labels to
synthetic values minted by a case driver.

A new case seals the preceding one before applying its behaviours. Arrival time
determines attribution, so health checks during the case are recorded too.
Only the exact case nonce survives body redaction. Seal accepts arrivals during
a 0.3-second settle grace, then waits up to `--case-window-s` for requests already
in flight. A timeout cancels those handlers and marks evidence incomplete.
Body reads stop at 64 KiB or five seconds; request caps and truncated captures
also mark evidence incomplete. Evidence contains `case_seq`, `case_id`,
`probe_id`, `complete`, `dropped` and `fixture: {requests, state}`.

Idle requests pass through the recorder and retain only bounded entry summaries.
Lease expiry removes case behaviours without requiring another control request.
The host disables access logs and returns fixed parser errors. Raw requests and
watch keys never enter evidence. Fixtures make no outbound calls.

## Fixture plugins

Register a function under the `argus.gateway_fixtures` entry-point group:

```toml
[project.entry-points."argus.gateway_fixtures"]
example = "example_fixtures:register"
```

The function receives a `Registry` and may call:

| Method | Contract |
| --- | --- |
| `add_origin(name, requirements)` | Add a required install origin; optional `https: true` or `symmetric_with: "other"` requirements |
| `add_entry(name, path_template, sheet_fn)` | `sheet_fn(install)` returns stable registration fields, including `auth`, optional `headers` and `sheet` lines; called only at init |
| `add_behavior(origin, name, factory)` | `factory(config)` validates the toggle and returns an async handler |
| `add_feature(name, validator)` | Claim a feature for strict `validate_features` validation |
| `add_drive_step(name, fn)` | Claim a driver step for strict `validate_drive_steps` validation |

An async behaviour handler receives `RequestContext` and returns an aiohttp
response, or `None` to defer to the next behaviour or idle handler. The context
contains the request, capped body, parsed message, install, origin, route, entry,
case ID, nonce, case `state` and request `ext`. Changes to route/entry classify
plugin routes. State and extension values must be bounded, derived observations;
never store raw headers, body values or secrets. The host copies them to evidence.
Handlers that vary tool calls must check the case nonce themselves so background
initialization and health checks stay idle. A behaviour named `idle` supplies the
origin's fallback handler, instantiated with an empty configuration at startup.

```python
import aiohttp.web as web

def register(registry):
    def factory(config):
        async def handle(context):
            context.state['example_served'] = True
            return web.json_response({'example': True})
        return handle
    registry.add_behavior('upstream', 'example', factory)
```

Duplicate registrations and failed plugin loads are definition errors. Plugins
load before listening; a failed plugin cannot silently disappear from a run.
The host currently supports legacy MCP initialization, tool listing and calls.
Gateway probes, the gateway target, registration checks and additional delivery
behaviours are separate units.
