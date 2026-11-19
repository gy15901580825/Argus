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


### Loopback OAuth fixtures

Add `--oauth` to `gateway-fixtures init` to mint an `oauth` entry and an `issuer`
origin alongside the existing fixtures. The registration sheet prints the synthetic
client ID, client secret, issuer and `argus.fixture` scope. These values remain
stable in the install file. Existing installs retain their two-origin layout.
OAuth fixture and control listeners must bind to loopback; this option supports
`local-hosts` and `local-ports`. HTTPS can use the existing certificate options;
HTTP is available for local development.

The protected entry serves RFC 9728 metadata at
`/.well-known/oauth-protected-resource/u/{path_token}/oauth/mcp` and
`/.well-known/oauth-protected-resource`. The root fallback selects this install's
OAuth entry. Its 401 Bearer challenge names the path-specific `resource_metadata`
URL. Metadata always reports the exact protected entry URL as `resource`.

The issuer identifier is `<issuer-origin>/a/{path_token}`. Discovery serves the
same metadata at the RFC 8414 OAuth path-insertion URL, the OpenID path-insertion
URL and the OpenID path-append URL. The GET authorize endpoint auto-approves a
registered client using `response_type=code`, PKCE S256 and the exact `resource`.
Authorization errors with a validated callback redirect with `error`, supplied
`state` and the configured `iss`. The first successful request pins the exact callback URI for the running install;
restart requires pinning again. POST token requests use form encoding and either
`client_secret_basic` or `client_secret_post`. Both `client_credentials` and
`authorization_code` produce opaque 60-second tokens, restricted to the OAuth
entry. Codes expire after 60 seconds and can be redeemed once. Refresh grants
and refresh tokens are unsupported. No fixture initiates network requests.

Case toggles use these shapes:

| Origin | Toggle | Values |
| --- | --- | --- |
| `upstream` | `prm` | `{"authorization_servers": ["issuer"]}` or `{"authorization_servers": ["foreign"]}` |
| `upstream` | `challenge` | `"invalid_token"`, revoking existing issuer tokens at case start |
| `issuer` | `iss` | `"always"` (default) or `"never"`; RFC 9207 metadata advertisement follows this toggle |
| `foreign` | `as_mode` | `"own"` (default) or `"mirror_authorize"`; issuer and token endpoint remain at the foreign origin |

Every accepted OAuth request passes through the recorder. `ext.oauth` and bounded
`state.oauth` events describe discovery, authorization, issued-code correlations
and token requests. Resource values use `corr` plus `matches_expected`; code
values use `corr` and hit labels. PKCE values use `verifier_s256`, including the
front-channel challenge. The raw code, verifier, client secret and access token
are excluded from evidence. Protocol state is separate from exported case state;
sealing removes outstanding codes, and the metadata/issuer toggles return to idle.
Case canary watches include `static_client_id` and `static_client_secret`.

The foreign origin also publishes all three authorization-server discovery
forms. `foreign.as_mode: own` names its own issuer, authorization and token
URLs. `mirror_authorize` keeps the issuer and token URL at the foreign origin
and points the authorization URL at the honest issuer's actual authorize route.
Its `authorization_response_iss_parameter_supported` flag follows the honest
issuer's `iss` toggle in mirror mode and is false in own mode.

Foreign authorize and token routes return only `{"error":"invalid_grant"}`,
with no callback redirect or received values. They record requests without
issuing or redeeming codes or tokens. A foreign token event reports
`code_issued_by: issuer` when its code correlation matches an issued-code event
in the same case. `verifier_matches_challenge_from: issuer` additionally requires
the verifier's S256 transform to match that code's recorded challenge. Unknown
codes, missing or changed verifiers, and codes from a sealed case cannot establish
that match. The raw code and verifier never enter evidence.

Programmatic callers opt in with `create_install(oauth=True)` or
`load_registry(oauth=True)`. `read_install` and `FixtureHost` select this registry
from an install containing the issuer origin. Behaviour factories still receive
only toggle configuration. The host's OAuth handler uses
`RequestContext.recorder.oauth_observation` to derive safe fields under the
case's correlation key. This fixture infrastructure adds no probe.

### Gateway-initiated authorization consent

The gateway target selects the OAuth registry before parsing recipes when its
install contains an `issuer` origin. Declare the upstream's static OAuth setup
in the target and enable the consent drive step in a case recipe:

```yaml
features:
  static_oauth_client:
    grant: authorization_code  # or client_credentials
    consent: follow_url        # none | follow_url | manual
    trigger: challenge         # challenge | manual_restart
```

```json
{"tool": "echo", "calls_per_case": 1, "steps": ["consent"]}
```

`follow_url` is the operator's standing consent for automated navigation in this
loopback conformance test. The client advertises URL elicitation and handles
`elicitation/create` with `mode: "url"`, or error `-32042` with the
`data.elicitations` list defined by [MCP 2025-11-25 elicitation](https://modelcontextprotocol.io/specification/2025-11-25/client/elicitation).
It accepts the URL elicitation before navigating and retries a tool call once
after completing an error's required elicitations. A repeated authorization
requirement reports skipped.

Each initial URL and redirect must use a configured fixture origin or the
gateway origin, with a literal loopback address. Navigation follows at most ten
redirects and shares the gateway's cookie jar. Configured gateway authentication
headers are sent only to the gateway origin. Each hop carries
`X-Argus-Consent-Agent` with the case nonce, so fixture front-channel requests
have actor `argus_user_agent`. Token exchanges made by the gateway retain actor
`gateway`.

`manual` prints the URL and instruction, then waits for Enter after the operator
completes authorization. It reports skipped immediately without a TTY and after
`timeout_s` without confirmation. Navigation also has a `timeout_s` deadline and
cases accept at most ten elicitations. `none` skips a required consent request.
The step is opt-in; recipes without it do not navigate authorization URLs.

Evidence in `client.consent_hops` contains only the origin name, route class,
HTTP status and query parameter names. Response bodies, URL paths and query
values are excluded. This step does not automate a gateway's administration UI
or its restart procedure.
