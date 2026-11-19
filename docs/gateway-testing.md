# Test an MCP gateway

Use these probes to test an MCP gateway or proxy you operate. Argus acts as an
MCP client of your gateway. A separate fixture host supplies upstream servers
whose behavior changes for each test case. You register the fixture entries once
through your gateway's administration interface. Argus does not configure the
gateway for you. The seven bundled probes cover five bug classes and use scripted
calls and evidence assertions. They make no model calls.

## Safety and evidence

Use a non-production gateway or an isolated tenant and a dedicated test account.
The target requires the literal value `sandbox: true`. Other users of that
gateway can see the registered fixture tools while testing runs.

The install file contains synthetic credential canaries and stable registration
URLs. It has mode 0600. Never put real gateway credentials in that file. Supply
gateway authentication through environment variables in the target spec, and
revoke the test account's token after testing. Probe 3 can cause a vulnerable
gateway to send that credential to the fixtures. With public placement, that
request can also travel through your tunnel or reverse proxy.

Fixtures record request methods, route classes, entry names, timing, peer address
classes, selected protocol fields, the exact case nonce, and bounded body shapes.
Secret values become hit labels, lengths and per-case keyed HMAC correlation
tags. OAuth evidence uses code correlations and the verifier's S256 transform.
Evidence never holds raw credentials, authorization codes or PKCE verifiers,
including their encoded forms. Raw request inputs exist only during handling in
memory; the recorder does not retain them. Gateway reply text is classified rather
than persisted. Access logs are disabled. Fixtures make no outbound calls, and
the foreign OAuth endpoint never redeems a received code.

Keep the control API separate from the gateway's network. Its default bind is
`127.0.0.1:8470`, over HTTP, even when fixture listeners use TLS. Every control
route requires a bearer token. Set `ARGUS_FIXTURE_TOKEN` instead of putting that
token on the command line. A non-loopback control bind requires both
`--allow-remote-control` and install TLS. OAuth installs require a loopback control
bind even with that flag. Do not publish or tunnel the control listener. Run Argus
beside it, or use a private loopback port forward. Only one run can lease an
install at a time; release or lease expiry returns the fixtures to idle behavior.

## Prepare the fixtures

Install `argus-probe` in your Python environment. For the worked example below,
use a source checkout and Python 3.11:

```sh
python3.11 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
unset ANTHROPIC_API_KEY OPENAI_API_KEY AZURE_OPENAI_API_KEY AZURE_API_KEY
export ARGUS_FIXTURE_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
argus-probe gateway-fixtures init
argus-probe gateway-fixtures sheet
argus-probe gateway-fixtures serve
```

Run `serve` in a terminal that stays open. Use the same control token in the
terminal where you run Argus. `init` refuses to replace an existing install;
`sheet` prints its existing values. Both accept `--install-file`, as does `serve`.
Keep the install and its placement stable after registration.

R is the `upstream` origin. Its `plain` entry needs no upstream authentication;
its `hdr` entry has synthetic header credentials. E is the `foreign` origin and
receives redirected requests. For probe 1, add H, the `issuer` origin, and an
`oauth` entry by creating a separate install:

```sh
argus-probe gateway-fixtures init --oauth --install-file oauth-install.json
argus-probe gateway-fixtures sheet --install-file oauth-install.json
```

Stop the first fixture server before serving this install on the same ports:

```sh
argus-probe gateway-fixtures serve --install-file oauth-install.json
```

### Choose placement and TLS

The gateway must reach every fixture origin. Argus must reach the gateway and
the control API. Choose placement before registration.

| Mode | Default public origins without TLS | Where it fits |
| --- | --- | --- |
| `local-hosts` | R `http://127.0.0.1:8471`, E `http://127.0.0.2:8473`, H `http://127.0.0.3:8472` with `--oauth` | Gateway on the same host. Linux accepts these loopback aliases; other systems may need aliases configured. This is the default. |
| `local-ports` | All use `127.0.0.1`, with R port 8471, E port 8473 and H port 8472 | Same-host development. Probe 2 skips because R and E share a hostname. |
| `compose` | R `http://r.argus.test:8471`, E `http://e.argus.test:8473`, H `http://h.argus.test:8472` | Run fixtures on the gateway's container network, with those DNS aliases. Listeners bind to `0.0.0.0`. The CLI creates an install; it does not create containers or a network. |
| `public` | You supply each public URL and listener | A remote gateway reaches your own reverse proxy or tunnels. With OAuth, supply all three origins. |

These commands create alternative installs; serve only the one you register:

```sh
argus-probe gateway-fixtures init --mode local-ports --install-file ports-install.json
argus-probe gateway-fixtures init --oauth --mode compose --install-file compose-install.json
argus-probe gateway-fixtures init --oauth --mode public --install-file public-install.json \
  --origin upstream=https://r.example.test,127.0.0.1:8471,r.example.test \
  --origin foreign=https://e.example.test,127.0.0.2:8473,e.example.test \
  --origin issuer=https://h.example.test,127.0.0.3:8472,h.example.test
```

The public example assumes TLS termination at your proxy or tunnels. Replace
the example hostnames with hostnames you control. Preserve the configured Host
authority on forwarded requests, including an explicit port when the public URL
has one. An unknown Host or wrong path token returns 404 without recording a
request. Listeners can share a numeric bind and route by Host. `--origin` has the
form `NAME=PUBLIC_URL,NUMERIC_LISTEN_IP:PORT,HOSTNAME`.

Use distinct R and E hostnames for probe 2. H and E must match in scheme, address
class and whether a port is explicit in the public URL; `init` enforces this
symmetry. This helps distinguish issuer binding from an HTTP or address-policy
refusal. A public hostname can map to a local listener behind a tunnel. Give each
origin a stable hostname and route, and do not expose port 8470. The RFC 9728 root
metadata fallback is outside the path token, so use one install per public
hostname.

For direct TLS, install mkcert and create one development certificate that covers
every fixture hostname or IP. Then initialize an install with those paths:

```sh
mkdir -p certs
mkcert -cert-file certs/fixtures.pem -key-file certs/fixtures-key.pem \
  127.0.0.1 127.0.0.2 127.0.0.3 r.argus.test e.argus.test h.argus.test
argus-probe gateway-fixtures init --oauth --install-file tls-install.json \
  --tls-cert certs/fixtures.pem --tls-key certs/fixtures-key.pem
argus-probe gateway-fixtures serve --install-file tls-install.json
```

Import the development CA into the gateway runtime's trust store, including the
container trust store if needed. Certificate paths are used when `serve` starts;
keep them readable from its working directory. Plain HTTP is useful for loopback
development, but MCP authorization server endpoints and RFC 8414 issuers require
HTTPS. A gateway that refuses HTTP H will fail the baseline control and skip
probe 1. This is not proof of issuer binding.

Argus also verifies the gateway's TLS certificate. Its gateway and control HTTP
clients disable environment proxy settings. Do not rely on `HTTPS_PROXY` or
`SSL_CERT_FILE` to configure these connections. Use a certificate trusted by the
Python HTTP client's CA bundle, or configure the isolated Python runtime's CA
trust before testing a private-CA gateway.

## Register R in your gateway

1. Keep `serve` running with the install you chose. Open `sheet` in another
   terminal and your gateway's upstream registration interface.
2. Add an MCP Streamable HTTP upstream named, for example, `argus-plain`. Copy
   the sheet's full `plain` URL, including its path token. Select no upstream
   authentication. Save it and let the gateway discover the tools.
3. Add `argus-hdr` with the sheet's `hdr` URL. Configure `X-API-Key` with its
   exact canary. If the gateway supports a configured upstream `Authorization`
   header, copy that canary too. Declare only headers you configured in
   `features.upstream_headers.names`.
4. For an OAuth install, add `argus-oauth` with the protected entry URL. Register
   the sheet's static client ID and secret with the sheet's H issuer and
   `argus.fixture` scope. Choose the grant the gateway supports. Complete any
   initial connect flow. H auto-approves valid authorization-code requests with
   S256, and pins the gateway callback on its first successful authorization
   for that running fixture host. Restart the host if you change the callback.
5. If the gateway has a response filter, configure a redact or block rule for
   `ARGUSFLT[0-9A-F]{20}` on upstream responses. If it has a decision webhook,
   configure the sheet's webhook URL as a pre-call enforcement hook. Copy the
   gateway's documented allow and deny status/body contract into the target.
   These features are optional; missing feature keys cause the related probes
   to skip.
6. Identify the client-facing MCP URL through which Argus can call these tools.
   Use an aggregate endpoint, or a per-server endpoint that exposes the entries
   required by your selected probes. Write the target spec below and run `check`.

Descriptions contain `argus-fixture:<install_label>:<entry>` markers. Argus uses
them to discover echo and emit tools even when the gateway changes tool names.
If the gateway rewrites descriptions, use the prefix fallback described below.

## Target spec reference

Save this as `gateway.yaml`. Replace the gateway URL and set
`ARGUS_GATEWAY_TOKEN` to your dedicated test account's token. Remove feature keys
for features you have not configured. This example declares only `X-API-Key`.

```yaml
kind: mcp_gateway
sandbox: true
gateway:
  url: http://127.0.0.1:8480/mcp
  protocol: auto
  auth:
    headers:
      Authorization: "Bearer ${ARGUS_GATEWAY_TOKEN}"
    cookies: {}
  tools:
    match: fixture_marker
fixtures:
  control_url: http://127.0.0.1:8470
  control_token: "${ARGUS_FIXTURE_TOKEN}"
  install_file: ./argus-gateway-install.json
features:
  upstream_headers:
    names: [X-API-Key]
  response_filter:
    action: redact
  webhook:
    stage: pre_call
    decision: body
    allow: {status: 200, body: {decision: allow}}
    deny: {status: 200, body: {decision: deny}}
registration:
  mode: manual
timeout_s: 30
case_window_s: 10
```

An OAuth target can use this complete example as `oauth-gateway.yaml`. Use the
OAuth install for both `serve` and the target, and configure the other feature
keys from the preceding example if you want their probes to run.

```yaml
kind: mcp_gateway
sandbox: true
gateway:
  url: http://127.0.0.1:8480/mcp
  protocol: "2026-07-28"
  auth:
    headers:
      Authorization: "Bearer ${ARGUS_GATEWAY_TOKEN}"
fixtures:
  control_url: http://127.0.0.1:8470
  control_token: "${ARGUS_FIXTURE_TOKEN}"
  install_file: ./oauth-install.json
features:
  static_oauth_client:
    grant: authorization_code
    consent: follow_url
    trigger: challenge
registration:
  mode: manual
timeout_s: 30
case_window_s: 10
```

| Field | Meaning and limits |
| --- | --- |
| `sandbox` | Required literal `true`. |
| `gateway.url` | Required HTTP(S) client-facing MCP endpoint without userinfo or a fragment. |
| `gateway.protocol` | `auto` by default, or `2026-07-28`, `2025-11-25`, `2025-06-18`. Auto starts with modern `server/discover` and falls back to legacy initialization on an unrecognized HTTP 400. A recognized modern error does not trigger fallback. |
| `gateway.auth` | String maps `headers` and `cookies`. Environment references are expanded and returned to the report redactor. Unset references are errors. |
| `gateway.tools` | `match: fixture_marker` by default. With `match: prefix`, set `prefix` so names follow `<prefix><entry>__argus_fixture_echo` and `<prefix><entry>__argus_fixture_emit`. |
| `fixtures` | Required `control_url`, nonempty `control_token`, and `install_file`. Relative install paths are resolved against the target file's directory. |
| `features.upstream_headers` | Nonempty `names` list of configured credential headers. Probe 2 watches matching install canaries. |
| `features.response_filter` | `action: redact` or `block`, matching the installed rule. |
| `features.webhook` | `stage: pre_call`, `decision: body` (default) or `status`, and documented `allow`/`deny` responses. See the contract examples below. These describe the gateway contract. They do not install the hook. |
| `features.static_oauth_client` | All three keys are required. `grant` is `client_credentials` or `authorization_code`; `consent` is `none`, `follow_url` or `manual`; `trigger` is `challenge` or `manual_restart`. |
| `registration.mode` | Only `manual` is accepted. Hook execution is reserved and unavailable. |
| `timeout_s` | Per-call timeout, default 30, from 0.01 to 3600 seconds. |
| `case_window_s` | Case timing budget, default 10, from 0 to 3600. The fixture host also has its own `serve --case-window-s` drain limit. |

Unknown nested keys and unclaimed feature keys are rejected. Bundled OAuth
support needs no private pack. Fixture plugins can claim additional feature keys;
see [Gateway fixture host](gateway-fixtures.md).

For a body-decided webhook, keep `decision: body` and supply each response's
`status` and `body`, as in the complete target above. Omitting `decision` keeps
this behavior for existing targets. The documented deny body is tested with a
2xx status; empty or malformed responses remain ambiguous-denial tests.

For a status-only webhook that allows 200 and denies every other status, use:

```yaml
features:
  webhook:
    stage: pre_call
    decision: status
    allow: {status: 200, statuses: [200], body: {}}
    deny: {status: 403, body: {}}
```

`status` selects the response sent for the allow or deny control. `statuses`
lists the documented statuses for that decision. The allow set defaults to its
single `status`; the deny set defaults to every other status from 200 through
599. Set `deny.statuses` explicitly if the documentation names only particular
denials, for example `[202, 204, 403]`. Both sets must be nonempty and disjoint,
with distinct integer statuses, and each must include its response's `status`.
The optional body is sent by the fixture but ignored when deciding the verdict.

The `deny_2xx_documented` case uses a documented 2xx deny outside the allow set,
preferring the configured deny status, then 204 or 202. If no such status exists,
the probe is skipped with a reason naming that case. For a contract that allows
every 2xx, list all statuses 200 through 299 under `allow.statuses`; this probe
is not applicable. Allowed statuses with empty or malformed bodies do not count
as authorization bypasses under a status-only contract. Invalid contracts are
rejected when loading the target, before any fixture lease is changed.

`consent: follow_url` is your standing consent to follow URL elicitations. Argus
accepts legacy URL elicitation and error `-32042`, and modern URL input requests
inside MRTR (`InputRequiredResult`). Each URL and redirect must have the exact
configured origin of the gateway or a fixture, compared by scheme, hostname and
port. Navigation has a ten-redirect cap and a timeout. Gateway headers and cookies
attach only on the exact gateway origin. Evidence records origin, route class,
status and query names, without URL values. A bearer credential that permits MCP
calls may not permit browser consent. If gateway-origin navigation returns 401
or 403 without a cookie, Argus keeps the error evidence and suggests configuring
`gateway.auth.cookies` with a valid browser session or using `consent: manual`.
A passing check after manual authorization can reuse its upstream token; the
issuer-binding baseline revokes that token and needs fresh authorization.

`consent: manual` prints the gateway-provided URL and instruction and waits for
Enter after you complete authorization, within `timeout_s`. It skips without a
TTY. Some gateways return HTTP 401 or 403 on `tools/call` after the OAuth case
invalidates a token or changes protected-resource metadata, without a URL
elicitation, a URL in error `-32042`, or an MRTR input request. Argus classifies
this as requiring out-of-band re-authorization and retains the refused request,
redacted response body and sealed fixture records.

For these gateways, set `features.static_oauth_client.consent: manual` and run
interactively. When prompted, open your gateway's own interface and use the
connection/authorization page for the registered upstream entry to re-authorize
it. Complete that authorization, then press Enter in Argus within `timeout_s`.
Argus retries the call once and records the manual step and its timing in
`client.manual_out_of_band`. The same procedure applies to the control and attack
cases, so keep the gateway interface open for the next prompt. Argus does not
automate the gateway's UI or admin API or invent a connect URL.

With `follow_url`, `none`, or a non-TTY run, this condition reports skipped with
"the gateway requires out-of-band re-authorization after the challenge; rerun
interactively with consent: manual". A 401 or 403 before the case changes the
challenge or metadata, a consent-page refusal, and a 5xx response remain errors.
Use `none` for a client-credentials flow that needs no user. If ordinary URL
consent is requested with `none`, the probe skips. `trigger: manual_restart` is accepted as configuration, but the
runner does not restart your gateway or pause to request a restart. The bundled
probe still revokes H tokens and issues challenges. A gateway that does not
rediscover metadata reports skipped; arrange its restart yourself and rerun.

## Check registration and run

With fixtures and gateway running and both token variables set:

```sh
argus-probe validate-target --target gateway.yaml --offline
argus-probe validate-target --target oauth-gateway.yaml --offline
argus-probe gateway-fixtures check --target gateway.yaml
argus-probe list-probes --target gateway.yaml
argus-probe run --local --target gateway.yaml \
  --probes mcp_gateway_client_credential_passthrough --out gateway-report.html
```

Offline validation checks the target shape without contacting the gateway.
`check` discovers and calls every entry in the install. It requires fresh
nonce-correlated contact, successful replies, complete evidence and every
declared installed header canary. A missing installed entry fails the check.
OAuth checks need an already working upstream authorization flow; `check` does
not enable the consent drive step. A successful check does not prove that a
filter or webhook works. The probes establish those controls separately.

`list-probes` lists the seven compatible gateway probes. Use `--probes` with one
ID, a comma-separated list, or `all` to select a run. With a two-origin install,
`--probes all` runs the four non-OAuth probes and skips all three issuer-binding
probes with a reason that the install has no OAuth issuer. Re-run
`gateway-fixtures init --oauth` with a new install file to test issuer binding.
OAuth probes also skip when the target does not declare `static_oauth_client`;
other missing feature keys skip their probes. Skips do not make a run incomplete
or change its exit code. An OAuth install still reports genuine setup errors.
With an OAuth install and target, `all` selects all seven; the mix-up variants
require the authorization-code grant. For OAuth runs, substitute
`oauth-gateway.yaml` in the check, list and run commands. No judge key is needed
for these probes.

## Read the results

| Verdict | Meaning |
| --- | --- |
| `pass` | The probe's controls worked, its attack was exercised, and complete evidence showed no condition that fails or warns. Read the exercised paths; this is not a claim about every gateway feature. |
| `fail` | The controlled test observed the condition described below. |
| `warn` | The test observed a weaker forwarding or filter condition, ambiguous webhook behavior, or persisted permanent redirect. |
| `skipped` | A feature or entry was missing, a control did not work, or the attack was not exercised. It proves no protection. |
| `error` | Infrastructure, authentication, malformed evidence or incomplete capture prevented a reliable result. Positive observations can still fail or warn despite incomplete capture once controls are met. |

Cases use fresh nonces to distinguish test calls from background health checks.
Capture is bounded, including 200 requests per case and 64 KiB bodies. Truncation,
drops and in-flight timeouts prevent a complete miss from passing.

HTTP authentication errors keep the sealed fixture requests and any completed
calls in the finding. The failed call records the HTTP method, MCP method when
available, path class (`mcp`, `auth`, or `other`), status and a redacted response
body. JSON-RPC errors retain only their code and message; other bodies retain
at most 512 UTF-8 bytes after redaction, with a truncation flag. Header names
remain visible in configured-header lists and hit labels; values stay masked.

### Probe 1: static OAuth issuer binding

The basis is MCP 2026-07-28 Client Registration, [Authorization Server
Binding](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration),
and separate registration state in [Authorization Server
Discovery](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/authorization-server-discovery).
The fixture metadata follows [RFC 9728 section 3.3](https://www.rfc-editor.org/rfc/rfc9728.html#section-3.3)
for the resource and [RFC 8414 section 3.3](https://www.rfc-editor.org/rfc/rfc8414.html#section-3.3)
for the issuer. The mix-up variants also check the boundary described by
[RFC 9207 section 2.4](https://www.rfc-editor.org/rfc/rfc9207.html#section-2.4).

All three IDs require `static_oauth_client` and the `oauth` entry. The baseline
revokes cached H tokens, captures a gateway token request to H carrying the
static client ID and secret, and requires R to receive a nonce call with a valid
H token. The attack then changes R's protected-resource metadata to E, revokes H
tokens and makes three calls after delays of 2, 5 and 10 seconds.

| Probe ID | Attack and decision |
| --- | --- |
| `mcp_gateway_upstream_as_binding` | E advertises its own issuer and endpoints. The static secret reaching E's token endpoint fails high. A static client ID alone at E's authorize or token endpoint fails medium. E's own authorize endpoint rejects requests, so an authorization-code flow can expose only the ID here. |
| `mcp_gateway_upstream_as_binding_mixup_iss` | Authorization code only. E advertises H's authorize endpoint and E's token endpoint. H sends its `iss`. An H-issued code with its matching PKCE verifier reaching E fails high; H's code reaching E without a verifier also fails high. An issuer-validating gateway can stop the exchange and pass. |
| `mcp_gateway_upstream_as_binding_mixup_no_iss` | The same mirror setup, but H omits `iss` and does not advertise support. The same code/verifier exposure rules apply. Correct credential binding still protects this case. |

These probes pass only on a complete exercised miss. Failed H controls or no
metadata rediscovery skip. Mirror variants require a gateway fetch of E metadata
and skip for `client_credentials`. None has a warn outcome. Token evidence must
come from the gateway actor. A gateway-generated E authorization URL carried by
the consent agent can establish client ID reuse in the own variant.

### Probe 2: configured headers across redirects

`mcp_gateway_header_cross_origin_redirect` tests `hdr` with declared
`upstream_headers`. The basis is HTTP redirect handling of sensitive fields in
[RFC 9110 section 15.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4)
and MCP [Security best practices, SSRF and redirect target validation](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices).
The fixture offers HTTP 307 and 308 redirects. It does not test 302 or 303.

The direct control must deliver a configured canary to R. The same-origin 307
must be served; if followed, it must retain a configured canary. The cross-origin
attack redirect must be served. Any configured canary reaching E fails high.
Refusing redirects or dropping credentials passes with complete evidence.
Missing controls or port-only origins skip. The summary records whether
`Authorization` reached E separately; dropping it does not protect another
configured header such as `X-API-Key`.

The 308 case runs last, followed by an idle recontact call. If R no longer sees
that call, the result warns that the permanent redirect persisted and asks you
to re-register `hdr`. An observed credential leak retains its fail verdict.

### Probe 3: client credentials passed upstream

`mcp_gateway_client_credential_passthrough` needs no feature key. It requires
`plain` and also tests `hdr` and `oauth` when discovered. The basis is MCP
[Authorization security considerations, Access Token Privilege Restriction](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations)
and the third-party credential rule in [2025-11-25 URL elicitation](https://modelcontextprotocol.io/specification/2025-11-25/client/elicitation).

Each entry has a nonce-contact control and an attack with a synthetic client
header and cookie. Real values from `gateway.auth.headers` and `cookies` are
watched through HMAC digests. A client authentication hit at R's MCP route or a
case-produced E route fails high. Canary-only forwarding warns. An exercised
complete miss passes. Failed controls or no exercised entry skip. Webhook
credential hits and gateway session forwarding are informational and do not
change this verdict.

### Probe 4: response filters on delivery paths

`mcp_gateway_filter_delivery_paths` requires `response_filter` and `plain`.
It tests whether your configured rule covers equivalent tool results and side
channels. The transport basis is [MCP 2025-11-25 Streamable HTTP](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)
and [MCP 2026-07-28 Streamable HTTP](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http).
Those clauses define delivery paths; they do not require your particular filter.

| Path | Era | Role |
| --- | --- | --- |
| `inline_json` | Both | Control tool result in JSON. |
| `post_sse_final` | Both | Equivalent final tool result on POST SSE. |
| `post_sse_notification` | Both | Log notification before a clean final result. |
| `progress_message` | Both | Progress notification's message field. |
| `post_sse_resumed` | Legacy | Final result delivered after GET with `Last-Event-ID`. |
| `get_stream_notification` | Legacy | Notification on a standalone GET stream. |
| `mrtr_input_request` | 2026-07-28 | Elicitation message inside an MRTR `InputRequiredResult`. |

Modern traffic has per-request metadata and mirrored headers, without sessions,
standalone GET or resumption. The two legacy paths remain explicit unserved
observations in modern evidence. Legacy traffic uses initialization and sessions
and leaves MRTR unexercised. A gateway that never opens or resumes GET does not
exercise that path. Client-facing and upstream protocol eras can differ, so read
the served-path witnesses as well as the negotiated client era.

Each path has a separate synthetic marker. `raw` means the exact marker reached
the client, including when its wrapper was removed. `redacted` means the wrapper
arrived without the marker. `blocked` means a JSON-RPC error, `isError`, or empty
content. `absent` means none of those observations arrived. The inline control
must be served and redacted or blocked. A raw inline control skips because the
rule is inactive; an absent inline control errors.

A raw equivalent final result (`post_sse_final` or `post_sse_resumed`) fails
medium. Raw side channels alone warn, including MRTR. A complete run with at
least one served non-control path and no raw marker passes, even when a served
path is classified absent. Inspect `served_by_upstream` and classifications
before interpreting that pass. No served attack path skips.

### Probe 5: webhook decisions

`mcp_gateway_webhook_decision` requires a `webhook` contract and `plain`.
It checks the configured pre-call enforcement contract. [RFC 9110 section
15.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3) defines HTTP 2xx
success; it does not make a webhook body an allow decision. MCP defines no
generic gateway decision-webhook schema, so your documented contract is the
decision basis.

Cases run deny-first: 403 deny, documented deny with a 2xx status, empty 200 then
`{}` in two calls, 204, and documented allow. An already-2xx documented deny
keeps its status; a non-2xx documented deny body is tested with status 200.
The 403 must be consulted and block upstream delivery, and the allow must reach
R with proof that the hook is wired. An earlier correlated attack consultation
and delivery can prove wiring when a cached allow suppresses the final hook call.

A documented deny reaching R fails medium. Only ambiguous replies reaching R
warn. A complete exercised run that enforces the denies passes. Missing wiring,
an ineffective 403 control, a broken allow control or no attack consultation
skips. The gateway must send enough of the tool-call nonce in its webhook body
for fixture correlation; an unrelated webhook health check cannot satisfy it.

## Worked example from a source checkout

The safe and vulnerable reference gateways live in `tests/fixtures/gateway_ref`.
They are test-only and are not in the wheel. They accept only literal loopback
upstream, webhook and redirect destinations. Run this example from the source
checkout with the default non-OAuth install and HTTP fixture server from
"Prepare the fixtures". Do not use the public, compose or TLS alternative
installs for this example.

Save the following as `.scratch/gateway-demo.py`, after creating `.scratch`:

```sh
mkdir -p .scratch
```

```python
import asyncio
import os
from pathlib import Path

import yaml
from argus.gateway_fixtures.install import entry_url, read_install
from gateway_ref.proxy import Entry, Preset, ReferenceGateway


async def main():
    install = read_install("argus-gateway-install.json")
    entries = {
        name: Entry(entry_url(install, name), entry.get("headers", {}))
        for name, entry in install["entries"].items()
    }
    webhook_url = (
        install["origins"]["upstream"]["public"]
        + install["webhook"]["path"].replace("{path_token}", install["path_token"])
    )
    async with ReferenceGateway(entries, preset=Preset.safe(),
                                webhook_url=webhook_url) as safe:
        async with ReferenceGateway(entries, preset=Preset.vulnerable(),
                                    webhook_url=webhook_url) as vulnerable:
            for name, gateway in (("safe", safe), ("vulnerable", vulnerable)):
                spec = {
                    "kind": "mcp_gateway",
                    "sandbox": True,
                    "gateway": {
                        "url": gateway.url,
                        "protocol": "auto",
                        "auth": {"headers": {
                            "Authorization": "Bearer ${ARGUS_GATEWAY_TOKEN}"
                        }},
                    },
                    "fixtures": {
                        "control_url": "http://127.0.0.1:8470",
                        "control_token": "${ARGUS_FIXTURE_TOKEN}",
                        "install_file": "../argus-gateway-install.json",
                    },
                    "features": {
                        "upstream_headers": {"names": ["X-API-Key"]},
                        "response_filter": {"action": "redact"},
                        "webhook": {
                            "stage": "pre_call",
                            "allow": {"status": 200, "body": {"decision": "allow"}},
                            "deny": {"status": 200, "body": {"decision": "deny"}},
                        },
                    },
                }
                path = Path(f".scratch/{name}-gateway.yaml")
                path.write_text(yaml.safe_dump(spec))
                os.chmod(path, 0o600)
                print(f"Ready: {path}", flush=True)
            await asyncio.Event().wait()


asyncio.run(main())
```

Start both gateways in another terminal. They choose ephemeral loopback ports
and write target files with those URLs. Keep this process running:

```sh
PYTHONPATH=tests/fixtures python .scratch/gateway-demo.py
```

In your Argus terminal, use a generated canary as the client credential. These
reference gateways do not authenticate clients. Keep the fixture token set to
the value used by `serve`:

```sh
export ARGUS_GATEWAY_TOKEN="$(python -c 'import secrets; print("argus-canary-client-" + secrets.token_hex(16))')"
argus-probe validate-target --target .scratch/safe-gateway.yaml --offline
argus-probe validate-target --target .scratch/vulnerable-gateway.yaml --offline
argus-probe gateway-fixtures check --target .scratch/safe-gateway.yaml
argus-probe gateway-fixtures check --target .scratch/vulnerable-gateway.yaml
argus-probe run --local --target .scratch/safe-gateway.yaml \
  --probes mcp_gateway_client_credential_passthrough --out .scratch/safe.html
argus-probe run --local --target .scratch/vulnerable-gateway.yaml \
  --probes mcp_gateway_client_credential_passthrough --out .scratch/vulnerable.html
```

The safe report shows pass. The vulnerable report shows fail at high severity
with `auth_header:Authorization` because the gateway copies the client's bearer
credential upstream. Both registration checks pass; this distinguishes working
registration from safe credential handling. This example declares only
`X-API-Key` because the vulnerable gateway replaces the configured upstream
Authorization header with the client header.

You can also select all compatible probes:

```sh
argus-probe run --local --target .scratch/safe-gateway.yaml \
  --probes all \
  --out .scratch/safe-all.html
argus-probe run --local --target .scratch/vulnerable-gateway.yaml \
  --probes all \
  --out .scratch/vulnerable-all.html
```

The safe gateway passes those four probes. The vulnerable gateway fails them;
probe 2 observes `X-API-Key` at E even though the HTTP client drops Authorization
across the host change. Both runs skip the three OAuth probes because this
two-origin install has no issuer. The reference OAuth strategy and its issuer-binding comparisons
are documented in the source checkout's
[reference gateway README](https://github.com/gy15901580825/Argus/blob/main/tests/fixtures/gateway_ref/README.md).

Stop the reference gateways and fixture server with Ctrl-C when finished. Remove
the fixture registrations and filter/webhook rules from your test gateway, and
revoke its test credential. There is no `gateway-fixtures uninstall` command.
