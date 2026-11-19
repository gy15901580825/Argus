# Reference gateway for offline tests

`ReferenceGateway(entries, preset=Preset.safe())` is an async context manager.
Its `url` is a legacy Streamable HTTP MCP endpoint on an ephemeral loopback port.
Unsupported protocol headers receive a fixed HTTP 400 so clients can fall back
to legacy initialization.
Entries are `Entry(url, headers)` values; discovered tool names become
`<entry>__<upstream-tool>`, while descriptions and schemas retain fixture markers.
The proxy exposes one client session and tracks each upstream's session separately.
POST SSE, standalone GET streams, and GET resumption use the same relay; event IDs
are prefixed with the entry name so resumption reaches the correct upstream.

`Preset.vulnerable()` follows redirects with httpx's header policy, copies client
Authorization and Cookie, redacts JSON responses only, and accepts any webhook
2xx. `Preset.safe()` drops all configured headers when the origin changes, never
copies client credentials, redacts every JSON-RPC message on JSON and SSE channels,
and requires the documented webhook allow status and JSON body. Change individual
fields with `dataclasses.replace`. Redirects also support `no_follow`, and the
filter supports `off` for inactive-filter controls. Webhook defaults are status 200
and `{"decision": "allow"}`; `allow_status` and `allow_body` configure the contract.
Set `cache_allow=True` to retain the first accepted webhook decision across calls.
The webhook probe runs deny cases before its allow control to avoid that cache.

httpx itself drops Authorization across the host change exercised by the tests;
X-API-Key survives in the vulnerable preset. Both observations come from the
fixture recorder. Filter tests return the received text in a subsequent tool call,
so R's redacted hit labels also show whether the client received an unfiltered
marker. This client feedback is test traffic, not proxy instrumentation.

Every upstream, webhook, and redirect destination must use a literal loopback IP.
Hostnames are refused to avoid DNS resolution changing the destination. Outbound
clients ignore environment proxies. The package stays under `tests/`, outside the
wheel's `argus*` package discovery. `support.py` provides case behaviors only for
these tests; production fixture behaviors belong to later units.

`oauth.OAuthReferenceGateway(entries, clients={entry: StaticClient(issuer,
client_id, client_secret, grant)}, strategy="issuer")` adds static upstream
OAuth. The default grant is `client_credentials`; `authorization_code` uses
S256 and the issuer fixture's automatic approval. The test client reads the
authorization redirect directly and validates its callback, state and `iss`
before the token exchange; interactive consent driving is a separate unit.

`strategy="entry"` keys credentials and tokens by upstream entry and reuses
the credentials with the server named by current protected-resource metadata.
`strategy="issuer"` keys registrations by their configured issuer and tokens
by issuer and resource. It refuses a changed authorization server before sending
client credentials, following MCP 2026-07-28 Authorization Server Binding.
It validates every present authorization-response `iss`, including when metadata
does not advertise it, and requires `iss` when advertised, following RFC 9207.
Both strategies re-read metadata after a 401, validate the metadata resource and
issuer, and return fixed JSON-RPC errors when authorization fails. Metadata,
authorization and token endpoints must use literal loopback IPs; redirects are
never automatically followed. A second honest issuer tests metadata switching
without depending on foreign-AS modes. Additional comparisons use the passive
foreign fixture's `own` and `mirror_authorize` modes, including H-issued code
correlations and S256 matches at its token endpoint. Own mode rejects authorize
requests, so the authorization-code comparison observes client ID reuse there;
mirror mode also observes the canary secret at the token endpoint.
No OAuth probe or target consent step is added here.
