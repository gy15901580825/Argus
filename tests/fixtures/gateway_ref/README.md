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

Override `upstream_headers(entry_name)` for a later upstream authentication
strategy. Authentication state and flows are not implemented here.
