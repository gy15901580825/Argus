# Local Development

## The argus package (engine, CLI and orchestrator server)

```bash
pip install -e ".[dev]"        # dev includes the server extra's websockets
argus-probe quickstart
python -m pytest -q           # from the repo root or from tests/
lint-imports
python -m argus.server        # the /redteam API and the /agent/connect hub, on 127.0.0.1:$PORT (default 8080)
```

## Other Python services (client_agent, demo_target, payment_testbed, mcp_testbed)

```bash
cd <service>
pip install -r requirements.txt
python client_agent.py        # client_agent only
```

`demo_target`, `payment_testbed` and `mcp_testbed` are FastAPI apps; run them with `uvicorn` (see each Dockerfile's `CMD`).

The REST API, web UI and database migrations were removed after tag `v0.3-full`. Check out that tag to run the full self-hosted stack.

## Target address policy for a shared service

Set `ARGUS_TARGET_ADDRESS_POLICY=public_only` before starting Argus to refuse
built-in target connections to any non-global address, including loopback,
private networks, link-local addresses, unspecified addresses, shared address
space, and multicast. IPv4-mapped, IPv4-compatible, IPv4-translated,
and well-known NAT64 IPv6 addresses use the embedded IPv4 classification.
A hostname with any non-global DNS answer is refused. Argus checks at connection
time and connects only to an address it checked; redirects and retries use the
same guard. Refusals appear as target errors in reports, never probe passes or
fails. Unknown values stop startup; unset or empty leaves the policy off.
When on, CLI and server startup also verify that a guarded loopback request is
refused, and stop if enforcement is unavailable.

This covers HTTP target adapters, transport submit/poll/setup/provision/cleanup
and follow-up URLs, server checks, HTTP MCP sessions, browser-agent HTTP delivery,
hosted trap control calls, native target SDK connections, and gRPC targets.
`web_chat` is refused at construction under `public_only`, including nested
target specs, because its browser navigation cannot use the shared socket guard.
When enabled, target HTTP clients and gRPC channels connect directly and ignore
environment proxies so a proxy cannot resolve an unchecked destination.
Target HTTP clients use `trust_env=False`, which also ignores `SSL_CERT_FILE`,
`SSL_CERT_DIR`, and netrc authentication. Only the first checked address is dialed;
there is no happy-eyeballs fallback to another DNS answer. Explicit
proxy, mount, and custom transport options are unavailable with this policy.
Supplied transport-engine clients must use the shared guarded client factory.
The server reads configuration from environment variables and has no separate settings object, so this variable
is also its server option.

The policy does not cover judge or attacker provider calls, page fetches made by
browser agents, the local trap server, or the operator-configured witness relay
upstream (witness probes already skip in server mode). Trusted Python targets,
plugins, and external agents execute their own code and need separate network
isolation. The default remains suitable for local CLI runs against loopback.
