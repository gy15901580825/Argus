# client_agent

The client agent runs browser_use probes. It connects to the orchestrator's WebSocket hub (`/agent/connect`), serves each adversarial scenario page (on localhost by default), and drives your browser agent at the target's `agent_url`.

In each `redteam_browser_probe` message, `prompt` is the user's instruction sent to your agent, and `payload` is the hostile scenario rendered into the trap page. Never treat `payload` as the instruction.

The message can also carry `trap_host`, `trap_port` and `trap_public_url` from the target spec. The client agent then listens on that address and port, and gives your agent `trap_public_url` followed by a random path token and `/scenario`. Requests without the token get a 404, so nobody who only finds the port can load the page or post to the sink. Set them when your browser agent runs on another host or in a container and can't open `127.0.0.1` on this machine. The [target spec cookbook](../docs/onboarding/target-spec-cookbook.md#browser_use) explains each field. The reply includes `trap_url`, the URL the agent was given, so the orchestrator can check the settings were used.

The reply also includes `trap_evidence`: how often your agent loaded the trap page and every request it sent to the trap's sink (method, path, query, body and whether the body arrived whole). The orchestrator decides browser probes from it. Use a client agent from the same release as the orchestrator: an older one sends no `trap_evidence` or sends it in the old shape, and every browser probe then ends as an `error` finding that asks you to upgrade it. The client agent's log shows only how many requests the sink recorded, never their bodies, because a body can hold credentials your browser autofilled.

You only need it in server mode. `argus-probe run --local` runs `browser_use` targets on your machine with no server and no client agent. In server mode, a browser_use run needs a server implementing the `/api/v1/redteam` API, backed by the orchestrator, with this client agent connected to that orchestrator. This repo does not ship such a server; the self-hosted stack is at tag `v0.3-full`.

## Direct mode (no registration)

Connect straight to the orchestrator. `--agent-name` is used as the agent id, and a second agent with the same id is refused while the first is connected. If an agent drops without closing its socket, the orchestrator's WebSocket pings clear the old connection within about 40 seconds, after which the same id can reconnect.

Whoever can reach `/agent/connect` can act as an agent and receive probe payloads. Set the same `AGENT_CONNECT_SECRET` on the orchestrator and the client agent so only agents that know it are accepted. The orchestrator listens on `127.0.0.1` by default. For a client agent on another machine, start it with `ARGUS_SERVER_HOST=0.0.0.0`, `AGENT_CONNECT_SECRET` and `ARGUS_SERVER_TOKEN` (a different value, for callers of `/redteam/*`); off loopback it refuses to start without both. On loopback, a missing secret only logs a warning. See [services.md](../docs/reference/services.md#orchestrator-python--m-argusserver-port-8080).

```bash
pip install -r client_agent/requirements.txt && playwright install chromium
export AGENT_CONNECT_SECRET=<shared secret>      # same value as on the orchestrator
python -m client_agent.client_agent --orchestrator-url ws://<orchestrator-host>:8080 --agent-name my-browser-agent
```

```bash
docker run -e ORCHESTRATOR_URL=ws://<orchestrator-host>:8080 \
           -e AGENT_NAME=my-browser-agent \
           -e AGENT_CONNECT_SECRET=<shared secret> \
           <your-gh-user>/client_agent:latest
```

## Register mode

If your server registers agents first, also pass `--api-service-url` and credentials. The agent then uses the id the server returns.

```bash
export AGENT_PASSWORD=<password>                     # or: export AGENT_API_TOKEN=<token>
export AGENT_CONNECT_SECRET=<shared secret>          # same value as on the orchestrator
python -m client_agent.client_agent --orchestrator-url wss://<orchestrator-host> \
    --api-service-url https://<your-server> --agent-name my-browser-agent \
    --username <username>
```

Pass the password, token and agent secret through these environment variables rather than flags: command-line arguments are visible to other users in `ps`. TLS certificates of the server are verified.

```bash
docker run -e ORCHESTRATOR_URL=wss://<orchestrator-host> \
           -e API_SERVICE_URL=https://<your-server> \
           -e AGENT_NAME=my-browser-agent \
           -e USERNAME=<username> \
           -e PASSWORD=<password> \
           -e AGENT_CONNECT_SECRET=<shared secret> \
           <your-gh-user>/client_agent:latest
```

## Declarative browser transport

Run the module from the repository root. Direct script startup also resolves the
repository's shared `argus_transport` package. Build the client image from that same
root, so the image contains both the service and the shared package:

```bash
docker build --network host --file "$PWD/client_agent/Dockerfile" --tag client-agent:local .
```

Clients advertise `transport_versions: [1]` on each WebSocket connection. The
orchestrator rejects declarative browser requests before sending a probe when
the connected client lacks version 1. Legacy `agent_url` targets retain their
existing request format and timeout.

Clients also advertise `scenarios`: each browser scenario kind they serve and the options it accepts. The orchestrator skips a probe whose kind or option the connected client does not list, with a reason that asks you to upgrade the client agent; nothing is sent to the client for it. A client that sends no `scenarios`, such as 1.12.0, is treated as serving the 1.12.0 set, so only the `dom_injection` probes with a `placement` skip on it.

Remote transport requests cannot authorize their own secret references or private
network destinations. At startup, the operator must explicitly allow each secret
directory, environment variable name, and private HTTP origin. The defaults deny
file and environment secrets and private addresses. These options are repeatable:

```bash
python -m client_agent.client_agent --orchestrator-url ws://127.0.0.1:8080     --transport-secret-root /run/agent-secrets     --transport-env-name TARGET_CREDENTIAL     --transport-origin http://127.0.0.1:18100
```

A secret root allows bounded regular files below that directory; mount only the
needed files read-only. An origin authorizes the exact scheme, host, and port.
Docker operators can append the same options after the image name. Keep
orchestrator authentication separate from target transport credentials.

Successful, refused, failed, and timed-out target requests return a normal RPC
result containing `transport_result`, `trap_evidence`, and `trap_url`. Logs retain
only the RPC method, id, outcome, and trap counts. They omit prompts, target
answers, metadata, and sink bodies. Unexpected execution exceptions produce a
matching RPC error with a fixed message.
