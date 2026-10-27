# client_agent

The client agent runs browser_use probes. It connects to the orchestrator's WebSocket hub (`/agent/connect`), serves each adversarial scenario page on localhost, and drives your browser agent at the target's `agent_url`.

You only need it in server mode. `argus-probe run --local` runs `browser_use` targets on your machine with no server and no client agent. In server mode, a browser_use run needs a server implementing the `/api/v1/redteam` API, backed by the orchestrator, with this client agent connected to that orchestrator. This repo does not ship such a server; the self-hosted stack is at tag `v0.3-full`.

## Direct mode (no registration)

Connect straight to the orchestrator. `--agent-name` is used as the agent id, and a second agent with the same id is refused while the first is connected. If an agent drops without closing its socket, the orchestrator's WebSocket pings clear the old connection within about 40 seconds, after which the same id can reconnect.

Whoever can reach `/agent/connect` can act as an agent and receive probe payloads. Set the same `AGENT_CONNECT_SECRET` on the orchestrator and the client agent so only agents that know it are accepted, and keep the orchestrator on localhost or a trusted network. Without the secret the orchestrator logs a warning at startup.

```bash
pip install -r requirements.txt && playwright install chromium
export AGENT_CONNECT_SECRET=<shared secret>      # same value as on the orchestrator
python client_agent.py --orchestrator-url ws://<orchestrator-host>:8080 --agent-name my-browser-agent
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
python client_agent.py --orchestrator-url wss://<orchestrator-host> \
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
           <your-gh-user>/client_agent:latest
```
