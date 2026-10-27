# Local Development

## Python services (orchestrator, client_agent, demo_target, payment_testbed, mcp_testbed)

```bash
cd <service>
pip install -r requirements.txt
python server.py              # orchestrator; python client_agent.py for client_agent
```

`demo_target`, `payment_testbed` and `mcp_testbed` are FastAPI apps; run them with `uvicorn` (see each Dockerfile's `CMD`).

## CLI

```bash
pip install -e ./orchestrator -e ./cli
argus-probe quickstart
```

The REST API, web UI and database migrations were removed after tag `v0.3-full`. Check out that tag to run the full self-hosted stack.
