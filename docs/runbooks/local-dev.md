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
