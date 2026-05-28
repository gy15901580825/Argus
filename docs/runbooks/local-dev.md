# Local Development

## Python services (api_service, orchestrator, client_agent, testing_*)

```bash
cd <service>
pip install -r requirements.txt
python server.py              # or python client_agent.py for client_agent
```

## Frontend

```bash
cd frontend
npm install
npm run dev       # Dev server with Turbopack (localhost:3000)
npm run build     # Production build
npm run test      # Vitest unit tests
npm run test:e2e  # Playwright e2e tests
npm run lint      # ESLint
```

## Database Migrations

```bash
cd database
flyway migrate    # Uses flyway.toml for connection config
```

Note: production PostgreSQL (`<YOUR_PG_SERVER>`) has `publicNetworkAccess=Disabled` — Flyway against prod/dev must run from an in-cluster pod, not your laptop.
