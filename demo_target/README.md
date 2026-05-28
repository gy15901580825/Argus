# demo_target

Deliberately-vulnerable chatbot used as a public demo target for `argus-probe`.

⚠️ **This service has no security hardening by design.** The system prompt
contains fake "secrets" so prompt-injection probes produce visible findings.
Do not use this for any real workload.

## Endpoint

`POST /chat` with body `{"message": "..."}` returns `{"reply": "..."}`.

## Local run

```bash
pip install -r requirements.txt
export AZURE_API_KEY=...
export AZURE_API_BASE=https://openai-argus.openai.azure.com/
uvicorn app:app --host 0.0.0.0 --port 8000
```

## Docker

```bash
docker build -t argus/demo_target:dev .
docker run -p 8000:8000 \
  -e AZURE_API_KEY=$AZURE_API_KEY \
  -e AZURE_API_BASE=$AZURE_API_BASE \
  argus/demo_target:dev
```

## Production

Deployed via Helm chart at `kubernets/charts/demo_target/`,
served from `https://demo.example.com/chat`. Rate-limited to 30 req/min/IP.
