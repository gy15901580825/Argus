# demo_target

Deliberately-vulnerable chatbot used as a public demo target for `argus-probe`.

⚠️ **This service has no security hardening by design.** The system prompt
contains fake "secrets" so prompt-injection probes produce visible findings.
Do not use this for any real workload.

## Endpoint

`POST /chat` with body `{"message": "..."}` returns `{"reply": "..."}`.

Include optional `history` to continue a conversation:

```json
{
  "message": "What about weekends?",
  "history": [
    {"role": "user", "content": "When is support open?"},
    {"role": "assistant", "content": "Monday to Friday."}
  ]
}
```

History defaults to an empty list. It accepts at most 40 turns, each with a
`role` of `user` or `assistant` and a string `content`. User turns are limited to
4000 characters, the same limit as `message`. Assistant turns have no separate
per-turn limit; they are bounded by the 32000-character total history limit.
A long conversation can still exceed that total and return HTTP 422.
Invalid history returns HTTP 422. The model receives the system prompt, the
history in order, and then the current message. Layer 1 keyword triggers inspect only the current message.
The service keeps no server-side conversation state; send prior turns on each request.

`DEMO_MAX_COMPLETION_TOKENS` sets the completion cap for both providers and
defaults to 300. Reasoning deployments may need a higher cap.

## Argus target spec

Save this transport v2 spec as `target.json` and pass it to
`argus-probe run --local --target target.json --probes all --mode deep --out report.html`:

```json
{
  "kind": "custom_http",
  "transport": {
    "version": 2,
    "request": {
      "method": "POST",
      "url": "https://demo.example.com/chat",
      "headers": {"Content-Type": "application/json"},
      "body": {
        "json": {
          "message": {"context": "prompt"},
          "history": {"context": "history"}
        }
      }
    },
    "auth": {"kind": "none"},
    "response": {
      "format": "json",
      "text": {"paths": ["$.reply"], "cast": "string", "empty": "error"},
      "metadata": {}
    },
    "outcome": {
      "kind": "rules",
      "unmatched": "target_error",
      "rules": [{"id": "completed", "priority": 10, "http_status": [200], "when": {"path": "$.reply", "exists": true}, "outcome": "succeeded"}]
    },
    "delivery": {"kind": "sync"},
    "timeout": {"total_deadline_s": 60, "read_s": 60},
    "session": {"mode": "none"},
    "limits": {"response_bytes": 1048576, "event_bytes": 1048576, "max_events": 1024, "max_rules": 32}
  }
}
```

The `{"context": "history"}` expression sends prior user and assistant turns
and enables history support in the adapter. A spec without that expression
and with session mode `none` makes deep rounds independent. Use this spec with
a deployment that supports the optional history field.

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

Served from `https://demo.example.com/chat`. Rate-limited to 30 req/min/IP.
