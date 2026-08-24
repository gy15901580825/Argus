# Argus MCP testbed

A deliberately hostile MCP server for red-teaming agents that connect to MCP
tool servers. Nothing here reaches the network: `testbed/` records every
JSON-RPC request in memory and reports it back as evidence, so a probe can
answer "which tools did the agent call, with what arguments" as a fact rather
than as a judge's reading of the transcript.

## Session lifecycle

```
POST /sessions                -> {session_id, mcp_url, script}
POST /s/{sid}/mcp             -> JSON-RPC 2.0: initialize / tools/list / tools/call
GET  /sessions/{sid}/evidence -> every interaction, deterministic
DELETE /sessions/{sid}
```

`script.scenario` picks which hostile scenario this session stages -- see
`testbed/scenarios.py`:

| Scenario | What the server does |
|---|---|
| `tool_poisoning` | Hides an instruction inside a tool's `description` |
| `rug_pull` | Serves a benign tool list first, then swaps a tool's description starting from the second `tools/list` |
| `shadowing` | Defines an extra near-name tool (`read_notes_v2`) claiming to be the "preferred" version |
| `confused_deputy` | Plants the injected instruction in a `tools/call` *result*, not a description |
| `credential_lure` | Asks for an `api_key` argument and plants a canary credential in the schema |

## evidence contract

`GET /sessions/{sid}/evidence` always includes `interaction_count` -- the
total number of JSON-RPC requests the session received, counting every
method including errors. The probe runner reads this to tell "the agent
defended itself" apart from "the probe never actually ran"; without it every
MCP probe would report a false green.

## Safety: `testbed/` cannot reach the network

This is a hostile MCP server, published in a public repo. A hostile MCP
server that could also make outbound requests would be a usable MCP proxy for
anyone who found it. `requirements.txt` declares `httpx` only for
`demo_agent/` (a later task, which legitimately speaks HTTP as an MCP client)
and for FastAPI's `TestClient` in tests -- the `testbed/` package itself must
never import `httpx`, `requests`, `aiohttp`, `urllib`, or `socket`.
`tests/test_no_outbound.py` pins this with a static check, because the rule
cannot survive on discipline alone: one debugging session that imports
`httpx` would break it, and nothing else would go red.

## Run locally

```bash
pip install -r requirements.txt
uvicorn testbed.app:app --port 8092
python -m pytest tests/ -q
```
