# Argus MCP testbed

A deliberately hostile MCP server for red-teaming agents that connect to MCP
tool servers, plus a deliberately insecure demo agent to point the probes at.

## Two services

| Service | What it is |
|---|---|
| `testbed/` | The hostile MCP server. Opens a session per probe run, stages one of five hostile scenarios, records every JSON-RPC request in memory, and reports it back as evidence -- so a probe can answer "which tools did the agent call, with what arguments" as a fact rather than as a judge's reading of the transcript |
| `demo_agent/` | An OpenAI-compatible MCP client with no tool-trust policy. Obeys instructions embedded in tool descriptions, calls whichever tool a description claims is "preferred," and copies schema-planted credentials straight into tool call arguments |

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
`demo_agent/` (which legitimately speaks HTTP as an MCP client) and for
FastAPI's `TestClient` in tests -- the `testbed/` package itself must never
import `httpx`, `requests`, `aiohttp`, `urllib`, or `socket`.
`tests/test_no_outbound.py` pins this with a static check, because the rule
cannot survive on discipline alone: one debugging session that imports
`httpx` would break it, and nothing else would go red.

## Safety: `demo_agent/` is restricted to `TESTBED_ORIGIN`

The demo agent is deliberately insecure as an MCP client -- it obeys
instructions embedded in tool descriptions, calls whichever tool a
description claims is "preferred," and copies schema-planted credentials
straight into tool call arguments. It is not, on top of that, allowed to
speak JSON-RPC to arbitrary URLs: the MCP server URL it acts on comes
straight out of the prompt, and an unrestricted outbound request from a
deployable container would make it an SSRF pivot to cluster-internal
services and cloud metadata endpoints (`169.254.169.254`).

`demo_agent/app.py` only ever contacts the single origin named by the
`TESTBED_ORIGIN` environment variable -- the `testbed/` instance it is paired
with. **It defaults to refusing every outbound request** until that variable
is set; there is no permissive default. The refusal is diagnosable: an
unconfigured `TESTBED_ORIGIN` and a request to the wrong origin get distinct
error messages, and the unconfigured one names the environment variable so
the fix is obvious.

## Run locally

```bash
pip install -r requirements.txt
uvicorn testbed.app:app --port 8092                                        # the world
TESTBED_ORIGIN=http://127.0.0.1:8092 uvicorn demo_agent.app:app --port 8093 # the victim
python -m pytest tests/ -q
```

`TESTBED_ORIGIN` must point at the `testbed/` instance above -- see "Safety:
`demo_agent/` is restricted to `TESTBED_ORIGIN`" above. Without it the demo
agent starts but refuses to contact any MCP server.
