# Framework coverage

`argus-probe coverage` shows what the probe library covers, per framework
standard. It asks a compatible server for its coverage manifest and runs no
probes, so it costs nothing: you can ask what is covered before paying for a
scan. Closed standards list every cell, including the empty ones — silently
omitting what is not covered would invert the point of the command. Open
standards list only the cells a probe maps to or a finding touched.

## Server and token

The command needs a server and a token:

```bash
argus-probe coverage --api-url https://your-server.example --token $ARGUS_API_TOKEN
```

- `--api-url` is the base URL of a server implementing the `/api/v1/redteam`
  API (the command calls `GET /api/v1/redteam/coverage`). It can also come
  from the `ARGUS_API_URL` environment variable.
- `--token` is the API token, sent as the `x-api-token` header. It can also
  come from the `ARGUS_API_TOKEN` environment variable.
- Both are required.

## Standards

By default the command prints all five standards, the known ones first and
then any extra standards the server reports, in the server's order:

- `owasp-llm-top10`
- `owasp-agentic-top10`
- `mitre-atlas`
- `nist-ai-rmf`
- `eu-ai-act`

Show one standard with `--standard`:

```bash
argus-probe coverage --standard owasp-llm-top10
argus-probe coverage --standard mitre-atlas --json
```

An unknown `--standard` value is rejected. A known standard the server does
not report fails with `Standard '<name>' is not reported by server.` — it
never silently prints an empty table.

## Reading the output

Each standard prints a heading with its universe, then one line per cell
(example output below; the counts vary by release):

```text
owasp-llm-top10 (closed universe)
  LLM01    Prompt Injection                         135 probes  covered
  LLM03    Supply Chain                              17 probes  covered
  LLM08    Vector and Embedding Weaknesses            1 probes  thin
```

The totals line at the end prints the whole library (example counts; the
numbers vary by release):

```text
329 probes in library, 0 run this scan
```

| Field | Meaning |
|---|---|
| `universe` | `closed` means the standard has a fixed set of cells and every one is listed, even with zero probes (OWASP LLM Top 10, LLM01–LLM10, and OWASP Agentic Top 10, ASI01–ASI10). `open` means a cell appears only when a probe maps to it or a finding touched it (MITRE ATLAS, NIST AI RMF, EU AI Act). |
| `probes_in_library` | How many probes in the library map to this cell. |
| `probes_run` | How many probes came back with a tested verdict (`pass`, `fail` or `warn`). Skipped, blocked, aborted or errored probes do not count. |
| `library_status` | `absent` means no probe maps here, `thin` means 1–2 probes map here, `covered` means more than 2. The status describes the library only — it says nothing about what happened in any run. |

## JSON output

`--json` emits the raw coverage manifest as JSON instead of the text table,
and `--standard` filters that manifest to the one standard. Each cell in the
manifest also carries `run_status` and `verdicts`, which the text output does
not show. See `argus/coverage.py` for how the statuses are derived.

## Limits

Library coverage is not a compliance claim. A cell marked `covered` means
probes exist for it, not that a target is safe; a cell marked `absent` or
`thin` is a gap in the library, shown on purpose so it is not mistaken for
coverage. For the per-probe breakdown behind these counts, see the generated
[Probe mappings](../probe-mapping.md) table.
