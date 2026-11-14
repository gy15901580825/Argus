# Re-render a run you already stored

Every `run` in server mode stores the run on the server it was submitted to.
`argus-probe report` renders another format from that stored run, so you can add
SARIF for code scanning or JUnit for a CI job without pointing Argus at the
agent again.

## What you need

- a run you already submitted to a server implementing the `/api/v1/redteam`
  API, and its run id
- `ARGUS_API_URL` and `ARGUS_API_TOKEN` exported, or the same values passed as
  flags (see [step 3 of the quickstart](./quickstart.md#3-get-an-api-token-server-mode))

## Command

```bash
argus-probe report \
  --run-id <run-id> \
  --format sarif \
  --out report.sarif \
  --api-url https://<your-server> \
  --token "<your token>"
```

On success it prints `Wrote sarif report for run <run-id> to report.sarif`.

## Flags

| Flag | Purpose |
|---|---|
| `--run-id` | required; the id of the stored run |
| `--format` | `html` (default), `sarif` or `junit` |
| `--out` | required; the file the report is written to |
| `--token` | API token (or set `ARGUS_API_TOKEN`) |
| `--api-url` | server base URL (or set `ARGUS_API_URL`) |

## The output name is yours

`--format` changes the report the server renders; `--out` is the path it lands
on. Nothing rewrites the extension for you, so pick the one your consumer
expects:

```bash
argus-probe report --run-id <run-id> --format html  --out report.html
argus-probe report --run-id <run-id> --format sarif --out report.sarif   # code scanning
argus-probe report --run-id <run-id> --format junit --out report.xml     # CI test reporting
```

## This needs a server-stored run

The command reads the run from the API. It does not take a local `run.json`:
a run started with `--local` never leaves your machine, so the server has
nothing to render. If you ran locally and now want SARIF, submit the run in
server mode (`run` without `--local`) and use that run id.

## Common use

Fetch SARIF for a run from last week and hand it to code scanning, or re-render
the HTML you deleted, without spending judge or attacker calls a second time.
