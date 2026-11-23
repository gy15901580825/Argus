# Re-render a run you already have

`argus-probe report` writes HTML, SARIF or JUnit from a local `run.json` or a
server-stored run. You can add code scanning or a report for people without
sending the attacks again.

## Local run.json

Save the scan as a run record, then render as many reports as you need:

```bash
argus-probe run --local --target target.json --probes all --out run.json
argus-probe report --from run.json --out report.html
argus-probe report --from run.json --out report.sarif
argus-probe report --from run.json --out report.xml
```

`report --from` reads only the file. It needs no target, judge key, API
token or server URL and makes no network calls. `run.json` is already redacted;
the reports retain its masking. Keep the record even if the scan exits non-zero
after writing it.

An unreadable file, invalid JSON, missing `schema_version`, or an unsupported
version exits 1 with an error before writing a report. This build accepts
`argus.run/1`; see [the record format](../run-json.md).

The record does not store the original process exit code or `--fail-on`
policy. Re-rendered SARIF uses the existing renderer's status fallback:
`exitCode` is 0 for `completed`, otherwise 1. It does not reproduce the scan's
severity gate exit 3 or cost-cap exit 4. Findings, notes and coverage remain in
the report. A successful `report` command exits 0 even for an incomplete scan.

## Server-stored run

Every `run` in server mode stores the run on the server it was submitted to.
Use `--run-id` to fetch another report from that server.

### What you need

- a run you already submitted to a server implementing the `/api/v1/redteam`
  API, and its run id
- `ARGUS_API_URL` and `ARGUS_API_TOKEN` exported, or the same values passed as
  flags (see [step 3 of the quickstart](./quickstart.md#3-get-an-api-token-server-mode))

### Command

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
| `--from` | local `run.json` path; use exactly one of `--from` or `--run-id` |
| `--run-id` | id of the server-stored run |
| `--format` | `html`, `sarif` or `junit`; inferred from `--out` when omitted (HTML for other extensions) |
| `--out` | required; the file the report is written to |
| `--token` | required with `--run-id`; API token (or set `ARGUS_API_TOKEN`) |
| `--api-url` | required with `--run-id`; server base URL (or set `ARGUS_API_URL`) |

## The output name is yours

When `--format` is omitted, `.html`, `.sarif` and `.xml` select HTML, SARIF
and JUnit respectively. Other extensions default to HTML. An explicit format
that disagrees with a recognized extension exits 2. `report` does not write
JSON; save the record with `run --local --out run.json`.

```bash
argus-probe report --run-id <run-id> --format html  --out report.html
argus-probe report --run-id <run-id> --format sarif --out report.sarif   # code scanning
argus-probe report --run-id <run-id> --format junit --out report.xml     # CI test reporting
```

## Common use

Fetch SARIF for a run from last week and hand it to code scanning, or re-render
the HTML you deleted, without spending judge or attacker calls a second time.
