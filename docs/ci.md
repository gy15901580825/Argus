# Run Argus in CI

These recipes use argus-probe 1.18.0 and Python 3.11. Commit an
`argus-target.json` that points at a test agent reachable from your runner. See
[the target spec cookbook](onboarding/target-spec-cookbook.md) for other transports.
For an OpenAI-compatible agent, start with this and replace the URL and model:

```json
{
  "kind": "openai_compat",
  "endpoint_url": "https://agent.example.test/v1/chat/completions",
  "model": "agent",
  "timeout_s": 15
}
```

If your agent requires authentication, add `"api_key": "${AGENT_API_KEY}"` and
bind `AGENT_API_KEY` from your CI secret store. Agent credentials and judge
credentials are separate. Do not put either key in the target file.

## Keys, cost and the gate

The examples select `--probes all`, which runs every non-opt-in probe that fits
this target kind. They include `--skip-judged`: without a judge key, probes that
need a judge are reported as skipped, and deterministic probes still run. If
all selected probes need a judge, the command exits 1 even with this flag.
Skipped probes are not passes. Check the report to see which probes ran.

Set `ANTHROPIC_API_KEY` in your CI secret store to include judged probes. For an
OpenAI judge, bind `OPENAI_API_KEY` instead; when it is the only judge key,
Argus selects OpenAI automatically. If both are present, choose with
`--judge-provider openai` or `--judge-provider anthropic`. Remove `--skip-judged`
(or set the Action input to `"false"`) when a missing judge key should fail CI.
Do not expose keys to untrusted pull requests. GitHub fork and Dependabot PRs
receive no repository secrets. The GitHub jobs below skip those runs, matching
the generated workflow guard. Trusted jobs without a judge key can still run
deterministic probes with `--skip-judged`. Your target may need its own credentials.

`--per-run-cap 0.50` caps the estimated USD judge/attacker spend for one scan.
A scan whose estimate exceeds the cap refuses to start. During a scan, Argus
stops when a completed call reaches the cap; a completed call can take spend
past it. This is not a hard billing limit and does not cover your agent's own
model costs. Static mode defaults to $0.50 and deep mode to $5.00; the examples
set the cap explicitly.

`--fail-on high` exits 3 for a `fail` finding at high or critical severity.
Accepted thresholds, in order, are `info`, `low`, `medium`, `high`, `critical`.
Without `--fail-on`, failing findings alone do not fail the CLI. The Action
defaults to `fail-on: critical`, so these recipes set their threshold explicitly.

The current source CLI ends each completed run with counts per verdict and the
exit rule in force. With no `--fail-on`, the line explains that findings alone
leave exit 0 and names the flag to gate CI. Counts include individual trials.
The pinned 1.18.0 recipes predate this summary and the missing-baseline handling
described below; those changes require a CLI build containing the first-use fixes.

| CLI exit | Meaning | Report |
| --- | --- | --- |
| 0 | Completed; no failure met the selected gate. Without a gate, failures can still exist. | Written. |
| 1 | Error or incomplete run, including a missing required judge key. Takes priority over 3. | Written if the scan reached findings; startup failures may leave none. |
| 2 | Usage error, such as an unknown probe or a missing output directory. | Not written. |
| 3 | Completed, but a failing finding met `--fail-on`. | Written before exit. |
| 4 | Cost cap refused or stopped the scan. Takes priority over 1 and 3. | None for a refusal before starting; partial report for a stop during the scan. |
| 130 / 143 | Interrupted or terminated, for example by a CI timeout. | Not written. |

Publish reports even when the scan fails, and preserve its exit code. A report
may be absent after startup failure or cancellation. Each scan in 1.18.0 writes
one `--format`; SARIF and JUnit together require two scans, each with its own
cost cap. JUnit represents failures and errors regardless of `--fail-on`, so a
CI test publisher can impose a stricter policy than the CLI. The Azure and
Jenkins examples leave the severity gate to the CLI.

## Compare local runs in CI

Save a main-branch run.json as a CI artifact, then download it as `baseline.json`
in the pull-request job. Compare locally without a server:

```bash
argus-probe run --local --target argus-target.json --probes all --skip-judged --per-run-cap 0.50 \
  --format json --out main-run.json

argus-probe run --local --target argus-target.json --probes all --skip-judged --per-run-cap 0.50 \
  --baseline baseline.json --fail-on high --format json --out pr-run.json
```

With `--baseline`, exit 3 gates only new high or critical failures; existing
failures do not trip that gate. Cost-cap exit 4 and incomplete-run exit 1 still
take priority. The current source CLI treats a missing baseline file as empty
and prints a note, so every current failure counts as new on the first run.
The pinned 1.18.0 CLI requires the baseline file to exist. Existing unreadable
or invalid baselines still stop the scan. Keep the target and scan mode stable;
see [the local comparison rules](cli.md#compare-local-runs-in-ci).

## GitHub Actions

Save this as `.github/workflows/argus.yml`. The
[Argus Action](https://github.com/gy15901580825/argus-probe-action) installs the
CLI from PyPI and uploads SARIF before applying the gate. The pinned Action
release supports these inputs; `argus-version` also pins the CLI.

The workflow generator on current main uses a fork/Dependabot guard, a
30-minute timeout and an always-run report upload. These examples use the same
settings. They also set `skip-judged: "true"`, matching the generator's keyless
next-step command. The pinned 1.18.0 CLI predates those generator changes, so
copy these settings when using a workflow generated by that release.

```yaml
name: Argus
on: [push, pull_request]
permissions:
  contents: read
  actions: read
  security-events: write
jobs:
  scan:
    if: ${{ github.actor != 'dependabot[bot]' && (github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository) }}
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@v4
      - uses: gy15901580825/argus-probe-action@v2.14.0
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        with:
          argus-version: "1.18.0"
          target: argus-target.json
          probes: all
          format: sarif
          output: argus.sarif
          fail-on: high
          skip-judged: "true"
          per-run-cap: "0.50"
          upload-sarif: "true"
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: argus-sarif
          path: argus.sarif
          if-no-files-found: warn
```

SARIF code scanning requires a public repository or code scanning enabled for
your private repository. Set `upload-sarif: "false"` if it is unavailable; the
artifact still works. The job guard skips fork pull requests and Dependabot
runs whose credentials or tokens may be unavailable.

## GitLab CI

Save this job in `.gitlab-ci.yml`. Add a masked `ANTHROPIC_API_KEY` CI/CD
variable for judged probes. Protect it according to your branch policy; when
it is unavailable, this job runs keyless. The Python image supplies Python 3.11,
and pip installs the pinned CLI.

```yaml
argus:
  image: python:3.11-slim
  timeout: 30m
  script:
    - python -m pip install 'argus-probe==1.18.0'
    - mkdir -p reports
    - >-
      argus-probe run --local --target argus-target.json
      --probes all --skip-judged --fail-on high --per-run-cap 0.50
      --format junit --out reports/argus.xml
  artifacts:
    when: always
    paths:
      - reports/argus.xml
    reports:
      junit: reports/argus.xml
```

To make gate findings a warning while errors and cost-cap stops still fail,
add this to the `argus` job. The report is still published:

```yaml
allow_failure:
  exit_codes: [3]
```

## Azure Pipelines

Save this as `azure-pipelines.yml`. In pipeline variables, create
`ARGUS_JUDGE_KEY` as a secret for judged runs, or as an empty variable for keyless
runs. Azure secret variables need an explicit environment mapping. Change the
trigger if your default branch differs; configure PR validation according to
your repository provider's policy.

```yaml
trigger:
  - main
pool:
  vmImage: ubuntu-latest
jobs:
  - job: Argus
    timeoutInMinutes: 30
    steps:
      - checkout: self
      - task: UsePythonVersion@0
        inputs:
          versionSpec: "3.11"
      - script: python -m pip install 'argus-probe==1.18.0'
        displayName: Install Argus
      - bash: |
          mkdir -p reports
          argus-probe run --local --target argus-target.json \
            --probes all --skip-judged --fail-on high --per-run-cap 0.50 \
            --format junit --out reports/argus.xml
        displayName: Scan agent
        env:
          ANTHROPIC_API_KEY: $(ARGUS_JUDGE_KEY)
      - task: PublishTestResults@2
        condition: always()
        inputs:
          testResultsFormat: JUnit
          testResultsFiles: reports/argus.xml
          failTaskOnFailedTests: false
          failTaskOnMissingResultsFile: false
      - task: PublishPipelineArtifact@1
        condition: always()
        inputs:
          targetPath: reports
          artifact: argus-reports
```

`PublishTestResults` shows the findings on the Tests tab. It does not replace
an already failed scan step. `PublishPipelineArtifact` applies to Azure DevOps
Services; use `PublishBuildArtifacts@1` for Azure DevOps Server.

## Jenkins

Save this as `Jenkinsfile`. Use a Linux executor with Python 3.11, the Pipeline
and JUnit plugins, and the Credentials Binding plugin for judged runs. Create a
Secret text credential with ID `argus-judge-key`. For a keyless job, remove the
`withCredentials` wrapper and run its enclosed `sh` step directly.

```groovy
pipeline {
  agent any
  options { timeout(time: 30, unit: 'MINUTES') }
  stages {
    stage('Argus') {
      steps {
        sh '''
          python3.11 -m venv .argus-venv
          .argus-venv/bin/python -m pip install 'argus-probe==1.18.0'
          mkdir -p reports
        '''
        withCredentials([string(credentialsId: 'argus-judge-key', variable: 'ANTHROPIC_API_KEY')]) {
          sh '''
            .argus-venv/bin/argus-probe run --local --target argus-target.json \
              --probes all --skip-judged --fail-on high --per-run-cap 0.50 \
              --format junit --out reports/argus.xml
          '''
        }
      }
      post {
        always {
          junit testResults: 'reports/argus.xml', allowEmptyResults: true, skipMarkingBuildUnstable: true
          archiveArtifacts artifacts: 'reports/argus.xml', allowEmptyArchive: true
          sh 'rm -rf .argus-venv'
        }
      }
    }
  }
}
```

`skipMarkingBuildUnstable: true` keeps JUnit failures below the chosen CLI
threshold from marking the build unstable. The `sh` step still fails on any
nonzero scan exit. Groovy's single-quoted shell strings let the shell read the
secret from its environment without interpolating it into the command text.

## Scan an agent started in this job

Use this GitHub workflow when your repository's `Dockerfile` builds the agent
from the checked-out commit. The agent must listen on `0.0.0.0:8000`, expose
`GET /health` with a 2xx response when ready, and accept OpenAI-compatible
requests at `POST /v1/chat/completions` with model name `agent`. Change those
settings for your agent. Pass any agent-side model keys through your own
Compose environment bindings; the judge key below belongs to Argus.

Commit `compose.yaml`:

```yaml
services:
  agent:
    build: .
    ports:
      - "127.0.0.1:8000:8000"
```

Commit `argus-target.json`:

```json
{
  "kind": "openai_compat",
  "endpoint_url": "http://127.0.0.1:8000/v1/chat/completions",
  "model": "agent",
  "timeout_s": 15
}
```

Save this as `.github/workflows/argus-local-agent.yml`. The readiness loop
waits up to about 90 seconds and exits before scanning if the agent never
becomes ready. Logs and teardown run even after a failed scan.

```yaml
name: Argus against this commit
on: [push, pull_request]
permissions:
  contents: read
jobs:
  scan:
    if: ${{ github.actor != 'dependabot[bot]' && (github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository) }}
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@v4
      - name: Start agent and wait for readiness
        shell: bash
        run: |
          docker compose up -d --build
          ready=false
          for attempt in $(seq 1 30); do
            if curl --fail --silent --show-error --max-time 2 http://127.0.0.1:8000/health; then
              ready=true
              break
            fi
            sleep 1
          done
          if [ "$ready" != true ]; then
            echo "Agent did not become ready at http://127.0.0.1:8000/health"
            exit 1
          fi
      - uses: gy15901580825/argus-probe-action@v2.14.0
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        with:
          argus-version: "1.18.0"
          target: argus-target.json
          probes: all
          format: sarif
          output: argus.sarif
          fail-on: high
          skip-judged: "true"
          per-run-cap: "0.50"
          upload-sarif: "false"
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: argus-sarif
          path: argus.sarif
          if-no-files-found: warn
      - name: Agent logs and teardown
        if: always()
        run: |
          docker compose logs --no-color
          docker compose down --volumes
```

The Action runs the CLI on the runner, so it reaches the container through the
published host port at `127.0.0.1:8000`. A CLI running inside another container
must use the Compose service name `agent:8000` on the same Docker network;
`127.0.0.1` there refers to that container. The same start, wait and teardown
steps work around the CLI scan in other systems with a Docker-capable runner.

## Use the published CLI image

The public image is `ghcr.io/gy15901580825/argus-probe:1.18.0`; no registry login
is needed. It supports Linux amd64 and arm64. For a Docker-capable Linux runner,
this replaces the pip install and scan steps above. The image entrypoint is
`argus-probe`, so arguments start with `run`:

```bash
mkdir -p reports
docker run --rm --network host --user "$(id -u):$(id -g)" \
  -e ANTHROPIC_API_KEY \
  --mount type=bind,src="$PWD/argus-target.json",dst=/target.json,readonly \
  --mount type=bind,src="$PWD/reports",dst=/reports \
  ghcr.io/gy15901580825/argus-probe:1.18.0 \
  run --local --target /target.json --probes all --skip-judged \
  --fail-on high --per-run-cap 0.50 --format junit --out /reports/argus.xml
```

`-e ANTHROPIC_API_KEY` passes the runner's environment value; omit it for a
keyless run or replace it with `-e OPENAI_API_KEY`. The bind mount and user ID
leave the report readable by the runner. Linux host networking also lets this
image reach an agent published on the runner's loopback address. On other
platforms, use an address reachable from the container instead of loopback.
The image has the base package dependencies, without Playwright/Chromium, the
MCP SDK extras, or a Docker CLI/daemon for `scan-skill`. Use a suitable custom
image or pip extras for targets and commands that need those dependencies.
