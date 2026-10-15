# Local Mode and `--fail-on` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `pip install "argus-probe[local]"` plus one judge API key lets a user run Argus probes in-process against their own agent and get an HTML / SARIF / JUnit report, and `argus-probe run --fail-on <severity>` makes CI fail on findings.

**Architecture:** The orchestrator directory becomes a pip-installable package (`argus-orchestrator`). A new `orchestrator/redteam/local.py` wraps the existing in-process generator in `orchestrator/redteam/api.py` (which stays untouched, because the API tests patch `api._run_probes`) and translates its FastAPI / cost exceptions into one plain `LocalRunError`. The CLI imports that module lazily under `--local`, renders the report with a byte-identical mirror of `api_service/redteam/reports.py` guarded by a drift test, and gains `--fail-on`.

**Tech Stack:** Python 3.11, click, setuptools, jinja2, pytest (asyncio_mode=auto in orchestrator).

**Spec:** This plan's Design section below is the spec. It implements phase 1, tasks 1 and 3, of the roadmap doc "Argus 落地计划". Design verdicts from TypeSafe/Jev on 2026-10-15: package the orchestrator 0.93; mirror the renderer with a drift test 0.97; local mode feasible 0.86 (settled empirically by Task 7).

## Design

- `argus-probe run --local --target T --probes P --format F --out O [--per-run-cap N] [--fail-on S]` runs probes in this process. No `--api-url` / `--token`. Passing either together with `--local` is a usage error.
- Local mode needs the `argus-orchestrator` package. Without it, the CLI exits 2 with a one-line install hint. It is installed by the `[local]` extra of `argus-probe`.
- Judge configuration follows the orchestrator's existing env contract: `REDTEAM_MODEL_PROVIDER` (`anthropic` default, or `azure`), `ANTHROPIC_API_KEY` required when the provider is anthropic. The check is the same one `POST /redteam/run` makes.
- `run_local` yields the same finding dicts `_run_probes` yields, then one `{"type": "coverage", "coverage": {...}}` event, the same shape as the SSE stream.
- The report is rendered from a run dict shaped exactly like `api_service/redteam/routes.py` builds for `GET /runs/{id}/report`.
- Exit codes of `argus-probe run`: 0 success; 1 target-load, config or input error, or a failure mid-run; 2 usage error or local mode unavailable; 3 `--fail-on` threshold hit; 402 cost cap rejected the run.
- `--fail-on S` counts findings with `verdict == "fail"` and severity rank at or above S, ranks `info < low < medium < high < critical`, unknown or missing severity ranks as `info`. It applies to both remote and local runs.
- Both copies of the renderer stop pointing at placeholders: `informationUri` becomes `https://github.com/gy15901580825/Argus`, `helpUri` becomes `https://github.com/gy15901580825/Argus/tree/main/orchestrator/orchestrator/redteam/probes`.

## Global Constraints

- Python `>=3.11` everywhere (cli/pyproject.toml, orchestrator CI).
- `orchestrator/orchestrator/redteam/api.py` is not modified. Tests patch `orchestrator.redteam.api._run_probes` (orchestrator/tests/test_redteam_api.py:35, test_redteam_coverage_api.py:51); `local.py` must look that function up through the module at call time so those patches keep working.
- import-linter contracts (orchestrator/.importlinter): `orchestrator.redteam` must not import `orchestrator.web_ui_test`, `orchestrator.web_ui_runner`, `orchestrator.web_ui_phases`.
- The CLI's remote path (`run` without `--local`) keeps its current behavior and its 54 passing tests. A job that omits the URL must still fail with the text `Missing option '--api-url'` (docs promise that string).
- `cli/argus_probe/reports.py` must be byte-identical to `api_service/redteam/reports.py`; the drift test enforces it.
- New English prose in docs: no em dashes, sentence-case headings, plain words (CLAUDE.md §8 and the unslop rules).
- Every commit message ends with `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`.
- Run orchestrator tests from the `orchestrator/` directory (`tests/test_redteam_probe.py` resolves the probe dir relative to it) and CLI tests from `cli/`.

## Review Focus

1. `--local --probes all`: `[]` resolves to the whole library and the default per-run cap of $0.50 rejects it. The CLI must print the cost message and exit 402, not a traceback. Test in Task 5 (`test_local_cost_cap_exits_402`).
2. A finding with `severity` missing or `None` under `--fail-on`: ranks as `info`, never raises. Test in Task 4 (`test_findings_at_or_above_treats_unknown_severity_as_info`).
3. A failure mid-run (judge provider misconfigured, target unreachable after some probes): the CLI prints one line to stderr and exits 1, no traceback. Test in Task 5 (`test_local_midrun_error_exits_1`).
4. `--local` together with `--api-url` or `--token`: usage error, exit 2, so a misconfigured CI job does not silently run locally. Test in Task 5 (`test_local_rejects_api_url`).
5. Installed from a wheel (not the source tree), the orchestrator package must still find its 205 probe YAMLs and rubrics. Verified in Task 1 step 5 and Task 7.

---

### Task 1: Make the orchestrator pip-installable

**Files:**
- Modify: `orchestrator/pyproject.toml` (whole file; currently has no `[project]` table)

**Interfaces:**
- Produces: a package named `argus-orchestrator`, version `0.3.0`, providing the top-level import package `orchestrator` with `orchestrator.redteam.*`, its `probes/**/*.yaml`, `rubrics/*.md` and `data/**/*.md` files included in the wheel.

- [ ] **Step 1: Replace `orchestrator/pyproject.toml` with the following (keep every existing tool section exactly as it is; only the `[project]`, `[build-system]` and `[tool.setuptools*]` tables are new)**

```toml
[project]
name = "argus-orchestrator"
version = "0.3.0"
description = "Argus red-team engine: probe library, target adapters, judge harness"
requires-python = ">=3.11"
license = "Apache-2.0"
dependencies = [
    "fastapi>=0.110",
    "pydantic>=2.5",
    "pyyaml>=6.0,<7",
    "httpx>=0.27",
    "jinja2>=3.1",
    "jsonpath-ng>=1.6",
    "anthropic>=0.40.0",
    "litellm",
    "grpcio>=1.60",
    "grpcio-reflection>=1.60",
    "protobuf>=4.25",
]

[project.optional-dependencies]
dev = ["import-linter>=2.0,<3.0"]

[build-system]
requires = ["setuptools>=68", "wheel"]
build-backend = "setuptools.build_meta"

[tool.setuptools.packages.find]
where = ["."]
include = ["orchestrator*"]

[tool.setuptools.package-data]
"orchestrator.redteam" = [
    "probes/*.yaml",
    "probes/*/*.yaml",
    "rubrics/*.md",
    "data/*/*.md",
]
```

Then re-append, unchanged, the existing `[tool.pytest.ini_options]`, `[tool.coverage.run]` and `[tool.coverage.report]` tables from the current file.

- [ ] **Step 2: Build a wheel and install it into a fresh venv**

Run from the repo root:
```bash
python3 -m venv /tmp/argus-pkg-venv && /tmp/argus-pkg-venv/bin/pip install -q --upgrade pip
/tmp/argus-pkg-venv/bin/pip install -q ./orchestrator
```
Expected: exit 0. If pip reports a missing build dependency, fix the `[build-system]` table; do not add packages that are not imported.

- [ ] **Step 3: Verify the installed package imports and finds its data files, from outside the repo**

```bash
cd /tmp && /tmp/argus-pkg-venv/bin/python -c "
import orchestrator.redteam.api as api
from orchestrator.redteam.probe import load_all_probes
print('probes_dir', api.PROBES_DIR)
print('probes', len(list(load_all_probes(api.PROBES_DIR))))
print('rubrics', len(list(api.RUBRICS_DIR.glob('*.md'))))
from orchestrator.redteam.persona_loader import default_personas, default_strategies
print('personas', len(default_personas()), 'strategies', len(default_strategies()))
"
```
Expected: `probes_dir` contains `site-packages`, `probes 205`, `rubrics` > 0, `personas` > 0, `strategies` > 0. If `import orchestrator.redteam.api` raises `ModuleNotFoundError` for a third-party module, add that module to `dependencies` and repeat from Step 2. Record the final dependency list in the report.

- [ ] **Step 4: Confirm the orchestrator test suite and import contracts still pass**

Run from `orchestrator/`:
```bash
python -m pytest tests/ -q 2>&1 | tail -3
lint-imports --config .importlinter
```
Expected: same pass count as before the change (run `git stash; python -m pytest tests/ -q | tail -1; git stash pop` first if you need the baseline), and `Contracts: 2 kept, 0 broken`.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/pyproject.toml
git commit -m "build(orchestrator): make the orchestrator pip-installable as argus-orchestrator

Local mode in the CLI imports orchestrator.redteam in-process, so the
package needs [project] metadata and its probe, rubric and persona
files in the wheel.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 2: `orchestrator.redteam.local.run_local`

**Files:**
- Create: `orchestrator/orchestrator/redteam/local.py`
- Test: `orchestrator/tests/test_redteam_local.py`

**Interfaces:**
- Consumes (all existing, in `orchestrator/orchestrator/redteam/api.py`): `RunRequest(target: dict, probe_ids: list[str] = [], suite: str | None = None, mode: str = "static", deep_pairs: int = DEFAULT_DEEP_PAIRS, per_run_cap_usd: float | None = None)`; `_resolve_request_probe_ids(req) -> list[str]` (raises `fastapi.HTTPException` with `.detail`); `_resolve_target_kind(target) -> str`; `_judged_exchanges(req, probe_ids) -> int`; `_COST_METER.check_or_abort_pre_run(probe_ids=..., target_kind=..., total_exchanges=..., deep=..., per_run_cap_override=...)` (raises `orchestrator.redteam.cost_meter.CostExceededError`); `_run_probes(req, anthropic_api_key) -> AsyncIterator[dict]`; `PROBES_DIR`. Also `orchestrator.redteam.llm.resolve_config(env) -> LLMConfig` (raises `ValueError`; `.provider`), `orchestrator.redteam.llm.PROVIDER_ANTHROPIC`, `orchestrator.redteam.targets.build_target(spec)` (raises `ValueError`), `orchestrator.redteam.coverage.build_coverage(probes, findings) -> dict`, `orchestrator.redteam.probe.load_all_probes(path)`.
- Produces:
  ```python
  class LocalRunError(Exception):
      code: str   # "config" | "input" | "cost"
      def __init__(self, message: str, code: str) -> None: ...

  async def run_local(
      target: dict,
      probe_ids: list[str],
      *,
      mode: str = "static",
      per_run_cap_usd: float | None = None,
      env: Mapping[str, str] | None = None,
  ) -> AsyncIterator[dict]:
      """Yield finding dicts, then one {"type": "coverage", "coverage": dict} event."""
  ```

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/tests/test_redteam_local.py`:

```python
"""Tests for orchestrator.redteam.local — the in-process entry point the CLI uses."""

import pytest
from unittest.mock import patch

from orchestrator.redteam.cost_meter import CostExceededError
from orchestrator.redteam.local import LocalRunError, run_local

TARGET = {
    "kind": "openai_compat",
    "endpoint_url": "https://api.example.com/v1/chat/completions",
    "model": "gpt-4",
    "api_key": "sk-test",
}

FAKE_FINDING = {
    "id": "00000000-0000-0000-0000-000000000001",
    "probe_id": "owasp_01_prompt_injection_basic",
    "verdict": "fail",
    "severity": "high",
    "atlas_id": ["AML.T0051.000"],
}


async def _fake_run(*args, **kwargs):
    yield FAKE_FINDING


async def _collect(gen):
    return [e async for e in gen]


async def test_run_local_yields_findings_then_coverage(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    with patch("orchestrator.redteam.api._run_probes", _fake_run):
        events = await _collect(run_local(TARGET, ["owasp_01_prompt_injection_basic"]))
    assert events[0] == FAKE_FINDING
    assert events[-1]["type"] == "coverage"
    assert isinstance(events[-1]["coverage"], dict)
    assert len(events) == 2


async def test_run_local_passes_the_key_to_run_probes(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-abc")
    seen = {}

    async def _spy(req, anthropic_api_key):
        seen["key"] = anthropic_api_key
        seen["probe_ids"] = req.probe_ids
        seen["cap"] = req.per_run_cap_usd
        yield FAKE_FINDING

    with patch("orchestrator.redteam.api._run_probes", _spy):
        await _collect(run_local(TARGET, ["owasp_01_prompt_injection_basic"], per_run_cap_usd=2.0))
    assert seen == {"key": "sk-ant-abc", "probe_ids": ["owasp_01_prompt_injection_basic"], "cap": 2.0}


async def test_run_local_requires_anthropic_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("REDTEAM_MODEL_PROVIDER", raising=False)
    with pytest.raises(LocalRunError) as exc:
        await _collect(run_local(TARGET, ["owasp_01_prompt_injection_basic"]))
    assert exc.value.code == "config"
    assert "ANTHROPIC_API_KEY" in str(exc.value)


async def test_run_local_rejects_unknown_mode(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    with pytest.raises(LocalRunError) as exc:
        await _collect(run_local(TARGET, ["owasp_01_prompt_injection_basic"], mode="bogus"))
    assert exc.value.code == "input"
    assert "unknown mode" in str(exc.value)


async def test_run_local_rejects_bad_target(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    with pytest.raises(LocalRunError) as exc:
        await _collect(run_local({"kind": "nope"}, ["owasp_01_prompt_injection_basic"]))
    assert exc.value.code == "input"
    assert "nope" in str(exc.value)


async def test_run_local_translates_cost_cap(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")

    def _boom(**kwargs):
        raise CostExceededError("estimated $9.00 exceeds per-run cap $0.50")

    with patch("orchestrator.redteam.api._COST_METER.check_or_abort_pre_run", _boom):
        with pytest.raises(LocalRunError) as exc:
            await _collect(run_local(TARGET, ["owasp_01_prompt_injection_basic"]))
    assert exc.value.code == "cost"
    assert "per-run cap" in str(exc.value)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run from `orchestrator/`: `python -m pytest tests/test_redteam_local.py -q`
Expected: collection error `ModuleNotFoundError: No module named 'orchestrator.redteam.local'`.

- [ ] **Step 3: Create `orchestrator/orchestrator/redteam/local.py`**

```python
"""In-process entry point for `argus-probe run --local`.

Wraps the generator and validators that already power POST /redteam/run so
the CLI can run probes without api_service, Postgres or an HTTP hop. api.py
is deliberately left untouched: its tests patch `api._run_probes`, and this
module reaches every api function through the module object so those
patches keep applying.
"""
from __future__ import annotations

import os
from typing import AsyncIterator, Mapping

from fastapi import HTTPException

from orchestrator.redteam import api, llm
from orchestrator.redteam.cost_meter import CostExceededError
from orchestrator.redteam.coverage import build_coverage
from orchestrator.redteam.probe import load_all_probes
from orchestrator.redteam.targets import build_target


class LocalRunError(Exception):
    """A run could not start. `code` is "config", "input" or "cost"."""

    def __init__(self, message: str, code: str) -> None:
        super().__init__(message)
        self.code = code


async def run_local(
    target: dict,
    probe_ids: list[str],
    *,
    mode: str = "static",
    per_run_cap_usd: float | None = None,
    env: Mapping[str, str] | None = None,
) -> AsyncIterator[dict]:
    """Yield finding dicts, then one {"type": "coverage", "coverage": dict} event."""
    env = os.environ if env is None else env

    # Same credential rule as POST /redteam/run: the configured provider decides
    # which key is mandatory.
    try:
        cfg = llm.resolve_config(env)
    except ValueError as e:
        raise LocalRunError(str(e), code="config") from e
    anthropic_api_key = env.get("ANTHROPIC_API_KEY")
    if cfg.provider == llm.PROVIDER_ANTHROPIC and not anthropic_api_key:
        raise LocalRunError(
            "ANTHROPIC_API_KEY is not set (REDTEAM_MODEL_PROVIDER=anthropic). "
            "Set the key, or set REDTEAM_MODEL_PROVIDER=azure to run the judge on Azure OpenAI.",
            code="config",
        )

    try:
        build_target(target)
    except ValueError as e:
        raise LocalRunError(str(e), code="input") from e

    req = api.RunRequest(
        target=target, probe_ids=probe_ids, mode=mode, per_run_cap_usd=per_run_cap_usd
    )
    try:
        requested = api._resolve_request_probe_ids(req)
    except HTTPException as e:
        raise LocalRunError(str(e.detail), code="input") from e

    try:
        api._COST_METER.check_or_abort_pre_run(
            probe_ids=requested,
            target_kind=api._resolve_target_kind(target),
            total_exchanges=api._judged_exchanges(req, requested),
            deep=mode == "deep",
            per_run_cap_override=per_run_cap_usd,
        )
    except CostExceededError as e:
        raise LocalRunError(str(e), code="cost") from e

    emitted: list[dict] = []
    async for finding in api._run_probes(req, anthropic_api_key):
        emitted.append(finding)
        yield finding
    yield {
        "type": "coverage",
        "coverage": build_coverage(load_all_probes(api.PROBES_DIR), emitted),
    }
```

- [ ] **Step 4: Run the tests to verify they pass, then the whole orchestrator suite and the import contracts**

Run from `orchestrator/`:
```bash
python -m pytest tests/test_redteam_local.py -q
python -m pytest tests/ -q 2>&1 | tail -3
lint-imports --config .importlinter
```
Expected: 6 passed; the full suite passes with 6 more tests than before; `Contracts: 2 kept, 0 broken`.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/orchestrator/redteam/local.py orchestrator/tests/test_redteam_local.py
git commit -m "feat(redteam): add run_local, the in-process entry point for the CLI

Wraps the validators and generator behind POST /redteam/run and turns
their HTTP and cost exceptions into one LocalRunError. api.py is not
changed; its tests patch api._run_probes and keep working.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 3: Mirror the report renderer into the CLI, with a drift test

**Files:**
- Modify: `api_service/redteam/reports.py:59` (helpUri) and `:110` (informationUri)
- Create: `cli/argus_probe/reports.py` (byte-identical copy of the modified `api_service/redteam/reports.py`)
- Create: `cli/argus_probe/templates/report.html.j2` (byte-identical copy of `api_service/redteam/templates/report.html.j2`)
- Modify: `cli/pyproject.toml` (add `jinja2>=3.1` to `dependencies`; add package-data for templates)
- Test: `cli/tests/test_reports_mirror.py`, `cli/tests/test_reports.py`

**Interfaces:**
- Produces: `argus_probe.reports.render_html(run: dict) -> str`, `render_sarif(run: dict) -> str`, `render_junit(run: dict) -> str`. `run` carries `id`, `status`, `started_at`, `finished_at`, `target_spec`, `coverage`, `findings: list[dict]`.

- [ ] **Step 1: Write the failing tests**

Create `cli/tests/test_reports_mirror.py`:

```python
"""The CLI renders reports with a copy of api_service's renderer. Keep them identical."""

from pathlib import Path

import pytest

_CLI_PKG = Path(__file__).resolve().parents[1] / "argus_probe"
_API_SERVICE = Path(__file__).resolve().parents[2] / "api_service" / "redteam"

pytestmark = pytest.mark.skipif(
    not _API_SERVICE.exists(), reason="api_service checkout not present (installed from a wheel)"
)


def test_reports_module_matches_api_service_copy():
    assert (_CLI_PKG / "reports.py").read_bytes() == (_API_SERVICE / "reports.py").read_bytes()


def test_report_template_matches_api_service_copy():
    assert (
        (_CLI_PKG / "templates" / "report.html.j2").read_bytes()
        == (_API_SERVICE / "templates" / "report.html.j2").read_bytes()
    )
```

Create `cli/tests/test_reports.py`:

```python
"""Smoke tests for the three renderers over a minimal run dict."""

import json
from xml.etree import ElementTree as ET

from argus_probe import reports

RUN = {
    "id": "11111111-2222-3333-4444-555555555555",
    "status": "completed",
    "started_at": "2026-10-15T00:00:00+00:00",
    "finished_at": "2026-10-15T00:00:05+00:00",
    "target_spec": {"kind": "openai_compat"},
    "coverage": None,
    "findings": [
        {
            "id": "00000000-0000-0000-0000-000000000001",
            "probe_id": "owasp_01_prompt_injection_basic",
            "verdict": "fail",
            "severity": "critical",
            "confidence": 0.9,
            "reasoning": "leaked the system prompt",
            "attack_prompt": "ignore previous instructions",
            "target_response": "INTERNAL CONFIGURATION ...",
            "target_latency_ms": 120.0,
            "judge_model": "claude-haiku-4-5-20251001",
            "escalated_model": None,
            "atlas_id": ["AML.T0051.000"],
            "owasp_id": ["LLM01"],
            "nist_id": [],
            "eu_ai_act_id": [],
        }
    ],
}


def test_render_sarif_has_one_error_result_and_repo_links():
    sarif = json.loads(reports.render_sarif(RUN))
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0"
    assert run["tool"]["driver"]["informationUri"] == "https://github.com/gy15901580825/Argus"
    assert run["tool"]["driver"]["rules"][0]["helpUri"].startswith("https://github.com/gy15901580825/Argus/")
    assert len(run["results"]) == 1
    assert run["results"][0]["level"] == "error"
    assert run["results"][0]["kind"] == "fail"
    assert run["invocations"][0]["executionSuccessful"] is True


def test_render_junit_marks_fail_as_failure():
    root = ET.fromstring(reports.render_junit(RUN))
    assert root.attrib["failures"] == "1"
    case = root.find("testsuite/testcase")
    assert case.attrib["name"] == "owasp_01_prompt_injection_basic"
    assert case.find("failure").attrib["type"] == "critical"


def test_render_html_mentions_probe_and_verdict():
    html = reports.render_html(RUN)
    assert "owasp_01_prompt_injection_basic" in html
    assert "fail" in html
```

- [ ] **Step 2: Run the tests to verify they fail**

Run from `cli/`: `python -m pytest tests/test_reports_mirror.py tests/test_reports.py -q`
Expected: errors `No module named 'argus_probe.reports'` and `FileNotFoundError` for the mirror paths.

- [ ] **Step 3: Fix the two placeholder URLs in `api_service/redteam/reports.py`**

Line 59, replace
```python
                "helpUri": f"https://github.com/argus-research/probes/tree/main/probes#{rid}",
```
with
```python
                "helpUri": "https://github.com/gy15901580825/Argus/tree/main/orchestrator/orchestrator/redteam/probes",
```
Line 110, replace
```python
                "informationUri": "https://www.example.com",
```
with
```python
                "informationUri": "https://github.com/gy15901580825/Argus",
```
Then run the api_service tests that cover reports, from `api_service/`: `python -m pytest tests -q -k "report or sarif" 2>&1 | tail -3`. Expected: pass. If a test asserted the old placeholder, update that assertion to the new URL.

- [ ] **Step 4: Copy the renderer and template into the CLI package**

```bash
cp api_service/redteam/reports.py cli/argus_probe/reports.py
mkdir -p cli/argus_probe/templates
cp api_service/redteam/templates/report.html.j2 cli/argus_probe/templates/report.html.j2
```
The module computes its template dir as `os.path.join(os.path.dirname(__file__), "templates")`, so the copy works unchanged.

- [ ] **Step 5: Declare the dependency and the package data in `cli/pyproject.toml`**

Change `dependencies` to:
```toml
dependencies = [
    "click>=8.1",
    "httpx>=0.27",
    "pyyaml>=6.0,<7",
    "pydantic>=2.5",
    "jinja2>=3.1",
]
```
Append after `[build-system]`:
```toml
[tool.setuptools.package-data]
argus_probe = ["templates/*.j2"]
```

- [ ] **Step 6: Run the tests to verify they pass, then the whole CLI suite**

Run from `cli/`:
```bash
pip install -q -e . && python -m pytest tests/test_reports_mirror.py tests/test_reports.py -q
python -m pytest tests -q 2>&1 | tail -2
```
Expected: 5 passed; full suite 59 passed.

- [ ] **Step 7: Commit**

```bash
git add api_service/redteam/reports.py cli/argus_probe/reports.py cli/argus_probe/templates/report.html.j2 cli/pyproject.toml cli/tests/test_reports_mirror.py cli/tests/test_reports.py
git commit -m "feat(cli): mirror the report renderer into the CLI for local mode

api_service is not importable from the CLI, so reports.py and its
template are copied; a test fails if the two copies ever differ. Both
copies now point SARIF links at this repo instead of placeholders.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 4: `--fail-on <severity>` for `argus-probe run`

**Files:**
- Create: `cli/argus_probe/severity.py`
- Modify: `cli/argus_probe/cmd_run.py` (add the option; apply after polling)
- Test: `cli/tests/test_severity.py`, `cli/tests/test_cmd_run.py` (append two tests)

**Interfaces:**
- Produces:
  ```python
  SEVERITY_ORDER: tuple[str, ...] = ("info", "low", "medium", "high", "critical")
  def findings_at_or_above(findings: list[dict], threshold: str) -> list[dict]
  ```
  Task 5 calls `findings_at_or_above` on local findings too.

- [ ] **Step 1: Write the failing tests**

Create `cli/tests/test_severity.py`:

```python
from argus_probe.severity import SEVERITY_ORDER, findings_at_or_above


def _f(verdict, severity):
    return {"probe_id": "p", "verdict": verdict, "severity": severity}


def test_order_is_info_to_critical():
    assert SEVERITY_ORDER == ("info", "low", "medium", "high", "critical")


def test_findings_at_or_above_filters_by_rank_and_verdict():
    findings = [_f("fail", "low"), _f("fail", "high"), _f("fail", "critical"), _f("pass", "critical"), _f("warn", "high")]
    hits = findings_at_or_above(findings, "high")
    assert [h["severity"] for h in hits] == ["high", "critical"]


def test_findings_at_or_above_treats_unknown_severity_as_info():
    findings = [_f("fail", None), _f("fail", "weird"), {"probe_id": "p", "verdict": "fail"}]
    assert findings_at_or_above(findings, "info") == findings
    assert findings_at_or_above(findings, "low") == []
```

Append to `cli/tests/test_cmd_run.py` (keep the existing imports; add `from argus_probe import api_client` and `from argus_probe.cmd_run import cmd_run` if they are not already imported there):

```python
def _stub_remote(monkeypatch, findings):
    monkeypatch.setattr(api_client, "post_run", lambda *a, **k: {"run_id": "r1"})
    monkeypatch.setattr(
        api_client, "poll_until_complete", lambda *a, **k: {"status": "completed", "findings": findings}
    )
    monkeypatch.setattr(api_client, "get_report", lambda *a, **k: "<html></html>")


def test_run_fail_on_exits_3_when_threshold_hit(tmp_path, monkeypatch):
    _stub_remote(monkeypatch, [{"probe_id": "p", "verdict": "fail", "severity": "critical"}])
    target = tmp_path / "t.json"
    target.write_text('{"kind":"openai_compat","endpoint_url":"https://x","model":"m"}')
    out = tmp_path / "r.html"
    result = CliRunner().invoke(
        cmd_run,
        ["--target", str(target), "--probes", "p", "--out", str(out), "--token", "t",
         "--api-url", "https://argus.example", "--fail-on", "high"],
    )
    assert result.exit_code == 3, result.output
    assert "1 finding" in result.output
    assert out.read_text() == "<html></html>"


def test_run_without_fail_on_exits_0_on_findings(tmp_path, monkeypatch):
    _stub_remote(monkeypatch, [{"probe_id": "p", "verdict": "fail", "severity": "critical"}])
    target = tmp_path / "t.json"
    target.write_text('{"kind":"openai_compat","endpoint_url":"https://x","model":"m"}')
    out = tmp_path / "r.html"
    result = CliRunner().invoke(
        cmd_run,
        ["--target", str(target), "--probes", "p", "--out", str(out), "--token", "t",
         "--api-url", "https://argus.example"],
    )
    assert result.exit_code == 0, result.output
```

- [ ] **Step 2: Run the tests to verify they fail**

Run from `cli/`: `python -m pytest tests/test_severity.py tests/test_cmd_run.py -q`
Expected: `ModuleNotFoundError: No module named 'argus_probe.severity'`, and the `--fail-on` test fails with `no such option`.

- [ ] **Step 3: Create `cli/argus_probe/severity.py`**

```python
"""Severity ranking for --fail-on."""
from __future__ import annotations

SEVERITY_ORDER: tuple[str, ...] = ("info", "low", "medium", "high", "critical")


def _rank(severity) -> int:
    # Anything the server did not label (None, unknown string) ranks lowest, so a
    # gate on "low" or above never trips on an unlabelled finding.
    try:
        return SEVERITY_ORDER.index(severity)
    except ValueError:
        return 0


def findings_at_or_above(findings: list[dict], threshold: str) -> list[dict]:
    """Findings with verdict "fail" whose severity ranks at or above `threshold`."""
    floor = SEVERITY_ORDER.index(threshold)
    return [
        f for f in findings
        if f.get("verdict") == "fail" and _rank(f.get("severity")) >= floor
    ]
```

- [ ] **Step 4: Add the option to `cli/argus_probe/cmd_run.py`**

Add the import after the existing ones:
```python
from argus_probe.severity import SEVERITY_ORDER, findings_at_or_above
```
Add this option directly below the `--per-run-cap` option:
```python
@click.option("--fail-on", "fail_on", type=click.Choice(SEVERITY_ORDER), default=None,
              help="Exit 3 when any finding has verdict=fail and severity at or above this level.")
```
Add `fail_on: str | None` as the last parameter of `cmd_run`. Replace the final two lines of the function body
```python
    Path(out_file).write_text(report)
    click.echo(f"Wrote report to {out_file}")
```
with
```python
    Path(out_file).write_text(report)
    click.echo(f"Wrote report to {out_file}")
    _apply_fail_on(run.get("findings", []), fail_on)
```
and add at module level, below `cmd_run`:
```python
def _apply_fail_on(findings: list[dict], fail_on: str | None) -> None:
    """Exit 3 when findings cross the --fail-on threshold. Report is already on disk."""
    if fail_on is None:
        return
    hits = findings_at_or_above(findings, fail_on)
    if hits:
        ids = ", ".join(sorted({h.get("probe_id", "?") for h in hits}))
        click.echo(
            f"{len(hits)} finding(s) at or above {fail_on}: {ids}",
            file=sys.stderr,
        )
        sys.exit(3)
```

- [ ] **Step 5: Run the tests to verify they pass, then the whole CLI suite**

Run from `cli/`:
```bash
python -m pytest tests/test_severity.py tests/test_cmd_run.py -q
python -m pytest tests -q 2>&1 | tail -2
```
Expected: all pass; full suite 64 passed.

- [ ] **Step 6: Commit**

```bash
git add cli/argus_probe/severity.py cli/argus_probe/cmd_run.py cli/tests/test_severity.py cli/tests/test_cmd_run.py
git commit -m "feat(cli): add --fail-on <severity> so CI can gate on findings

Exit 3 when any finding has verdict=fail at or above the given severity.
The report is written before the exit so the SARIF still uploads.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 5: `argus-probe run --local`

**Files:**
- Create: `cli/argus_probe/local_run.py`
- Modify: `cli/argus_probe/cmd_run.py` (add `--local`; relax `--token` / `--api-url`; branch)
- Modify: `cli/pyproject.toml` (add the `[local]` extra)
- Test: `cli/tests/test_cmd_run_local.py`

**Interfaces:**
- Consumes: `orchestrator.redteam.local.run_local(target, probe_ids, *, mode="static", per_run_cap_usd=None, env=None) -> AsyncIterator[dict]` and `orchestrator.redteam.local.LocalRunError(message, code)` with `.code in {"config","input","cost"}` (Task 2); `argus_probe.reports.render_html/render_sarif/render_junit(run: dict) -> str` (Task 3); `argus_probe.severity.findings_at_or_above` and `cmd_run._apply_fail_on(findings, fail_on)` (Task 4).
- Produces:
  ```python
  class LocalUnavailable(RuntimeError): ...   # orchestrator package not installed
  def run_local_and_render(spec: dict, probe_ids: list[str], per_run_cap: float | None, report_format: str) -> tuple[str, list[dict]]
  ```
  `run_local_and_render` raises `LocalUnavailable`, or re-raises `orchestrator.redteam.local.LocalRunError`, or any exception raised mid-run.

- [ ] **Step 1: Write the failing tests**

Create `cli/tests/test_cmd_run_local.py`:

```python
"""Tests for `argus-probe run --local`. The orchestrator package is replaced by a
fake module in sys.modules so the CLI suite needs no orchestrator install."""

import json
import sys
import types

import pytest
from click.testing import CliRunner

from argus_probe.cmd_run import cmd_run

FAIL_FINDING = {
    "id": "00000000-0000-0000-0000-000000000001",
    "probe_id": "owasp_01_prompt_injection_basic",
    "verdict": "fail",
    "severity": "critical",
    "confidence": 0.9,
    "reasoning": "leaked",
    "attack_prompt": "p",
    "target_response": "r",
    "target_latency_ms": 10.0,
    "judge_model": "fake",
    "escalated_model": None,
    "atlas_id": [],
    "owasp_id": [],
    "nist_id": [],
    "eu_ai_act_id": [],
}


class _LocalRunError(Exception):
    def __init__(self, message, code):
        super().__init__(message)
        self.code = code


def _install_fake_orchestrator(monkeypatch, run_local):
    pkg = types.ModuleType("orchestrator")
    redteam = types.ModuleType("orchestrator.redteam")
    local = types.ModuleType("orchestrator.redteam.local")
    local.run_local = run_local
    local.LocalRunError = _LocalRunError
    monkeypatch.setitem(sys.modules, "orchestrator", pkg)
    monkeypatch.setitem(sys.modules, "orchestrator.redteam", redteam)
    monkeypatch.setitem(sys.modules, "orchestrator.redteam.local", local)


async def _ok_run(target, probe_ids, *, mode="static", per_run_cap_usd=None, env=None):
    yield FAIL_FINDING
    yield {"type": "coverage", "coverage": {"owasp_llm": {"tested": ["LLM01"]}}}


def _target(tmp_path):
    p = tmp_path / "t.json"
    p.write_text('{"kind":"openai_compat","endpoint_url":"https://x","model":"m"}')
    return str(p)


def test_local_writes_sarif_without_api_url(tmp_path, monkeypatch):
    _install_fake_orchestrator(monkeypatch, _ok_run)
    monkeypatch.delenv("ARGUS_API_URL", raising=False)
    monkeypatch.delenv("ARGUS_API_TOKEN", raising=False)
    out = tmp_path / "r.sarif"
    result = CliRunner().invoke(
        cmd_run, ["--local", "--target", _target(tmp_path), "--probes", "owasp_01_prompt_injection_basic",
                  "--format", "sarif", "--out", str(out)],
    )
    assert result.exit_code == 0, result.output
    sarif = json.loads(out.read_text())
    assert len(sarif["runs"][0]["results"]) == 1
    assert sarif["runs"][0]["properties"]["coverage"] == {"owasp_llm": {"tested": ["LLM01"]}}
    assert "fail" in result.output and "owasp_01_prompt_injection_basic" in result.output


def test_local_fail_on_exits_3(tmp_path, monkeypatch):
    _install_fake_orchestrator(monkeypatch, _ok_run)
    out = tmp_path / "r.html"
    result = CliRunner().invoke(
        cmd_run, ["--local", "--target", _target(tmp_path), "--probes", "owasp_01_prompt_injection_basic",
                  "--out", str(out), "--fail-on", "high"],
    )
    assert result.exit_code == 3, result.output
    assert out.exists()


def test_local_passes_probes_and_cap_through(tmp_path, monkeypatch):
    seen = {}

    async def _spy(target, probe_ids, *, mode="static", per_run_cap_usd=None, env=None):
        seen.update(target=target, probe_ids=probe_ids, cap=per_run_cap_usd)
        yield {"type": "coverage", "coverage": {}}

    _install_fake_orchestrator(monkeypatch, _spy)
    result = CliRunner().invoke(
        cmd_run, ["--local", "--target", _target(tmp_path), "--probes", "all",
                  "--out", str(tmp_path / "r.html"), "--per-run-cap", "6"],
    )
    assert result.exit_code == 0, result.output
    assert seen["probe_ids"] == []          # "all" is the empty list by convention
    assert seen["cap"] == 6.0
    assert seen["target"]["kind"] == "openai_compat"


def test_local_cost_cap_exits_402(tmp_path, monkeypatch):
    async def _cost(target, probe_ids, **kw):
        raise _LocalRunError("estimated $9.00 exceeds per-run cap $0.50", "cost")
        yield  # pragma: no cover

    _install_fake_orchestrator(monkeypatch, _cost)
    result = CliRunner().invoke(
        cmd_run, ["--local", "--target", _target(tmp_path), "--probes", "all", "--out", str(tmp_path / "r.html")],
    )
    assert result.exit_code == 402, result.output
    assert "per-run cap" in result.output


def test_local_config_error_exits_1(tmp_path, monkeypatch):
    async def _cfg(target, probe_ids, **kw):
        raise _LocalRunError("ANTHROPIC_API_KEY is not set", "config")
        yield  # pragma: no cover

    _install_fake_orchestrator(monkeypatch, _cfg)
    result = CliRunner().invoke(
        cmd_run, ["--local", "--target", _target(tmp_path), "--probes", "p", "--out", str(tmp_path / "r.html")],
    )
    assert result.exit_code == 1, result.output
    assert "ANTHROPIC_API_KEY" in result.output


def test_local_midrun_error_exits_1(tmp_path, monkeypatch):
    async def _mid(target, probe_ids, **kw):
        yield FAIL_FINDING
        raise RuntimeError("judge call failed: 401 from provider")

    _install_fake_orchestrator(monkeypatch, _mid)
    out = tmp_path / "r.html"
    result = CliRunner().invoke(
        cmd_run, ["--local", "--target", _target(tmp_path), "--probes", "p", "--out", str(out)],
    )
    assert result.exit_code == 1, result.output
    assert "judge call failed" in result.output
    assert "Traceback" not in result.output
    assert not out.exists()


def test_local_without_orchestrator_exits_2_with_hint(tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, "orchestrator", None)
    result = CliRunner().invoke(
        cmd_run, ["--local", "--target", _target(tmp_path), "--probes", "p", "--out", str(tmp_path / "r.html")],
    )
    assert result.exit_code == 2, result.output
    assert "argus-probe[local]" in result.output


def test_local_rejects_api_url(tmp_path, monkeypatch):
    _install_fake_orchestrator(monkeypatch, _ok_run)
    result = CliRunner().invoke(
        cmd_run, ["--local", "--api-url", "https://argus.example", "--target", _target(tmp_path),
                  "--probes", "p", "--out", str(tmp_path / "r.html")],
    )
    assert result.exit_code == 2, result.output
    assert "--local" in result.output and "--api-url" in result.output


def test_remote_still_requires_api_url(tmp_path, monkeypatch):
    monkeypatch.delenv("ARGUS_API_URL", raising=False)
    result = CliRunner().invoke(
        cmd_run, ["--target", _target(tmp_path), "--probes", "p", "--out", str(tmp_path / "r.html"), "--token", "t"],
    )
    assert result.exit_code == 2, result.output
    assert "Missing option '--api-url'" in result.output
```

- [ ] **Step 2: Run the tests to verify they fail**

Run from `cli/`: `python -m pytest tests/test_cmd_run_local.py -q`
Expected: every test fails with `no such option: --local` except `test_remote_still_requires_api_url`, which passes already.

- [ ] **Step 3: Create `cli/argus_probe/local_run.py`**

```python
"""Run probes in this process (`argus-probe run --local`) and render the report."""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone

import click

from argus_probe import reports

_INSTALL_HINT = (
    "local mode needs the argus-orchestrator package: "
    'pip install "argus-probe[local] @ git+https://github.com/gy15901580825/Argus.git#subdirectory=cli"'
)


class LocalUnavailable(RuntimeError):
    """The orchestrator package is not importable."""


def run_local_and_render(
    spec: dict, probe_ids: list[str], per_run_cap: float | None, report_format: str
) -> tuple[str, list[dict]]:
    """Run the probes, print one line per finding, return (report_text, findings).

    Raises LocalUnavailable when the orchestrator package is missing, re-raises
    orchestrator.redteam.local.LocalRunError when the run cannot start, and
    lets any mid-run exception propagate.
    """
    try:
        from orchestrator.redteam.local import run_local
    except ImportError as e:
        raise LocalUnavailable(_INSTALL_HINT) from e

    started_at = datetime.now(timezone.utc)
    findings: list[dict] = []
    coverage: dict | None = None

    async def _consume() -> None:
        nonlocal coverage
        async for event in run_local(spec, probe_ids, per_run_cap_usd=per_run_cap):
            if event.get("type") == "coverage":
                coverage = event.get("coverage")
                continue
            findings.append(event)
            click.echo(f"  {event.get('verdict', '?'):<18} {event.get('severity', '?'):<9} {event.get('probe_id', '?')}")

    asyncio.run(_consume())

    run = {
        "id": str(uuid.uuid4()),
        "status": "completed",
        "started_at": started_at.isoformat(),
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "target_spec": spec,
        "coverage": coverage,
        "findings": findings,
    }
    render = {"html": reports.render_html, "sarif": reports.render_sarif, "junit": reports.render_junit}[report_format]
    return render(run), findings
```

- [ ] **Step 4: Wire `--local` into `cli/argus_probe/cmd_run.py`**

Add the import:
```python
from argus_probe.local_run import LocalUnavailable, run_local_and_render
```
Change the two credential options so they are no longer required by click:
```python
@click.option("--token", envvar="ARGUS_API_TOKEN", default=None, help="Your Argus API token (or env ARGUS_API_TOKEN). Not used with --local.")
@click.option("--api-url", envvar="ARGUS_API_URL", default=None, help="Argus API base URL (or env ARGUS_API_URL). Not used with --local.")
```
Add, directly below the `--fail-on` option:
```python
@click.option("--local", "local", is_flag=True, default=False,
              help="Run probes in this process instead of submitting to an Argus API server. Needs the argus-orchestrator package and a judge API key in the environment.")
```
Add `local: bool` as the last parameter of `cmd_run`. Change the signature types of `token` and `api_url` to `str | None`.

Insert this block right after the `tokens` resolution (after the line `tokens = []` and its enclosing `if`), before `body = {...}`:
```python
    if local:
        if api_url is not None or token is not None:
            raise click.UsageError("--local runs in this process; do not pass --api-url or --token")
        _run_locally(spec, tokens, per_run_cap, report_format, out_file, fail_on)
        return
    if api_url is None:
        raise click.UsageError("Missing option '--api-url'")
    if token is None:
        raise click.UsageError("Missing option '--token'")
```
Add at module level, below `_apply_fail_on`:
```python
def _run_locally(spec, tokens, per_run_cap, report_format, out_file, fail_on) -> None:
    click.echo(f"Running {('all probes' if not tokens else f'{len(tokens)} probe(s)')} locally ...")
    try:
        report, findings = run_local_and_render(spec, tokens, per_run_cap, report_format)
    except LocalUnavailable as e:
        click.echo(f"Error: {e}", file=sys.stderr)
        sys.exit(2)
    except Exception as e:  # LocalRunError or a mid-run failure; no traceback for the operator
        code = getattr(e, "code", None)
        if code == "cost":
            click.echo(f"Argus rejected run for cost: {e}", file=sys.stderr)
            sys.exit(402)
        click.echo(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    Path(out_file).write_text(report)
    click.echo(f"Wrote report to {out_file}")
    _apply_fail_on(findings, fail_on)
```
Note: `--local` must not catch `LocalRunError` by class, because the CLI must not import the orchestrator at module import time; the `code` attribute is the contract.

- [ ] **Step 5: Add the `[local]` extra to `cli/pyproject.toml`**

Append after the `[project.scripts]` table:
```toml
[project.optional-dependencies]
# Direct URL dependencies are refused by PyPI. Before the first PyPI upload,
# publish argus-orchestrator too and change this to a version specifier.
local = [
    "argus-orchestrator @ git+https://github.com/gy15901580825/Argus.git#subdirectory=orchestrator",
]
```

- [ ] **Step 6: Run the tests to verify they pass, then the whole CLI suite**

Run from `cli/`:
```bash
python -m pytest tests/test_cmd_run_local.py -q
python -m pytest tests -q 2>&1 | tail -2
```
Expected: 9 passed; full suite 73 passed. If `test_remote_still_requires_api_url` fails on exit code, check that click reports usage errors with exit code 2 (it does by default).

- [ ] **Step 7: Commit**

```bash
git add cli/argus_probe/local_run.py cli/argus_probe/cmd_run.py cli/pyproject.toml cli/tests/test_cmd_run_local.py
git commit -m "feat(cli): add run --local, probes in-process without an Argus server

Imports orchestrator.redteam.local lazily, renders the report with the
mirrored renderer, and maps LocalRunError codes to the existing exit
codes (402 for cost). --token and --api-url stay mandatory without
--local and are refused with it.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 6: Docs and the generated workflow

**Files:**
- Modify: `README.md` (section "Running against your own agent"; the paragraph starting "There is no published GitHub Action")
- Modify: `docs/onboarding/quickstart.md` (step 1, step 3, "What's next", CLI reference table)
- Modify: `cli/README.md` (Install, Quickstart, CI integration, Subcommands)
- Modify: `docs/onboarding/target-spec-cookbook.md` (the workflow block and the two paragraphs after it)
- Modify: `docs/onboarding/probe-id-cheatsheet.md` (the paragraph starting "There is no published GitHub Action")
- Modify: `cli/argus_probe/cmd_init.py` (`_WORKFLOW_TEMPLATE` run step), `cli/tests/test_cmd_init.py` (one assertion)

**Interfaces:**
- Consumes: the CLI flags `--local`, `--fail-on`, the exit codes, and the `[local]` extra from Tasks 4 and 5.

- [ ] **Step 1: Update the generated workflow and its test**

In `cli/argus_probe/cmd_init.py`, change the run step of `_WORKFLOW_TEMPLATE` from
```
      - run: >
          argus-probe run --target {target_path}
          --probes owasp_01_prompt_injection_basic,syscard_crescendo
          --format sarif --out argus.sarif
```
to
```
      - run: >
          argus-probe run --target {target_path}
          --probes owasp_01_prompt_injection_basic,syscard_crescendo
          --format sarif --out argus.sarif --fail-on critical
```
In `cli/tests/test_cmd_init.py::test_init_with_workflow_writes_workflow_file`, add after the `--target argus-target.json` assertion:
```python
    assert "--fail-on critical" in content
```
Run from `cli/`: `python -m pytest tests/test_cmd_init.py -q`. Expected: pass.

- [ ] **Step 2: `README.md`**

In the "Running against your own agent" section, replace the paragraph that begins `The CLI is not on PyPI; install it from this repo as above. There is no` (through `and "api_token_only": true.`) with:

```markdown
The CLI is not on PyPI; install it from this repo as above. There are two
ways to run it:

- **Local mode** (`--local`): probes run in this process. Install the
  engine with the `[local]` extra and set a judge key:

  ```bash
  pip install "argus-probe[local] @ git+https://github.com/gy15901580825/Argus.git#subdirectory=cli"
  export ANTHROPIC_API_KEY=<your key>      # or REDTEAM_MODEL_PROVIDER=azure with the Azure variables
  argus-probe run --local --target argus-target.json \
                  --probes owasp_01_prompt_injection_basic,syscard_crescendo \
                  --format sarif --out argus.sarif
  ```

- **Server mode**: `ARGUS_API_URL` is your own `api_service` deployment
  (see [`docs/runbooks/local-dev.md`](docs/runbooks/local-dev.md)) and the
  token is a `users.api_token` row on that server, minted by an admin with
  `POST /api/v1/admin/users` and `"api_token_only": true`. There is no
  hosted instance.
```

Replace the paragraph that begins `There is no published GitHub Action.` (through `has to read the SARIF.`) with:

```markdown
There is no published GitHub Action. `argus-probe init --workflow` writes a
workflow that installs the CLI, runs it, uploads the SARIF with
`github/codeql-action/upload-sarif`, and fails the job with
`--fail-on critical` (example in [`cli/README.md`](cli/README.md)).
```

- [ ] **Step 3: `docs/onboarding/quickstart.md`**

Replace the step 1 code block and the sentence after it with:

```markdown
```bash
pip install "argus-probe[local] @ git+https://github.com/gy15901580825/Argus.git#subdirectory=cli"
argus-probe --version
```

The `[local]` extra pulls in the probe engine so step 3a works without a server. From a clone, `pip install ./orchestrator ./cli` does the same.
```

Insert a new step before "## 3. Get an Argus API token":

```markdown
## 3a. Run locally (no server)

Set a judge key and add `--local`. The CLI loads the 205 probes, sends them to your agent and judges the replies in this process:

```bash
export ANTHROPIC_API_KEY="<your key>"        # or REDTEAM_MODEL_PROVIDER=azure plus the Azure variables
argus-probe run --local --target argus-target.json --probes owasp_07_system_prompt_leakage --format html --out report.html
```

`--per-run-cap` and `--fail-on` work the same way as in server mode. Skip step 3 if this is all you need.
```

Retitle "## 3. Get an Argus API token" to "## 3. Get an Argus API token (server mode)".

In "What's next", replace the "Add to CI" bullet with:
```markdown
- **Add to CI**: `argus-probe init --workflow` writes a starter workflow that uploads SARIF and fails on critical findings (`--fail-on critical`); see [target-spec-cookbook.md](./target-spec-cookbook.md) § "GitHub Actions integration". There is no published GitHub Action
```

In the flags table at the end, add two rows after `--per-run-cap`:
```markdown
| `--local` | run probes in this process; needs the `[local]` extra and a judge key, no `--api-url`/`--token` |
| `--fail-on` | `info` / `low` / `medium` / `high` / `critical`; exit 3 when a failing finding is at or above it |
```

- [ ] **Step 4: `cli/README.md`**

Replace the Install section body with:
```markdown
Python 3.11+ is required. There are no prebuilt binaries and no PyPI package; install from the Argus repo:

```bash
pip install "argus-probe[local] @ git+https://github.com/gy15901580825/Argus.git#subdirectory=cli"
```

The `[local]` extra installs the probe engine for `--local`. Without it the CLI only talks to an Argus API server. From a clone of the repo, `pip install ./orchestrator ./cli` does the same.
```

In the Quickstart block, replace steps 2 to 4 with:
```bash
# 2a. Run locally: set a judge key, no server needed
export ANTHROPIC_API_KEY="<your key>"
argus-probe run --local --target argus-target.json \
  --probes owasp_07_system_prompt_leakage --format html --out report.html

# 2b. Or submit to your own Argus API server
export ARGUS_API_TOKEN="<your token>"
export ARGUS_API_URL="https://<your-argus-host>"
argus-probe validate-target --target argus-target.json
argus-probe run --target argus-target.json \
  --probes owasp_07_system_prompt_leakage --format html --out report.html
```

In "What it does", replace the first paragraph with:
```markdown
Without `--local`, `argus-probe` is a thin client: it submits the target spec and probe selection to an Argus service over HTTPS; the service runs the probes against your agent and returns the report. With `--local` the same engine runs in this process and calls the judge model directly with your key.
```

In "CI integration", add `--fail-on critical` to the end of the `argus-probe run` line in the YAML, and replace the paragraph `` `argus-probe run` does not exit non-zero on findings. To fail the build on severity, read `argus.sarif` in a later step.`` with:
```markdown
`--fail-on <severity>` exits 3 when a failing finding is at or above that level; the SARIF is written first, so it still uploads. Exit codes: 0 success, 1 run or configuration error, 2 usage error or `--local` without the engine installed, 3 threshold hit, 402 cost cap.
```

- [ ] **Step 5: `docs/onboarding/target-spec-cookbook.md` and `docs/onboarding/probe-id-cheatsheet.md`**

Cookbook: add `--fail-on critical` to the end of the `argus-probe run` line in the YAML block, and replace the paragraph `` `argus-probe run` does not exit non-zero on findings, so this workflow reports but does not block. To fail the build by severity, read `argus.sarif` in a later step.`` with:
```markdown
`--fail-on critical` fails the job when a critical finding lands; use `high` to tighten it, or drop the flag to report without blocking. The SARIF is written before the exit, so it uploads either way.
```

Cheatsheet: replace the paragraph `There is no published GitHub Action, and `argus-probe run` does not exit non-zero on findings. To fail CI by severity, read the SARIF in a later workflow step; the workflow itself is in [target-spec-cookbook.md](./target-spec-cookbook.md) § "GitHub Actions integration".` with:
```markdown
There is no published GitHub Action. `argus-probe run --fail-on <severity>` exits 3 when a failing finding is at or above that level; the workflow in [target-spec-cookbook.md](./target-spec-cookbook.md) § "GitHub Actions integration" uses `--fail-on critical`.
```

- [ ] **Step 6: Check the result**

```bash
grep -rn "does not exit non-zero\|read the SARIF in a later\|read \`argus.sarif\`" README.md docs/onboarding cli/README.md
grep -rn "argus-probe\[local\]" README.md docs/onboarding/quickstart.md cli/README.md | wc -l
cd cli && python -m pytest tests -q 2>&1 | tail -1
```
Expected: the first grep prints nothing; the second prints at least 3; the suite passes.

- [ ] **Step 7: Commit**

```bash
git add README.md docs/onboarding/quickstart.md docs/onboarding/target-spec-cookbook.md docs/onboarding/probe-id-cheatsheet.md cli/README.md cli/argus_probe/cmd_init.py cli/tests/test_cmd_init.py
git commit -m "docs: document run --local and --fail-on; generated workflow gates on critical

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 7: End-to-end check without an LLM key

**Files:**
- Create: `/tmp/argus-e2e/` (scratch only, nothing committed)

**Interfaces:**
- Consumes: everything above. Payment probes carry `assertions` and never call the judge, so a placeholder `ANTHROPIC_API_KEY` satisfies the config check without any paid call.

- [ ] **Step 1: Fresh venv with both packages installed from the working tree**

Run from the repo root:
```bash
rm -rf /tmp/argus-e2e && mkdir -p /tmp/argus-e2e && python3 -m venv /tmp/argus-e2e/venv
/tmp/argus-e2e/venv/bin/pip install -q --upgrade pip
/tmp/argus-e2e/venv/bin/pip install -q ./orchestrator ./cli
/tmp/argus-e2e/venv/bin/argus-probe --help | grep -c "run" 
```
Expected: pip exits 0; the grep prints a number >= 1.

- [ ] **Step 2: Start the payment testbed and its insecure demo agent**

```bash
/tmp/argus-e2e/venv/bin/pip install -q -r payment_testbed/requirements.txt
cd payment_testbed
nohup /tmp/argus-e2e/venv/bin/uvicorn testbed.app:app --port 8090 > /tmp/argus-e2e/testbed.log 2>&1 &
TESTBED_ORIGIN=http://127.0.0.1:8090 nohup /tmp/argus-e2e/venv/bin/uvicorn demo_agent.app:app --port 8091 > /tmp/argus-e2e/agent.log 2>&1 &
sleep 3; curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8090/docs; curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8091/docs
cd ..
```
Expected: two `200` lines. If a port is busy, pick free ports and use them below.

- [ ] **Step 3: Write the target spec and run two payment probes locally**

```bash
cat > /tmp/argus-e2e/target.json <<'EOF'
{"kind": "payment_agent", "testbed_url": "http://127.0.0.1:8090", "sandbox": true,
 "inner": {"kind": "openai_compat", "endpoint_url": "http://127.0.0.1:8091/v1/chat/completions", "model": "argus-demo-payment-agent"}}
EOF
cd /tmp/argus-e2e && ANTHROPIC_API_KEY=sk-ant-placeholder-no-calls ./venv/bin/argus-probe run --local \
  --target target.json --probes pay_approval_forged,pay_inject_json_field \
  --format sarif --out out.sarif --per-run-cap 1 2>&1 | tee run.log; echo "exit=${PIPESTATUS[0]}"
```
Expected: one line per finding on stdout, `Wrote report to out.sarif`, `exit=0`. Then:
```bash
./venv/bin/python -c "
import json; s=json.load(open('out.sarif')); r=s['runs'][0]
print('results', len(r['results']), 'kinds', sorted({x['kind'] for x in r['results']}))
print('informationUri', r['tool']['driver']['informationUri']); print('coverage' in r.get('properties', {}))
"
```
Expected: `results` >= 2, `informationUri https://github.com/gy15901580825/Argus`, `True`.

- [ ] **Step 4: Confirm `--fail-on` and the no-key path**

```bash
cd /tmp/argus-e2e && ANTHROPIC_API_KEY=sk-ant-placeholder-no-calls ./venv/bin/argus-probe run --local --target target.json --probes pay_approval_forged,pay_inject_json_field --format junit --out out.xml --per-run-cap 1 --fail-on low > /dev/null 2> fail.log; echo "exit=$?"; cat fail.log
env -u ANTHROPIC_API_KEY ./venv/bin/argus-probe run --local --target target.json --probes pay_approval_forged --out x.html 2>&1 | tail -1; echo "exit=${PIPESTATUS[0]}"
```
Expected: first command exits 3 when any probe failed (the demo agent is insecure, so at least one should) or 0 if none did; either way `out.xml` exists. Second command prints the `ANTHROPIC_API_KEY` message and `exit=1`.

- [ ] **Step 5: Stop the servers and record the evidence**

```bash
pkill -f "uvicorn testbed.app:app --port 8090"; pkill -f "uvicorn demo_agent.app:app --port 8091"
ls -la /tmp/argus-e2e/
```
Write the outputs of steps 1 to 4 (exit codes, result counts, the exact `--fail-on` outcome) in the task report. Nothing is committed in this task.
