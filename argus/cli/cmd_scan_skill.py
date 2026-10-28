"""`argus-probe scan-skill`: run an untrusted agent skill in a sandbox and report what it did."""
from __future__ import annotations

import contextlib
import json
import math
import os
import re
import sys

import click

from argus.cli import reports
from argus.cli.cmd_run import _apply_fail_on
from argus.cli.severity import SEVERITY_ORDER

# These codes mean the user must fix their machine; the message already says how.
_SETUP_CODES = {"docker_missing", "docker_down", "docker_old", "docker_version", "build"}
_EVIDENCE_MAX = 100
# Terminal control bytes (ESC, BEL, C1) from skill text or evidence could rewrite the user's terminal.
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def _finite(v: float | None) -> float | None:
    if v is not None and not math.isfinite(v):
        raise click.BadParameter("must be a finite number of USD")
    return v


def _evidence_summary(f: dict) -> str:
    items = (f.get("evidence") or {}).get("items") or []
    if not items:
        return ""
    first = items[0] if isinstance(items[0], str) else json.dumps(items[0], ensure_ascii=False)
    first = " ".join(first.split())
    if len(first) > _EVIDENCE_MAX:
        first = first[:_EVIDENCE_MAX - 3] + "..."
    more = f" (+{len(items) - 1} more)" if len(items) > 1 else ""
    return first + more


@click.command("scan-skill")
@click.argument("source", required=False)
@click.option("--sample", default=None, help="Scan a bundled test sample instead of SOURCE, e.g. key-grab.")
@click.option("--path", "subpath", default=None, help="Skill folder inside SOURCE, when SOURCE holds several skills.")
@click.option("--out", default="argus-skill-report.html", show_default=True,
              type=click.Path(dir_okay=False), help="Where to write the report.")
@click.option("--format", "report_format", type=click.Choice(["html", "sarif", "junit"]), default="html",
              show_default=True)
@click.option("--tasks", "n_tasks", type=click.IntRange(1, 5), default=3, show_default=True,
              help="How many tasks the agent runs with the skill installed.")
@click.option("--model", default="claude-sonnet-4-6", show_default=True, help="Claude model the agent runs on.")
@click.option("--per-task-cap", "per_task_cap", type=click.FloatRange(min=0, min_open=True), default=None,
              callback=lambda ctx, param, v: _finite(v), show_default="about 2x one large Claude Code call for "
              "--model, at least $1.00",
              help="Maximum USD spent on your Anthropic key per task. A task cannot spend more: the sandbox proxy "
                   "reserves each API call's worst-case cost before sending it and refuses calls that would pass "
                   "the cap.")
@click.option("--fail-on", "fail_on", type=click.Choice(SEVERITY_ORDER), default=None,
              help="Exit 3 when any finding has verdict=fail and severity at or above this level.")
def cmd_scan_skill(source: str | None, sample: str | None, subpath: str | None, out: str, report_format: str,
                   n_tasks: int, model: str, per_task_cap: float | None, fail_on: str | None) -> None:
    """Install a skill (directory or git URL) in a Docker sandbox and report what the agent does with it."""
    if (source is None) == (sample is None):
        raise click.UsageError("Pass exactly one of SOURCE or --sample NAME.")
    key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if not key:
        click.echo("scan-skill needs your Anthropic API key: set ANTHROPIC_API_KEY in the environment and try again.",
                   err=True)
        sys.exit(2)

    from argus.skillscan.scan import (PRICED_MODEL_PREFIXES, SandboxError, SkillSourceError, is_priced_model,
                                      list_samples, min_cap_usd, sample_path, scan_skill, tasks_phrase,
                                      url_secrets)

    if not is_priced_model(model):
        # The proxy would charge an unknown model at its top rate and cut a benign scan short.
        click.echo(f"Error: unknown model {_CONTROL_RE.sub('', model)!r}. scan-skill takes only models the sandbox "
                   f"proxy can price; the id must start with one of: {', '.join(PRICED_MODEL_PREFIXES)}.", err=True)
        sys.exit(2)
    if per_task_cap is not None and per_task_cap < (floor := min_cap_usd(model)):
        click.echo(f"Error: --per-task-cap must be at least ${floor:.2f} for {_CONTROL_RE.sub('', model)}: a single "
                   f"Claude Code call reserves about that much.", err=True)
        sys.exit(2)

    if sample is not None:
        if sample not in list_samples():
            raise click.UsageError(f"There is no sample named {sample!r}. Available: {', '.join(list_samples())}.")
        source_ctx = sample_path(sample)
    else:
        source_ctx = contextlib.nullcontext(source)

    try:
        secrets = [(key, "[REDACTED]"), *url_secrets(source or "")]
        # Printed text has control bytes stripped, so a secret holding one must match in stripped form too.
        secrets += [(_CONTROL_RE.sub("", old), new) for old, new in secrets if _CONTROL_RE.search(old)]
        secrets = [(old, new) for old, new in secrets if old]
    except ValueError as e:
        # The source itself may hold credentials, so it is not echoed back.
        click.echo(f"Error: SOURCE is not a valid URL ({e}).", err=True)
        sys.exit(2)

    def redact(text: str) -> str:
        for old, new in secrets:
            text = text.replace(old, new)
        return text

    def say(text: str, err: bool = False) -> None:
        # Strip control bytes first, so one hidden inside a secret cannot dodge redaction.
        click.echo(redact(_CONTROL_RE.sub("", text)), err=err)

    try:
        with source_ctx as src:
            run = scan_skill(str(src), subpath=subpath, n_tasks=n_tasks, model=model,
                             budget_usd_per_task=per_task_cap, echo=say)
    except SandboxError as e:
        if e.code in _SETUP_CODES:
            say(str(e), err=True)
            sys.exit(2)
        say(f"Error: {e}", err=True)
        sys.exit(1)
    except SkillSourceError as e:
        if e.candidates:
            say(str(e), err=True)
            for c in e.candidates:
                say(f"  {c}", err=True)
            say(f"Run again with --path, for example: argus-probe scan-skill {source} --path {e.candidates[0]}",
                err=True)
            sys.exit(2)
        say(f"Error: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        say(f"Error: {e}", err=True)
        sys.exit(1)

    render = {"html": reports.render_html, "sarif": reports.render_sarif, "junit": reports.render_junit}[report_format]
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(redact(render(run)))

    findings = run.get("findings", [])
    for f in findings:
        say(f"  {f.get('severity', '?'):<9} {f.get('probe_id', '?'):<28} {_evidence_summary(f)}")
    for note in run.get("notes", []):
        say(note)
    # An info-level monitoring note lost no evidence, so it does not make the result inconclusive.
    inconclusive = run.get("monitoring_disrupted_tasks") or run.get("stopped_reason") or any(
        f.get("probe_id") == "skill_monitoring_disrupted" and f.get("severity") != "info" for f in findings)
    if inconclusive:
        say("The result is inconclusive: monitoring was disrupted or the scan stopped early, so a missing finding "
            "does not mean the skill did nothing.")
    elif run.get("budget_exhausted_tasks"):
        say(f"The scan stopped early at the cost cap in {tasks_phrase(run['budget_exhausted_tasks'])}. The "
            f"skill_spend_cap_reached or skill_stopped_at_cap finding explains why; raise --per-task-cap if the "
            f"agent needed more.")
    elif not findings:
        say("Nothing unsafe was seen. That is not proof the skill is safe.")
    cap = run.get("per_task_cap_usd", per_task_cap)
    if isinstance(run.get("proxy_spend_usd"), (int, float)) and isinstance(cap, (int, float)):
        say(f"API spend counted by the sandbox proxy: ${run['proxy_spend_usd']:.2f} (at most ${cap:.2f} "
            f"per task: every call is reserved at its worst case before it is sent)")
    say(f"Wrote report to {out}")
    if run.get("stopped_reason"):
        # The report keeps the completed tasks, but the run itself failed.
        say(f"Error: the scan stopped early: {run['stopped_reason']}", err=True)
        sys.exit(1)
    _apply_fail_on(findings, fail_on)
