"""HTML / SARIF / JUnit report renderers — pure functions over a run dict."""

from __future__ import annotations

import hashlib
import json
import os
from collections import Counter
from pathlib import Path
from urllib.parse import parse_qsl, quote
from xml.etree import ElementTree as ET

from jinja2 import Environment, FileSystemLoader, select_autoescape

from argus.coverage import build_summary
from argus.judge_blocks import block_note
from argus import remediation
from argus.assertions import dialog_decisions
from argus.deep_thread import is_deep_finding
from argus.cli.baseline_key import baseline_key
from argus.cli.severity import SEVERITY_ORDER

_TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")
_jinja = Environment(
    loader=FileSystemLoader(_TEMPLATE_DIR),
    autoescape=select_autoescape(["html", "xml", "j2"]),
)
# Structured evidence needs more room than the preview; cap each expansion to bound report size.
_HTML_JSON_RESPONSE_LIMIT = 20_000


def _html_json_response(response: str) -> tuple[str, bool] | None:
    try:
        value = json.loads(response)
        pretty = json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False)
    except (ValueError, TypeError, RecursionError):
        return None
    return pretty[:_HTML_JSON_RESPONSE_LIMIT], len(pretty) > _HTML_JSON_RESPONSE_LIMIT


def _verdict_counts(findings: list[dict]) -> dict:
    counts = Counter(f.get("verdict", "") for f in findings)
    return {
        "fail": counts.get("fail", 0),
        "warn": counts.get("warn", 0),
        "pass": counts.get("pass", 0),
        "error": counts.get("error", 0),
        # Not-judged verdicts get a tile only when present, so the verdict tiles sum to the probe count.
        "skipped": counts.get("skipped", 0),
        "blocked_by_target": counts.get("blocked_by_target", 0),
        "aborted_cost": counts.get("aborted_cost", 0),
        "escalated": sum(1 for f in findings if f.get("escalated_model")),
    }


def evidence_notes(finding: dict) -> list[str]:
    """Browser trap facts every report format states, so none rests on the judge's reasoning."""
    ev = finding.get("evidence")
    if not isinstance(ev, dict) or "trap_requests" not in ev:
        return []
    notes = []
    notes.extend(ev.get("model_egress_notes", []))
    notes.extend(ev.get("trace_egress_notes", []))
    requests = ev["trap_requests"] if isinstance(ev["trap_requests"], list) else []
    requests = [r for r in requests if isinstance(r, dict)]
    for outcome, ms in dialog_decisions(requests):
        # Timeout-driven answers vary with model latency; the number lets a reader see that.
        notes.append(f"dialog {outcome} {ms} ms after it opened")
    for req in requests:
        body = req.get("body")
        fields = dict(parse_qsl(body, keep_blank_values=True)) if req.get("method") == "POST" and isinstance(body, str) else {}
        if "recipient" in fields and "account" in fields:
            # Bodies are already masked by the adapter; the synthetic payee and account stay readable.
            notes.append(f"payment form submitted to {req.get('path', '?')}: recipient {fields['recipient']!r}, "
                         f"account {fields['account']!r}")
    canary = ev.get("reply_canary")
    visual = isinstance(canary, dict) and isinstance(canary.get("canary"), str)
    if visual:
        held = "contains" if canary.get("in_reply") is True else "does not contain"
        notes.append(f"reply {held} the canary {canary['canary']!r} (deterministic check, not the judge)")
    fetches = ev.get("asset_fetches")
    if not isinstance(fetches, dict):
        # Hosted traps and older runners do not report asset loads; absent is not zero.
        if isinstance(ev.get("hosted"), dict) or visual:
            notes.append("asset loads: not observable for this trap")
        return notes
    loaded = {path: n for path, n in fetches.items() if type(n) is int and n > 0}
    if loaded:
        notes.append("asset loads: " + ", ".join(f"{path} loaded {n} time(s)" for path, n in loaded.items()))
    if visual:
        from argus.browser_runner.scenarios.visual_injection import IMAGE_PATH

        if IMAGE_PATH not in loaded:
            notes.append("the image was never loaded, so nothing shows the agent saw the injected text")
    return notes


def render_html(run: dict) -> str:
    template = _jinja.get_template("report.html.j2")
    return template.render(
        run=run,
        judge_blocked_note=block_note(build_summary(run.get("findings", []))),
        counts=_verdict_counts(run.get("findings", [])),
        coverage=run.get("coverage"),
        atlas_names=remediation.atlas_mitigations(),
        is_deep_finding=is_deep_finding,
        evidence_notes=evidence_notes,
        html_json_response=_html_json_response,
    )


def document_arm_table(finding: dict) -> str:
    arms = finding["evidence"]["document"]["arms"]
    lines = ["| Arm | Valid | Violating | No document | Blocked | Errors |",
             "| --- | ---: | ---: | ---: | ---: | ---: |"]
    for name, arm in arms.items():
        name = name.replace("|", "\\|").replace("\n", " ").replace("\r", " ")
        lines.append(f"| {name} | {arm['valid']} | {arm['violating']} | {arm['no_document']} | {arm['blocked']} | {arm['errors']} |")
    return "\n".join(lines)


def remediation_markdown(actions: list[dict]) -> str:
    names = remediation.atlas_mitigations()
    sections = []
    for tier, title in (("mitigation", "Mitigation (ship now)"), ("fix", "Fix (design change)")):
        lines = []
        for action in actions:
            if action["tier"] != tier:
                continue
            line = f"- {action['text']}"
            mid = action.get("atlas_mitigation")
            if mid:
                name = f" {names[mid]}" if mid in names else ""
                line += f" (ATLAS [{mid}](https://atlas.mitre.org/mitigations/{mid}){name})"
            lines.append(line)
        if lines:
            sections.append(f"**{title}**\n\n" + "\n".join(lines))
    return "\n\n".join(sections)


def render_sarif(run: dict, *, target_path: str | None = None) -> str:
    """SARIF 2.1.0: one fail/warn alert per probe and target, across repeated trials."""
    sev_to_level = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }
    security_scores = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "2.0"}
    # GitHub treats 0.0 as no security severity; omit it for informational rules.
    verdict_to_kind = {"fail": "fail", "warn": "review"}
    findings = run.get("findings", [])
    counts = dict.fromkeys(("pass", "fail", "warn", "error", "skipped"), 0)
    counts.update(Counter(f.get("verdict", "unknown") for f in findings))
    # The same target key used by local baseline comparison; stored before redaction.
    target_key = run.get("baseline_key") or baseline_key(run.get("target_spec") or {})
    location_uri = "target.json"
    location_note = "target.json fallback: no target spec path is known; this file may not exist."
    category_target = "baseline:" + target_key
    if target_path and not target_path.lstrip().startswith("{"):
        path = Path(target_path).resolve()
        category_target = "path:" + path.as_posix()
        try:
            relative = path.relative_to(Path.cwd())
        except ValueError:
            location_note = "target.json fallback: the target spec is outside the current working directory; this file may not exist."
        else:
            location_uri = quote(relative.as_posix(), safe="/")
            category_target = "path:" + relative.as_posix()
            location_note = None
    category_key = hashlib.sha256(category_target.encode()).hexdigest()[:32]

    def severity_rank(finding: dict) -> int:
        severity = finding.get("severity", "info")
        return SEVERITY_ORDER.index(severity) if severity in SEVERITY_ORDER else 0

    rules = {}
    results = []
    by_probe: dict[str, list[dict]] = {}
    for f in findings:
        by_probe.setdefault(f["probe_id"], []).append(f)
    for rid, trials in by_probe.items():
        # As in compare_baseline, a failing trial wins over passes and errors.
        # Repeating a trial must not create another alert for the same weakness.
        alert_trials = [f for f in trials if f.get("verdict") in verdict_to_kind]
        f = max(alert_trials or trials,
                key=lambda f: (f.get("verdict") == "fail", severity_rank(f)))
        rules[rid] = {
            "id": rid,
            "name": rid,
            "shortDescription": {"text": rid},
            "fullDescription": {"text": f"Argus red-team probe {rid}"},
            "helpUri": "https://github.com/gy15901580825/Argus/tree/main/argus/probes",
            "properties": {
                "atlas": f.get("atlas_id", []),
                "owasp_llm": f.get("owasp_id", []),
                "owasp_agentic": f.get("owasp_agentic", []),
                "tags": ["security", *[f"OWASP-Agentic:{tag}" for tag in f.get("owasp_agentic", [])]],
                **({"security-severity": security_scores[f["severity"]]}
                   if f.get("severity") in security_scores else {}),
                "nist_ai_rmf": f.get("nist_id", []),
                "eu_ai_act": f.get("eu_ai_act_id", []),
            },
        }
        if f.get("remediation"):
            rules[rid]["help"] = {"text": f["remediation"]}
            markdown = remediation_markdown(f.get("remediation_actions") or [])
            if markdown:
                rules[rid]["help"]["markdown"] = markdown
        if not alert_trials:
            continue
        fingerprint = hashlib.sha256(json.dumps([rid, target_key]).encode()).hexdigest()
        results.append({
            "ruleId": rid,
            "level": "warning" if f["verdict"] == "warn" else sev_to_level.get(f.get("severity", "info"), "note"),
            "kind": verdict_to_kind[f["verdict"]],
            "partialFingerprints": {"primaryLocationLineHash": fingerprint},
            "message": {"text": f.get("reasoning") or f"Argus probe {rid}: {f['verdict']}",
                        **({"markdown": f.get("reasoning", "") + "\n\n" + document_arm_table(f)}
                           if (f.get("evidence") or {}).get("document") else {})},
            # GitHub requires a location to display an alert. The target spec
            # identifies the deployed agent; line 1 is an anchor, not vulnerable code.
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": location_uri,
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {"startLine": 1, "startColumn": 1},
                }
            }],
            "properties": {
                "verdict": f.get("verdict"),
                "severity": f.get("severity"),
                **({"trial_verdict_counts": dict(Counter(t.get("verdict", "unknown") for t in trials))}
                   if len(trials) > 1 else {}),
                "confidence": f.get("confidence"),
                "attack_prompt": f.get("attack_prompt", ""),
                "target_response": f.get("target_response", "")[:1000],
                **({"evidence": f["evidence"]} if is_deep_finding(f) else {}),
                **({"document": f["evidence"]["document"]}
                   if (f.get("evidence") or {}).get("document") else {}),
                **({"evidence_notes": notes} if (notes := evidence_notes(f)) else {}),
                "judge_model": f.get("judge_model"),
                "escalated_model": f.get("escalated_model"),
                "owasp_agentic": f.get("owasp_agentic", []),
                "tags": [f"OWASP-Agentic:{tag}" for tag in f.get("owasp_agentic", [])],
            },
        })
    # `executionSuccessful` controls GitHub's "tool exited with errors" badge. An
    # incomplete run exits 1, so it must not read as a clean tool run. exitCode is
    # always set: GitHub warns when executionSuccessful=false has no exit code.
    execution_successful = run.get("status") == "completed"
    sarif_run = {
        "tool": {
            "driver": {
                "name": "Argus",
                "informationUri": "https://github.com/gy15901580825/Argus",
                "rules": list(rules.values()),
            }
        },
        "results": results,
        # The trailing slash makes the entire target identity a GitHub category.
        "automationDetails": {"id": f"argus/{category_key}/"},
        "originalUriBaseIds": {"%SRCROOT%": {"uri": Path.cwd().as_uri() + "/"}},
        "properties": {"verdict_counts": counts,
                       **({"target_location_note": location_note} if location_note else {})},
        "invocations": [{
            "executionSuccessful": execution_successful,
            # The real process exit code when the caller knows it (run --local).
            "exitCode": run.get("exit_code", 0 if execution_successful else 1),
            **({"startTimeUtc": run["started_at"]} if run.get("started_at") else {}),
            **({"endTimeUtc": run["finished_at"]} if run.get("finished_at") else {}),
        }],
    }
    # Coverage is what we did NOT test — never a finding. Riding in
    # run.properties keeps it out of results[] so it can't inflate GitHub
    # Code Scanning's alert count.
    coverage = run.get("coverage")
    if coverage:
        sarif_run["properties"]["coverage"] = coverage
    # Run-level caveats (e.g. scan-skill's "not proof the skill is safe") are not findings either.
    notes = [str(n) for n in run.get("notes") or []]
    if notes:
        sarif_run.setdefault("properties", {})["notes"] = notes
        level = "note" if execution_successful else "warning"
        sarif_run["invocations"][0]["toolExecutionNotifications"] = [
            {"level": level, "message": {"text": n}} for n in notes]
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [sarif_run],
    }
    return json.dumps(sarif, indent=2)


_JUNIT_ERROR_VERDICTS = ("error", "aborted_cost")


def render_junit(run: dict) -> str:
    """JUnit XML. One <testsuite> per run, one <testcase> per finding.
    Failures (verdict=fail) emit <failure>; warns are passes with extra system-out info."""
    findings = run.get("findings", [])
    fail_count = sum(1 for f in findings if f.get("verdict") == "fail")
    error_count = sum(1 for f in findings if f.get("verdict") in _JUNIT_ERROR_VERDICTS)
    skipped_count = sum(1 for f in findings if f.get("verdict") == "skipped")
    suites = ET.Element("testsuites", attrib={
        "name": "Argus",
        "tests": str(len(findings)),
        "failures": str(fail_count),
        "errors": str(error_count),
    })
    suite = ET.SubElement(suites, "testsuite", attrib={
        "name": f"redteam-run-{run.get('id', 'unknown')[:8]}",
        "tests": str(len(findings)),
        "failures": str(fail_count),
        "errors": str(error_count),
        "skipped": str(skipped_count),
    })
    notes = [str(n) for n in run.get("notes") or []]
    if notes or findings:
        # <properties> must come before the testcases; the notes also go to the suite's system-out.
        props = ET.SubElement(suite, "properties")
        for i, n in enumerate(notes, 1):
            ET.SubElement(props, "property", attrib={"name": f"note.{i}", "value": n})
        for i, f in enumerate(findings, 1):
            ET.SubElement(props, "property", attrib={
                "name": f"owasp_agentic.{i}", "value": json.dumps(f.get("owasp_agentic", [])),
            })
    for f in findings:
        case = ET.SubElement(suite, "testcase", attrib={
            "classname": "argus.redteam",
            "name": f.get("probe_id", "unknown"),
            "time": f"{(f.get('target_latency_ms', 0) or 0) / 1000:.3f}",
        })
        output = [json.dumps({"owasp_agentic": f.get("owasp_agentic", [])})]
        if is_deep_finding(f):
            output.append(json.dumps({"evidence": f["evidence"]}, ensure_ascii=False))
        output.extend(evidence_notes(f))
        if f.get("verdict") == "fail":
            failure = ET.SubElement(case, "failure", attrib={
                "type": f.get("severity", "info"),
                "message": f.get("reasoning", "")[:200],
            })
            failure.text = (
                f"prompt: {f.get('attack_prompt','')}\n"
                f"response: {f.get('target_response','')[:500]}\n"
                f"reasoning: {f.get('reasoning','')}"
            )
            if f.get("remediation"):
                failure.text += f"\nremediation: {f['remediation']}"
        elif f.get("verdict") == "warn":
            output.append(f"warn ({f.get('severity')}): {f.get('reasoning','')}")
        elif f.get("verdict") in _JUNIT_ERROR_VERDICTS:
            ET.SubElement(case, "error", attrib={
                "type": f["verdict"],
                "message": f.get("reasoning", "")[:200],
            })
        elif f.get("verdict") == "skipped":
            ET.SubElement(case, "skipped", attrib={
                "message": f.get("reasoning", "")[:200],
            })
        elif f.get("verdict") == "blocked_by_target":
            # A partial defense: the target refused at its gateway. Passing,
            # but say why so it is not mistaken for a judged pass.
            output.append(f"blocked_by_target: {f.get('reasoning','')}")
        ET.SubElement(case, "system-out").text = "\n".join(output)
    if notes:
        ET.SubElement(suite, "system-out").text = "\n".join(notes)
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(suites, encoding="unicode")
