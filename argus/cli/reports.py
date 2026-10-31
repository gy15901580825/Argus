"""HTML / SARIF / JUnit report renderers — pure functions over a run dict."""

from __future__ import annotations

import json
import os
from collections import Counter
from xml.etree import ElementTree as ET

from jinja2 import Environment, FileSystemLoader, select_autoescape

_TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")
_jinja = Environment(
    loader=FileSystemLoader(_TEMPLATE_DIR),
    autoescape=select_autoescape(["html", "xml", "j2"]),
)


def _verdict_counts(findings: list[dict]) -> dict:
    counts = Counter(f.get("verdict", "") for f in findings)
    return {
        "fail": counts.get("fail", 0),
        "warn": counts.get("warn", 0),
        "pass": counts.get("pass", 0),
        "error": counts.get("error", 0),
        "escalated": sum(1 for f in findings if f.get("escalated_model")),
    }


def render_html(run: dict) -> str:
    template = _jinja.get_template("report.html.j2")
    return template.render(
        run=run,
        counts=_verdict_counts(run.get("findings", [])),
        coverage=run.get("coverage"),
    )


def render_sarif(run: dict) -> str:
    """SARIF 2.1.0. Each finding is a result; severity → SARIF level."""
    sev_to_level = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }
    # Only judged verdicts map to a SARIF kind. error / skipped /
    # blocked_by_target / aborted_cost were not judged and must not read as a
    # pass; the real verdict stays in properties.verdict.
    verdict_to_kind = {"fail": "fail", "warn": "review", "pass": "pass"}

    rules = {}
    results = []
    for f in run.get("findings", []):
        rid = f["probe_id"]
        if rid not in rules:
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
                    "tags": [f"OWASP-Agentic:{tag}" for tag in f.get("owasp_agentic", [])],
                    "nist_ai_rmf": f.get("nist_id", []),
                    "eu_ai_act": f.get("eu_ai_act_id", []),
                },
            }
            if f.get("remediation"):
                rules[rid]["help"] = {"text": f["remediation"]}
        results.append({
            "ruleId": rid,
            "level": sev_to_level.get(f.get("severity", "info"), "note"),
            "kind": verdict_to_kind.get(f.get("verdict"), "notApplicable"),
            "message": {"text": f.get("reasoning", "")},
            # SARIF 2.1.0 requires every result to carry at least one location
            # so GitHub code-scanning can dedupe and place alerts. Red-team
            # findings target a deployed agent (not a source line), so we
            # synthesize a location pointing at the target spec file the
            # operator committed (target.json by convention). This makes the
            # alert appear next to the file that defines what was probed.
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": "target.json",
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {"startLine": 1, "startColumn": 1},
                }
            }],
            "properties": {
                "verdict": f.get("verdict"),
                "severity": f.get("severity"),
                "confidence": f.get("confidence"),
                "attack_prompt": f.get("attack_prompt", ""),
                "target_response": f.get("target_response", "")[:1000],
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
        "invocations": [{
            "executionSuccessful": execution_successful,
            # The real process exit code when the caller knows it (run --local).
            "exitCode": run.get("exit_code", 0 if execution_successful else 1),
            "startTimeUtc": run.get("started_at"),
            "endTimeUtc": run.get("finished_at"),
        }],
    }
    # Coverage is what we did NOT test — never a finding. Riding in
    # run.properties keeps it out of results[] so it can't inflate GitHub
    # Code Scanning's alert count.
    coverage = run.get("coverage")
    if coverage:
        sarif_run["properties"] = {"coverage": coverage}
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
