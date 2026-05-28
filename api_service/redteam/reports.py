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
    autoescape=select_autoescape(["html", "xml"]),
)


def _verdict_counts(findings: list[dict]) -> dict:
    counts = Counter(f.get("verdict", "") for f in findings)
    return {
        "fail": counts.get("fail", 0),
        "warn": counts.get("warn", 0),
        "pass": counts.get("pass", 0),
        "escalated": sum(1 for f in findings if f.get("escalated_model")),
    }


def render_html(run: dict) -> str:
    template = _jinja.get_template("report.html.j2")
    return template.render(run=run, counts=_verdict_counts(run.get("findings", [])))


def render_sarif(run: dict) -> str:
    """SARIF 2.1.0. Each finding is a result; severity → SARIF level."""
    sev_to_level = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }
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
                "helpUri": f"https://github.com/argus-research/probes/tree/main/probes#{rid}",
                "properties": {
                    "atlas": f.get("atlas_id", []),
                    "owasp_llm": f.get("owasp_id", []),
                    "nist_ai_rmf": f.get("nist_id", []),
                    "eu_ai_act": f.get("eu_ai_act_id", []),
                },
            }
        results.append({
            "ruleId": rid,
            "level": sev_to_level.get(f.get("severity", "info"), "note"),
            "kind": verdict_to_kind.get(f.get("verdict", "pass"), "pass"),
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
            },
        })
    # `executionSuccessful` controls GitHub's "tool exited with errors" badge.
    # A run that produced any findings has done its job — orchestrator timeouts
    # / partial completions late in the stream don't change that. We only mark
    # the invocation as failed when there are truly no findings AND the run
    # status indicates outright failure. exitCode is always set: GitHub
    # specifically warns when executionSuccessful=false has no exit code.
    status = run.get("status")
    findings_count = len(run.get("findings", []))
    execution_successful = status == "completed" or findings_count > 0
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Argus",
                    "informationUri": "https://www.example.com",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
            "invocations": [{
                "executionSuccessful": execution_successful,
                "exitCode": 0 if execution_successful else 1,
                "startTimeUtc": run.get("started_at"),
                "endTimeUtc": run.get("finished_at"),
            }],
        }],
    }
    return json.dumps(sarif, indent=2)


def render_junit(run: dict) -> str:
    """JUnit XML. One <testsuite> per run, one <testcase> per finding.
    Failures (verdict=fail) emit <failure>; warns are passes with extra system-out info."""
    findings = run.get("findings", [])
    fail_count = sum(1 for f in findings if f.get("verdict") == "fail")
    suites = ET.Element("testsuites", attrib={
        "name": "Argus",
        "tests": str(len(findings)),
        "failures": str(fail_count),
    })
    suite = ET.SubElement(suites, "testsuite", attrib={
        "name": f"redteam-run-{run.get('id', 'unknown')[:8]}",
        "tests": str(len(findings)),
        "failures": str(fail_count),
    })
    for f in findings:
        case = ET.SubElement(suite, "testcase", attrib={
            "classname": "argus.redteam",
            "name": f.get("probe_id", "unknown"),
            "time": f"{(f.get('target_latency_ms', 0) or 0) / 1000:.3f}",
        })
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
        elif f.get("verdict") == "warn":
            sysout = ET.SubElement(case, "system-out")
            sysout.text = f"warn ({f.get('severity')}): {f.get('reasoning','')}"
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(suites, encoding="unicode")
