"""Rendered report navigation, verdict presentation and trial counts."""

from xml.etree import ElementTree as ET

import pytest

from argus.cli.reports import render_html
from argus.cli.run_json import scrub_run


def finding(probe_id, verdict, severity="info", **fields):
    return {
        "probe_id": probe_id, "verdict": verdict, "severity": severity,
        "confidence": 1.0, "judge_model": "", "reasoning": "Captured evidence.",
        "attack_prompt": "Check the boundary.", "target_response": "Safe reply.",
        "target_latency_ms": 12, "probed_at": "2026-11-22T00:00:00Z", **fields,
    }


def run(findings, **fields):
    return {"id": "offline-report-fixture", "status": "completed", "findings": findings, **fields}


def body(report):
    content = report.split("<body>", 1)[1].split("</body>", 1)[0]
    return ET.fromstring(f"<body>{content}</body>")


def cards(tree):
    return tree.findall(".//*[@class='finding']")


def test_html_orders_verdicts_then_severity_then_probe_id():
    findings = [finding("pass", "pass", "critical"), finding("skip", "skipped"),
                finding("error", "error"), finding("warn", "warn", "critical"),
                finding("low", "fail", "low"), finding("medium", "fail", "medium"),
                finding("info", "fail"), finding("high", "fail", "high"),
                finding("z-critical", "fail", "critical"), finding("a-critical", "fail", "critical")]
    expected = ["a-critical", "z-critical", "high", "medium", "low", "info", "warn", "error", "skip", "pass"]
    tree = body(render_html(run(findings)))
    assert ["".join(card.itertext()).split(" —", 1)[0].strip() for card in cards(tree)] == expected


def test_html_index_links_to_every_finding_even_with_repeated_probe_ids():
    tree = body(render_html(run([finding("same", "pass"), finding("same", "fail"), finding("other", "warn")])))
    index = tree.find(".//table[@class='finding-index']")
    assert index is not None
    rows = index.findall("tbody/tr")
    assert len(rows) == 3
    assert [["".join(td.itertext()).strip() for td in row.findall("td")] for row in rows] == [
        ["same", "fail", "info", "2"], ["other", "warn", "info", "1"], ["same", "pass", "info", "2"]]
    links = [a.get("href") for a in index.findall(".//a")]
    anchors = ["#" + card.get("id", "") for card in cards(tree)]
    assert len(set(links)) == 3
    assert links == anchors


@pytest.mark.parametrize("verdict, collapsed", [("fail", False), ("warn", False), ("error", False), ("pass", True), ("skipped", True)])
def test_html_collapses_only_pass_and_skipped(verdict, collapsed):
    tree = body(render_html(run([finding("probe", verdict)])))
    card, = cards(tree)
    assert (card.tag == "details") == collapsed
    assert "open" not in card.attrib
    if collapsed:
        assert card[0].tag == "summary"
    assert "Check the boundary." in "".join(card.itertext())
    assert "Safe reply." in "".join(card.itertext())


@pytest.mark.parametrize("findings, counts", [
    ([finding("a", "fail"), finding("a", "warn"), finding("a", "error"), finding("b", "skipped"), finding("b", "pass")], "Probes: 2 · Findings: 5"),
    ([], "Probes: 0 · Findings: 0"),
])
def test_html_header_counts_distinct_probes_and_trials(findings, counts):
    tree = body(render_html(run(findings)))
    assert counts in "".join(tree.find("p").itertext())


@pytest.mark.parametrize("verdict, model, confidence, visible", [
    ("fail", "offline-judge", 1.0, True), ("warn", "offline-judge", 0.6, True),
    ("pass", "offline-judge", 1.0, True), ("fail", "", 0.6, False),
    ("skipped", "", 1.0, False), ("error", "offline-judge", 1.0, False),
])
def test_html_confidence_requires_a_judge_decided_verdict(verdict, model, confidence, visible):
    tree = body(render_html(run([finding("probe", verdict, judge_model=model, confidence=confidence)])))
    card, = cards(tree)
    text = "".join(card.itertext())
    assert (f"confidence {confidence:.2f}" in text) == visible
    assert "probe" in text and verdict in text


@pytest.mark.parametrize("name", [None, "Boundary protection"])
def test_html_coverage_omits_empty_name_column_but_preserves_available_names(name):
    cell = {"id": "CELL01", "library_status": "thin", "run_status": "tested", "probes_in_library": 1,
            "probes_run": 1, "verdicts": {"fail": 1}, **({"name": name} if name else {})}
    coverage = {"thin_threshold": 2, "standards": {"standard": {"universe": "open", "cells": [cell]}}}
    tree = body(render_html(run([], coverage=coverage)))
    table = tree.find(".//table[@class='coverage-table']")
    assert table is not None
    assert ("Name" in [th.text for th in table.findall("tr/th")]) == bool(name)
    assert len(table.findall("tr")[1].findall("td")) == (7 if name else 6)
    assert ("Boundary protection" in "".join(table.itertext())) == bool(name)


def test_html_collapsed_finding_keeps_secrets_masked_and_markup_escaped():
    secret = "synthetic-private-token"
    report = render_html(scrub_run(run([finding("probe", "pass", attack_prompt=secret,
                                               target_response=f"{secret} <script>bad</script>", reasoning=secret)]), [secret]))
    tree = body(report)
    card, = cards(tree)
    assert card.tag == "details"
    assert secret not in report and "***" in "".join(card.itertext())
    assert "<script>" not in report and "&lt;script&gt;" in report
