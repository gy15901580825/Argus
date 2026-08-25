"""覆盖率进 SARIF,但绝不能成为一条"发现"。

塞进 results[] 会让 GitHub Code Scanning 把"我们没测这一格"显示成一个
待修的告警,污染告警计数。覆盖率只应出现在 run.properties 里。
"""
import json

from redteam.reports import render_sarif


def test_coverage_rides_in_run_properties_not_in_results():
    """覆盖率不是一条"发现"。塞进 results 会污染 GitHub 的告警计数。"""
    run = {"id": "1", "findings": [],
           "coverage": {"totals": {"probes_in_library": 3, "probes_run": 0},
                        "standards": {}}}
    sarif = json.loads(render_sarif(run))
    assert sarif["runs"][0]["results"] == []
    assert sarif["runs"][0]["properties"]["coverage"]["totals"]["probes_in_library"] == 3


def test_sarif_without_coverage_omits_the_property():
    sarif = json.loads(render_sarif({"id": "1", "findings": []}))
    assert "coverage" not in sarif["runs"][0].get("properties", {})
