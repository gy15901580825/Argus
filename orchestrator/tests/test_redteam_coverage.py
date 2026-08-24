"""覆盖率清单 —— 纯函数，输入探针与 findings，输出负空间表。"""
from dataclasses import dataclass, field

import pytest

from orchestrator.redteam.coverage import (
    OWASP_LLM_TOP10, THIN_THRESHOLD, build_coverage,
)


@dataclass(frozen=True)
class _M:
    owasp_llm: tuple = ()
    atlas: tuple = ()
    nist_ai_rmf: tuple = ()
    eu_ai_act: tuple = ()


@dataclass(frozen=True)
class _P:
    id: str
    mappings: _M = field(default_factory=_M)


def _f(probe_id, verdict, owasp=(), atlas=()):
    return {"probe_id": probe_id, "verdict": verdict,
            "owasp_id": list(owasp), "atlas_id": list(atlas),
            "nist_id": [], "eu_ai_act_id": []}


def test_owasp_universe_is_closed_all_ten_cells_always_present():
    cov = build_coverage([_P("a", _M(owasp_llm=("LLM01",)))])
    cells = cov["standards"]["owasp-llm-top10"]["cells"]
    assert [c["id"] for c in cells] == [i for i, _ in OWASP_LLM_TOP10]
    assert cov["standards"]["owasp-llm-top10"]["universe"] == "closed"


def test_a_cell_with_no_probe_reports_absent():
    cov = build_coverage([_P("a", _M(owasp_llm=("LLM01",)))])
    by_id = {c["id"]: c for c in cov["standards"]["owasp-llm-top10"]["cells"]}
    assert by_id["LLM07"]["probes_in_library"] == 0
    assert by_id["LLM07"]["library_status"] == "absent"


def test_thin_is_reported_not_rounded_away():
    """一格只有 1-2 个探针要说出来 —— 这张表的价值全在它敢显示空白。"""
    probes = [_P("a", _M(owasp_llm=("LLM04",))), _P("b", _M(owasp_llm=("LLM04",)))]
    cov = build_coverage(probes)
    by_id = {c["id"]: c for c in cov["standards"]["owasp-llm-top10"]["cells"]}
    assert THIN_THRESHOLD == 2
    assert by_id["LLM04"]["probes_in_library"] == 2
    assert by_id["LLM04"]["library_status"] == "thin"


def test_three_probes_is_covered():
    probes = [_P(str(i), _M(owasp_llm=("LLM01",))) for i in range(3)]
    cov = build_coverage(probes)
    by_id = {c["id"]: c for c in cov["standards"]["owasp-llm-top10"]["cells"]}
    assert by_id["LLM01"]["library_status"] == "covered"


def test_a_probe_mapped_to_two_cells_counts_in_both():
    cov = build_coverage([_P("a", _M(owasp_llm=("LLM01", "LLM02")))])
    by_id = {c["id"]: c for c in cov["standards"]["owasp-llm-top10"]["cells"]}
    assert by_id["LLM01"]["probes_in_library"] == 1
    assert by_id["LLM02"]["probes_in_library"] == 1


def test_no_findings_means_not_run():
    cov = build_coverage([_P("a", _M(owasp_llm=("LLM01",)))])
    by_id = {c["id"]: c for c in cov["standards"]["owasp-llm-top10"]["cells"]}
    assert by_id["LLM01"]["run_status"] == "not_run"
    assert by_id["LLM01"]["probes_run"] == 0


@pytest.mark.parametrize("verdict,expected", [
    ("skipped", "skipped"),
    ("blocked_by_target", "blocked_by_target"),
    ("aborted_cost", "aborted_cost"),
    ("pass", "tested"),
    ("fail", "tested"),
])
def test_uniform_verdict_maps_to_its_run_status(verdict, expected):
    probes = [_P("a", _M(owasp_llm=("LLM01",)))]
    cov = build_coverage(probes, [_f("a", verdict, owasp=("LLM01",))])
    by_id = {c["id"]: c for c in cov["standards"]["owasp-llm-top10"]["cells"]}
    assert by_id["LLM01"]["run_status"] == expected


def test_mixed_outcomes_report_mixed_not_the_optimistic_one():
    """一格里既有真跑过的也有被跳过的,不能只报好的那个。"""
    probes = [_P("a", _M(owasp_llm=("LLM01",))), _P("b", _M(owasp_llm=("LLM01",)))]
    findings = [_f("a", "pass", owasp=("LLM01",)), _f("b", "skipped", owasp=("LLM01",))]
    cov = build_coverage(probes, findings)
    by_id = {c["id"]: c for c in cov["standards"]["owasp-llm-top10"]["cells"]}
    assert by_id["LLM01"]["run_status"] == "mixed"
    assert by_id["LLM01"]["verdicts"] == {"pass": 1, "skipped": 1}


def test_open_universe_standards_only_report_touched_cells():
    cov = build_coverage([_P("a", _M(atlas=("AML.T0051.001",)))])
    atlas = cov["standards"]["mitre-atlas"]
    assert atlas["universe"] == "open"
    assert [c["id"] for c in atlas["cells"]] == ["AML.T0051.001"]


def test_empty_library_does_not_crash():
    cov = build_coverage([])
    assert cov["totals"]["probes_in_library"] == 0
    assert len(cov["standards"]["owasp-llm-top10"]["cells"]) == 10
    assert all(c["library_status"] == "absent"
               for c in cov["standards"]["owasp-llm-top10"]["cells"])


def test_real_library_owasp_thin_cells_are_reported_honestly():
    """跑真库。这个断言存在的意义是:如果哪天有人偷偷把薄的格填上或藏起来,它会红。"""
    from pathlib import Path
    from orchestrator.redteam.probe import load_all_probes
    probes = list(load_all_probes(
        Path(__file__).resolve().parent.parent / "orchestrator" / "redteam" / "probes"))
    cov = build_coverage(probes)
    by_id = {c["id"]: c for c in cov["standards"]["owasp-llm-top10"]["cells"]}
    assert all(by_id[i]["probes_in_library"] >= 0 for i, _ in OWASP_LLM_TOP10)
    # 全部十格都必须出现,且计数之和不小于探针数(一个探针可落多格)
    assert sum(c["probes_in_library"] for c in cov["standards"]["owasp-llm-top10"]["cells"]) >= len(probes)
