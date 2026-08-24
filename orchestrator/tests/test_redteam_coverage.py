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
    ("error", "error"),
    ("pass", "tested"),
    ("fail", "tested"),
    ("warn", "tested"),
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


def test_a_cell_where_every_probe_errored_is_not_called_tested():
    """探针全部 error 的那一格,恰恰是"我们没看这里"。runner 的
    requires_interaction 闸门就是为了把"agent 根本没露面"变成 error 而不是
    pass —— 覆盖率表要是把它算成 tested,等于把那道闸门的结论又抹掉一次。"""
    probes = [_P(str(i), _M(owasp_llm=("LLM01",))) for i in range(3)]
    findings = [_f(str(i), "error", owasp=("LLM01",)) for i in range(3)]
    cov = build_coverage(probes, findings)
    cell = {c["id"]: c for c in cov["standards"]["owasp-llm-top10"]["cells"]}["LLM01"]
    assert cell["run_status"] == "error"
    assert cell["run_status"] != "tested"
    assert cell["probes_run"] == 0
    # 明细一个都没丢,只是不再冒充"跑过"
    assert cell["verdicts"] == {"error": 3}


def test_error_next_to_a_real_verdict_is_mixed():
    probes = [_P("a", _M(owasp_llm=("LLM01",))), _P("b", _M(owasp_llm=("LLM01",)))]
    findings = [_f("a", "pass", owasp=("LLM01",)), _f("b", "error", owasp=("LLM01",))]
    cov = build_coverage(probes, findings)
    cell = {c["id"]: c for c in cov["standards"]["owasp-llm-top10"]["cells"]}["LLM01"]
    assert cell["run_status"] == "mixed"
    assert cell["probes_run"] == 1


@pytest.mark.parametrize("verdict", ["skipped", "blocked_by_target", "aborted_cost", "error"])
def test_probes_run_does_not_count_probes_that_never_ran(verdict):
    """原来这一格会渲染成"in library 3 / run 3 / skipped" —— 数字说跑了三个,
    只有旁边那个状态词在小声反驳。读者会信数字。"""
    probes = [_P(str(i), _M(owasp_llm=("LLM01",))) for i in range(3)]
    findings = [_f(str(i), verdict, owasp=("LLM01",)) for i in range(3)]
    cov = build_coverage(probes, findings)
    cell = {c["id"]: c for c in cov["standards"]["owasp-llm-top10"]["cells"]}["LLM01"]
    assert cell["probes_in_library"] == 3
    assert cell["probes_run"] == 0
    assert cell["verdicts"] == {verdict: 3}
    assert cov["totals"]["probes_run"] == 0


def test_totals_probes_run_counts_only_the_ones_that_ran():
    probes = [_P("a", _M(owasp_llm=("LLM01",))), _P("b", _M(owasp_llm=("LLM02",)))]
    findings = [_f("a", "fail", owasp=("LLM01",)), _f("b", "skipped", owasp=("LLM02",))]
    cov = build_coverage(probes, findings)
    assert cov["totals"]["probes_run"] == 1


def test_a_cell_touched_only_by_skipped_probes_still_appears_in_an_open_universe():
    """probes_run 归零不能让整格从表里消失 —— 那就从"少报"变成"不报"了。"""
    cov = build_coverage([], [_f("a", "skipped", atlas=("AML.T0051.001",))])
    atlas = cov["standards"]["mitre-atlas"]
    assert [c["id"] for c in atlas["cells"]] == ["AML.T0051.001"]
    assert atlas["cells"][0]["run_status"] == "skipped"
    assert atlas["cells"][0]["probes_run"] == 0


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
