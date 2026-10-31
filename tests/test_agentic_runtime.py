"""Agentic mappings survive loading and all runtime finding adapters."""
from dataclasses import asdict
from types import SimpleNamespace

import pytest
import yaml

from argus.probe import Probe, ProbeMappings, load_probe


def _probe(**kwargs):
    return Probe(id="agentic", name="Agentic", target_class=("http-chat",),
                 attack_class=("prompt-injection",), severity="high", prompts=("hello",),
                 mappings=kwargs.pop("mappings", ProbeMappings()), judge_model="test",
                 judge_rubric_path="default.md", **kwargs)


@pytest.mark.parametrize("value", [["ASI01", "ASI10"], [], "ASI01", ["ASI11"], [1], None, {}])
def test_loader_validates_agentic_mapping_list(tmp_path, value):
    path = tmp_path / "probe.yaml"
    raw = {"id": "external", "name": "external", "target_class": ["http-chat"],
           "attack_class": ["prompt-injection"], "severity": "high", "prompts": ["hello"],
           "mappings": {"owasp_agentic": value}}
    path.write_text(yaml.safe_dump(raw))
    if value in (["ASI01", "ASI10"], []):
        assert load_probe(path).mappings.owasp_agentic == tuple(value)
    else:
        with pytest.raises(ValueError, match="owasp_agentic"):
            load_probe(path)


def test_legacy_pack_defaults_to_empty_agentic_mapping(tmp_path):
    path = tmp_path / "legacy.yaml"
    path.write_text("id: legacy\nname: legacy\ntarget_class: [http-chat]\n"
                    "attack_class: [prompt-injection]\nseverity: high\nprompts: [hello]\n")
    assert load_probe(path).mappings.owasp_agentic == ()


@pytest.mark.parametrize("verdict,status,ran", [("pass", "tested", 1), ("fail", "tested", 1),
    ("warn", "tested", 1), ("skipped", "skipped", 0), ("error", "error", 0),
    ("blocked_by_target", "blocked_by_target", 0), ("aborted_cost", "aborted_cost", 0)])
def test_agentic_coverage_keeps_library_and_run_status_independent(verdict, status, ran):
    from argus.coverage import build_coverage
    probes = [_probe(mappings=ProbeMappings(owasp_agentic=("ASI01",)))]
    finding = {"probe_id": "agentic", "verdict": verdict, "owasp_agentic": ["ASI01", "ASI10"]}
    standard = build_coverage(probes, [finding])["standards"]["owasp-agentic-top10"]
    assert standard["universe"] == "closed"
    cells = {cell["id"]: cell for cell in standard["cells"]}
    assert list(cells) == [f"ASI{i:02}" for i in range(1, 11)]
    assert cells["ASI01"]["library_status"] == "thin"
    assert cells["ASI01"]["run_status"] == status
    assert cells["ASI01"]["probes_run"] == ran
    assert cells["ASI10"]["library_status"] == "absent"
    assert cells["ASI10"]["run_status"] == status
    assert cells["ASI09"]["run_status"] == "not_run"


def test_custom_legacy_mappings_work_in_coverage_and_suites():
    from argus.coverage import build_coverage
    from argus.suites import derive_suites
    probe = _probe(mappings=SimpleNamespace(atlas=(), owasp_llm=(), nist_ai_rmf=(), eu_ai_act=()))
    cells = build_coverage([probe])["standards"]["owasp-agentic-top10"]["cells"]
    assert all(c["library_status"] == "absent" for c in cells)
    assert "owasp-agentic-top10" not in derive_suites([probe])


def test_agentic_suite_selects_only_mapped_runnable_probes():
    from argus.suites import derive_suites
    from dataclasses import replace
    probe = _probe(mappings=ProbeMappings(owasp_agentic=("ASI01",)))
    trap = replace(probe, id="trap", target_class=("mcp_trap",))
    scan = replace(probe, id="scan", target_class=("mcp_scan",))
    assert derive_suites([probe, trap, scan])["owasp-agentic-top10"] == ["agentic"]


def test_skipped_aborted_findings_emit_agentic_mapping_and_legacy_default():
    from argus.api import finding_dict
    from argus.runner import aborted_finding, skipped_finding
    probe = _probe(mappings=ProbeMappings(owasp_agentic=("ASI02", "ASI03")))
    for factory in (skipped_finding, aborted_finding):
        result = finding_dict(factory(probe, "did not run"), probe)
        assert result["owasp_agentic"] == ["ASI02", "ASI03"]
        assert "owasp_agentic_id" not in result
    legacy = _probe()
    assert finding_dict(skipped_finding(legacy, "legacy"), legacy)["owasp_agentic"] == []


@pytest.mark.asyncio
@pytest.mark.parametrize("mode,verdict", [("success", "pass"), ("compat", "skipped"),
                                            ("transport", "error"), ("rubric", "error")])
async def test_runner_preserves_agentic_in_success_skip_and_error(tmp_path, mode, verdict):
    from argus.runner import Runner
    from argus.targets._base import Target

    class LocalTarget(Target):
        compatible_classes = frozenset({"rag"}) if mode == "compat" else frozenset({"http-chat"})

        async def send_prompt(self, prompt, history=()):
            if mode == "transport":
                raise ConnectionError("connection failed")
            return "refused", 1.0

    class LocalJudge:
        async def judge(self, **kwargs):
            return SimpleNamespace(verdict="pass", severity="info", confidence=1.0,
                                   reasoning="refused", judge_model="test", escalated_model=None)

    if mode != "rubric":
        (tmp_path / "default.md").write_text("Assess the response")
    probe = _probe(mappings=ProbeMappings(owasp_agentic=("ASI01",)))
    runner = Runner(target=LocalTarget(), judge=LocalJudge(), rubrics_dir=tmp_path)
    findings = [asdict(f) async for f in runner.run_probe(probe)]
    assert len(findings) == 1
    assert findings[0]["verdict"] == verdict
    assert findings[0]["owasp_agentic"] == ["ASI01"]


@pytest.mark.parametrize("verdict", ["pass", "fail", "error", "skipped"])
def test_scan_adapter_preserves_agentic(verdict):
    from argus.mcp_scan.findings import finding
    probe = _probe(mappings=ProbeMappings(owasp_agentic=("ASI02",)))
    result = finding(probe, verdict=verdict, severity="info", reasoning="test", evidence={})
    assert result["owasp_agentic"] == ["ASI02"]


@pytest.mark.parametrize("outcome,verdict", [("passed", "pass"), ("failed", "fail"),
                                            ("inconclusive", "error")])
def test_trap_adapter_preserves_agentic(outcome, verdict):
    from argus.mcp_trap.driver import RoundOutcome, scenario_finding
    probe = _probe(mappings=ProbeMappings(owasp_agentic=("ASI03",)))
    round_ = RoundOutcome(round=1, outcome=outcome, reason="test", prompt="hello", reply="reply", evidence={})
    result = scenario_finding(probe, [round_], 1)
    assert result["verdict"] == verdict
    assert result["owasp_agentic"] == ["ASI03"]


@pytest.mark.parametrize("value,want", [(None, []), ("ASI01", []), (["ASI01"], ["ASI01"])])
def test_skillscan_normalizer_supplies_agentic_list(value, want):
    from argus.skillscan.scan import _normalise
    assert _normalise({"owasp_agentic": value}, "now")["owasp_agentic"] == want


def test_skillscan_raw_rule_findings_default_to_empty_agentic_mapping():
    from argus.skillscan.rules import evaluate
    from argus.skillscan.sandbox import TaskRun
    run = TaskRun(prompt="Format files", transcript=[{"type": "result", "result":
        "Do not run `mdtidy --fix <file>` here."}], proxy_log=[], file_log=[], exit_code=0, timed_out=False)
    findings = evaluate([run], [], skill_name="s", skill_files={"SKILL.md": "Run `mdtidy --fix <file>`."})
    assert len(findings) == 1
    assert findings[0]["owasp_agentic"] == []


@pytest.mark.asyncio
@pytest.mark.parametrize("aborted", [False, True])
async def test_iterative_runner_preserves_agentic_on_judged_and_cost_aborted_findings(tmp_path, aborted):
    from argus.cost_meter import CostExceededError
    from argus.iterative_pair import PAIRProbe
    from argus.runner import Runner
    from argus.targets._base import Target

    class LocalTarget(Target):
        async def send_prompt(self, prompt, history=()):
            return "refused", 1.0

    class LocalJudge:
        async def judge(self, **kwargs):
            return SimpleNamespace(verdict="pass", severity="info", confidence=1.0,
                                   reasoning="refused", judge_model="test", escalated_model=None)

    class LocalProbe(PAIRProbe):
        async def next_prompt(self, ctx):
            if aborted:
                raise CostExceededError("budget reached")
            return await super().next_prompt(ctx)

    (tmp_path / "default.md").write_text("Assess the response")
    probe = LocalProbe(seed_prompt="hello", max_rounds=1, judge_rubric_path="default.md",
                       mappings=ProbeMappings(owasp_agentic=("ASI01",)))
    runner = Runner(target=LocalTarget(), judge=LocalJudge(), rubrics_dir=tmp_path)
    findings = [asdict(f) async for f in runner.run_probe(probe)]
    assert len(findings) == 1
    assert findings[0]["verdict"] == ("aborted_cost" if aborted else "pass")
    assert findings[0]["owasp_agentic"] == ["ASI01"]
