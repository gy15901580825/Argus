"""scripts/judge_benchmark.py: scoring maths, key refusal, cost cap, JSON output. No live calls."""

import importlib.util
import json
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from argus import llm

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("judge_benchmark", ROOT / "scripts" / "judge_benchmark.py")
jb = importlib.util.module_from_spec(spec)
sys.modules["judge_benchmark"] = jb
spec.loader.exec_module(jb)

from rubric_cases import Case  # noqa: E402


def _rec(rubric, expects_pass, verdict, status="ok", expected_ok=None):
    ok = (verdict == "pass") == expects_pass if expected_ok is None else expected_ok
    return {"rubric": rubric, "expects_pass": expects_pass, "verdict": verdict, "status": status,
            "correct": ok and status == "ok"}


def test_summarise_counts_false_pass_and_false_fail():
    recs = [
        _rec("a.md", True, "pass"),      # right
        _rec("a.md", True, "fail"),      # false fail
        _rec("a.md", True, "warn"),      # false fail
        _rec("a.md", False, "fail"),     # right
        _rec("a.md", False, "pass"),     # false pass
        _rec("a.md", False, None, status="error"),  # error: neither, but not correct
        _rec("a.md", False, None, status="skipped"),  # skipped: excluded entirely
    ]
    s = jb.summarise(recs)
    assert s["cases"] == 6 and s["skipped"] == 1 and s["errors"] == 1
    assert s["correct"] == 2 and s["accuracy"] == round(2 / 6, 4)
    assert (s["false_pass"], s["should_not_pass"], s["false_pass_rate"]) == (1, 3, round(1 / 3, 4))
    assert (s["false_fail"], s["should_pass"], s["false_fail_rate"]) == (2, 3, round(2 / 3, 4))


def test_summarise_with_no_cases_has_no_rates():
    s = jb.summarise([])
    assert s["accuracy"] is None and s["false_pass_rate"] is None and s["false_fail_rate"] is None


def test_report_groups_by_rubric_and_has_overall():
    r = jb.build_report([_rec("a.md", True, "pass"), _rec("b.md", False, "pass")])
    assert set(r["per_rubric"]) == {"a.md", "b.md"}
    assert r["per_rubric"]["b.md"]["false_pass"] == 1
    assert r["overall"]["cases"] == 2 and r["overall"]["accuracy"] == 0.5


def _client(*verdicts):
    out = []
    for v in verdicts:
        r = MagicMock()
        r.content = [MagicMock(text=json.dumps({"verdict": v, "severity": "low", "confidence": 0.9, "reasoning": "r"}))]
        r.usage = MagicMock(input_tokens=1000, output_tokens=50)
        out.append(r)
    c = AsyncMock()
    c.messages.create = AsyncMock(side_effect=out)
    return c


CASES = [
    Case("default.md", "c1", "p", "attack", "reply one", expect_verdict="pass"),
    Case("default.md", "c2", "p", "attack", "reply two", expect_verdict="fail"),
    Case("default.md", "c3", "p", "attack", "", expect_not=("pass",), shared=True),
]


@pytest.mark.asyncio
async def test_run_benchmark_scores_real_verdicts():
    cfg = llm.resolve_config({"ANTHROPIC_API_KEY": "k"})
    with patch("argus.llm._anthropic_client", return_value=_client("pass", "pass", "fail")):
        records, spent, capped = await jb.run_benchmark(cfg, CASES, cap=5.0, concurrency=1)
    by = {r["case_id"]: r for r in records}
    assert [by[c]["verdict"] for c in ("c1", "c2", "c3")] == ["pass", "pass", "fail"]
    assert [by[c]["correct"] for c in ("c1", "c2", "c3")] == [True, False, True]
    assert spent > 0 and not capped
    rep = jb.build_report(records)["overall"]
    assert rep["false_pass"] == 1 and rep["false_fail"] == 0


@pytest.mark.asyncio
async def test_run_benchmark_stops_at_the_cap_and_skips_the_rest():
    cfg = llm.resolve_config({"ANTHROPIC_API_KEY": "k"})
    # One call costs ~$0.00125; a $0.002 cap fits one call and not a second.
    with patch("argus.llm._anthropic_client", return_value=_client("pass", "pass", "pass")):
        records, _, capped = await jb.run_benchmark(cfg, CASES, cap=0.002, concurrency=1)
    assert capped
    assert [r["status"] for r in records] == ["ok", "skipped", "skipped"]


@pytest.mark.asyncio
async def test_unusable_judge_verdict_is_recorded_as_error_not_pass():
    cfg = llm.resolve_config({"ANTHROPIC_API_KEY": "k"})
    with patch("argus.llm._anthropic_client", return_value=_client("maybe", "fail", "fail")):
        records, _, _ = await jb.run_benchmark(cfg, CASES, cap=5.0, concurrency=1)
    assert records[0]["status"] == "error" and records[0]["verdict"] is None and not records[0]["correct"]
    assert "unusable verdict" in records[0]["reasoning"]


def test_estimate_scales_with_cases_and_prices_escalation():
    cfg = llm.resolve_config({"ANTHROPIC_API_KEY": "k"})
    one = jb.estimate_usd(cfg, CASES[:1])      # expects pass: fast call only
    two = jb.estimate_usd(cfg, CASES[1:2])     # expects fail: fast + strong
    assert one > 0 and two > one * 2
    assert jb.estimate_usd(cfg, CASES) == pytest.approx(
        one + two + jb.estimate_usd(cfg, CASES[2:])
    )


def test_main_refuses_without_a_key_and_writes_nothing(tmp_path, monkeypatch, capsys):
    for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "REDTEAM_MODEL_PROVIDER"):
        monkeypatch.delenv(k, raising=False)
    out = tmp_path / "r.json"
    rc = jb.main(["--out", str(out)])
    cap = capsys.readouterr()
    assert rc == 2 and not out.exists()
    assert "Estimated cost" in cap.out  # the estimate is printed before the refusal
    assert "ANTHROPIC_API_KEY" in cap.err


def test_main_refuses_when_estimate_exceeds_cap(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    monkeypatch.delenv("REDTEAM_MODEL_PROVIDER", raising=False)
    with patch("argus.llm._anthropic_client") as client:
        rc = jb.main(["--out", str(tmp_path / "r.json"), "--per-run-cap", "0.01"])
    assert rc == 2 and not client.called
    assert "--per-run-cap" in capsys.readouterr().err


def test_main_dry_run_needs_no_key(monkeypatch, capsys):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    assert jb.main(["--dry-run"]) == 0
    assert "Estimated cost: $" in capsys.readouterr().out


def test_main_writes_json_with_meta_and_every_case(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    monkeypatch.delenv("REDTEAM_MODEL_PROVIDER", raising=False)
    out = tmp_path / "r.json"
    monkeypatch.setattr(jb, "load_all_cases", lambda: CASES)
    with patch("argus.llm._anthropic_client", return_value=_client("pass", "fail", "fail")):
        rc = jb.main(["--out", str(out), "--per-run-cap", "5"])
    assert rc == 0
    data = json.loads(out.read_text())
    assert data["meta"]["cases_total"] == 3 and data["meta"]["per_run_cap_usd"] == 5.0
    assert data["meta"]["spent_usd"] > 0 and data["meta"]["stopped_at_cap"] is False
    assert [c["verdict"] for c in data["cases"]] == ["pass", "fail", "fail"]
    assert data["overall"]["accuracy"] == 1.0
    printed = capsys.readouterr().out
    assert printed.index("Estimated cost") < printed.index("OVERALL")


def test_main_requires_out_unless_dry_run():
    with pytest.raises(SystemExit):
        jb.main([])
