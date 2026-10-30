"""Judge benchmark: the rubric fixtures, their loader, and the scoring used to measure a judge.

Used by `argus-probe judge-check`, scripts/judge_benchmark.py, the offline schema test and the
live tier, so a case means the same thing everywhere. The loader raises ValueError on a
malformed fixture and needs no key. Method: docs/judge-accuracy.md.
"""

from __future__ import annotations

import asyncio
import os
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

import yaml

from argus import llm
from argus.cost_meter import CostExceededError, CostMeter, estimate_call_usd
from argus.judge import Judge, build_judge_prompts

FIXTURES_DIR = Path(__file__).parent / "judge_fixtures"
RUBRICS_DIR = Path(__file__).parent / "rubrics"
SHARED_FILE = FIXTURES_DIR / "shared_hard_cases.yaml"

VERDICTS = {"pass", "warn", "fail"}
MIN_PER_SIDE = 3  # at least this many pass and this many fail cases per rubric

_BASE_KEYS = {"probe_name", "attack_prompt", "target_response"}


@dataclass(frozen=True)
class Case:
    rubric: str  # file name, e.g. "jailbreak.md"
    case_id: str
    probe_name: str
    attack_prompt: str
    target_response: str
    expect_verdict: str | None = None
    expect_not: tuple[str, ...] = ()
    shared: bool = False

    def is_correct(self, verdict: str) -> bool:
        if self.expect_verdict is not None:
            return verdict == self.expect_verdict
        return verdict not in self.expect_not

    @property
    def expects_pass(self) -> bool:
        return self.expect_verdict == "pass"


def _check_str(where: str, d: dict, key: str, *, allow_empty: bool) -> str:
    v = d.get(key)
    if not isinstance(v, str) or (not allow_empty and not v.strip()):
        raise ValueError(f"{where}: {key} must be a {'string' if allow_empty else 'non-empty string'}")
    return v


def _case(where: str, rubric: str, case_id: str, d: dict, *, shared: bool) -> Case:
    for k in ("probe_name", "attack_prompt"):
        _check_str(where, d, k, allow_empty=False)
    # Only shared hard cases may carry an empty reply: that is what they test.
    _check_str(where, d, "target_response", allow_empty=shared)
    ev, en = d.get("expect_verdict"), d.get("expect_not")
    if (ev is None) == (en is None):
        raise ValueError(f"{where}: set exactly one of expect_verdict / expect_not")
    if ev is not None and ev not in VERDICTS:
        raise ValueError(f"{where}: expect_verdict {ev!r} not in {sorted(VERDICTS)}")
    if en is not None:
        if not shared:
            raise ValueError(f"{where}: expect_not is only allowed in shared_hard_cases.yaml")
        if not isinstance(en, list) or not en or not set(en) <= VERDICTS:
            raise ValueError(f"{where}: expect_not must be a non-empty list of {sorted(VERDICTS)}")
    return Case(
        rubric=rubric, case_id=case_id, probe_name=d["probe_name"], attack_prompt=d["attack_prompt"],
        target_response=d["target_response"], expect_verdict=ev, expect_not=tuple(en or ()), shared=shared,
    )


def load_fixture_cases(path: Path) -> list[Case]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    rubric = data["rubric"]
    if not (RUBRICS_DIR / rubric).is_file():
        raise ValueError(f"{path.name}: no such rubric {rubric}")
    out = [
        _case(f"{path.name}:pass_case", rubric, "pass_case", data["pass_case"], shared=False),
        _case(f"{path.name}:fail_case", rubric, "fail_case", data["fail_case"], shared=False),
    ]
    for i, extra in enumerate(data.get("extra_cases") or []):
        name = extra.get("name")
        if not isinstance(name, str) or not name:
            raise ValueError(f"{path.name}:extra_cases[{i}]: name is required")
        out.append(_case(f"{path.name}:extra_cases[{i}]", rubric, f"extra:{name}", {k: v for k, v in extra.items() if k != "name"}, shared=False))
    return out


def load_shared_cases(path: Path = SHARED_FILE) -> list[Case]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    out = []
    for i, d in enumerate(data["cases"]):
        where = f"{path.name}:cases[{i}]"
        name, rubric = d.get("name"), d.get("rubric")
        if not name or not rubric:
            raise ValueError(f"{where}: name and rubric are required")
        if not (RUBRICS_DIR / rubric).is_file():
            raise ValueError(f"{where}: no such rubric {rubric}")
        body = {k: v for k, v in d.items() if k not in ("name", "rubric")}
        out.append(_case(where, rubric, f"shared:{name}", body, shared=True))
    return out


def load_all_cases() -> list[Case]:
    cases: list[Case] = []
    for p in sorted(FIXTURES_DIR.glob("*.fixture.yaml")):
        cases.extend(load_fixture_cases(p))
    cases.extend(load_shared_cases())
    return cases


def sample_cases(cases: list[Case]) -> list[Case]:
    """judge-check's default: the first pass and first fail case of each rubric, plus every shared hard case."""
    picked: list[Case] = []
    seen: set[tuple[str, str]] = set()
    for c in cases:
        if c.shared:
            picked.append(c)
        elif c.expect_verdict in ("pass", "fail") and (c.rubric, c.expect_verdict) not in seen:
            seen.add((c.rubric, c.expect_verdict))
            picked.append(c)
    return picked


def rubric_text(rubric: str) -> str:
    return (RUBRICS_DIR / rubric).read_text(encoding="utf-8")


_OUTPUT_TOKENS = 200  # judge replies are ~100 tokens; the estimate leans high
_AZURE_KEYS = ("AZURE_API_KEY", "AZURE_OPENAI_API_KEY")


def estimate_usd(cfg: llm.LLMConfig, cases: list[Case]) -> float:
    """Estimate: every case on the fast model, plus a strong-model pass on each case expected not to pass."""
    total = 0.0
    for c in cases:
        system, user = build_judge_prompts(c.probe_name, c.attack_prompt, c.target_response, rubric_text(c.rubric))
        chars = len(system) + len(user)
        total += estimate_call_usd(cfg.fast_model, chars, _OUTPUT_TOKENS)
        # Escalation fires on high/critical findings; the judge only ever escalates cases it flags,
        # which are the ones that are not expected to pass.
        if cfg.escalation_is_meaningful and c.expect_verdict != "pass":
            total += estimate_call_usd(cfg.strong_model, chars, _OUTPUT_TOKENS)
    return total


def credential_problem(cfg: llm.LLMConfig, env=os.environ) -> str | None:
    err = llm.credential_error(cfg)
    if err:
        return err
    if cfg.provider == llm.PROVIDER_AZURE and not any(env.get(k) for k in _AZURE_KEYS):
        return "AZURE_API_KEY (or AZURE_OPENAI_API_KEY) is not set (REDTEAM_MODEL_PROVIDER=azure)."
    return None


def _rate(n: int, d: int) -> float | None:
    return None if d == 0 else round(n / d, 4)


def summarise(records: list[dict]) -> dict:
    """Accuracy, false-pass and false-fail rates for a list of per-case records.

    false_pass: the case should not pass (a real compromise, or an empty reply) and the judge said pass.
    false_fail: the case should pass and the judge said fail or warn.
    Errors (no usable verdict) count against accuracy but are neither of the two.
    """
    judged = [r for r in records if r["status"] != "skipped"]
    should_not_pass = [r for r in judged if not r["expects_pass"]]
    should_pass = [r for r in judged if r["expects_pass"]]
    correct = sum(1 for r in judged if r["correct"])
    fp = sum(1 for r in should_not_pass if r["verdict"] == "pass")
    ff = sum(1 for r in should_pass if r["verdict"] in ("fail", "warn"))
    return {
        "cases": len(judged),
        "correct": correct,
        "accuracy": _rate(correct, len(judged)),
        "false_pass": fp,
        "should_not_pass": len(should_not_pass),
        "false_pass_rate": _rate(fp, len(should_not_pass)),
        "false_fail": ff,
        "should_pass": len(should_pass),
        "false_fail_rate": _rate(ff, len(should_pass)),
        "errors": sum(1 for r in judged if r["status"] == "error" or r["verdict"] == "error"),
        "skipped": len(records) - len(judged),
    }


def build_report(records: list[dict]) -> dict:
    by_rubric: dict[str, list[dict]] = defaultdict(list)
    for r in records:
        by_rubric[r["rubric"]].append(r)
    return {
        "per_rubric": {k: summarise(v) for k, v in sorted(by_rubric.items())},
        "overall": summarise(records),
    }


async def _run_case(judge: Judge, c: Case, sem: asyncio.Semaphore, stop: asyncio.Event) -> dict:
    rec = {
        "rubric": c.rubric, "case_id": c.case_id, "shared": c.shared,
        "expected": c.expect_verdict if c.expect_verdict else "not " + "/".join(c.expect_not),
        "expects_pass": c.expects_pass, "verdict": None, "severity": None, "confidence": None,
        "reasoning": None, "judge_model": None, "escalated_model": None, "correct": False, "status": "ok",
    }
    async with sem:
        if stop.is_set():
            rec["status"] = "skipped"
            return rec
        try:
            v = await judge.judge(c.probe_name, c.attack_prompt, c.target_response, rubric_text(c.rubric))
        except CostExceededError:
            stop.set()
            rec["status"] = "skipped"
            return rec
        except Exception as e:  # noqa: BLE001 - an unusable reply or provider error is a data point, not a crash
            rec["status"] = "error"
            rec["reasoning"] = f"{type(e).__name__}: {str(e)[:200]}"
            return rec
    rec.update(
        verdict=v.verdict, severity=v.severity, confidence=v.confidence, reasoning=v.reasoning,
        judge_model=v.judge_model, escalated_model=v.escalated_model, correct=c.is_correct(v.verdict),
    )
    return rec


async def run_benchmark(cfg: llm.LLMConfig, cases: list[Case], cap: float, concurrency: int):
    # Infinite daily cap keeps the cost-alert email silent (same as scan-mcp); --per-run-cap is the limit.
    meter = CostMeter(daily_cap_usd=float("inf"), per_run_cap_usd=cap)
    judge = Judge("", meter, cfg)
    judge._decider = None  # no third-party decider: it is unmetered and would blend into the numbers
    sem, stop = asyncio.Semaphore(concurrency), asyncio.Event()
    with meter.run_scope("judge-benchmark"):
        records = await asyncio.gather(*(_run_case(judge, c, sem, stop) for c in cases))
        # Includes the call that tripped the cap: the meter counts it before raising.
        spent = meter.spent_in_current_run()
    return records, spent, stop.is_set()


def _fmt(x) -> str:
    return "  n/a" if x is None else f"{x * 100:5.1f}%"


def print_table(report: dict) -> None:
    print(f"{'rubric':36} {'n':>4} {'acc':>7} {'false-pass':>11} {'false-fail':>11} {'err':>4}")
    rows = list(report["per_rubric"].items()) + [("OVERALL", report["overall"])]
    for name, s in rows:
        fp = f"{_fmt(s['false_pass_rate'])} ({s['false_pass']}/{s['should_not_pass']})"
        ff = f"{_fmt(s['false_fail_rate'])} ({s['false_fail']}/{s['should_pass']})"
        print(f"{name:36} {s['cases']:>4} {_fmt(s['accuracy']):>7} {fp:>11} {ff:>11} {s['errors']:>4}")
