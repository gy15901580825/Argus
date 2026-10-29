"""Load and validate the rubric fixtures (per-rubric files plus shared hard cases).

Used by the offline schema test, the live tier and scripts/judge_benchmark.py, so a case
means the same thing everywhere. Raises ValueError on a malformed fixture; needs no key.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

FIXTURES_DIR = Path(__file__).parent / "rubrics"
RUBRICS_DIR = Path(__file__).resolve().parents[1] / "argus" / "rubrics"
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


def rubric_text(rubric: str) -> str:
    return (RUBRICS_DIR / rubric).read_text(encoding="utf-8")
