"""README.md 的探针计数不能跟磁盘上的探针库脱节。

这份计数曾经过时(还停留在 167,库里其实有 205 个),修正之后又跟自己
列出的分项加总对不上(204 vs 205)——两次都不是靠肉眼查出来的。这个测试
从 README 正文里用窄正则抠出总数和各分项数字,拿真实探针库的数量、以及
分项自身的加总去对照;只锁数字,不锁措辞,改一句话不会让它变红,改错
一个数字才会。
"""
import importlib.util
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

_SPEC = importlib.util.spec_from_file_location(
    "gen_probe_mapping", REPO / "orchestrator" / "scripts" / "gen_probe_mapping.py"
)
gen_probe_mapping = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(gen_probe_mapping)

README = REPO / "README.md"

_TOTAL_PATTERN = r"\*\*(\d+)\s+probes\*\*\s+in the bundled library"

# label -> narrow regex anchored on the fixed phrase that follows the count,
# so an unrelated number (e.g. the "10" inside "OWASP LLM Top 10") can't match.
_FAMILY_PATTERNS = {
    "OWASP hand-authored": r"(\d+)\s+OWASP LLM Top 10 hand-authored",
    "public system-card": r"(\d+)\s+from public LLM system cards",
    "browser-agent specific": r"(\d+)\s+browser-agent specific",
    "payment-abuse": r"(\d+)\s+payment-abuse probes",
    "MCP-abuse": r"(\d+)\s+MCP-abuse probes",
    "Semia-mapped": r"(\d+)\s+Semia-mapped agent-skill detectors",
    "custom": r"(\d+)\s+custom unicode-smuggling probe",
    "garak": r"(\d+)\s+\[garak\]",
}


def _find_one(pattern: str, text: str, label: str) -> int:
    matches = re.findall(pattern, text)
    assert len(matches) == 1, (
        f"expected exactly one match for {label!r} ({pattern!r}) in README.md, "
        f"found {len(matches)} — the Scope section's probe-composition bullet "
        "may have been reworded out from under this test."
    )
    return int(matches[0])


def test_readme_probe_total_matches_the_library():
    text = README.read_text()
    stated_total = _find_one(_TOTAL_PATTERN, text, "total probe count")
    actual_total = len(list(gen_probe_mapping.load_all_probes(gen_probe_mapping.PROBES_DIR)))
    assert stated_total == actual_total, (
        f"README.md's Scope section claims **{stated_total} probes** but the library "
        f"currently has {actual_total}. Fix the '**N probes**' figure in README.md."
    )


def test_readme_probe_breakdown_sums_to_the_stated_total():
    text = README.read_text()
    stated_total = _find_one(_TOTAL_PATTERN, text, "total probe count")
    family_counts = {
        label: _find_one(pattern, text, label) for label, pattern in _FAMILY_PATTERNS.items()
    }
    breakdown_sum = sum(family_counts.values())
    assert breakdown_sum == stated_total, (
        f"README.md's per-family probe counts {family_counts} sum to {breakdown_sum}, "
        f"not the stated total of {stated_total}. Fix the family counts in the Scope "
        "section's probe-composition bullet (README.md) so they add up to the total."
    )
