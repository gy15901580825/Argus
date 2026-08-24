"""docs/probe-mapping.md 必须由 build_coverage 生成,且与当前探针库一致。

它曾经是手写的,与代码算出来的数字对不上。一个公开仓里摆着两套互相
矛盾的覆盖率数字,正是这个产品要卖的可信度的反面。
"""
import importlib.util
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

_SPEC = importlib.util.spec_from_file_location(
    "gen_probe_mapping", REPO / "orchestrator" / "scripts" / "gen_probe_mapping.py"
)
gen_probe_mapping = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(gen_probe_mapping)


def test_probe_mapping_doc_matches_generator():
    generated = subprocess.run(
        [sys.executable, str(REPO / "orchestrator" / "scripts" / "gen_probe_mapping.py")],
        capture_output=True, text=True, check=True, cwd=REPO / "orchestrator",
    ).stdout
    on_disk = (REPO / "docs" / "probe-mapping.md").read_text()
    assert generated == on_disk, (
        "docs/probe-mapping.md is stale — regenerate it with:\n"
        "  cd orchestrator && python scripts/gen_probe_mapping.py > ../docs/probe-mapping.md"
    )


def test_no_probe_declares_an_owasp_id_outside_the_fixed_ten():
    """A typo like `LLM011` would silently erase that probe's coverage — no other check catches it."""
    probes = list(gen_probe_mapping.load_all_probes(gen_probe_mapping.PROBES_DIR))
    assert gen_probe_mapping.invalid_owasp_ids(probes) == []
