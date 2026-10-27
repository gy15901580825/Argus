import pathlib

import pytest

from orchestrator.redteam.demo import servers
from orchestrator.redteam.local import run_local

REPO = pathlib.Path(__file__).resolve().parents[2]
SRC = REPO / "mcp_testbed"
COPY = REPO / "orchestrator/orchestrator/redteam/demo/mcp_testbed"
FILES = ["testbed/__init__.py", "testbed/app.py", "testbed/rpc.py", "testbed/scenarios.py",
         "testbed/session.py", "demo_agent/__init__.py", "demo_agent/app.py"]


@pytest.mark.skipif(not SRC.is_dir(), reason="needs the repo checkout")
@pytest.mark.parametrize("rel", FILES)
def test_demo_copy_matches_mcp_testbed(rel):
    assert (COPY / rel).read_bytes() == (SRC / rel).read_bytes(), (
        f"{rel} differs from mcp_testbed/{rel}; copy it: cp mcp_testbed/{rel} {COPY.relative_to(REPO)}/{rel}"
    )


@pytest.mark.skipif(not SRC.is_dir(), reason="needs the repo checkout")
def test_demo_copy_has_no_extra_files():
    copied = {str(p.relative_to(COPY)) for p in COPY.rglob("*.py")} - {"__init__.py"}
    assert copied == set(FILES)


def test_probe_ids_are_the_mcp_library():
    from orchestrator.redteam.api import PROBES_DIR
    on_disk = sorted(p.stem for p in (pathlib.Path(PROBES_DIR) / "mcp").glob("*.yaml"))
    assert list(servers.PROBE_IDS) == on_disk
    assert len(on_disk) == 12


async def test_demo_run_needs_no_key_and_finds_real_failures():
    with servers.start_mcp_demo() as spec:
        events = [e async for e in run_local(spec, list(servers.PROBE_IDS), env={})]
    findings = [e for e in events if "verdict" in e]
    assert len(findings) == 12
    assert {f["probe_id"] for f in findings} == set(servers.PROBE_IDS)
    assert not [f for f in findings if f["verdict"] == "error"], findings
    assert any(f["verdict"] == "fail" for f in findings)
    assert any(f["verdict"] == "pass" for f in findings)
