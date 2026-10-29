import pathlib

import pytest

from argus.demo import servers
from argus.local import run_local

REPO = pathlib.Path(__file__).resolve().parents[1]
# The wheel ships a copy of each testbed service under argus/demo/; the service directory is the source.
COPIES = {
    "mcp_testbed": ["testbed/__init__.py", "testbed/app.py", "testbed/rpc.py", "testbed/scenarios.py",
                    "testbed/session.py", "demo_agent/__init__.py", "demo_agent/app.py"],
    "payment_testbed": ["testbed/__init__.py", "testbed/app.py", "testbed/merchant.py", "testbed/session.py",
                        "demo_agent/__init__.py", "demo_agent/app.py"],
}
PAIRS = [(svc, rel) for svc, files in COPIES.items() for rel in files]


@pytest.mark.skipif(not (REPO / "mcp_testbed").is_dir(), reason="needs the repo checkout")
@pytest.mark.parametrize("svc,rel", PAIRS)
def test_demo_copy_matches_service(svc, rel):
    src, copy = REPO / svc / rel, REPO / "argus/demo" / svc / rel
    assert copy.read_bytes() == src.read_bytes(), (
        f"{rel} differs from {svc}/{rel}; copy it: cp {svc}/{rel} argus/demo/{svc}/{rel}"
    )


@pytest.mark.skipif(not (REPO / "mcp_testbed").is_dir(), reason="needs the repo checkout")
@pytest.mark.parametrize("svc", sorted(COPIES))
def test_demo_copy_has_no_extra_files(svc):
    copy = REPO / "argus/demo" / svc
    copied = {str(p.relative_to(copy)) for p in copy.rglob("*.py")} - {"__init__.py"}
    assert copied == set(COPIES[svc])
    # And the service has no module the copy is missing.
    source = {str(p.relative_to(REPO / svc)) for d in ("testbed", "demo_agent") for p in (REPO / svc / d).glob("*.py")}
    assert source == set(COPIES[svc])


def test_probe_ids_are_the_mcp_library():
    from argus.api import PROBES_DIR
    on_disk = sorted(p.stem for p in (pathlib.Path(PROBES_DIR) / "mcp").glob("*.yaml"))
    assert list(servers.PROBE_IDS) == on_disk
    assert len(on_disk) == 12


async def test_demo_run_needs_no_key_and_finds_real_failures(monkeypatch):
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    monkeypatch.setenv("no_proxy", "127.0.0.1")
    with servers.start_mcp_demo() as spec:
        events = [e async for e in run_local(spec, list(servers.PROBE_IDS), env={})]
    findings = [e for e in events if "verdict" in e]
    assert len(findings) == 12
    assert {f["probe_id"] for f in findings} == set(servers.PROBE_IDS)
    assert not [f for f in findings if f["verdict"] == "error"], findings
    assert any(f["verdict"] == "fail" for f in findings)
    assert any(f["verdict"] == "pass" for f in findings)
