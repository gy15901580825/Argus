"""Each package ships copies of the root LICENSE and NOTICE, because PEP 639
license-files cannot reach outside the package directory. The copies must
stay identical to the root files."""

from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
COPIES = [
    ("LICENSE", "cli/LICENSE"),
    ("NOTICE", "cli/NOTICE"),
    ("LICENSE", "orchestrator/LICENSE"),
    ("NOTICE", "orchestrator/NOTICE"),
]


@pytest.mark.parametrize("root_name,copy_path", COPIES)
def test_packaged_copy_matches_root(root_name, copy_path):
    root = REPO / root_name
    copy = REPO / copy_path
    assert copy.is_file(), f"{copy_path} is missing; copy it from the repo root {root_name}"
    assert copy.read_bytes() == root.read_bytes(), (
        f"{copy_path} differs from the repo root {root_name}; copy the root file over it"
    )
