import json
from pathlib import Path

from argus import remediation
from argus.api import PROBES_DIR
from argus.probe import VALID_ATTACK_CLASSES, load_probe_library

SNAPSHOT = json.loads((Path(__file__).parent / "fixtures/remediation/text-v0.10.0.json").read_text(encoding="utf-8"))


def test_snapshot_covers_every_v0_10_0_probe():
    assert len(SNAPSHOT["probes"]) == 256 and len(SNAPSHOT["classes"]) == 17


def test_flat_remediation_text_unchanged_since_0_10_0():
    library = {p.id: p for p in load_probe_library(PROBES_DIR)}
    missing = sorted(set(SNAPSHOT["probes"]) - set(library))
    assert not missing, missing
    changed = [pid for pid, text in SNAPSHOT["probes"].items() if remediation.for_probe(library[pid]) != text]
    assert not changed, changed
    for cls, text in SNAPSHOT["classes"].items():
        assert remediation.for_classes([cls]) == text, cls
