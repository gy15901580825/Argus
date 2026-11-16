"""Offline validation against the exact bytes of the pinned ATLAS release."""
import gzip
import hashlib
import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from argus.atlas import ATLAS_METADATA, ATLAS_TECHNIQUES, invalid_atlas_ids
from argus.coverage import build_coverage
from argus.probe import ProbeMappings, load_all_probes

ROOT = Path(__file__).resolve().parents[1]
PROBES_DIR = ROOT / "argus/probes"
SPEC = importlib.util.spec_from_file_location("gen_atlas_techniques", ROOT / "scripts/gen_atlas_techniques.py")
generator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(generator)


def test_every_builtin_probe_has_pinned_atlas_labels():
    errors = invalid_atlas_ids(load_all_probes(PROBES_DIR))
    assert not errors, "Unknown ATLAS labels:\n" + "\n".join(
        f"{probe_id}: {technique_id}" for probe_id, technique_id in errors
    )


def test_invalid_atlas_labels_name_probe_and_id():
    probes = [SimpleNamespace(id="example", mappings=ProbeMappings(atlas=("AML.T9999", "AML.T0051")))]
    assert invalid_atlas_ids(probes) == [("example", "AML.T9999")]


def test_pinned_list_matches_hash_verified_source_and_mitigation_metadata():
    source_bytes = gzip.decompress((ROOT / "tests/fixtures/atlas/ATLAS-2026.10.yaml.gz").read_bytes())
    metadata = yaml.safe_load((ROOT / "argus/data/atlas_mitigations.yaml").read_text())
    assert hashlib.sha256(source_bytes).hexdigest() == ATLAS_METADATA["source_sha256"]
    assert ATLAS_METADATA == {key: metadata[key] for key in generator.METADATA_FIELDS}
    extracted = generator.extract(source_bytes, metadata)
    assert extracted["techniques"] == ATLAS_TECHNIQUES
    assert generator.render(extracted) == (ROOT / "argus/data/atlas_techniques.yaml").read_text()


def test_generator_rejects_source_with_wrong_hash():
    with pytest.raises(ValueError, match="SHA256"):
        generator.extract(b"untrusted source", ATLAS_METADATA)


def test_coverage_displays_current_atlas_names():
    probe = SimpleNamespace(id="example", mappings=ProbeMappings(atlas=("AML.T0010", "AML.T0085.003")))
    cells = build_coverage([probe])["standards"]["mitre-atlas"]["cells"]
    assert {cell["id"]: cell["name"] for cell in cells} == {
        "AML.T0010": "Supply Chain Compromise",
        "AML.T0085.003": "Data from AI Services: System Instructions",
    }


@pytest.mark.parametrize("probe_id,expected", [
    ("owasp_05_output_cmd_injection", ("AML.T0102", "AML.T0049")),
    ("owasp_05_output_eval_injection", ("AML.T0102", "AML.T0049")),
    ("owasp_05_output_sql_rce", ("AML.T0102", "AML.T0049")),
    ("owasp_05_improper_output_handling", ()),
    ("owasp_05_output_svg_xss", ()),
    ("owasp_05_upload_svg_xss_render", ("AML.T0049",)),
    ("garak_ansiescape_ansiescaped", ()),
    ("garak_ansiescape_ansiraw", ()),
    ("owasp_08_vector_weaknesses", ("AML.T0051",)),
])
def test_output_and_simulated_rag_probes_do_not_claim_dataset_poisoning_or_exfiltration(probe_id, expected):
    probes = {probe.id: probe for probe in load_all_probes(PROBES_DIR)}
    assert probes[probe_id].mappings.atlas == expected
