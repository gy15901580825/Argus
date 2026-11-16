"""Technique IDs and display names from the packaged MITRE ATLAS release."""
from importlib.resources import files

import yaml


_taxonomy = yaml.safe_load(
    files("argus").joinpath("data/atlas_techniques.yaml").read_text(encoding="utf-8")
)
ATLAS_TECHNIQUES: dict[str, str] = _taxonomy["techniques"]
VALID_ATLAS_IDS = frozenset(ATLAS_TECHNIQUES)
ATLAS_METADATA = {key: value for key, value in _taxonomy.items() if key != "techniques"}


def invalid_atlas_ids(probes) -> list[tuple[str, str]]:
    """Name every probe and label missing from the pinned ATLAS release."""
    return [
        (probe.id, technique_id)
        for probe in probes
        for technique_id in probe.mappings.atlas
        if technique_id not in VALID_ATLAS_IDS
    ]
