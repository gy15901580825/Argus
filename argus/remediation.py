"""How to fix a failed probe: the probe's own text, else per attack_class from argus/data/remediation.yaml."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Iterable

import yaml

_PATH = Path(__file__).parent / "data" / "remediation.yaml"


@lru_cache(maxsize=1)
def table() -> dict[str, str]:
    return yaml.safe_load(_PATH.read_text(encoding="utf-8"))


def for_probe(probe) -> str:
    """The probe's own `remediation`, else the text for its attack classes."""
    return (getattr(probe, "remediation", "") or "").strip() or for_classes(probe.attack_class)


def for_classes(attack_classes: Iterable[str]) -> str:
    """The entries for these classes, in the probe's order, one per line."""
    texts = table()
    return "\n".join(dict.fromkeys(texts[c].strip() for c in attack_classes if c in texts))


@lru_cache(maxsize=1)
def atlas_mitigations() -> dict[str, str]:
    """Names from the pinned ATLAS release for labels and report display."""
    path = _PATH.with_name("atlas_mitigations.yaml")
    return yaml.safe_load(path.read_text(encoding="utf-8"))["mitigations"]
