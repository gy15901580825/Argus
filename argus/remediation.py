"""How to fix a failed probe: short text per attack_class, from argus/data/remediation.yaml."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Iterable

import yaml

_PATH = Path(__file__).parent / "data" / "remediation.yaml"


@lru_cache(maxsize=1)
def table() -> dict[str, str]:
    return yaml.safe_load(_PATH.read_text(encoding="utf-8"))


def for_classes(attack_classes: Iterable[str]) -> str:
    """The entries for these classes, in the probe's order, one per line."""
    texts = table()
    return "\n".join(dict.fromkeys(texts[c].strip() for c in attack_classes if c in texts))
