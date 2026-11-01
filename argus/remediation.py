"""How to fix a failed probe: the probe's own text, else per attack_class from argus/data/remediation.yaml."""
from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path
from typing import Iterable

import yaml

_PATH = Path(__file__).parent / "data" / "remediation.yaml"
TIERS = ("mitigation", "fix")


@lru_cache(maxsize=1)
def table() -> dict[str, str]:
    return {key: value["text"] for key, value in yaml.safe_load(_PATH.read_text(encoding="utf-8")).items()}


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


def parse_actions(raw, where: str) -> tuple[dict, ...]:
    """Normalize optional probe-pack actions at the YAML boundary."""
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise ValueError(f"invalid remediation_actions in {where}: expected a list")
    actions = []
    for entry in raw:
        if not isinstance(entry, dict) or set(entry) - {"tier", "text", "atlas_mitigation"}:
            raise ValueError(f"invalid remediation_actions entry in {where}")
        tier, text, atlas = entry.get("tier"), entry.get("text"), entry.get("atlas_mitigation")
        if tier not in TIERS or not isinstance(text, str) or not text.strip():
            raise ValueError(f"invalid remediation_actions tier or text in {where}")
        if atlas is not None and (not isinstance(atlas, str) or not re.fullmatch(r"AML\.M\d{4}", atlas)):
            raise ValueError(f"invalid remediation_actions atlas_mitigation in {where}")
        actions.append({"tier": tier, "text": text.strip(), "atlas_mitigation": atlas})
    return tuple(actions)


@lru_cache(maxsize=1)
def actions_table() -> dict[str, tuple[dict, ...]]:
    return {key: parse_actions(value.get("actions"), f"{_PATH}: {key}")
            for key, value in yaml.safe_load(_PATH.read_text(encoding="utf-8")).items()}


def actions_for_classes(attack_classes: Iterable[str]) -> list[dict]:
    """Class actions in caller order, with repeated tier/text pairs removed."""
    table = actions_table()
    seen = set()
    actions = []
    for cls in attack_classes:
        for action in table.get(cls, ()):
            key = (action["tier"], action["text"])
            if key not in seen:
                seen.add(key)
                actions.append(dict(action))
    return actions


def actions_for_probe(probe) -> list[dict]:
    """Honor probe overrides without mixing server advice with class advice."""
    actions = getattr(probe, "remediation_actions", ())
    if actions:
        return [dict(action) for action in actions]
    if getattr(probe, "remediation", ""):
        return []
    return actions_for_classes(probe.attack_class)
