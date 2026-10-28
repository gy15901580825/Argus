"""Persona / strategy dataclasses + markdown-with-YAML-frontmatter loader.

Data files live under `redteam/data/{personas,strategies}/*.md`. Each file is
YAML frontmatter delimited by `---` lines, followed by a prose body of
improvisation guidance. Errors are raised at load time and name the offending
file, matching `load_probe` in `probe.py`.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml


DATA_DIR = Path(__file__).parent / "data"
PERSONAS_DIR = DATA_DIR / "personas"
STRATEGIES_DIR = DATA_DIR / "strategies"

_FRONTMATTER_DELIMITER = "---"

PERSONA_KEYS = ("id", "name", "voice", "traits", "when_to_use")
STRATEGY_KEYS = ("id", "name", "mechanics", "when_to_use", "escalation_notes")


@dataclass(frozen=True)
class Persona:
    """A social-engineering voice the attacker LLM improvises within."""

    id: str
    name: str
    voice: str
    traits: str
    when_to_use: str
    body: str


@dataclass(frozen=True)
class Strategy:
    """An attack mechanism the attacker LLM improvises within."""

    id: str
    name: str
    mechanics: str
    when_to_use: str
    escalation_notes: str
    body: str


def _parse_frontmatter(path: Path) -> tuple[dict, str]:
    """Split a markdown file into its YAML frontmatter mapping and prose body."""
    lines = Path(path).read_text().splitlines()
    if not lines or lines[0].strip() != _FRONTMATTER_DELIMITER:
        raise ValueError(f"missing opening '---' frontmatter delimiter in {path}")
    closing = None
    for index in range(1, len(lines)):
        if lines[index].strip() == _FRONTMATTER_DELIMITER:
            closing = index
            break
    if closing is None:
        raise ValueError(f"unterminated frontmatter — no closing '---' in {path}")
    try:
        raw = yaml.safe_load("\n".join(lines[1:closing]))
    except yaml.YAMLError as exc:
        raise ValueError(f"malformed YAML frontmatter in {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ValueError(f"frontmatter must be a YAML mapping in {path}")
    return raw, "\n".join(lines[closing + 1 :]).strip()


def _required(raw: dict, keys: tuple[str, ...], path: Path) -> dict[str, str]:
    """Pull `keys` out of `raw`, rejecting missing, non-string or blank values."""
    values: dict[str, str] = {}
    for key in keys:
        if key not in raw:
            raise ValueError(f"missing required key {key!r} in {path}")
        value = raw[key]
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"empty or non-string value for key {key!r} in {path}")
        values[key] = value.strip()
    return values


def load_persona(path: Path) -> Persona:
    raw, body = _parse_frontmatter(Path(path))
    values = _required(raw, PERSONA_KEYS, Path(path))
    return Persona(**values, body=body)


def load_strategy(path: Path) -> Strategy:
    raw, body = _parse_frontmatter(Path(path))
    values = _required(raw, STRATEGY_KEYS, Path(path))
    return Strategy(**values, body=body)


def load_personas(personas_dir: Path) -> tuple[Persona, ...]:
    personas = tuple(load_persona(p) for p in sorted(Path(personas_dir).glob("*.md")))
    return tuple(sorted(personas, key=lambda persona: persona.id))


def load_strategies(strategies_dir: Path) -> tuple[Strategy, ...]:
    strategies = tuple(load_strategy(p) for p in sorted(Path(strategies_dir).glob("*.md")))
    return tuple(sorted(strategies, key=lambda strategy: strategy.id))


def default_personas() -> tuple[Persona, ...]:
    """The shipped persona set."""
    return load_personas(PERSONAS_DIR)


def default_strategies() -> tuple[Strategy, ...]:
    """The shipped strategy set."""
    return load_strategies(STRATEGIES_DIR)
