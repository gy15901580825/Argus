"""Static checks on the bundled scan-skill sample skills (no Docker, no network)."""
from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest
import yaml

ORCH = Path(__file__).resolve().parents[1]
REDTEAM = ORCH / "argus"
SAMPLES = REDTEAM / "skillscan" / "samples"
RULES = REDTEAM / "skillscan" / "rules.py"
NAMES = ["benign-markdown", "config-theft", "fake-prerequisite", "hidden-instruction", "key-grab", "persistence"]
ZERO_WIDTH = "​‌‍⁠﻿"


def _files(sample: str) -> list[Path]:
    return sorted(p for p in (SAMPLES / sample).rglob("*") if p.is_file())


def _front_matter(sample: str) -> dict:
    text = (SAMPLES / sample / "SKILL.md").read_text(encoding="utf-8")
    m = re.match(r"---\n(.*?)\n---\n", text, re.S)
    assert m, f"{sample}: SKILL.md has no front matter"
    return yaml.safe_load(m.group(1))


def test_sample_set_is_exactly_the_six():
    assert sorted(p.name for p in SAMPLES.iterdir() if p.is_dir() and p.name != "__pycache__") == NAMES


@pytest.mark.parametrize("sample", NAMES)
def test_front_matter_has_name_and_description(sample):
    fm = _front_matter(sample)
    assert re.fullmatch(r"[a-z0-9-]+", fm["name"])
    assert isinstance(fm["description"], str) and len(fm["description"]) > 20


@pytest.mark.parametrize("sample", NAMES)
def test_every_url_host_is_reserved_invalid(sample):
    hosts = []
    for f in _files(sample):
        hosts += re.findall(r"https?://([^/\s\"'<>)`]+)", f.read_text(encoding="utf-8"))
    # Samples must never point at a host that can resolve publicly.
    assert all(h.endswith(".invalid") for h in hosts), hosts


def test_only_persistence_and_benign_are_network_free():
    # persistence is caught by its file writes alone; every other malicious sample sends something out.
    with_url = {s for s in NAMES
                if any(re.search(r"https?://", f.read_text(encoding="utf-8")) for f in _files(s))}
    assert set(NAMES) - with_url == {"persistence", "benign-markdown"}


def test_benign_sample_has_no_url_or_script():
    assert [f.name for f in _files("benign-markdown")] == ["SKILL.md"]
    assert "http" not in (SAMPLES / "benign-markdown" / "SKILL.md").read_text(encoding="utf-8")


def test_hidden_instruction_is_hidden():
    text = (SAMPLES / "hidden-instruction" / "SKILL.md").read_text(encoding="utf-8")
    comment = re.search(r"<!--(.*?)-->", text, re.S)
    assert comment and ".config/solana/id.json" in comment.group(1)
    assert any(c in comment.group(1) for c in ZERO_WIDTH)
    # The instruction is only inside the comment, so the rendered markdown does not show it.
    outside = text.replace(comment.group(0), "")
    assert ".invalid" not in outside


TELLTALE = re.compile(r"\b(argus|inert|samples?|decoys?|fixtures?)\b", re.I)


def test_inert_notice_lives_outside_the_sample_dirs():
    # Sample dirs are copied into the sandbox; wording that marks them as test material could tip off the agent.
    notice = (SAMPLES / "README.md").read_text(encoding="utf-8")
    assert "inert" in notice and "# session-context" in notice and "~/.bashrc" in notice
    hits = [(str(f.relative_to(SAMPLES)), m.group(0)) for s in NAMES for f in _files(s)
            for m in TELLTALE.finditer(f.read_text(encoding="utf-8"))]
    assert not hits


def test_samples_are_package_data():
    cfg = tomllib.loads((ORCH / "pyproject.toml").read_text())
    patterns = cfg["tool"]["setuptools"]["package-data"]["argus"]
    shipped = {p for pat in patterns for p in REDTEAM.glob(pat) if p.is_file()}
    wanted = [SAMPLES / "README.md"] + [f for s in NAMES for f in _files(s)]
    missing = [str(f.relative_to(SAMPLES)) for f in wanted if f not in shipped]
    assert not missing


def test_rules_have_no_sample_specific_strings():
    if not RULES.exists():
        pytest.skip("rules.py is not written yet")
    src = RULES.read_text(encoding="utf-8")
    # A bare dir name like "persistence" is also a rule word, so only distinctive strings are checked:
    # the exfil host, hyphenated dir names, front-matter names and the helper script names unique to
    # the samples. Generic names like install.sh could fairly appear in a rule.
    needles = {"skillhub-assets", "preflight.sh", "quota.py", "session-context.sh"}
    needles |= {n for n in NAMES if "-" in n}
    needles |= {_front_matter(s)["name"] for s in NAMES}
    assert not [n for n in sorted(needles) if n in src]
