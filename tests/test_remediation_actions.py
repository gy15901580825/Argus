import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

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


def test_vendored_atlas_mitigations_are_v2026_10():
    ids = remediation.atlas_mitigations()
    assert list(ids) == [f"AML.M{n:04d}" for n in range(44)]
    assert ids["AML.M0030"] == "Restrict AI Agent Tool Invocation on Untrusted Data"
    assert all(name.strip() for name in ids.values())


def test_parse_actions_normalises():
    assert remediation.parse_actions([{"tier": "fix", "text": "  Do X.  "}], "t") == (
        {"tier": "fix", "text": "Do X.", "atlas_mitigation": None},)
    assert remediation.parse_actions(None, "t") == ()


@pytest.mark.parametrize("raw", [
    "Do X.", [{"tier": "patch", "text": "Do X."}], [{"tier": "fix", "text": "  "}],
    [{"tier": "fix", "text": "Do X.", "atlas_mitigation": "AML.M28"}],
    [{"tier": "fix", "text": "Do X.", "extra": 1}], ["Do X."]])
def test_parse_actions_rejects(raw):
    with pytest.raises(ValueError, match="where.yaml"):
        remediation.parse_actions(raw, "where.yaml")


def _pack_probe(tmp_path, actions):
    from argus.probe import load_probe
    path = tmp_path / "p.yaml"
    path.write_text(yaml.safe_dump({"id": "p", "name": "p", "target_class": ["http-chat"],
                    "attack_class": ["jailbreak"], "severity": "low", "prompts": ["x"],
                    "remediation": "Own server text.", "remediation_actions": actions}))
    return load_probe(path)


def test_load_probe_reads_remediation_actions(tmp_path):
    raw = [{"tier": "mitigation", "text": "  Gate tool calls.  "},
           {"tier": "fix", "text": "Limit tool scope.", "atlas_mitigation": "AML.M0028"}]
    assert _pack_probe(tmp_path, raw).remediation_actions == (
        {"tier": "mitigation", "text": "Gate tool calls.", "atlas_mitigation": None},
        {"tier": "fix", "text": "Limit tool scope.", "atlas_mitigation": "AML.M0028"})


def test_load_probe_rejects_malformed_remediation_actions(tmp_path):
    import re
    with pytest.raises(ValueError, match=re.escape(str(tmp_path / "p.yaml"))):
        _pack_probe(tmp_path, [{"tier": "patch", "text": "Do X."}])


def test_load_probe_accepts_unknown_but_well_formed_atlas_id(tmp_path):
    probe = _pack_probe(tmp_path, [{"tier": "fix", "text": "Do X.", "atlas_mitigation": "AML.M0044"}])
    assert probe.remediation_actions[0]["atlas_mitigation"] == "AML.M0044"


def test_actions_for_classes_keeps_order_drops_repeats_and_unknowns(monkeypatch):
    ma = {"tier": "mitigation", "text": "Gate A.", "atlas_mitigation": None}
    mb = {"tier": "mitigation", "text": "Gate B.", "atlas_mitigation": None}
    fa = {"tier": "fix", "text": "Fix A.", "atlas_mitigation": None}
    monkeypatch.setattr(remediation, "actions_table", lambda: {"a": (ma, fa), "b": (mb, fa)})
    assert remediation.actions_for_classes(["b", "zzz", "a", "b"]) == [mb, fa, ma]
    assert remediation.actions_for_classes([]) == []


def test_actions_for_probe_returns_copies(monkeypatch):
    act = {"tier": "fix", "text": "Fix the tool.", "atlas_mitigation": None}
    probe = SimpleNamespace(remediation_actions=(act,), remediation="Own text.", attack_class=("a",))
    remediation.actions_for_probe(probe)[0]["text"] = "Changed."
    assert remediation.actions_for_probe(probe)[0]["text"] == "Fix the tool."
    monkeypatch.setattr(remediation, "actions_table", lambda: {"a": (act,)})
    remediation.actions_for_classes(["a"])[0]["text"] = "Changed."
    assert remediation.actions_for_classes(["a"])[0]["text"] == "Fix the tool."


def test_pack_probe_with_own_text_and_no_actions_gets_none():
    p = SimpleNamespace(remediation="Server text.", remediation_actions=(), attack_class=("mcp-abuse",))
    assert remediation.actions_for_probe(p) == []


def test_probe_without_override_uses_class_actions(monkeypatch):
    act = {"tier": "fix", "text": "Fix the tool.", "atlas_mitigation": None}
    monkeypatch.setattr(remediation, "actions_table", lambda: {"a": (act,)})
    assert remediation.actions_for_probe(SimpleNamespace(attack_class=("a",))) == [act]


def test_probe_own_actions_win():
    act = {"tier": "fix", "text": "Fix the tool.", "atlas_mitigation": None}
    p = SimpleNamespace(remediation_actions=(act,), remediation="Own text.", attack_class=("jailbreak",))
    assert remediation.actions_for_probe(p) == [act]


FORBIDDEN_ATLAS = {"AML.M0035", "AML.M0018", "AML.M0042"}
FILLER = ("validate input", "validate inputs", "sanitize input", "sanitize inputs", "best practice",
          "be careful", "as appropriate", "appropriate measures", "proper security", "implement proper",
          "ensure security", "security controls", "regularly review", "consider using")


def check_entry(actions, where):
    problems = []
    names = remediation.atlas_mitigations()
    for action in actions:
        text = action["text"]
        if not 40 <= len(text) <= 300:
            problems.append(f"{where}: length")
        if not text.endswith("."):
            problems.append(f"{where}: final period")
        if "\u2014" in text or "\u2013" in text:
            problems.append(f"{where}: long dash")
        if any(word in text.lower() for word in FILLER):
            problems.append(f"{where}: filler")
        mid = action["atlas_mitigation"]
        if mid is not None and (mid not in names or mid in FORBIDDEN_ATLAS):
            problems.append(f"{where}: ATLAS id")
    if len({a["text"] for a in actions}) != len(actions):
        problems.append(f"{where}: repeated text")
    return problems


@pytest.mark.parametrize("cls", sorted(VALID_ATTACK_CLASSES))
def test_class_has_one_mitigation_then_one_fix(cls):
    assert [a["tier"] for a in remediation.actions_table()[cls]] == ["mitigation", "fix"]


@pytest.mark.parametrize("cls", sorted(VALID_ATTACK_CLASSES))
def test_class_actions_meet_the_bar(cls):
    assert check_entry(remediation.actions_table()[cls], cls) == []


def test_check_entry_rejects_bad_text_and_atlas_ids():
    bad = [("Configure the tool gateway to validate inputs before each model call.", None, "filler"),
           ("Require user approval before every irreversible tool call.", "AML.M0035", "ATLAS id"),
           ("Require user approval before every irreversible tool call.", "AML.M0099", "ATLAS id"),
           ("x" * 301 + ".", None, "length"),
           ("Require user approval\u2014before every irreversible tool call.", None, "long dash")]
    for text, mid, problem in bad:
        assert f"bad: {problem}" in check_entry([{"tier": "fix", "text": text, "atlas_mitigation": mid}], "bad")
