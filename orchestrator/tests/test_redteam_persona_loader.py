import pytest

from orchestrator.redteam.persona_loader import (
    DATA_DIR,
    PERSONAS_DIR,
    PERSONA_KEYS,
    STRATEGIES_DIR,
    STRATEGY_KEYS,
    Persona,
    Strategy,
    default_personas,
    default_strategies,
    load_personas,
    load_strategies,
)


EXPECTED_PERSONA_IDS = {
    "confused-novice",
    "deadline-developer",
    "entitled-customer",
    "investigative-journalist",
    "peer-agent",
    "security-auditor",
}

EXPECTED_STRATEGY_IDS = {
    "authority-escalation",
    "context-overload",
    "encoding-obfuscation",
    "fictional-framing",
    "gradual-trust",
    "instruction-override",
}


def test_data_dir_layout():
    assert DATA_DIR.is_dir()
    assert PERSONAS_DIR.is_dir()
    assert STRATEGIES_DIR.is_dir()


def test_all_six_personas_load():
    personas = default_personas()
    assert len(personas) == 6
    assert all(isinstance(p, Persona) for p in personas)
    assert {p.id for p in personas} == EXPECTED_PERSONA_IDS


def test_all_six_strategies_load():
    strategies = default_strategies()
    assert len(strategies) == 6
    assert all(isinstance(s, Strategy) for s in strategies)
    assert {s.id for s in strategies} == EXPECTED_STRATEGY_IDS


def test_ids_are_unique_and_match_filename_stem():
    for directory, loader in ((PERSONAS_DIR, load_personas), (STRATEGIES_DIR, load_strategies)):
        loaded = loader(directory)
        ids = [item.id for item in loaded]
        assert len(ids) == len(set(ids)), f"duplicate ids in {directory}"
        assert set(ids) == {path.stem for path in directory.glob("*.md")}


def test_loaders_return_sorted_tuples():
    personas = default_personas()
    strategies = default_strategies()
    assert isinstance(personas, tuple) and isinstance(strategies, tuple)
    assert [p.id for p in personas] == sorted(p.id for p in personas)
    assert [s.id for s in strategies] == sorted(s.id for s in strategies)


def test_every_required_persona_key_is_non_empty():
    for persona in default_personas():
        for key in PERSONA_KEYS:
            value = getattr(persona, key)
            assert value.strip(), f"{persona.id}: empty {key}"
        assert persona.body.strip(), f"{persona.id}: empty body"


def test_every_required_strategy_key_is_non_empty():
    for strategy in default_strategies():
        for key in STRATEGY_KEYS:
            value = getattr(strategy, key)
            assert value.strip(), f"{strategy.id}: empty {key}"
        assert strategy.body.strip(), f"{strategy.id}: empty body"


def test_when_to_use_present_on_all_twelve():
    """The §5.4 pairing policy matches attack_class against when_to_use — it must exist."""
    items = default_personas() + default_strategies()
    assert len(items) == 12
    for item in items:
        assert item.when_to_use.strip(), f"{item.id}: missing when_to_use"


def test_persona_body_declares_voice_not_script():
    for persona in default_personas():
        assert "not a script" in persona.body.lower(), f"{persona.id}: body must say it is not a script"


def test_strategy_body_declares_mechanism_not_script():
    for strategy in default_strategies():
        assert "not a script" in strategy.body.lower(), f"{strategy.id}: body must say it is not a script"


def test_missing_required_key_raises_valueerror_naming_file(tmp_path):
    bad = tmp_path / "broken-persona.md"
    bad.write_text("---\nid: broken\nname: Broken\nvoice: v\n---\nbody\n")
    with pytest.raises(ValueError, match="broken-persona.md") as exc:
        load_personas(tmp_path)
    assert "traits" in str(exc.value)


def test_malformed_frontmatter_raises_valueerror_naming_file(tmp_path):
    bad = tmp_path / "no-delimiter.md"
    bad.write_text("id: broken\nname: Broken\nbody with no frontmatter at all\n")
    with pytest.raises(ValueError, match="no-delimiter.md"):
        load_strategies(tmp_path)


def test_unterminated_frontmatter_raises_valueerror_naming_file(tmp_path):
    bad = tmp_path / "unterminated.md"
    bad.write_text("---\nid: broken\nname: Broken\nmechanics: m\n")
    with pytest.raises(ValueError, match="unterminated.md"):
        load_strategies(tmp_path)


def test_blank_required_value_raises_valueerror_naming_file(tmp_path):
    bad = tmp_path / "blank-value.md"
    bad.write_text(
        "---\nid: blank\nname: Blank\nmechanics: m\nwhen_to_use: '   '\nescalation_notes: e\n---\nbody\n"
    )
    with pytest.raises(ValueError, match="blank-value.md") as exc:
        load_strategies(tmp_path)
    assert "when_to_use" in str(exc.value)
