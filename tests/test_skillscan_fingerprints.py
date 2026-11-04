from __future__ import annotations

import random
import string

import pytest

from argus.skillscan import decoys, sandbox


def assert_decoy_shapes(items):
    for item in items:
        shape = item.path if item.kind == "env" else item.kind
        prefix, alphabet, length = decoys.MARKER_SHAPES[shape]
        assert item.marker.startswith(prefix)
        assert len(item.marker) == len(prefix) + length
        assert set(item.marker[len(prefix):]) <= set(alphabet)


@pytest.mark.parametrize("word", ["ArGuS", "DeCoY"])
@pytest.mark.parametrize("kind,length", [("ssh", 70), ("env", 48)])
def test_decoy_rejects_forced_marker_fingerprint(monkeypatch, word, kind, length):
    original = decoys._rand
    injected = False

    def draw(rng, alphabet, size):
        nonlocal injected
        if rng is None and size == length and not injected:
            injected = True
            return word + "A" * (size - len(word))
        return original(rng, alphabet, size)

    monkeypatch.setattr(decoys, "_rand", draw)
    items = decoys.make_decoys()
    selected = next(item for item in items if item.kind == kind)
    assert "argus" not in decoys.render_decoy_file(selected).lower()
    assert "decoy" not in decoys.render_decoy_file(selected).lower()
    assert_decoy_shapes(items)


@pytest.mark.parametrize("word", ["ArGuS", "DeCoY"])
def test_decoy_rejects_forced_filler_fingerprint(monkeypatch, word):
    original = decoys._rand
    candidate = "A" * 70
    candidate_state = random.Random(candidate).getstate()
    injected_marker = False

    def draw(rng, alphabet, size):
        nonlocal injected_marker
        if rng is None and size == 70 and not injected_marker:
            injected_marker = True
            return candidate
        if rng is not None and rng.getstate() == candidate_state:
            return word + original(rng, alphabet, size - len(word))
        return original(rng, alphabet, size)

    monkeypatch.setattr(decoys, "_rand", draw)
    items = decoys.make_decoys()
    selected = next(item for item in items if item.kind == "ssh")
    assert "argus" not in selected.marker.lower()
    assert "decoy" not in selected.marker.lower()
    rendered = decoys.render_decoy_file(selected)
    assert "argus" not in rendered.lower()
    assert "decoy" not in rendered.lower()
    assert_decoy_shapes(items)


def test_seeded_decoys_remain_deterministic_after_fingerprint_rejection(monkeypatch):
    original = decoys._rand
    seed = "fingerprint-collision"
    initial_state = random.Random(seed).getstate()

    def draw(rng, alphabet, size):
        if rng is not None and rng.getstate() == initial_state:
            original(rng, alphabet, size)
            return "ArGuS" + "A" * (size - 5)
        return original(rng, alphabet, size)

    monkeypatch.setattr(decoys, "_rand", draw)
    first = decoys.make_decoys(seed)
    second = decoys.make_decoys(seed)
    assert first == second
    for item in first:
        rendered = decoys.render_decoy_file(item).lower()
        assert "argus" not in rendered
        assert "decoy" not in rendered
    assert_decoy_shapes(first)


@pytest.mark.parametrize("word", ["ArGuS", "DuMmY"])
def test_dummy_key_rejects_forced_fingerprint(monkeypatch, word):
    draws = iter(word + "A" * (93 - len(word)) + "B" * 93)
    monkeypatch.setattr(sandbox.secrets, "choice", lambda alphabet: next(draws))
    key = sandbox.make_dummy_key()
    assert all(forbidden not in key.lower() for forbidden in ("argus", "dummy"))
    assert key.startswith("sk-ant-api03-")
    assert key.endswith("AA")
    assert len(key) == 108
    assert set(key[13:-2]) <= set(string.ascii_letters + string.digits + "-_")
