"""Repeated catalog loads reuse YAML parsing without sharing mutable probe data."""
from unittest.mock import patch

import pytest
import yaml

from argus.probe import load_probe

SOURCE = """id: cache_example
name: Example
severity: low
target_class: [http-chat]
attack_class: [prompt-injection]
prompts: [hello]
assertions:
  - response_fields:
      equals:
        $.ok: "yes"
"""


def test_unchanged_probe_is_parsed_once(tmp_path):
    path = tmp_path / "probe.yaml"
    path.write_text(SOURCE)
    with patch("argus.probe.yaml.safe_load", wraps=yaml.safe_load) as parse:
        first = load_probe(path)
        second = load_probe(path)
    assert first == second
    assert parse.call_count == 1


def test_file_edits_are_seen_even_with_the_same_size_and_mtime(tmp_path):
    import os

    path = tmp_path / "probe.yaml"
    path.write_text(SOURCE)
    first = load_probe(path)
    stat = path.stat()
    path.write_text(SOURCE.replace("hello", "world"))
    os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns))
    assert first.prompts == ("hello",)
    assert load_probe(path).prompts == ("world",)


def test_probe_mutation_does_not_change_later_loads(tmp_path):
    path = tmp_path / "probe.yaml"
    path.write_text(SOURCE)
    first = load_probe(path)
    first.assertions[0]["response_fields"]["equals"]["$.ok"] = "no"
    assert load_probe(path).assertions[0]["response_fields"]["equals"]["$.ok"] == "yes"


def test_cached_yaml_still_validates_each_load(tmp_path, monkeypatch):
    from argus import probe

    path = tmp_path / "probe.yaml"
    path.write_text(SOURCE)
    load_probe(path)
    monkeypatch.setattr(probe, "VALID_SEVERITIES", set())
    with pytest.raises(ValueError, match="invalid severity"):
        load_probe(path)
