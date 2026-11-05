import json
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from argus.drafting import openapi


def write_document(tmp_path, **extra):
    document = {"openapi": "3.1.0", "info": {"title": "Neutral", "version": "1"}, "paths": {}}
    document.update(extra)
    path = tmp_path / "api.json"
    path.write_text(json.dumps(document))
    return path


@pytest.mark.parametrize("shape", ["bytes", "nodes", "depth"])
def test_admits_documents_above_previous_limits(tmp_path, shape):
    extra = {}
    if shape == "bytes":
        extra["x-text"] = "a" * (2 * 1024 * 1024)
    elif shape == "nodes":
        extra["x-values"] = list(range(50_001))
    else:
        nested = {}
        extra["x-nested"] = nested
        for _ in range(70):
            nested["next"] = {}
            nested = nested["next"]
    document = openapi.load_openapi(write_document(tmp_path, **extra))
    assert document.data["openapi"] == "3.1.0"
    assert {key: document.data[key] for key in extra} == extra


def test_byte_limit_exact_boundary(tmp_path, monkeypatch):
    path = write_document(tmp_path)
    size = path.stat().st_size
    monkeypatch.setattr(openapi, "MAX_BYTES", size)
    assert openapi.load_openapi(path).data["info"]["title"] == "Neutral"
    monkeypatch.setattr(openapi, "MAX_BYTES", size - 1)
    with pytest.raises(openapi.DocumentError) as error:
        openapi.load_openapi(path)
    assert str(error.value) == f"Document byte limit exceeded (MAX_BYTES={size - 1}, observed={size})"


def test_oversized_stat_rejects_before_open(tmp_path, monkeypatch):
    path = tmp_path / "large.json"
    path.write_bytes(b"{}" + b" " * 100)
    monkeypatch.setattr(openapi, "MAX_BYTES", 10)
    opened = []
    original = Path.open

    def tracked(file, *args, **kwargs):
        opened.append(file)
        return original(file, *args, **kwargs)

    monkeypatch.setattr(Path, "open", tracked)
    with pytest.raises(openapi.DocumentError) as error:
        openapi._Reader(tmp_path).read(path)
    assert str(error.value) == "Document byte limit exceeded (MAX_BYTES=10, observed=102)"
    assert opened == []


def test_cumulative_bytes_and_cached_file_counted_once(tmp_path, monkeypatch):
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    first.write_text('{"a":1}')
    second.write_text('{"b":2}')
    size = first.stat().st_size + second.stat().st_size
    monkeypatch.setattr(openapi, "MAX_BYTES", size)
    reader = openapi._Reader(tmp_path)
    assert reader.read(first) == reader.read(first) == {"a": 1}
    assert reader.read(second) == {"b": 2}
    assert reader.bytes == size
    monkeypatch.setattr(openapi, "MAX_BYTES", size - 1)
    reader = openapi._Reader(tmp_path)
    reader.read(first)
    with pytest.raises(openapi.DocumentError) as error:
        reader.read(second)
    assert str(error.value) == f"Document byte limit exceeded (MAX_BYTES={size - 1}, observed={size})"


def test_growth_after_stat_remains_bounded(tmp_path, monkeypatch):
    path = tmp_path / "growing.json"
    path.write_bytes(b"{}" + b" " * 100)
    monkeypatch.setattr(openapi, "MAX_BYTES", 10)
    original = Path.stat

    def underreported(file, *args, **kwargs):
        if file == path:
            return SimpleNamespace(st_mode=stat.S_IFREG, st_size=2)
        return original(file, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", underreported)
    with pytest.raises(openapi.DocumentError) as error:
        openapi._Reader(tmp_path).read(path)
    assert str(error.value) == "Document byte limit exceeded (MAX_BYTES=10, observed=11)"


def test_nonregular_file_is_not_a_byte_limit(tmp_path):
    path = tmp_path / "directory.json"
    path.mkdir()
    with pytest.raises(openapi.DocumentError) as error:
        openapi._Reader(tmp_path).read(path)
    assert str(error.value) == "Document file is not regular"


def test_yaml_event_boundary(tmp_path, monkeypatch):
    path = tmp_path / "events.yaml"
    text = "a: 1\n"
    path.write_text(text)
    events = len(list(yaml.parse(text)))
    monkeypatch.setattr(openapi, "MAX_YAML_EVENTS", events, raising=False)
    assert openapi._Reader(tmp_path).read(path) == {"a": 1}
    monkeypatch.setattr(openapi, "MAX_YAML_EVENTS", events - 1)
    with pytest.raises(openapi.DocumentError) as error:
        openapi._Reader(tmp_path).read(path)
    assert str(error.value) == f"YAML event limit exceeded (MAX_YAML_EVENTS={events - 1}, observed={events})"


def test_yaml_depth_boundary(tmp_path, monkeypatch):
    path = tmp_path / "depth.yaml"
    path.write_text("a: {b: {c: 1}}\n")
    monkeypatch.setattr(openapi, "MAX_DEPTH", 3)
    assert openapi._Reader(tmp_path).read(path) == {"a": {"b": {"c": 1}}}
    monkeypatch.setattr(openapi, "MAX_DEPTH", 2)
    with pytest.raises(openapi.DocumentError) as error:
        openapi._Reader(tmp_path).read(path)
    assert str(error.value) == "YAML depth limit exceeded (MAX_DEPTH=2, observed=3)"


def test_expansion_node_boundary(tmp_path, monkeypatch):
    path = tmp_path / "api.json"
    monkeypatch.setattr(openapi, "MAX_NODES", 3)
    reader = openapi._Reader(tmp_path)
    assert reader.expand([1, 2], path, "") == [1, 2]
    assert reader.nodes == 3
    monkeypatch.setattr(openapi, "MAX_NODES", 2)
    with pytest.raises(openapi.DocumentError) as error:
        openapi._Reader(tmp_path).expand([1, 2], path, "")
    assert str(error.value) == "Expanded document node limit exceeded (MAX_NODES=2, observed=3)"


def test_expansion_depth_boundary(tmp_path, monkeypatch):
    path = tmp_path / "api.json"
    monkeypatch.setattr(openapi, "MAX_DEPTH", 2)
    assert openapi._Reader(tmp_path).expand([[1]], path, "") == [[1]]
    monkeypatch.setattr(openapi, "MAX_DEPTH", 1)
    with pytest.raises(openapi.DocumentError) as error:
        openapi._Reader(tmp_path).expand([[1]], path, "")
    assert str(error.value) == "Expanded document depth limit exceeded (MAX_DEPTH=1, observed=2)"


def test_alias_bomb_rejected_before_construction(tmp_path, monkeypatch):
    path = tmp_path / "aliases.yaml"
    path.write_text("a: &a [x, x, x]\nb: &b [*a, *a, *a]\nc: &c [*b, *b, *b]\nd: [*c, *c, *c]\n")
    constructed = []
    original = yaml.load

    def tracked(*args, **kwargs):
        constructed.append(True)
        return original(*args, **kwargs)

    monkeypatch.setattr(yaml, "load", tracked)
    monkeypatch.setattr(openapi, "MAX_NODES", 20)
    with pytest.raises(openapi.DocumentError) as error:
        reader = openapi._Reader(tmp_path)
        reader.expand(reader.read(path), path, "")
    assert str(error.value) == "YAML aliases are not allowed"
    assert constructed == []


def test_active_chain_cycle_is_an_issue_not_a_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(openapi, "MAX_DEPTH", 20)
    path = write_document(tmp_path, components={"schemas": {"A": {"$ref": "#/components/schemas/B"}, "B": {"$ref": "#/components/schemas/A"}}})
    try:
        document = openapi.load_openapi(path)
    except openapi.DocumentError as error:
        pytest.fail(f"Cycle guard must produce an issue instead of a resource error: {error}")
    assert document.issues
    assert {issue.code for issue in document.issues} == {"reference_cycle"}


def test_sibling_reference_reuse_retains_provenance(tmp_path):
    path = write_document(tmp_path, components={"schemas": {"A": {"type": "string"}, "B": {"$ref": "#/components/schemas/A"}, "C": {"$ref": "#/components/schemas/A"}}})
    document = openapi.load_openapi(path)
    assert document.issues == ()
    for name in ("B", "C"):
        assert document.data["components"]["schemas"][name] == {"type": "string"}
        assert document.sources[f"/components/schemas/{name}/type"].pointer == "/components/schemas/A/type"
