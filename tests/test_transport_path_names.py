import json

import pytest
from click.testing import CliRunner

from argus.cli.__main__ import main
from argus_transport import TransportSpecV2
from argus_transport.engine import select
from argus_transport.models import path

UNREADABLE = ["it's", "back\\slash", "new\nline", "carriage\rreturn", ""]
CODE_POINTS = sorted({*range(0, 0x10000, 31), 0x0A, 0x0D, 0x27, 0x5C, 0x4E2D, 0x1F600, 0x10FFFF}
                     - set(range(0xD800, 0xE000)))
NAMES = [chr(point) for point in CODE_POINTS] + ["a" + chr(point) + "b" for point in CODE_POINTS] + [
    *UNREADABLE, "where", "wherenot", "job state"]


def accepted(value):
    try:
        path(value)
    except ValueError:
        return False
    return True


def test_every_field_path_the_validator_accepts_reads_that_field():
    readable = 0
    for name in NAMES:
        # A dot path splits on ".", so it names one field only when the name has none.
        for candidate in ["$['" + name + "']"] + (["$." + name] if "." not in name else []):
            if accepted(candidate):
                readable += 1
                assert select({name: "hit", name + "x": "miss"}, candidate) == "hit", repr(candidate)
    assert readable > len(NAMES)


@pytest.mark.parametrize("name", UNREADABLE, ids=["quote", "backslash", "newline", "carriage_return", "empty"])
def test_a_bracket_name_the_evaluator_cannot_read_is_rejected(name):
    with pytest.raises(ValueError, match="Unsupported transport JSONPath"):
        path("$['" + name + "']")


def hand_written(reply_path):
    return {"kind": "custom_http", "transport": {
        "version": 2,
        "request": {"method": "POST", "url": "http://127.0.0.1:8123/ask", "headers": {}, "query": {},
                    "body": {"json": {"question": {"context": "prompt"}}}},
        "auth": {"kind": "none"},
        "response": {"format": "json", "text": {"paths": [reply_path], "cast": "string", "empty": "error"}, "metadata": {}},
        "outcome": {"kind": "http_only"},
        "delivery": {"kind": "sync"},
        "timeout": {"total_deadline_s": 30, "read_s": 30},
        "session": {"mode": "none"},
        "limits": {},
    }}


def validate_target(tmp_path, spec):
    target = tmp_path / "target.json"
    target.write_text(json.dumps(spec))
    return CliRunner().invoke(main, ["validate-target", "--target", str(target), "--offline"])


def test_a_hand_written_spec_with_a_backslash_field_name_does_not_validate(tmp_path):
    spec = hand_written("$['back\\slash']")
    with pytest.raises(ValueError, match="Unsupported transport JSONPath"):
        TransportSpecV2.from_dict(spec["transport"])
    result = validate_target(tmp_path, spec)
    assert result.exit_code != 0
    assert ("target spec invalid: ValueError: Unsupported transport JSONPath: use $.name, $[0] or $['name'], "
            "where a bracket name is not empty and has no quote, backslash or line break") in result.output


def test_validate_target_masks_header_values_in_the_validator_message(tmp_path, monkeypatch):
    spec = hand_written("$['back\\slash']")
    spec["transport"]["request"]["headers"] = {"X-Trace": "trace-value-7"}

    def rejects(_spec):
        raise ValueError("Invalid header trace-value-7")

    monkeypatch.setattr("argus.cli.validate_transport_v2.build_target", rejects)
    result = validate_target(tmp_path, spec)
    assert result.exit_code != 0
    assert "target spec invalid: ValueError: Invalid header ***" in result.output
    assert "trace-value-7" not in result.output


def test_the_same_spec_with_a_plain_bracket_name_validates(tmp_path):
    result = validate_target(tmp_path, hand_written("$['job state']"))
    assert result.exit_code == 0, result.output
