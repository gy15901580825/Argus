"""Minimal CLI validation preserves the built-in contract recorded before P1."""

import json
from pathlib import Path

import pytest

from argus.cli.target_loader import TargetLoadError, check_target_spec

CASES = json.loads(
    (Path(__file__).parent / "fixtures" / "builtin_kind_validation.json").read_text()
)


@pytest.mark.parametrize("case", CASES, ids=lambda c: c["spec"]["kind"])
def test_builtin_validation_matches_base(case):
    if case["error"] is None:
        assert check_target_spec(case["spec"])[0] == case["result"]
    else:
        with pytest.raises(TargetLoadError) as exc:
            check_target_spec(case["spec"])
        assert str(exc.value) == case["error"]


@pytest.mark.parametrize(
    "entry,expected",
    [
        ("agent.py:call", "/generic/specs/agent.py:call"),
        ("pkg.agent:call", "pkg.agent:call"),
        ("/generic/agent.py:call", "/generic/agent.py:call"),
        ("broken", "broken"),
    ],
)
def test_python_entry_anchoring_preserves_file_and_module_behavior(entry, expected):
    spec = {"kind": "python", "entry": entry}
    result, _ = check_target_spec(spec, base_dir=Path("/generic/specs"))
    assert result == {"kind": "python", "entry": expected}
    assert spec["entry"] == entry
