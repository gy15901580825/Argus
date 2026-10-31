import copy
from pathlib import Path

import pytest
import yaml

WORKTREE = Path(__file__).parents[1]


def validator_source():
    workflow = yaml.safe_load((WORKTREE / ".github/workflows/ci.yml").read_text())
    step = next(
        step
        for step in workflow["jobs"]["probe-library"]["steps"]
        if step.get("name")
        == "Every probe parses and declares mappings + a real rubric"
    )
    return step["run"].split("python - <<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]


def fixture_data():
    return yaml.safe_load(
        (WORKTREE / "argus/probes/mcp_world/approval_forged_narration.yaml").read_text()
    )


def validate(monkeypatch, tmp_path, data):
    source = validator_source()
    probe_dir = tmp_path / "argus/probes"
    probe_dir.mkdir(parents=True)
    (probe_dir / "sample.yaml").write_text(yaml.safe_dump(data))
    rubric_dir = tmp_path / "argus/rubrics"
    rubric_dir.mkdir(parents=True)
    (rubric_dir / "mcp_tool_abuse.md").write_text("Synthetic rubric fixture.")
    monkeypatch.chdir(tmp_path)
    exec(compile(source, "ci-probe-library", "exec"), {"__name__": "__main__"})


def test_ci_checks_sessions_only_probe(monkeypatch, tmp_path, capsys):
    validate(monkeypatch, tmp_path, fixture_data())
    assert "checked 1 probes" in capsys.readouterr().out


def test_ci_checks_legacy_prompts_probe(monkeypatch, tmp_path, capsys):
    data = fixture_data()
    data["prompts"] = data.pop("sessions")[0]
    data.pop("trials")
    data.pop("decision_point")
    data["scenario"].pop("control")
    validate(monkeypatch, tmp_path, data)
    assert "checked 1 probes" in capsys.readouterr().out


@pytest.mark.parametrize(
    "change",
    [
        {"sessions": []},
        {"sessions": [[""]]},
        {"sessions": ["one conversation"]},
        {"trials": True},
        {"trials": 21},
        {"decision_point": [{"unrecognized": {}}]},
        {"prompts": ["ambiguous"]},
    ],
)
def test_ci_rejects_invalid_phased_shape(monkeypatch, tmp_path, change):
    data = copy.deepcopy(fixture_data())
    data.update(change)
    with pytest.raises(SystemExit) as failure:
        validate(monkeypatch, tmp_path, data)
    assert failure.value.code == 1


def test_ci_rejects_empty_legacy_prompts(monkeypatch, tmp_path):
    data = fixture_data()
    data.pop("sessions")
    data.pop("trials")
    data.pop("decision_point")
    data["scenario"].pop("control")
    data["prompts"] = []
    with pytest.raises(SystemExit) as failure:
        validate(monkeypatch, tmp_path, data)
    assert failure.value.code == 1
