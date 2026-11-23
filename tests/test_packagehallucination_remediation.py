"""Package-install failures need dependency controls in the rendered report."""
from dataclasses import replace
from pathlib import Path
import sys
from types import ModuleType

import pytest
import yaml

from argus.api import PROBES_DIR, finding_dict
from argus.cli import reports
from argus.probe import load_probe, load_probe_library
from argus.runner import skipped_finding
from scripts import wrap_garak_probes


LIBRARY = {p.id: p for p in load_probe_library(PROBES_DIR)}
PACKAGE_IDS = sorted(pid for pid in LIBRARY if pid.startswith("garak_packagehallucination_"))
ADVICE = (
    "Check every package name the agent suggests against the registry or an allowlist before installing.",
    "Treat agent-suggested install commands as untrusted.",
    "Pin dependencies with hashes",
    "private mirror or proxy that blocks unknown names.",
)
HARM_ADVICE = ("harm-category filters", "mandatory moderation service")


def _report(probe):
    finding = replace(skipped_finding(probe, "Package missing from registry."),
                      verdict="fail", severity=probe.severity)
    return reports.render_html({"id": "11111111-2222", "status": "completed",
                               "target_spec": {"kind": "openai_compat"}, "coverage": None,
                               "findings": [finding_dict(finding, probe)]})


@pytest.mark.parametrize("probe_id", PACKAGE_IDS)
def test_package_failure_report_gives_dependency_advice(probe_id):
    assert len(PACKAGE_IDS) == 7
    probe = LIBRARY[probe_id]
    assert probe.attack_class == ("harmful-content",)
    html = _report(probe)
    assert "How to fix" in html
    for text in ADVICE:
        assert text in html, probe_id
    for text in HARM_ADVICE:
        assert text not in html, probe_id


def test_harmful_content_failure_report_keeps_moderation_advice():
    html = _report(LIBRARY["garak_malwaregen_evasion"])
    assert "How to fix" in html
    for text in HARM_ADVICE:
        assert text in html
    for text in ADVICE:
        assert text not in html


def test_garak_generator_writes_package_remediation(tmp_path, monkeypatch):
    # Only upstream class discovery is replaced; no garak download or constructor runs.
    module_name = "garak.probes.packagehallucination"
    mod = ModuleType(module_name)
    mod.Python = type("Python", (), {"__module__": module_name, "prompts": ["Suggest a package."]})
    monkeypatch.setattr(wrap_garak_probes.importlib, "import_module", lambda name: mod)
    assert wrap_garak_probes.wrap_module(module_name, "harmful-content", "LLM09", "AML.T0040", tmp_path) == 1
    html = _report(load_probe(tmp_path / "garak_packagehallucination_python.yaml"))
    for text in ADVICE:
        assert text in html
    for text in HARM_ADVICE:
        assert text not in html


def test_garak_remediation_refresh_preserves_reviewed_probe_data(tmp_path, monkeypatch):
    original = {}
    for probe_id in ("garak_packagehallucination_python", "garak_malwaregen_evasion"):
        source = Path(PROBES_DIR) / "garak" / f"{probe_id}.yaml"
        original[probe_id] = source.read_text()
        if probe_id.startswith("garak_packagehallucination_"):
            data = yaml.safe_load(original[probe_id])
            data.pop("remediation", None)
            data.pop("remediation_actions", None)
            original[probe_id] = yaml.safe_dump(data, sort_keys=False, allow_unicode=True)
        (tmp_path / source.name).write_text(original[probe_id])
    monkeypatch.setattr(sys, "argv", ["wrap_garak_probes.py", "--output", str(tmp_path),
                                     "--update-remediation"])
    wrap_garak_probes.main()
    path = tmp_path / "garak_packagehallucination_python.yaml"
    updated = yaml.safe_load(path.read_text())
    assert {k: v for k, v in updated.items() if k not in {"remediation", "remediation_actions"}} == (
        yaml.safe_load(original["garak_packagehallucination_python"]))
    assert (tmp_path / "garak_malwaregen_evasion.yaml").read_text() == original["garak_malwaregen_evasion"]
    html = _report(load_probe(path))
    for text in ADVICE:
        assert text in html
    for text in HARM_ADVICE:
        assert text not in html
    first = path.read_text()
    wrap_garak_probes.main()
    assert path.read_text() == first
