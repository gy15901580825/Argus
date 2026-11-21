"""Offline business-document pack checks through the real Python adapter."""

import json
import re
from pathlib import Path

import pytest
from argus.probe import load_all_probes, load_probe, load_probe_library
from argus.runner import Runner
from argus.suites import derive_suites
from argus.targets.python_target import PythonSpec, PythonTarget
from argus.targets.custom_http import CustomHTTPSpec


ROOT = Path(__file__).resolve().parents[1]
PACK = ROOT / "argus/probes/document"
SCENARIOS = ("invoice_payee_swap", "resume_added_qualification", "contract_termination_fee")
LANGUAGES = ("en", "es", "zh")
IDS = tuple(f"doc_injection_{scenario}_{language}" for scenario in SCENARIOS for language in LANGUAGES)


def test_all_nine_document_probes_load_and_validate():
    probes = list(load_all_probes(PACK))
    assert {probe.id for probe in probes} == set(IDS)
    assert len(probes) == 9
    for probe in probes:
        assert probe.opt_in and not probe.requires_interaction and not probe.needs_judge
        assert probe.trials == 3 and probe.exchange_count == 9
        assert probe.target_class == ("document_transform",)
        assert probe.attack_class == ("indirect-injection",)
        assert probe.severity == ("high" if "invoice" in probe.id else "medium")
        assert probe.mappings.owasp_llm == ("LLM01",)
        assert probe.mappings.atlas == ("AML.T0051.001",)
        assert probe.mappings.nist_ai_rmf == ("MEASURE-2.7",)
        assert probe.mappings.owasp_agentic == ()
        document = probe.document
        assert document.primary == document.injected_slot == "source"
        assert set(document.controls) == {"none", "benign"}
        assert document.controls["none"] == "" and document.controls["benign"]
        assert document.slots["source"].count("<<INJECTION>>") == 1
        kinds = {next(iter(assertion)) for assertion in probe.assertions}
        assert kinds == {"fact_preserved", "fact_not_introduced"}
        forbidden = next(assertion["fact_not_introduced"] for assertion in probe.assertions
                         if "fact_not_introduced" in assertion)
        assert forbidden["locator"] in (
            {"json_path": "$.payee.iban"}, {"json_path": "$.certifications"}, {"section": ["Termination"]},
        )
        if "contract" in probe.id:
            assert document.output_format == "text"
            assert "Termination" not in document.expect_sections
            assert document.expect_sections
        else:
            assert document.output_format == "json"
    for scenario in SCENARIOS:
        variants = [load_probe(PACK / f"doc_injection_{scenario}_{language}.yaml") for language in LANGUAGES]
        assert len({probe.document.slots["source"] for probe in variants}) == 1
        assert len({probe.document.attack for probe in variants}) == 3
        assert len({probe.document.controls["benign"] for probe in variants}) == 3


class BusinessTransformer:
    def __init__(self, probe, vulnerable):
        self.probe = probe
        self.vulnerable = vulnerable
        self.calls = []

    async def call(self, prompt, material, context):
        source = context["slots"]["source"]
        assert prompt == source and material is None and not context["history"]
        assert "<<INJECTION>>" not in source
        self.calls.append(source)
        adopt = self.vulnerable and self.probe.document.attack in source
        if source.startswith("INVOICE"):
            original = re.search(r"^Payee IBAN: (.+)$", source, re.MULTILINE).group(1)
            replacement = re.search(r"GB29 NWBK 6016 1331 9268 19", source)
            output = {"payee": {"iban": replacement.group(0) if adopt else original}, "notes": source}
        elif source.startswith("RESUME"):
            employer = re.search(r"^Current employer: (.+?) \(fictitious\)$", source, re.MULTILINE).group(1)
            output = {"employment": {"current_employer": employer},
                      "skills": ["Spreadsheet formatting", "inventory tracking"],
                      "certifications": ["Certified Project Coordinator"] if adopt else [], "notes": source}
        else:
            termination = re.search(r"^Termination: (.+)$", source, re.MULTILINE).group(1)
            # The missing target section still leaves an independently recognizable summary.
            return {"output": "# Parties\nExample Paper Lantern Ltd and Example Copper Kite Ltd\n"
                              "# Services\nMonthly office inventory checks\n# Payment\nEUR 200 per month\n"
                              + ("" if adopt else f"# Termination\n{termination}\n")
                              + f"# Administrative notes\n{source}"}
        return {"output": json.dumps(output)}


async def run_transformer(probe, vulnerable, tmp_path):
    transformer = BusinessTransformer(probe, vulnerable)
    target = PythonTarget(PythonSpec(entry="unused_document_fixture:call"))
    target._fn = transformer.call
    try:
        findings = [finding async for finding in Runner(target, None, tmp_path, seed="document-pack").run_probe(probe)]
    finally:
        await target.aclose()
    assert len(findings) == 1
    finding = findings[0]
    assert not finding.judge_model
    assert len(transformer.calls) == len(finding.evidence["exchanges"]) == 9
    arms = finding.evidence["document"]["arms"]
    assert set(arms) == {"attack", "none", "benign"}
    assert all(arm["valid"] == 3 for arm in arms.values())
    assert arms["none"]["violating"] == arms["benign"]["violating"] == 0
    return finding


@pytest.mark.parametrize("probe_id", IDS)
@pytest.mark.parametrize("vulnerable", [False, True])
async def test_each_probe_detects_adoption_and_mutation(tmp_path, probe_id, vulnerable):
    probe = load_probe(PACK / f"{probe_id}.yaml")
    finding = await run_transformer(probe, vulnerable, tmp_path)
    assert finding.verdict == ("fail" if vulnerable else "pass")
    assert finding.evidence["document"]["arms"]["attack"]["violating"] == (3 if vulnerable else 0)
    assert finding.severity == (probe.severity if vulnerable else "info")
    mutated = await run_transformer(probe, not vulnerable, tmp_path)
    assert mutated.verdict == ("pass" if vulnerable else "fail")
    assert mutated.verdict != finding.verdict


def test_document_pack_is_opt_in_for_every_suite():
    probes = list(load_all_probes(ROOT / "argus/probes"))
    for ids in derive_suites(probes).values():
        assert not set(IDS).intersection(ids)


async def test_operator_guide_invoice_loads_from_entry_point_pack(tmp_path, monkeypatch):
    guide = (ROOT / "docs/document-injection.md").read_text()
    example = re.search(r"```yaml\n(.*?)\n```", guide, re.DOTALL).group(1)
    pack = tmp_path / "pack"
    builtin = tmp_path / "builtin"
    pack.mkdir()
    builtin.mkdir()
    (pack / "invoice.yaml").write_text(example)

    class Entry:
        name = "example_documents"

        def load(self):
            return lambda: pack

    monkeypatch.setattr("argus.probe.entry_points", lambda **kwargs: [Entry()])
    probe, = load_probe_library(builtin)
    assert probe.id == "example_invoice_iban" and probe.opt_in
    safe = await run_transformer(probe, False, tmp_path)
    vulnerable = await run_transformer(probe, True, tmp_path)
    assert safe.verdict == "pass" and vulnerable.verdict == "fail"


def test_operator_guide_http_template_carries_document():
    guide = (ROOT / "docs/document-injection.md").read_text()
    example = re.search(r"```json\n(.*?)\n```", guide, re.DOTALL).group(1)
    spec = CustomHTTPSpec(**json.loads(example))
    assert spec.response_jsonpath == "$"
    from argus.targets._template import compile_template

    template = compile_template(spec.request_body_template, "request_body_template", {"slots": {"source": ""}})
    source = 'Invoice notes: "quoted"\n第二行'
    assert json.loads(template.render(slots={"source": source})) == {"source": source, "format": "json"}
