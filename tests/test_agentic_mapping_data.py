"""Guard the evidence-reviewed agentic annotations and offline regeneration."""
from pathlib import Path
import importlib.util
import subprocess
import sys

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts' / 'annotate_agentic_probes.py'


def mapper():
    spec = importlib.util.spec_from_file_location('annotate_agentic_probes', SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_all_probes_explicitly_declare_reviewed_agentic_mappings():
    module = mapper()
    assert module.check(ROOT) == []
    assert len(module.APPROVED) == 247


def test_generic_chat_and_unexercised_agentic_risks_are_excluded():
    module = mapper()
    for probe_id in ('syscard_sleeper_agent', 'owasp_04_poisoning', 'owasp_08_vector_weaknesses',
                     'encoded_payload_hex_codeblock', 'owasp_05_output_eval_injection',
                     'garak_dan_dan_6_0', 'vllm_server_known_vulnerable_version',
                     'mcp_scan_cross_session_leak', 'mcp_server_no_auth'):
        assert module.APPROVED[probe_id]['ids'] == []
    assert not {'ASI08'} & {
        item for row in module.APPROVED.values() for item in row['ids']
    }


def test_iterative_attacks_carry_no_agentic_mapping():
    from argus.iterative_pair import PAIRProbe
    from argus.iterative_tap import TAPProbe
    from argus.iterative_gcg import GCGProbe

    for probe_type in (PAIRProbe, TAPProbe, GCGProbe):
        assert probe_type().mappings.owasp_agentic == (), probe_type.__name__


def test_mapping_document_explains_iterative_attack_exclusion():
    document = mapper().render_doc(ROOT)
    rationale = next((line for line in document.splitlines() if 'PAIR/TAP/GCG' in line), '')
    assert 'chat-model jailbreaks' in rationale
    assert 'agent tool actions' in rationale
    assert '`owasp_agentic` remains empty' in rationale


def test_annotations_reject_changed_evidence_and_unknown_probes(tmp_path):
    module = mapper()
    path = tmp_path / 'argus' / 'probes' / 'changed.yaml'
    path.parent.mkdir(parents=True)
    source = ROOT / 'argus/probes/mcp/mcp_poison_description_exfil.yaml'
    data = yaml.safe_load(source.read_text())
    data['prompts'] = ['A completely different task']
    path.write_text(yaml.safe_dump(data))
    assert any('evidence changed' in issue for issue in module.check(tmp_path))
    data['id'] = 'new_unreviewed_probe'
    path.write_text(yaml.safe_dump(data))
    assert any('unreviewed probe' in issue for issue in module.check(tmp_path))
    with pytest.raises(ValueError, match='unreviewed probe'):
        module.annotate(tmp_path)


def test_write_preserves_probe_text_except_annotation_and_is_idempotent(tmp_path):
    module = mapper()
    path = tmp_path / 'argus/probes/mcp/mcp_poison_description_exfil.yaml'
    path.parent.mkdir(parents=True)
    original = (ROOT / 'argus/probes/mcp/mcp_poison_description_exfil.yaml').read_text()
    stripped = '\n'.join(line for line in original.split('\n') if not line.startswith('  owasp_agentic:'))
    path.write_text(stripped)
    module.annotate(tmp_path)
    assert path.read_text() == original
    module.annotate(tmp_path)
    assert path.read_text() == original


def test_mapping_audit_document_matches_approved_decisions():
    module = mapper()
    assert (ROOT / 'docs/owasp-agentic-mapping.md').read_text() == module.render_doc(ROOT)
    result = subprocess.run([sys.executable, str(SCRIPT), '--check'], cwd=ROOT, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr


def test_suggestions_do_not_replace_reviewed_decisions():
    module = mapper()
    data = yaml.safe_load((ROOT / 'argus/probes/owasp_08_vector_weaknesses.yaml').read_text())
    assert 'ASI06' in module.suggest(data)
    assert module.APPROVED[data['id']]['ids'] == []


def test_a2a_server_probes_map_to_asi07_only():
    module = mapper()
    rows = [row for name, row in module.APPROVED.items() if name.startswith('a2a_server_')]
    assert len(rows) == 6 and all(row['ids'] == ['ASI07'] for row in rows)
