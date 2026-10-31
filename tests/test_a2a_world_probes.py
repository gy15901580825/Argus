"""Nine plan-reviewed outgoing A2A probe contracts."""
import importlib.util
import json
from pathlib import Path

import yaml

from argus.probe import load_probe

ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = ROOT / 'argus/probes/a2a_world'
PEER = 'peer_http_json_1_0'
SINK = 'observable_action_sink'
LINEAGE = 'observable_agent_lineage'
EXPECTED = {
 'a2a_peer_impersonation': (['ASI07'], [PEER,SINK], 'delegated', ['a2a_no_untrusted_delegation']),
 'a2a_business_approval_replay': (['ASI07'], ['target_receiver',SINK], 'ingress_handled', ['a2a_max_effects_per_approval']),
 'a2a_peer_result_injection': (['ASI01','ASI07'], [PEER,SINK], 'action_requested', ['a2a_no_injected_effect']),
 'a2a_card_instruction_injection': (['ASI01','ASI07'], [PEER,SINK], 'delegated', ['a2a_no_injected_effect']),
 'a2a_sensitive_peer_egress': (['ASI07'], [PEER,SINK], 'delegated', ['a2a_no_sensitive_egress','a2a_no_production_plaintext_secret']),
 'a2a_upstream_error_propagation': (['ASI08'], [PEER,SINK,LINEAGE], 'action_requested', ['a2a_no_causal_invalid_action']),
 'a2a_retry_fanout_storm': (['ASI08'], [PEER,LINEAGE], 'peer_attempts', ['a2a_max_delegated_attempts','a2a_max_fanout']),
 'a2a_approval_trust_chain': (['ASI08'], [PEER,SINK,LINEAGE], 'action_requested', ['a2a_no_laundered_approval']),
 'a2a_three_hop_error_amplification': (['ASI08'], [PEER,SINK,LINEAGE,'three_hop_chain'], 'action_requested', ['a2a_max_causal_effects']),
}


def all_data():
    assert DIRECTORY.is_dir()
    return {p.stem: yaml.safe_load(p.read_text()) for p in DIRECTORY.glob('*.yaml')}


def test_library_has_exactly_the_nine_a2a_world_probes():
    assert set(all_data()) == set(EXPECTED)


def test_each_probe_matches_the_table():
    for probe_id, (ids, caps, decision, assertions) in EXPECTED.items():
        data = all_data()[probe_id]
        assert data['mappings']['owasp_agentic'] == ids
        assert data['requires_capabilities'] == caps
        assert list(data['decision_point'][0]) == [decision]
        assert [next(iter(row)) for row in data['assertions']] == assertions
        assert data['target_class'] == ['a2a_agent']
        load_probe(DIRECTORY / (probe_id+'.yaml'))


def test_every_probe_is_paired_assertion_backed_unjudged():
    for data in all_data().values():
        assert data['scenario']['kind'] == 'a2a_world'
        assert data['scenario']['control']
        assert data['trials'] == 1 and data['judge_when_assertions_pass'] is False
        assert data['assertions'] and len(data['sessions']) == len(data['sessions'][0]) == 1
        assert data['technique'] == ['a2a-peer']
        assert data['judge'] == {'model':'claude-haiku-4-5-20251001','rubric_path':'rubrics/mcp_tool_abuse.md'}
        assert data['remediation'] and not any(c in data['remediation'] for c in ('—','–'))


def test_control_changes_exactly_one_payload_key():
    for data in all_data().values():
        payload = json.loads(data['scenario']['payload'])
        control = json.loads(data['scenario']['control'])
        assert len(control) == 1
        assert all(key in payload and payload[key] != value for key,value in control.items())


def test_prompts_carry_a2a_url_and_avoid_tell_words():
    banned = ('argus','malicious','poison','trap','canary','attack')
    for data in all_data().values():
        prompt = data['sessions'][0][0]
        assert '{a2a_url}' in prompt
        assert not any(word in prompt.lower() for word in banned)


def test_scope_notes():
    for probe_id,data in all_data().items():
        note=data['scope_note']
        if probe_id=='a2a_business_approval_replay':
            assert 'single-use business approvals' in note and 'messageId deduplication is optional' in note
        elif data['mappings']['owasp_agentic']==['ASI08']:
            assert 'one seeded upstream fault' in note and 'distinct agent identities' in note
        else:
            assert 'outbound agent-to-peer' in note and 'PKI and mTLS were not tested' in note
    assert 'production_tls_policy is declared' in all_data()['a2a_sensitive_peer_egress']['scope_note']


def test_asi08_is_exactly_the_four_cascade_probes():
    assert {key for key,row in all_data().items() if 'ASI08' in row['mappings']['owasp_agentic']} == {'a2a_upstream_error_propagation','a2a_retry_fanout_storm','a2a_approval_trust_chain','a2a_three_hop_error_amplification'}


def test_mapping_reasons_cover_all_nine():
    spec=importlib.util.spec_from_file_location('mapping',ROOT/'scripts/annotate_agentic_probes.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    for probe_id,data in all_data().items():
        approval=module.APPROVED[probe_id]
        assert approval['ids']==data['mappings']['owasp_agentic']
        assert approval['evidence_sha256']==module.evidence_hash(data)
        assert 'Cascade:' in approval['reason'] if approval['ids']==['ASI08'] else 'Outbound A2A:' in approval['reason']
