import re
from pathlib import Path
import pytest
from argus.probe import load_probe_library
from argus.runner import Runner
from tests.a2a_helpers import BINDINGS, target_for, cross_second

CHECKS=('unauthenticated_task','invalid_credentials','cross_client_task','extended_card_auth','card_unsigned','push_private_callback')
PROBE_DIR=Path(__file__).resolve().parents[1]/'argus'/'probes'/'a2a_server'
AUTH_CELLS=[('naive','naive',{},'fail'),('safe','safe',{},'pass'),('message_ack','message_ack',{},'fail'),('auth_required_state','auth_required_state',{},'warn'),('optional_auth','optional_auth',{},'skipped'),('custom_code_mapped','jsonrpc_custom_code',{'jsonrpc_auth_error_codes':{'authentication':[-31001]}},'pass'),('custom_code_unmapped','jsonrpc_custom_code',{},'error'),('allow_send_off','naive',{'allow_send':False},'skipped')]
CASES={
    'unauthenticated_task':AUTH_CELLS,
    'invalid_credentials':AUTH_CELLS,
    'cross_client_task':[('naive','naive',{},'fail'),('safe','safe',{},'pass'),('shared_undeclared','shared_workspace',{'second_client':cross_second([])},'skipped'),('shared_declared','shared_workspace',{},'fail'),('sync_complete','sync_complete',{},'pass'),('cancel_anomaly','cancel_anomaly',{},'warn')],
    'extended_card_auth':[('naive','naive',{},'fail'),('safe','safe',{},'pass'),('no_extended_card','no_extended_card',{},'skipped')],
    'card_unsigned':[('naive','naive',{},'warn'),('safe','safe',{},'pass')],
    'push_private_callback':[('naive_no_policy','naive',{},'warn'),('naive_deny_private','naive',{'push_callback_policy':'deny_private'},'fail'),('safe','safe',{},'pass'),('jsonrpc_error_200','push_jsonrpc_error_200',{},'pass'),('no_push','no_push',{},'skipped'),('message_only','message_only',{},'skipped')],
}
CELLS=[(binding,check,cell,variant,patch,want) for check,cases in CASES.items() for cell,variant,patch,want in cases for binding in BINDINGS if not(binding=='HTTP+JSON' and variant in ('jsonrpc_custom_code','push_jsonrpc_error_200'))]

class _NoJudge:
    _cost_meter=None
    async def judge(self,**kwargs): raise AssertionError('A2A assertions must decide without a judge')

async def run_cell(tmp_path,binding,check,variant,patch):
    probes=load_probe_library(PROBE_DIR)
    assert {p.id for p in probes}=={'a2a_server_'+c for c in CHECKS}
    probe=next(p for p in probes if p.id=='a2a_server_'+check)
    target,ledger=target_for(variant,binding,**{'second_client':cross_second(),**patch})
    runner=Runner(target=target,judge=_NoJudge(),rubrics_dir=tmp_path)
    findings=[f async for f in runner.run_probe(probe)]
    assert len(findings)==1
    return findings[0],ledger

@pytest.mark.parametrize('binding,check,cell,variant,patch,want',CELLS,ids=[f'{b}-{c}-{cell}' for b,c,cell,_,_,_ in CELLS])
async def test_matrix_cell(tmp_path,binding,check,cell,variant,patch,want):
    finding,ledger=await run_cell(tmp_path,binding,check,variant,patch)
    assert finding.verdict==want
    if cell=='allow_send_off': assert ledger.state_changing==0
    if cell=='sync_complete': assert 'cancel: skipped' in finding.reasoning
    if cell=='cancel_anomaly': assert 'cancel anomaly' in finding.reasoning
    assert finding.owasp_agentic==['ASI07']


def test_matrix_has_every_design_cell():
    expected=set()
    auth=('naive','safe','message_ack','auth_required_state','optional_auth','allow_send_off')
    for check in ('unauthenticated_task','invalid_credentials'):
        expected.update((binding,check,cell) for binding in ('JSONRPC','HTTP+JSON') for cell in auth)
        expected.update(('JSONRPC',check,cell) for cell in ('custom_code_mapped','custom_code_unmapped'))
    for check,names in [('cross_client_task',('naive','safe','shared_undeclared','shared_declared','sync_complete','cancel_anomaly')),('extended_card_auth',('naive','safe','no_extended_card')),('card_unsigned',('naive','safe')),('push_private_callback',('naive_no_policy','naive_deny_private','safe','no_push','message_only'))]:
        expected.update((binding,check,cell) for binding in ('JSONRPC','HTTP+JSON') for cell in names)
    expected.add(('JSONRPC','push_private_callback','jsonrpc_error_200'))
    assert len(CELLS)==61 and len(expected)==61
    assert {(b,c,cell) for b,c,cell,_,_,_ in CELLS}==expected

async def test_pass_reasons_report_observations_not_safety(tmp_path):
    reasons=[]
    for binding,check,cell,variant,patch,want in CELLS:
        if want=='pass':
            finding,_=await run_cell(tmp_path,binding,check,variant,patch)
            assert finding.verdict=='pass'
            reasons.append(finding.reasoning)
    assert reasons and all(re.search(r'\b(secure|safe|not vulnerable|protected)\b',reason,re.I) is None for reason in reasons)

@pytest.mark.parametrize('binding',BINDINGS)
async def test_allow_send_off_sends_no_state_changing_request(tmp_path,binding):
    actual=[]
    for check in CHECKS:
        finding,ledger=await run_cell(tmp_path,binding,check,'naive',{'allow_send':False})
        actual.append(finding.verdict)
        assert ledger.state_changing==0
    assert actual==['skipped','skipped','skipped','fail','warn','skipped']
