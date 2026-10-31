import httpx
import pytest
from tests.a2a_helpers import BINDINGS, target_for, run_target

@pytest.mark.parametrize('binding',BINDINGS)
async def test_extended_card_without_credentials_is_fail(binding):
    target,_=target_for('naive',binding)
    assert (await run_target(target,'extended_card_auth'))[0][0]=='fail'

@pytest.mark.parametrize('binding',BINDINGS)
async def test_extended_card_rejected_is_pass(binding):
    target,_=target_for('safe',binding)
    assert (await run_target(target,'extended_card_auth'))[0][0]=='pass'

@pytest.mark.parametrize('binding',BINDINGS)
async def test_no_extended_card_capability_is_skipped(binding):
    target,_=target_for('no_extended_card',binding)
    (outcome,_),ev=await run_target(target,'extended_card_auth')
    assert outcome=='skipped' and ev['exchanges']==[]

@pytest.mark.parametrize('binding',BINDINGS)
async def test_extended_card_needs_no_allow_send(binding):
    target,ledger=target_for('naive',binding,allow_send=False)
    assert (await run_target(target,'extended_card_auth'))[0][0]=='fail' and ledger.state_changing==0

@pytest.mark.parametrize('binding',BINDINGS)
async def test_unsigned_card_is_warn_and_signed_card_is_pass(binding):
    target,_=target_for('naive',binding)
    assert (await run_target(target,'card_unsigned'))[0][0]=='warn'
    target,_=target_for('safe',binding)
    (outcome,reason),_=await run_target(target,'card_unsigned')
    assert outcome=='pass' and 'did not verify' in reason

async def test_card_unsigned_runs_on_grpc_only_card():
    target,_=target_for('naive','JSONRPC')
    target._transport=httpx.MockTransport(lambda req:httpx.Response(200,json={'supportedInterfaces':[{'url':'http://127.0.0.1','protocolBinding':'GRPC','protocolVersion':'1.0'}]}))
    assert (await run_target(target,'card_unsigned'))[0][0]=='warn'

@pytest.mark.parametrize('binding',BINDINGS)
async def test_extended_card_failed_control_is_error(binding):
    target,_=target_for('safe',binding,credentials={'headers':[['Authorization','Bearer wrong']]})
    (outcome,reason),_=await run_target(target,'extended_card_auth')
    assert outcome=='error' and reason.startswith('clean_control_failed:')
