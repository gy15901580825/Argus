"""Credential forwarding verdicts from offline, nonce-correlated fixture evidence."""
import copy
import secrets
from dataclasses import replace
from pathlib import Path

import pytest

from argus.assertions import evaluate_assertions
from argus.probe import load_probe
from argus.runner import Runner
from argus.targets import build_target
from tests.fixtures.gateway_ref import Preset, ReferenceGateway
from tests.gateway_target.test_target import entries, host, target_spec
from tests.test_redteam_runner_assertions import _ExplodingJudge


PROBE = Path(__file__).parents[2] / 'argus/probes/mcp_gateway/mcp_gateway_client_credential_passthrough.yaml'
ASSERTIONS = ({'gateway_no_client_credential_upstream': {}},)


def verdict(evidence):
    result, = evaluate_assertions(ASSERTIONS, evidence, '')
    return ('error' if result.error else result.verdict or ('pass' if result.passed else 'fail')), result


def captured(hits=()):
    cases = []
    for role in ('control', 'attack'):
        nonce = role + '-nonce'
        cases.append({'id': role, 'entry': 'plain', 'role': role, 'complete': True, 'dropped': 0,
                      'client': {'calls': [{'nonce': nonce, 'status': 200, 'reply': 'result', 'channels': ['post_json'], 'markers': []}]},
                      'fixture': {'requests': [{'origin': 'upstream', 'route': 'mcp', 'entry': 'plain', 'actor': 'gateway',
                                                'headers': [], 'body': {'complete': True, 'jsonrpc': {'method': 'tools/call', 'nonce': nonce}},
                                                'hits': list(hits)}], 'state': {}}})
    return {'interaction_count': 4, 'cases': cases, 'summary': {}}


@pytest.mark.parametrize('label,want,severity', [
    ('auth_header:Authorization', 'fail', 'high'), ('auth_header:Authorization:payload', 'fail', 'high'),
    ('cookie:session', 'fail', 'high'), ('auth_header:X-Test-Key', 'fail', 'high'),
    ('client_canary', 'warn', None), ('upstream_header:Authorization', 'pass', None),
])
def test_hit_kind_decides_verdict_and_hit_removal_flips_it(label, want, severity):
    evidence = captured([label])
    outcome, result = verdict(evidence)
    assert outcome == want
    assert result.severity == severity
    if want == 'fail':
        assert label.removesuffix(':payload') in result.reason and 'plain' in result.reason
    for case in evidence['cases']:
        case['fixture']['requests'][0]['hits'] = []
    assert verdict(evidence)[0] == 'pass'


@pytest.mark.parametrize('complete,dropped,want', [(False, 0, 'error'), (True, 1, 'error'), (True, 0, 'pass')])
def test_incomplete_miss_is_error_but_positive_hit_survives(complete, dropped, want):
    evidence = captured()
    evidence['cases'][1].update(complete=complete, dropped=dropped)
    assert verdict(evidence)[0] == want
    evidence['cases'][1]['fixture']['requests'][0]['hits'] = ['auth_header:Authorization']
    assert verdict(evidence)[0] == 'fail'


@pytest.mark.parametrize('role', ['control', 'attack'])
def test_missing_nonce_contact_skips_instead_of_passing(role):
    evidence = captured(['auth_header:Authorization'])
    case = next(c for c in evidence['cases'] if c['role'] == role)
    case['fixture']['requests'][0]['body']['jsonrpc']['nonce'] = 'background'
    assert verdict(evidence)[0] == 'skipped'


def test_background_and_user_agent_hits_do_not_count():
    evidence = captured()
    record = copy.deepcopy(evidence['cases'][1]['fixture']['requests'][0])
    record['hits'] = ['auth_header:Authorization']
    record['body']['jsonrpc']['nonce'] = 'background'
    evidence['cases'][1]['fixture']['requests'].append(record)
    record = copy.deepcopy(record)
    record['body']['jsonrpc']['nonce'] = 'attack-nonce'
    record['actor'] = 'argus_user_agent'
    evidence['cases'][1]['fixture']['requests'].append(record)
    assert verdict(evidence)[0] == 'pass'


def test_foreign_route_hit_fails_and_webhook_hit_is_information():
    evidence = captured()
    record = copy.deepcopy(evidence['cases'][1]['fixture']['requests'][0])
    record.update(origin='foreign', route='redirect_target', hits=['cookie:session'])
    evidence['cases'][1]['fixture']['requests'].append(record)
    assert verdict(evidence)[0] == 'fail'
    record.update(origin='upstream', route='webhook')
    assert verdict(evidence)[0] == 'pass'
    assert evidence['summary']['webhook_received_client_credential'] == ['cookie:session']


@pytest.mark.parametrize('evidence', [{}, {'cases': []}, {'cases': [None]}, {'cases': captured()['cases'][:1]}])
def test_missing_or_malformed_case_evidence_cannot_pass(evidence):
    assert verdict(evidence)[0] in {'error', 'skipped'}


@pytest.mark.parametrize('preset', [Preset.safe(), Preset.vulnerable()])
@pytest.mark.parametrize('enabled,want', [(False, 'pass'), (True, 'fail')])
async def test_real_gateway_toggle_and_evidence_mutation(host, preset, enabled, want):
    token, cookie = secrets.token_hex(24), secrets.token_hex(24)
    async with ReferenceGateway(entries(host), preset=replace(preset, passthrough=enabled)) as gateway:
        settings = target_spec(host, gateway)
        settings['gateway']['auth'] = {'headers': {'Authorization': 'Bearer ' + token}, 'cookies': {'session': cookie}}
        target = build_target(settings)
        try:
            probe = load_probe(PROBE)
            runner = Runner(target, _ExplodingJudge(), PROBE.parents[2] / 'rubrics')
            finding, = [f async for f in runner.run_probe(probe)]
            assert finding.verdict == want
            text = finding.target_response
            evidence = await target.collect_evidence()
            outcome, result = verdict(evidence)
            assert outcome == want
            assert evidence['summary']['entries_exercised'] == ['hdr', 'plain']
            assert token not in text and cookie not in text
            if enabled:
                assert 'auth_header:Authorization' in result.reason
            mutated = copy.deepcopy(evidence)
            for case in mutated['cases']:
                for request in case['fixture']['requests']:
                    request['hits'] = []
            assert verdict(mutated)[0] == 'pass'
        finally:
            await target.aclose()


async def test_canary_only_forwarding_warns_and_optional_missing_entry_runs(host):
    async with ReferenceGateway({'plain': entries(host)['plain']}, preset=Preset.vulnerable()) as gateway:
        target = build_target(target_spec(host, gateway))
        try:
            await target.begin_probe(load_probe(PROBE))
            await target.send_prompt('')
            evidence = await target.collect_evidence()
            assert verdict(evidence)[0] == 'warn'
            assert evidence['summary']['entries_exercised'] == ['plain']
            assert 'cookie' in evidence['summary']['forwarded_client_header_names']
        finally:
            await target.aclose()


async def test_unregistered_required_entry_reports_skipped(host):
    async with ReferenceGateway({'hdr': entries(host)['hdr']}) as gateway:
        target = build_target(target_spec(host, gateway))
        try:
            runner = Runner(target, _ExplodingJudge(), PROBE.parents[2] / 'rubrics')
            finding, = [f async for f in runner.run_probe(load_probe(PROBE))]
            assert finding.verdict == 'skipped'
            assert 'entry not registered' in finding.reasoning
            assert host[0].lease_id is None
        finally:
            await target.aclose()


@pytest.mark.parametrize('optional', ['hdr', [None], ['plain'], ['hdr', 'hdr']])
async def test_invalid_optional_entries_refused_before_teardown(optional):
    from tests.gateway_target.test_target import probe, recipe, spec
    target = build_target(spec())
    target._lease_id = 'existing'
    try:
        with pytest.raises(ValueError):
            await target.begin_probe(probe(recipe(optional_entries=optional)))
        assert target._lease_id == 'existing'
    finally:
        target._lease_id = None
        await target.aclose()


def test_session_hit_is_informational_and_authentication_failure_is_error():
    evidence = captured(['gateway_session_id'])
    assert verdict(evidence)[0] == 'pass'
    assert evidence['summary']['gateway_session_id_forwarded_entries'] == ['plain']
    evidence['cases'][0]['client']['calls'][0]['status'] = 401
    assert verdict(evidence)[0] == 'error'
