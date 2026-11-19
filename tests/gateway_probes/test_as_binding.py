"""OAuth issuer conformance verdicts from passive, sealed loopback observations."""
import copy
import json
import secrets
from dataclasses import replace
from pathlib import Path

import pytest

from argus.assertions import evaluate_assertions
from argus.gateway_fixtures.host import FixtureHost
from argus.gateway_fixtures.install import entry_url, write_install
from argus.gateway_fixtures.oauth import issuer_url
from argus.probe import load_probe
from argus.runner import Runner
from tests.test_redteam_runner_assertions import _ExplodingJudge
from argus.targets import build_target
from argus.targets._base import ProbeNotApplicable
from tests.fixtures.gateway_ref.oauth import OAuthReferenceGateway, StaticClient
from tests.fixtures.gateway_ref.proxy import Entry
from tests.gateway_fixtures.test_oauth import installation, assert_private

PROBES = Path(__file__).parents[2] / 'argus/probes/mcp_gateway'
ASSERTIONS = ({'gateway_upstream_as_binding': {}},)


def verdict(evidence, mode='own'):
    result, = evaluate_assertions(({'gateway_upstream_as_binding': {'mode': mode}},), evidence, '')
    return 'error' if result.error else result.verdict or ('pass' if result.passed else 'fail'), result


def record(origin, route, event=None, *, nonce=None, actor='gateway', hits=()):
    return {'origin': origin, 'route': route, 'actor': actor, 'entry': 'oauth', 'hits': list(hits),
            'body': {'complete': True, 'jsonrpc': {'method': 'tools/call', 'nonce': nonce}},
            'ext': {'oauth': event or {}}}


def captured():
    baseline = [record('issuer', 'token', {'token': {'client_id_hit': True, 'client_secret_hit': True}}),
                record('upstream', 'mcp', {'token_valid': True}, nonce='control')]
    attack = [record('upstream', 'prm', {'prm_served': {'as': 'foreign'}}),
              record('foreign', 'as_metadata', {'as_metadata_fetched': {'at': 'foreign'}})]
    cases = [{'id': name, 'role': role, 'entry': 'oauth', 'complete': True, 'dropped': 0,
              'client': {'calls': [{'nonce': role}]}, 'fixture': {'requests': requests, 'state': {}}}
             for name, role, requests in [('baseline_issuer', 'control', baseline), ('switch_to_foreign', 'attack', attack)]]
    return {'interaction_count': 4, 'cases': cases, 'summary': {},
            'static_oauth_client': {'grant': 'client_credentials', 'confidential': True}}


@pytest.mark.parametrize('secret,want,severity', [(True, 'fail', 'high'), (False, 'fail', 'medium')])
def test_static_credentials_at_foreign_and_record_removal(secret, want, severity):
    evidence = captured()
    evidence['cases'][1]['fixture']['requests'].append(record('foreign', 'token', {
        'token': {'client_id_hit': True, 'client_secret_hit': secret}}))
    status, result = verdict(evidence)
    assert status == want and result.severity == severity
    assert ('client_secret_hit' if secret else 'client_id_hit') in result.reason
    evidence['cases'][1]['fixture']['requests'] = [r for r in evidence['cases'][1]['fixture']['requests'] if r['origin'] != 'foreign']
    assert verdict(evidence)[0] == 'pass'


@pytest.mark.parametrize('remove', ['token', 'mcp', 'prm'])
def test_missing_control_or_metadata_contact_skips(remove):
    evidence = captured()
    for case in evidence['cases']:
        case['fixture']['requests'] = [r for r in case['fixture']['requests'] if r['route'] != remove]
    assert verdict(evidence)[0] == 'skipped'


@pytest.mark.parametrize('complete,dropped', [(False, 0), (True, 1)])
def test_incomplete_miss_is_error_and_secret_hit_survives(complete, dropped):
    evidence = captured()
    evidence['cases'][1].update(complete=complete, dropped=dropped)
    assert verdict(evidence)[0] == 'error'
    evidence['cases'][1]['fixture']['requests'].append(record('foreign', 'token', {'token': {'client_secret_hit': True}}))
    assert verdict(evidence)[0] == 'fail'


@pytest.mark.parametrize('code_match,verifier,want', [(True, 'challenge', 'fail'), (True, None, 'fail'),
                                                    (False, 'challenge', 'pass'), (True, 'other', 'pass')])
def test_mirror_correlates_exact_code_and_challenge(code_match, verifier, want):
    evidence = captured()
    requests = evidence['cases'][1]['fixture']['requests']
    requests.append(record('issuer', 'authorize', {'codes_issued': {'by': 'issuer', 'corr': 'h-code', 'verifier_s256': 'challenge', 'h_sent_iss': False}}))
    requests.append(record('foreign', 'token', {'token': {'code': {'corr': 'h-code' if code_match else 'other', 'len': 43},
        'verifier_s256': verifier, 'client_secret_hit': True, 'code_issued_by': 'issuer', 'verifier_matches_challenge_from': 'issuer'}}))
    assert verdict(evidence, 'mirror_authorize')[0] == want
    requests[:] = [r for r in requests if r['origin'] != 'foreign' or r['route'] != 'token']
    assert verdict(evidence, 'mirror_authorize')[0] == 'pass'


def test_background_and_consent_actor_cannot_satisfy_control_or_leak():
    evidence = captured()
    evidence['cases'][1]['fixture']['requests'].append(record('foreign', 'token', {'token': {'client_secret_hit': True}}, actor='argus_user_agent'))
    assert verdict(evidence)[0] == 'pass'
    evidence['cases'][0]['fixture']['requests'][1]['body']['jsonrpc']['nonce'] = 'background'
    assert verdict(evidence)[0] == 'skipped'


@pytest.mark.parametrize('evidence', [{}, {'cases': []}, {'cases': [None]}])
def test_malformed_evidence_never_passes(evidence):
    assert verdict(evidence)[0] == 'error'


class NoRediscoveryGateway(OAuthReferenceGateway):
    async def _document(self, url):
        if 'oauth-protected-resource' in url:
            if not hasattr(self, 'cached_prm'):
                self.cached_prm = await super()._document(url)
            return self.cached_prm
        return await super()._document(url)


@pytest.mark.parametrize('variant,grant,strategy,want', [
    ('', 'client_credentials', 'entry', 'fail'), ('', 'client_credentials', 'issuer', 'pass'),
    ('', 'authorization_code', 'entry', 'fail'), ('', 'authorization_code', 'issuer', 'pass'),
    ('_mixup_iss', 'authorization_code', 'issuer', 'pass'),
    ('_mixup_iss', 'authorization_code', 'entry_validate_iss', 'pass'),
    ('_mixup_no_iss', 'authorization_code', 'entry', 'fail'),
    ('_mixup_no_iss', 'authorization_code', 'issuer', 'pass'),
    ('', 'client_credentials', 'cached', 'skipped'),
])
async def test_reference_strategies_and_e_record_mutation(tmp_path, variant, grant, strategy, want):
    async with FixtureHost(installation(), control_token=secrets.token_hex(16), control_bind='127.0.0.1:0', settle_s=0.001) as host:
        for name, url in host.origin_urls.items():
            host.install['origins'][name]['public'] = url
        path = tmp_path / 'install.json'
        write_install(path, host.install)
        client = host.install['entries']['oauth']
        gateway_class = NoRediscoveryGateway if strategy == 'cached' else OAuthReferenceGateway
        async with gateway_class({'oauth': Entry(entry_url(host.install, 'oauth'))},
            clients={'oauth': StaticClient(issuer_url(host.install), client['client_id'], client['client_secret'], grant)},
            strategy='entry' if strategy in ('cached', 'entry_validate_iss') else strategy,
            validate_iss=True if strategy == 'entry_validate_iss' else None) as gateway:
            target = build_target({'kind': 'mcp_gateway', 'sandbox': True, 'gateway': {'url': gateway.url},
                'fixtures': {'control_url': host.control_url, 'control_token': host.control_token, 'install_file': str(path)},
                'features': {'static_oauth_client': {'grant': grant, 'consent': 'none', 'trigger': 'challenge'}},
                'timeout_s': 2, 'case_window_s': 0.1})
            probe = load_probe(PROBES / ('mcp_gateway_upstream_as_binding' + variant + '.yaml'))
            script = json.loads(probe.scenario_payload)
            script['drive']['backoff_s'] = [0, 0, 0]
            probe = replace(probe, scenario_payload=json.dumps(script))
            try:
                runner = Runner(target, _ExplodingJudge(), PROBES.parents[1] / 'rubrics')
                finding, = [finding async for finding in runner.run_probe(probe)]
                assert finding.verdict == want, finding.reasoning
                evidence = await target.collect_evidence()
                mode = 'mirror_authorize' if variant else 'own'
                status, result = verdict(evidence, mode)
                assert status == want, result.reason
                if strategy == 'cached':
                    assert 'never re-read' in result.reason
                if strategy == 'entry_validate_iss':
                    facts = evidence['summary']['upstream_as_binding']['cases'][1]
                    assert facts['h_sent_iss'] and facts['h_authorize_static_client_id']
                    assert not facts['token']
                if want == 'fail':
                    assert result.severity == 'high' if variant else result.severity in ('high', 'medium')
                    if variant:
                        assert 'verifier_s256' in result.reason
                    else:
                        assert ('client_secret_hit' if grant == 'client_credentials' else 'client_id_hit') in result.reason
                    mutated = copy.deepcopy(evidence)
                    for case in mutated['cases']:
                        if case['role'] == 'attack':
                            case['fixture']['requests'] = [r for r in case['fixture']['requests'] if r['origin'] != 'foreign']
                    assert verdict(mutated, mode)[0] == 'pass'
                failed_control = copy.deepcopy(evidence)
                failed_control['cases'][0]['fixture']['requests'] = []
                assert verdict(failed_control, mode)[0] == 'skipped'
                assert_private(evidence, client['client_id'], client['client_secret'])
                assert host.lease_id is None
            finally:
                await target.aclose()


async def test_mirror_client_credentials_is_not_applicable(tmp_path):
    path = tmp_path / 'install.json'
    write_install(path, installation())
    target = build_target({'kind': 'mcp_gateway', 'sandbox': True, 'gateway': {'url': 'http://127.0.0.1:1/mcp'},
        'fixtures': {'control_url': 'http://127.0.0.1:2', 'control_token': secrets.token_hex(16), 'install_file': str(path)},
        'features': {'static_oauth_client': {'grant': 'client_credentials', 'consent': 'none', 'trigger': 'challenge'}}})
    try:
        with pytest.raises(ProbeNotApplicable, match='authorization_code'):
            await target.begin_probe(load_probe(PROBES / 'mcp_gateway_upstream_as_binding_mixup_iss.yaml'))
    finally:
        await target.aclose()


@pytest.mark.parametrize('backoff', ['2,5,10', [-1, 0, 0], [float('inf'), 0, 0], [0], [False, 0, 0], [31, 0, 0], 'more_calls'])
async def test_invalid_backoff_is_refused_before_teardown(tmp_path, backoff):
    path = tmp_path / 'install.json'
    write_install(path, installation())
    target = build_target({'kind': 'mcp_gateway', 'sandbox': True, 'gateway': {'url': 'http://127.0.0.1:1/mcp'},
        'fixtures': {'control_url': 'http://127.0.0.1:2', 'control_token': secrets.token_hex(16), 'install_file': str(path)},
        'features': {'static_oauth_client': {'grant': 'client_credentials', 'consent': 'none', 'trigger': 'challenge'}}})
    target._lease_id = 'existing'
    try:
        probe = load_probe(PROBES / 'mcp_gateway_upstream_as_binding.yaml')
        recipe = json.loads(probe.scenario_payload)
        recipe['drive']['backoff_s'] = [0, 0, 0] if backoff == 'more_calls' else backoff
        if backoff == 'more_calls':
            recipe['cases'][1]['calls_per_case'] = 4
        with pytest.raises(ValueError):
            await target.begin_probe(replace(probe, scenario_payload=json.dumps(recipe)))
        assert target._lease_id == 'existing'
    finally:
        target._lease_id = None
        await target.aclose()


def test_confidential_control_requires_secret_and_public_control_does_not():
    evidence = captured()
    evidence['cases'][0]['fixture']['requests'][0]['ext']['oauth']['token']['client_secret_hit'] = False
    assert verdict(evidence)[0] == 'skipped'
    evidence['static_oauth_client']['confidential'] = False
    assert verdict(evidence)[0] == 'pass'


def test_other_location_secret_hit_is_high_and_id_at_authorize_is_medium():
    evidence = captured()
    evidence['cases'][1]['fixture']['requests'].append(record('foreign', 'token', hits=['static_client_secret']))
    assert verdict(evidence)[1].severity == 'high'
    evidence['cases'][1]['fixture']['requests'][-1] = record('foreign', 'authorize', hits=['static_client_id'])
    assert verdict(evidence)[1].severity == 'medium'


def test_mirror_requires_gateway_metadata_contact():
    evidence = captured()
    evidence['cases'][1]['fixture']['requests'][1]['actor'] = 'argus_user_agent'
    assert verdict(evidence, 'mirror_authorize')[0] == 'skipped'
    evidence['cases'][1]['fixture']['requests'][1]['actor'] = 'gateway'
    assert verdict(evidence, 'mirror_authorize')[0] == 'pass'


def test_mirror_e_record_removal_retains_sealed_metadata_exercise_witness():
    evidence = captured()
    case = evidence['cases'][1]
    case['oauth'] = {'as_metadata_fetched': {'foreign': 1}}
    case['fixture']['requests'] = [r for r in case['fixture']['requests'] if r['origin'] != 'foreign']
    assert verdict(evidence, 'mirror_authorize')[0] == 'pass'
    case['oauth'] = {}
    assert verdict(evidence, 'mirror_authorize')[0] == 'skipped'


def test_stale_fixture_state_and_summary_cannot_supply_foreign_exposure():
    evidence = captured()
    evidence['cases'][1]['fixture']['state']['oauth'] = {'token': [{'at': 'foreign', 'client_secret_hit': True}]}
    evidence['summary']['upstream_as_binding'] = {'token': [{'at': 'foreign', 'client_secret_hit': True}]}
    assert verdict(evidence)[0] == 'pass'
