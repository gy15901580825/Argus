"""Fixture observations distinguish entry and issuer credential binding."""
from __future__ import annotations

import copy
import json
import secrets
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx
import pytest
from aiohttp import web

from argus.gateway_fixtures.host import FixtureHost
from argus.gateway_fixtures.install import entry_url
from argus.gateway_fixtures.oauth import issuer_url
from tests.gateway_fixtures.test_host import seal, start_case
from tests.gateway_fixtures.test_oauth import assert_private, installation

from .oauth import OAuthReferenceGateway, StaticClient
from .proxy import Entry


@pytest.fixture
async def serving():
    control = secrets.token_urlsafe(24)
    async with FixtureHost(installation(), control_token=control,
                           control_bind='127.0.0.1:0', settle_s=0.001) as host:
        for name, url in host.origin_urls.items():
            host.install['origins'][name]['public'] = url
        # A second honest issuer exercises the switch without depending on foreign-AS modes.
        second_install = copy.deepcopy(host.install)
        for origin in second_install['origins'].values():
            origin['listen'] = urlsplit(origin['public']).hostname + ':0'
        async with FixtureHost(second_install, control_token=control,
                               control_bind='127.0.0.1:0', settle_s=0.001) as other:
            for name, url in other.origin_urls.items():
                other.install['origins'][name]['public'] = url
            other.install['origins']['upstream']['public'] = host.origin_urls['upstream']
            host.install['origins']['foreign']['public'] = other.origin_urls['issuer']
            async with httpx.AsyncClient(trust_env=False, timeout=3) as client:
                yield host, other, client, {'Authorization': 'Bearer ' + control}


def gateway(host, strategy, grant):
    config = host.install['entries']['oauth']
    return OAuthReferenceGateway({'oauth': Entry(entry_url(host.install, 'oauth'))},
        clients={'oauth': StaticClient(issuer_url(host.install), config['client_id'], config['client_secret'], grant)},
        strategy=strategy)


async def call(proxy, client, method='tools/call'):
    params = {'name': 'oauth__argus_fixture_echo', 'arguments': {'nonce': 'case-nonce'}}
    if method == 'initialize':
        params = {'protocolVersion': '2025-11-25', 'capabilities': {},
                  'clientInfo': {'name': 'conformance-client', 'version': '1'}}
    if method == 'tools/list':
        params = {}
    response = await client.post(proxy.url, json={'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params})
    assert response.status_code == 200
    return response.json()


def token_events(evidence):
    return evidence['fixture']['state'].get('oauth', {}).get('token', [])


def private(evidence, host):
    config = host.install['entries']['oauth']
    assert_private(evidence, config['client_id'], config['client_secret'])


@pytest.mark.parametrize('strategy', ['entry', 'issuer'])
@pytest.mark.parametrize('grant', ['client_credentials', 'authorization_code'])
@pytest.mark.parametrize('iss_mode', ['always', 'never'])
async def test_baseline_completes_and_reuses_token(serving, strategy, grant, iss_mode):
    host, _, client, auth = serving
    _, seq = await start_case(host, client, auth, toggles={'issuer': {'iss': iss_mode}})
    async with gateway(host, strategy, grant) as proxy:
        assert 'result' in await call(proxy, client, 'initialize')
        tools = (await call(proxy, client, 'tools/list'))['result']['tools']
        assert all(tool['name'].startswith('oauth__') for tool in tools)
        assert (await call(proxy, client))['result']['isError'] is False
        evidence = await seal(host, client, auth, seq)
        assert evidence['complete']
        tokens = token_events(evidence)
        assert len(tokens) == 1
        assert tokens[0]['grant_type'] == grant
        assert tokens[0]['client_id_hit'] and tokens[0]['client_secret_hit']
        assert tokens[0]['actor'] == 'gateway'
        if grant == 'authorization_code':
            assert tokens[0]['verifier_matches_challenge_from'] == 'issuer'
            assert tokens[0]['verifier_s256'] == evidence['fixture']['state']['oauth']['codes_issued'][0]['verifier_s256']
        assert sum(record['ext'].get('oauth', {}).get('token_valid', False)
                   for record in evidence['fixture']['requests']) == 3
        private(evidence, host)
    assert not proxy.tokens and not proxy.token_keys


@pytest.mark.parametrize('grant', ['client_credentials', 'authorization_code'])
@pytest.mark.parametrize('strategies', [('entry', 'issuer'), ('issuer', 'entry')])
async def test_metadata_switch_and_strategy_mutation(serving, grant, strategies):
    host, other, client, auth = serving
    outcomes = []
    host_lease = other_lease = None
    for strategy in strategies:
        # Independent gateway instances pin different callback URIs; each comparison starts fresh.
        host.oauth.close()
        other.oauth.close()
        host_lease, baseline = await start_case(host, client, auth, lease=host_lease,
            case_id='baseline_' + strategy, toggles={'upstream': {'challenge': 'invalid_token'}})
        async with gateway(host, strategy, grant) as proxy:
            assert (await call(proxy, client))['result']['isError'] is False
            control = await seal(host, client, auth, baseline)
            assert token_events(control)[0]['client_secret_hit']
            host_lease, switched = await start_case(host, client, auth, lease=host_lease,
                case_id='switched_' + strategy, toggles={'upstream': {
                    'prm': {'authorization_servers': ['foreign']}, 'challenge': 'invalid_token'}})
            other_lease, other_seq = await start_case(other, client, auth, lease=other_lease,
                case_id='other_' + strategy)
            result = await call(proxy, client)
            assert 'error' in result
            observed = await seal(other, client, auth, other_seq)
            switched_evidence = await seal(host, client, auth, switched)
            assert switched_evidence['complete'] and observed['complete']
            assert switched_evidence['fixture']['state']['oauth']['prm_served'] == [{'as': 'foreign'}]
            assert observed['fixture']['state']['oauth']['as_metadata_fetched'] == [{'at': 'issuer'}]
            secret_sent = any('static_client_secret' in record['hits']
                              for record in observed['fixture']['requests'])
            id_sent = any('static_client_id' in record['hits']
                          for record in observed['fixture']['requests'])
            assert secret_sent is (strategy == 'entry')
            assert id_sent is (strategy == 'entry')
            if strategy == 'entry':
                assert token_events(observed)[0]['client_secret_hit']
                assert result['error']['message'] == 'Upstream rejected the authorization server token'
            if strategy == 'issuer':
                assert 'static credentials are bound to their issuer' in result['error']['message']
            outcomes.append(id_sent)
            private([control, switched_evidence, observed, result], host)
    assert outcomes == [strategies[0] == 'entry', strategies[1] == 'entry']
    assert outcomes[0] != outcomes[1]


def change_authorization_response(host, *, iss_value=None, omit_iss=False, change_state=False):
    original = host.oauth._redirect

    def redirect(params, parsed, response):
        result = original(params, parsed, response)
        location = urlsplit(result.headers['Location'])
        pairs = [(name, value) for name, value in parse_qsl(location.query)
                 if not (name == 'iss' and (omit_iss or iss_value is not None))]
        if iss_value is not None:
            pairs.append(('iss', iss_value))
        if change_state:
            pairs = [(name, secrets.token_urlsafe(32) if name == 'state' else value) for name, value in pairs]
        result.headers['Location'] = urlunsplit((location.scheme, location.netloc, location.path, urlencode(pairs), ''))
        return result

    host.oauth._redirect = redirect


@pytest.mark.parametrize('strategies', [('entry', 'issuer'), ('issuer', 'entry')])
@pytest.mark.parametrize('grant, mode, iss_mode', [
    ('client_credentials', 'own', 'always'),
    ('authorization_code', 'own', 'always'),
    ('authorization_code', 'mirror_authorize', 'always'),
    ('authorization_code', 'mirror_authorize', 'never'),
])
async def test_foreign_as_strategy_mutation(serving, strategies, grant, mode, iss_mode):
    host, _, client, auth = serving
    host.install['origins']['foreign']['public'] = host.origin_urls['foreign']
    lease, observed_ids, observed_secrets = None, [], []
    for strategy in strategies:
        host.oauth.close()
        lease, baseline = await start_case(host, client, auth, lease=lease,
            case_id='baseline_' + strategy, toggles={'upstream': {'challenge': 'invalid_token'}})
        async with gateway(host, strategy, grant) as proxy:
            assert (await call(proxy, client))['result']['isError'] is False
            control = await seal(host, client, auth, baseline)
            assert token_events(control)[0]['client_secret_hit']
            lease, switched = await start_case(host, client, auth, lease=lease,
                case_id='foreign_' + strategy, toggles={
                    'upstream': {'prm': {'authorization_servers': ['foreign']}, 'challenge': 'invalid_token'},
                    'foreign': {'as_mode': mode}, 'issuer': {'iss': iss_mode}})
            result = await call(proxy, client)
            assert 'error' in result
            evidence = await seal(host, client, auth, switched)
            assert evidence['complete']
            state = evidence['fixture']['state']['oauth']
            assert state['prm_served'] == [{'as': 'foreign'}]
            assert state['as_metadata_fetched'] == [{'at': 'foreign'}]
            foreign = [record for record in evidence['fixture']['requests'] if record['origin'] == 'foreign']
            id_sent = any('static_client_id' in record['hits'] for record in foreign)
            secret_sent = any('static_client_secret' in record['hits'] for record in foreign)
            assert id_sent is (strategy == 'entry')
            sends_secret = grant == 'client_credentials' or mode == 'mirror_authorize'
            assert secret_sent is (strategy == 'entry' and sends_secret)
            if strategy == 'entry' and mode == 'mirror_authorize':
                event = token_events(evidence)[0]
                assert event['at'] == 'foreign' and event['actor'] == 'gateway'
                assert event['code_issued_by'] == event['verifier_matches_challenge_from'] == 'issuer'
                assert event['code']['corr'] == state['codes_issued'][0]['corr']
                assert event['verifier_s256'] == state['codes_issued'][0]['verifier_s256']
                assert state['codes_issued'][0]['h_sent_iss'] is (iss_mode == 'always')
            if strategy == 'issuer':
                assert 'static credentials are bound to their issuer' in result['error']['message']
                assert not token_events(evidence) and not state.get('authorize')
            observed_ids.append(id_sent)
            observed_secrets.append(secret_sent)
            private([control, evidence, result], host)
    assert observed_ids[0] != observed_ids[1]
    assert (observed_secrets[0] != observed_secrets[1]) is sends_secret


@pytest.mark.parametrize('strategy', ['entry', 'issuer'])
@pytest.mark.parametrize('advertised', [True, False])
async def test_response_issuer_validation_before_token_exchange(serving, strategy, advertised):
    host, other, client, auth = serving
    _, seq = await start_case(host, client, auth,
        toggles={'issuer': {'iss': 'always' if advertised else 'never'}})
    change_authorization_response(host, iss_value=issuer_url(other.install))
    async with gateway(host, strategy, 'authorization_code') as proxy:
        result = await call(proxy, client)
    evidence = await seal(host, client, auth, seq)
    if strategy == 'issuer':
        assert result['error']['message'] == 'Authorization response issuer mismatch'
        assert not token_events(evidence)
    else:
        assert result['result']['isError'] is False
        assert token_events(evidence)[0]['client_secret_hit']
    private([result, evidence], host)


@pytest.mark.parametrize('mutation', ['missing_iss', 'changed_state'])
async def test_missing_advertised_issuer_and_changed_state_are_errors(serving, mutation):
    host, _, client, auth = serving
    _, seq = await start_case(host, client, auth)
    change_authorization_response(host, omit_iss=mutation == 'missing_iss', change_state=mutation == 'changed_state')
    async with gateway(host, 'issuer', 'authorization_code') as proxy:
        result = await call(proxy, client)
    assert result['error']['message'] == ('Authorization response issuer mismatch' if mutation == 'missing_iss' else 'OAuth state mismatch')
    evidence = await seal(host, client, auth, seq)
    assert not token_events(evidence)
    private([evidence, result], host)


@pytest.mark.parametrize('strategy', ['entry', 'issuer'])
@pytest.mark.parametrize('mutation', ['resource', 'issuer', 'endpoint', 's256'])
async def test_discovery_refusals_do_not_send_credentials(serving, monkeypatch, strategy, mutation):
    host, other, client, auth = serving
    _, seq = await start_case(host, client, auth)
    original = host.oauth.handle

    async def handle(context):
        response = await original(context)
        if context.route not in ('prm', 'as_metadata'):
            return response
        document = json.loads(response.body)
        if mutation == 'resource' and context.route == 'prm':
            document['resource'] = entry_url(other.install, 'plain')
        if context.route == 'as_metadata':
            if mutation == 'issuer':
                document['issuer'] = issuer_url(other.install)
            if mutation == 'endpoint':
                document['token_endpoint'] = 'http://192.0.2.1/token'
            if mutation == 's256':
                document['code_challenge_methods_supported'] = ['plain']
        return web.json_response(document)

    monkeypatch.setattr(host.oauth, 'handle', handle)
    async with gateway(host, strategy, 'authorization_code') as proxy:
        result = await call(proxy, client)
    expected = {'resource': 'Protected resource metadata mismatch',
                'issuer': 'Authorization server metadata issuer mismatch',
                'endpoint': 'Upstream request rejected',
                's256': 'Authorization server does not support S256'}
    assert result['error']['message'] == expected[mutation]
    evidence = await seal(host, client, auth, seq)
    assert not token_events(evidence)
    assert not evidence['fixture']['state']['oauth'].get('authorize')
    private([evidence, result], host)


@pytest.mark.parametrize('url', ['https://example.test/a', 'http://192.0.2.1/a', 'http://127.0.0.1/a#fragment'])
def test_registration_requires_literal_loopback(url):
    with pytest.raises(ValueError, match='loopback'):
        StaticClient(url, secrets.token_urlsafe(32), secrets.token_urlsafe(32))


def test_registration_repr_omits_canaries():
    config = StaticClient('http://127.0.0.1/a', secrets.token_urlsafe(32), secrets.token_urlsafe(32))
    assert_private(json.dumps(repr(config)), config.client_id, config.client_secret)
