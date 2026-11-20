"""Code provenance and concise reasons from synthetic loopback OAuth exchanges."""
import copy
import json
import secrets
from dataclasses import replace
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from argus.gateway_fixtures.host import FixtureHost
from argus.gateway_fixtures.install import entry_url, write_install
from argus.gateway_fixtures.oauth import issuer_url
from argus.probe import load_probe
from argus.targets import build_target
from tests.fixtures.gateway_ref.oauth import OAuthReferenceGateway, StaticClient
from tests.fixtures.gateway_ref.proxy import Entry
from tests.gateway_fixtures.test_oauth import assert_private, installation
from tests.gateway_probes.test_as_binding import PROBES, captured, record, verdict

MIXUP = 'H-issued code reached foreign token endpoint; verifier_s256 matches the challenge for that code'


class BrowserExchangeClient(httpx.AsyncClient):
    def __init__(self, foreign_token, repeats):
        super().__init__(trust_env=False, timeout=5)
        self.foreign_token, self.repeats = foreign_token, repeats
        self.private_values = []
        self.rejections = []

    async def get(self, url, **kwargs):
        if urlsplit(url).path.endswith('/authorize'):
            # A separate browser carries authorize without the consent-agent header.
            async with httpx.AsyncClient(trust_env=False, headers={'User-Agent': 'SyntheticBrowser/1'}) as browser:
                response = await browser.get(url, **kwargs)
            values = parse_qs(urlsplit(response.headers.get('Location', '')).query)
            self.private_values.extend(values.get('code', []))
            return response
        return await super().get(url, **kwargs)

    async def post(self, url, **kwargs):
        self.private_values.extend([kwargs.get('data', {}).get('code_verifier', '')])
        for index in range(self.repeats if url == self.foreign_token else 1):
            response = await super().post(url, **kwargs)
            if url == self.foreign_token:
                self.rejections.append((response.status_code, response.json()))
            if index + 1 < self.repeats and url == self.foreign_token:
                await response.aclose()
        return response


@pytest.mark.parametrize('variant', ['', '_mixup_iss', '_mixup_no_iss'])
@pytest.mark.parametrize('strategy,want', [('entry', 'fail'), ('issuer', 'pass')])
@pytest.mark.parametrize('repeats', [1, 4])
async def test_browser_code_provenance_and_repeated_reasons(tmp_path, variant, strategy, want, repeats):
    async with FixtureHost(installation(), control_token=secrets.token_hex(16),
                           control_bind='127.0.0.1:0', settle_s=0.001) as host:
        for name, url in host.origin_urls.items():
            host.install['origins'][name]['public'] = url
        path = tmp_path / 'install.json'
        write_install(path, host.install)
        client = host.install['entries']['oauth']
        async with OAuthReferenceGateway({'oauth': Entry(entry_url(host.install, 'oauth'))},
            clients={'oauth': StaticClient(issuer_url(host.install), client['client_id'],
                                          client['client_secret'], 'authorization_code')}, strategy=strategy) as gateway:
            await gateway.client.aclose()
            gateway.client = BrowserExchangeClient(issuer_url(host.install, 'foreign') + '/token', repeats)
            target = build_target({'kind': 'mcp_gateway', 'sandbox': True, 'gateway': {'url': gateway.url},
                'fixtures': {'control_url': host.control_url, 'control_token': host.control_token, 'install_file': str(path)},
                'features': {'static_oauth_client': {'grant': 'authorization_code', 'consent': 'none', 'trigger': 'challenge'}},
                'timeout_s': 2, 'case_window_s': 0.1})
            probe = load_probe(PROBES / ('mcp_gateway_upstream_as_binding' + variant + '.yaml'))
            recipe = json.loads(probe.scenario_payload)
            recipe['drive']['backoff_s'] = [0]
            recipe['drive']['calls_per_case'] = 1
            try:
                await target.begin_probe(replace(probe, scenario_payload=json.dumps(recipe)))
                await target.send_prompt('scripted')
                evidence = await target.collect_evidence()
                mode = 'mirror_authorize' if variant else 'own'
                status, outcome = verdict(evidence, mode)
                assert status == want and (want == 'pass' or outcome.severity == 'high')
                fact = evidence['summary']['upstream_as_binding']['cases'][1]
                if want == 'fail':
                    issued, = fact['codes_issued']
                    origin = 'issuer' if variant else 'foreign'
                    assert issued['by'] == origin
                    assert len(fact['token']) == repeats
                    assert all(token['code_issued_by'] == origin and
                               token['verifier_matches_challenge_from'] == origin for token in fact['token'])
                    authorize, = [r for r in evidence['cases'][1]['fixture']['requests'] if r['route'] == 'authorize']
                    assert authorize['actor'] != 'argus_user_agent'
                    assert any(h.get('value') == 'SyntheticBrowser/1' for h in authorize['headers'])
                    assert gateway.client.rejections == [(400, {'error': 'invalid_grant'})] * repeats
                    assert outcome.reason.count('client_secret_hit at foreign token endpoint') == 1
                    assert outcome.reason.count(MIXUP) == bool(variant)
                    assert outcome.reason.count(f'({repeats} token requests)') == (2 if variant else 1) * (repeats > 1)
                    mutated = copy.deepcopy(evidence)
                    mutated['cases'][1]['fixture']['requests'] = [r for r in mutated['cases'][1]['fixture']['requests']
                                                                 if r['origin'] != 'foreign']
                    assert verdict(mutated, mode)[0] == 'pass'
                else:
                    assert not fact['codes_issued'] and not fact['token']
                assert_private(evidence, client['client_id'], client['client_secret'],
                               *(value for value in gateway.client.private_values if value))
            finally:
                await target.aclose()


@pytest.mark.parametrize('verifier,detail', [('challenge', 'verifier_s256 matches the challenge for that code'),
                                            (None, 'without a PKCE verifier')])
def test_each_sentence_counts_only_matching_tokens_in_its_case(verifier, detail):
    evidence = captured()
    requests = evidence['cases'][1]['fixture']['requests']
    requests.append(record('issuer', 'authorize', {'codes_issued': {'by': 'issuer', 'corr': 'code-tag',
                                                                  'verifier_s256': 'challenge'}}))
    token = record('foreign', 'token', {'token': {'code': {'corr': 'code-tag'}, 'verifier_s256': verifier}})
    requests.extend(copy.deepcopy(token) for _ in range(16))
    requests.append(record('foreign', 'token', {'token': {'code': {'corr': 'unrelated'}, 'verifier_s256': verifier}}))
    second = copy.deepcopy(evidence['cases'][1])
    second['id'] = 'another_switch'
    second['fixture']['requests'] = copy.deepcopy(requests[:3] + [token])
    evidence['cases'].append(second)
    status, outcome = verdict(evidence, 'mirror_authorize')
    assert status == 'fail' and outcome.severity == 'high'
    sentence = f'H-issued code reached foreign token endpoint; {detail}'
    assert outcome.reason.count(sentence) == 2
    assert outcome.reason.count('(16 token requests)') == 1
    assert '(1 token requests)' not in outcome.reason
    assert len(evidence['summary']['upstream_as_binding']['cases'][1]['token']) == 17
    requests[:] = [r for r in requests if r['route'] != 'token']
    second['fixture']['requests'] = [r for r in second['fixture']['requests'] if r['route'] != 'token']
    assert verdict(evidence, 'mirror_authorize')[0] == 'pass'


@pytest.mark.parametrize('actor', ['gateway', 'argus_user_agent', 'unknown', 'browser', 'script'])
def test_foreign_code_correlation_uses_issuance_from_every_actor(actor):
    evidence = captured()
    requests = evidence['cases'][1]['fixture']['requests']
    issued = record('foreign', 'authorize', {'codes_issued': {'by': 'foreign', 'corr': 'foreign-code',
                                                            'verifier_s256': 'challenge'}}, actor=actor)
    requests.extend([issued, record('foreign', 'token', {'token': {'code': {'corr': 'foreign-code'},
                                                                 'verifier_s256': 'challenge'}})])
    assert verdict(evidence)[0] == 'pass'
    token, = evidence['summary']['upstream_as_binding']['cases'][1]['token']
    assert token['code_issued_by'] == token['verifier_matches_challenge_from'] == 'foreign'
    requests[-1]['ext']['oauth']['token']['verifier_s256'] = 'other'
    assert verdict(evidence)[0] == 'pass'
    token, = evidence['summary']['upstream_as_binding']['cases'][1]['token']
    assert token['code_issued_by'] == 'foreign' and token['verifier_matches_challenge_from'] is None
    requests.remove(issued)
    assert verdict(evidence)[0] == 'pass'
    token, = evidence['summary']['upstream_as_binding']['cases'][1]['token']
    assert token['code_issued_by'] is token['verifier_matches_challenge_from'] is None


@pytest.mark.parametrize('route,secret,severity,unit', [('token', True, 'high', 'token requests'),
    ('token', False, 'medium', 'token requests'), ('authorize', False, 'medium', 'requests')])
def test_credential_sentence_counts_requests_without_changing_severity(route, secret, severity, unit):
    evidence = captured()
    requests = evidence['cases'][1]['fixture']['requests']
    event = {route: {'client_id_hit': True, 'client_secret_hit': secret}}
    requests.extend(record('foreign', route, copy.deepcopy(event)) for _ in range(4))
    status, outcome = verdict(evidence)
    assert status == 'fail' and outcome.severity == severity
    assert outcome.reason.count('violates MCP 2026-07-28 Authorization Server Binding') == 1
    assert f'(4 {unit})' in outcome.reason
    requests[:] = [r for r in requests if r['route'] != route]
    assert verdict(evidence)[0] == 'pass'
