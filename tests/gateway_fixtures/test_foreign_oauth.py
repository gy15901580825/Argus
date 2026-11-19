"""Loopback OAuth issuer binding observations and fixed foreign responses."""
from __future__ import annotations

import base64
import hashlib
import secrets
from urllib.parse import parse_qs, urlsplit

import pytest

from argus.gateway_fixtures.oauth import discovery_paths, issuer_url
from argus.gateway_fixtures.registry import DefinitionError, load_registry
from tests.gateway_fixtures.test_host import seal, start_case
from tests.gateway_fixtures.test_oauth import (
    CHALLENGE, VERIFIER, assert_private, authorize, authorize_params, request, serving, token, token_params,
)


async def foreign_token(serving, **kwargs):
    host, _, _ = serving
    return await request(serving, 'foreign', urlsplit(issuer_url(host.install, 'foreign')).path + '/token',
                         method='POST', **kwargs)


@pytest.mark.parametrize('mode', ['own', 'mirror_authorize'])
@pytest.mark.parametrize('iss_mode', ['always', 'never'])
async def test_foreign_discovery_names_its_issuer_and_token_endpoint(serving, mode, iss_mode):
    host, client, auth = serving
    lease, seq = await start_case(host, client, auth,
        toggles={'foreign': {'as_mode': mode}, 'issuer': {'iss': iss_mode}})
    documents = [(await request(serving, 'foreign', path)).json() for path in discovery_paths(host.install)]
    assert documents[0] == documents[1] == documents[2]
    document = documents[0]
    assert document['issuer'] == issuer_url(host.install, 'foreign')
    assert document['token_endpoint'] == document['issuer'] + '/token'
    expected = issuer_url(host.install, 'issuer' if mode == 'mirror_authorize' else 'foreign')
    assert document['authorization_endpoint'] == expected + '/authorize'
    assert document['code_challenge_methods_supported'] == ['S256']
    assert document['authorization_response_iss_parameter_supported'] == (mode == 'mirror_authorize' and iss_mode == 'always')
    evidence = await seal(host, client, auth, seq)
    assert evidence['fixture']['state']['oauth']['foreign_as_mode'] == mode
    records = evidence['fixture']['requests']
    assert len(records) == 3
    assert all(record['origin'] == 'foreign' and record['route'] == 'as_metadata' for record in records)
    other_mode = 'mirror_authorize' if mode == 'own' else 'own'
    _, seq = await start_case(host, client, auth, lease=lease, case_id='changed',
                             toggles={'foreign': {'as_mode': other_mode}})
    changed = (await request(serving, 'foreign', discovery_paths(host.install)[0])).json()
    assert changed['authorization_endpoint'] != document['authorization_endpoint']
    assert changed['issuer'] == document['issuer'] and changed['token_endpoint'] == document['token_endpoint']
    await seal(host, client, auth, seq)
    assert (await request(serving, 'foreign', discovery_paths(host.install)[0])).json()['authorization_endpoint'] == document['issuer'] + '/authorize'


@pytest.mark.parametrize('iss_mode', ['always', 'never'])
@pytest.mark.parametrize('change,expected_code,expected_match', [
    ({}, True, True), ({'code': 'unknown'}, False, False),
    ({'code_verifier': VERIFIER[:-1] + ('X' if VERIFIER[-1] != 'X' else 'Y')}, True, False),
    ({'code_verifier': ''}, True, False), ({'code_verifier': 'non-ascii-\N{SNOWMAN}'}, True, False),
])
async def test_h_code_and_s256_are_bound_at_foreign_without_redemption(serving, iss_mode, change, expected_code, expected_match):
    host, client, auth = serving
    _, seq = await start_case(host, client, auth,
        toggles={'foreign': {'as_mode': 'mirror_authorize'}, 'issuer': {'iss': iss_mode}})
    response = await authorize(serving)
    values = parse_qs(urlsplit(response.headers['location']).query)
    code = values['code'][0]
    params = {**token_params(host, grant_type='authorization_code', code=code, code_verifier=VERIFIER,
                              redirect_uri=authorize_params(host)['redirect_uri']), **change}
    response = await foreign_token(serving, data=params)
    assert response.status_code == 400 and response.json() == {'error': 'invalid_grant'}
    evidence = await seal(host, client, auth, seq)
    state = evidence['fixture']['state']['oauth']
    issued, event = state['codes_issued'][0], state['token'][0]
    assert (issued['corr'] == event['code']['corr']) is expected_code
    assert event['code_issued_by'] == ('issuer' if expected_code else None)
    assert event['verifier_matches_challenge_from'] == ('issuer' if expected_match else None)
    assert (expected_code and event['verifier_s256'] == issued['verifier_s256']) is expected_match
    assert state['authorize'][0]['challenge']['verifier_s256'] == CHALLENGE
    assert issued['h_sent_iss'] == (iss_mode == 'always')
    assert event['actor'] == 'gateway'
    assert evidence['complete'] is True
    assert_private(evidence, code, VERIFIER, host.install['entries']['oauth']['client_secret'])
    assert_private(dict(response.headers), code, VERIFIER, host.install['entries']['oauth']['client_secret'])


@pytest.mark.parametrize('client_auth', ['client_secret_post', 'client_secret_basic'])
async def test_foreign_records_credentials_and_h_control_still_succeeds(serving, client_auth):
    host, client, auth = serving
    _, seq = await start_case(host, client, auth)
    params = token_params(host)
    headers = {}
    if client_auth == 'client_secret_basic':
        raw = params.pop('client_id') + ':' + params.pop('client_secret')
        headers['Authorization'] = 'Basic ' + base64.b64encode(raw.encode()).decode()
    assert (await foreign_token(serving, data=params, headers=headers)).json() == {'error': 'invalid_grant'}
    assert (await token(serving)).status_code == 200
    changed = token_params(host, client_id='changed', client_secret='changed')
    assert (await foreign_token(serving, data=changed)).json() == {'error': 'invalid_grant'}
    evidence = await seal(host, client, auth, seq)
    events = evidence['fixture']['state']['oauth']['token']
    assert events[0]['client_auth'] == client_auth
    assert events[0]['client_id_hit'] and events[0]['client_secret_hit']
    assert not events[2]['client_id_hit'] and not events[2]['client_secret_hit']
    assert evidence['fixture']['requests'][0]['hits'] == ['static_client_id', 'static_client_secret']
    assert_private(evidence, host.install['entries']['oauth']['client_secret'])


@pytest.mark.parametrize('kind', ['form', 'json', 'duplicate', 'malformed', 'get', 'put'])
async def test_foreign_token_always_fixed_error_even_malformed(serving, kind):
    host, client, auth = serving
    _, seq = await start_case(host, client, auth)
    canary = secrets.token_urlsafe(48)
    kwargs = {'data': token_params(host, code=canary, code_verifier=canary)}
    method = 'POST'
    if kind == 'json':
        kwargs = {'json': kwargs['data']}
    elif kind in ('duplicate', 'malformed'):
        kwargs = {'content': 'code=' + canary + ('&code=other' if kind == 'duplicate' else '&invalid'),
                  'headers': {'Content-Type': 'application/x-www-form-urlencoded'}}
    elif kind in ('get', 'put'):
        method = kind.upper()
    response = await request(serving, 'foreign', urlsplit(issuer_url(host.install, 'foreign')).path + '/token',
                             method=method, **kwargs)
    assert response.status_code == 400 and response.json() == {'error': 'invalid_grant'}
    assert 'location' not in response.headers
    assert response.headers['cache-control'] == 'no-store'
    assert_private(response.text, canary, host.install['entries']['oauth']['client_secret'])
    evidence = await seal(host, client, auth, seq)
    assert len(evidence['fixture']['requests']) == 1
    assert evidence['fixture']['requests'][0]['route'] == 'token'
    assert evidence['fixture']['state']['oauth']['token'][0]['at'] == 'foreign'
    assert_private(evidence, canary, host.install['entries']['oauth']['client_secret'])


async def test_own_authorize_records_but_never_echoes_or_issues_code(serving):
    host, client, auth = serving
    _, seq = await start_case(host, client, auth)
    params = authorize_params(host)
    response = await request(serving, 'foreign', urlsplit(issuer_url(host.install, 'foreign')).path + '/authorize', params=params)
    assert response.json() == {'error': 'invalid_grant'} and 'location' not in response.headers
    evidence = await seal(host, client, auth, seq)
    assert evidence['fixture']['state']['oauth']['authorize'][0]['client_id_hit']
    assert 'codes_issued' not in evidence['fixture']['state']['oauth']
    assert_private(evidence, params['state'])
    assert not host.oauth.codes and not host.oauth.tokens


async def test_foreign_correlation_is_case_scoped_and_preserves_h_code(serving):
    host, client, auth = serving
    lease, seq = await start_case(host, client, auth)
    code = parse_qs(urlsplit((await authorize(serving)).headers['location']).query)['code'][0]
    params = token_params(host, grant_type='authorization_code', code=code, code_verifier=VERIFIER,
                          redirect_uri=authorize_params(host)['redirect_uri'])
    assert (await foreign_token(serving, data=params)).json() == {'error': 'invalid_grant'}
    assert (await token(serving, **{key: value for key, value in params.items() if key not in ('client_id', 'client_secret', 'resource')})).status_code == 200
    evidence = await seal(host, client, auth, seq)
    first = evidence['fixture']['state']['oauth']['token'][0]
    assert first['code_issued_by'] == 'issuer'
    _, seq = await start_case(host, client, auth, lease=lease, case_id='next')
    await foreign_token(serving, data=params, headers={'X-Argus-Consent-Agent': 'case-nonce'})
    second = (await seal(host, client, auth, seq))['fixture']['state']['oauth']['token'][0]
    assert second['code']['corr'] != first['code']['corr']
    assert second['code_issued_by'] is None and second['verifier_matches_challenge_from'] is None
    assert second['actor'] == 'argus_user_agent'


async def test_s256_match_requires_challenge_bound_to_the_same_code(serving):
    host, client, auth = serving
    _, seq = await start_case(host, client, auth)
    first_code = parse_qs(urlsplit((await authorize(serving)).headers['location']).query)['code'][0]
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode('ascii')).digest()).decode().rstrip('=')
    second_code = parse_qs(urlsplit((await authorize(serving, code_challenge=challenge)).headers['location']).query)['code'][0]
    for code in (first_code, second_code):
        await foreign_token(serving, data=token_params(host, grant_type='authorization_code',
                                                      code=code, code_verifier=verifier))
    events = (await seal(host, client, auth, seq))['fixture']['state']['oauth']['token']
    assert events[0]['code_issued_by'] == events[1]['code_issued_by'] == 'issuer'
    assert events[0]['verifier_matches_challenge_from'] is None
    assert events[1]['verifier_matches_challenge_from'] == 'issuer'


async def test_generated_foreign_evidence_privacy_and_s256(serving):
    host, client, auth = serving
    lease = None
    for index in range(200):
        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode('ascii')).digest()).decode().rstrip('=')
        lease, seq = await start_case(host, client, auth, lease=lease, case_id=f'generated-{index}',
                                     toggles={'foreign': {'as_mode': 'mirror_authorize'}})
        code = parse_qs(urlsplit((await authorize(serving, code_challenge=challenge)).headers['location']).query)['code'][0]
        response = await foreign_token(serving, data=token_params(host, grant_type='authorization_code', code=code,
            code_verifier=verifier, extra=secrets.token_urlsafe(32)))
        assert response.json() == {'error': 'invalid_grant'}
        evidence = await seal(host, client, auth, seq)
        event = evidence['fixture']['state']['oauth']['token'][0]
        assert event['verifier_s256'] == challenge
        assert event['verifier_matches_challenge_from'] == 'issuer'
        assert_private(evidence, code, verifier, host.install['entries']['oauth']['client_secret'])


@pytest.mark.parametrize('mode', ['other', True, {}, ['own']])
def test_foreign_mode_fails_closed(mode):
    with pytest.raises(DefinitionError):
        load_registry(oauth=True).build_behaviors({'foreign': {'as_mode': mode}})
