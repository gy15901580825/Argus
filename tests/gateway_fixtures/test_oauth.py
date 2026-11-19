"""Scripted OAuth clients exercise loopback discovery, grants and evidence privacy."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import secrets
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx
import pytest
from click.testing import CliRunner

from argus.cli.__main__ import main
from argus.gateway_fixtures.host import FixtureHost
from argus.gateway_fixtures.install import create_install, entry_url, read_install
from argus.gateway_fixtures.oauth import discovery_paths, issuer_url, prm_paths
from argus.gateway_fixtures.registry import DefinitionError, load_registry
from tests.gateway_fixtures.test_host import seal, start_case
from tests.gateway_fixtures.test_record import encodings

VERIFIER = secrets.token_urlsafe(48)
CHALLENGE = base64.urlsafe_b64encode(hashlib.sha256(VERIFIER.encode('ascii')).digest()).decode().rstrip('=')


def installation():
    return create_install(registry=load_registry(oauth=True), origins={
        'upstream': {'public': 'http://127.0.0.1:8471', 'listen': '127.0.0.1:0', 'host': '127.0.0.1'},
        'foreign': {'public': 'http://127.0.0.2:8473', 'listen': '127.0.0.2:0', 'host': '127.0.0.2'},
        'issuer': {'public': 'http://127.0.0.3:8472', 'listen': '127.0.0.3:0', 'host': '127.0.0.3'},
    })


@pytest.fixture
async def serving():
    control = secrets.token_urlsafe(24)
    async with FixtureHost(installation(), control_token=control, control_bind='127.0.0.1:0', settle_s=0.001) as host:
        async with httpx.AsyncClient(trust_env=False, follow_redirects=False, timeout=3) as client:
            yield host, client, {'Authorization': 'Bearer ' + control}


async def request(serving, origin, path, *, method='GET', **kwargs):
    host, client, _ = serving
    headers = {'Host': urlsplit(host.install['origins'][origin]['public']).netloc, **kwargs.pop('headers', {})}
    return await client.request(method, host.origin_urls[origin] + path, headers=headers, **kwargs)


def token_params(host, **overrides):
    return {'grant_type': 'client_credentials', 'client_id': host.install['entries']['oauth']['client_id'],
            'client_secret': host.install['entries']['oauth']['client_secret'],
            'resource': entry_url(host.install, 'oauth'), **overrides}


def authorize_params(host, **overrides):
    return {'client_id': host.install['entries']['oauth']['client_id'], 'response_type': 'code',
            'redirect_uri': 'http://127.0.0.1:9000/callback?existing=ok', 'state': secrets.token_urlsafe(32),
            'resource': entry_url(host.install, 'oauth'), 'code_challenge_method': 'S256',
            'code_challenge': CHALLENGE, **overrides}


async def authorize(serving, **overrides):
    host, _, _ = serving
    return await request(serving, 'issuer', urlsplit(issuer_url(host.install)).path + '/authorize',
                         params=authorize_params(host, **overrides))


def authorization_error(response):
    if response.status_code == 302:
        return {'error': parse_qs(urlsplit(response.headers['location']).query)['error'][0]}
    return response.json()


async def token(serving, **overrides):
    host, _, _ = serving
    return await request(serving, 'issuer', urlsplit(issuer_url(host.install)).path + '/token',
                         method='POST', data=token_params(host, **overrides))


async def protected(serving, access_token=None):
    host, _, _ = serving
    headers = {'Authorization': 'Bearer ' + access_token} if access_token else {}
    return await request(serving, 'upstream', urlsplit(entry_url(host.install, 'oauth')).path, method='POST',
        headers=headers, json={'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
                               'params': {'name': 'argus_fixture_echo', 'arguments': {'nonce': 'case-nonce'}}})


def assert_private(evidence, *credentials):
    serialized = json.dumps(evidence)
    for credential in credentials:
        for variant in encodings(credential):
            assert variant not in serialized


async def test_discovery_every_well_known_form_and_recording(serving):
    host, client, auth = serving
    _, seq = await start_case(host, client, auth)
    challenge = await protected(serving)
    assert challenge.status_code == 401
    assert f'resource_metadata="{host.install["origins"]["upstream"]["public"] + prm_paths(host.install)[0]}"' in challenge.headers['www-authenticate']
    for path in prm_paths(host.install):
        response = await request(serving, 'upstream', path)
        assert response.status_code == 200
        assert response.json()['resource'] == entry_url(host.install, 'oauth')
        assert response.json()['authorization_servers'] == [issuer_url(host.install)]
    documents = [(await request(serving, 'issuer', path)).json() for path in discovery_paths(host.install)]
    assert documents[0] == documents[1] == documents[2]
    assert documents[0]['issuer'] == issuer_url(host.install)
    assert documents[0]['code_challenge_methods_supported'] == ['S256']
    assert documents[0]['grant_types_supported'] == ['client_credentials', 'authorization_code']
    assert documents[0]['authorization_response_iss_parameter_supported'] is True
    records = (await seal(host, client, auth, seq))['fixture']['requests']
    assert [record['route'] for record in records] == ['mcp', 'prm', 'prm', 'as_metadata', 'as_metadata', 'as_metadata']
    assert len({record['seq'] for record in records}) == 6
    assert all(record['entry'] == 'oauth' for record in records)
    assert host.install['path_token'] not in json.dumps(records)
    assert (await request(serving, 'upstream', '/.well-known/oauth-protected-resource/wrong')).status_code == 404
    assert (await request(serving, 'issuer', '/.well-known/oauth-authorization-server')).status_code == 404


@pytest.mark.parametrize('client_auth', ['client_secret_post', 'client_secret_basic'])
async def test_client_credentials_and_token_revocation_switch(serving, client_auth):
    host, client, auth = serving
    lease, seq = await start_case(host, client, auth)
    params = token_params(host)
    headers = {}
    if client_auth == 'client_secret_basic':
        credential = params.pop('client_id') + ':' + params.pop('client_secret')
        headers['Authorization'] = 'Basic ' + base64.b64encode(credential.encode()).decode()
    response = await request(serving, 'issuer', urlsplit(issuer_url(host.install)).path + '/token',
                             method='POST', data=params, headers=headers)
    assert response.status_code == 200
    access_token = response.json()['access_token']
    assert 'refresh_token' not in response.json()
    assert response.json()['expires_in'] == 60
    assert (await protected(serving, access_token)).status_code == 200
    evidence = await seal(host, client, auth, seq)
    event = evidence['fixture']['state']['oauth']['token'][0]
    assert event['client_auth'] == client_auth
    assert event['client_id_hit'] and event['client_secret_hit']
    assert event['resource']['matches_expected']
    assert evidence['fixture']['requests'][0]['hits'] == ['static_client_id', 'static_client_secret']
    assert_private(evidence, access_token, host.install['entries']['oauth']['client_secret'])
    _, seq = await start_case(host, client, auth, lease=lease, case_id='switch',
        toggles={'upstream': {'prm': {'authorization_servers': ['foreign']}, 'challenge': 'invalid_token'}})
    response = await protected(serving, access_token)
    assert response.status_code == 401 and 'error="invalid_token"' in response.headers['www-authenticate']
    for path in prm_paths(host.install):
        response = await request(serving, 'upstream', path)
        assert response.json()['authorization_servers'] == [issuer_url(host.install, 'foreign')]
    evidence = await seal(host, client, auth, seq)
    assert evidence['fixture']['state']['oauth']['prm_served'] == [{'as': 'foreign'}, {'as': 'foreign'}]
    assert not host.oauth.tokens
    assert (await request(serving, 'upstream', prm_paths(host.install)[0])).json()['authorization_servers'] == [issuer_url(host.install)]


@pytest.mark.parametrize('iss_mode', ['always', 'never'])
async def test_authorization_code_pkce_and_private_evidence(serving, iss_mode):
    host, client, auth = serving
    _, seq = await start_case(host, client, auth, toggles={'issuer': {'iss': iss_mode}})
    metadata = (await request(serving, 'issuer', discovery_paths(host.install)[0])).json()
    assert metadata['authorization_response_iss_parameter_supported'] == (iss_mode == 'always')
    response = await authorize(serving)
    assert response.status_code == 302
    callback = urlsplit(response.headers['location'])
    values = parse_qs(callback.query)
    assert values['existing'] == ['ok'] and 'state' in values
    assert values.get('iss') == ([issuer_url(host.install)] if iss_mode == 'always' else None)
    code = values['code'][0]
    redirect_uri = 'http://127.0.0.1:9000/callback?existing=ok'
    response = await token(serving, grant_type='authorization_code', code=code,
                           code_verifier=VERIFIER, redirect_uri=redirect_uri)
    assert response.status_code == 200
    access_token = response.json()['access_token']
    assert 'refresh_token' not in response.json()
    assert (await protected(serving, access_token)).status_code == 200
    replay = await token(serving, grant_type='authorization_code', code=code,
                         code_verifier=VERIFIER, redirect_uri=redirect_uri)
    assert replay.json() == {'error': 'invalid_grant'}
    evidence = await seal(host, client, auth, seq)
    assert evidence['complete'] is True
    state = evidence['fixture']['state']['oauth']
    authorize_event = state['authorize'][0]
    event = state['token'][0]
    assert authorize_event['challenge']['verifier_s256'] == CHALLENGE
    assert event['verifier_s256'] == CHALLENGE
    assert event['verifier_matches_challenge_from'] == 'issuer'
    assert state['codes_issued'][0]['corr'] == event['code']['corr']
    assert event['actor'] == 'gateway'
    assert state['codes_issued'][0]['h_sent_iss'] == (iss_mode == 'always')
    assert state['codes_issued'][0]['verifier_s256'] == CHALLENGE
    assert len(event['code']['corr']) == 16
    assert_private(evidence, code, VERIFIER, access_token, host.install['entries']['oauth']['client_secret'])
    assert host.oauth.codes == {}


@pytest.mark.parametrize('bad_resource', ['', 'http://127.0.0.1:8471/other', 'relative', 'https://resource.test/#fragment'])
async def test_resource_indicator_mismatch_recorded_at_both_endpoints(serving, bad_resource):
    host, client, auth = serving
    _, seq = await start_case(host, client, auth)
    assert authorization_error(await authorize(serving, resource=bad_resource)) == {'error': 'invalid_target'}
    assert (await token(serving, resource=bad_resource)).json() == {'error': 'invalid_target'}
    assert (await token(serving)).status_code == 200
    evidence = await seal(host, client, auth, seq)
    state = evidence['fixture']['state']['oauth']
    assert state['authorize'][0]['resource']['matches_expected'] is False
    assert state['token'][0]['resource']['matches_expected'] is False
    assert state['token'][1]['resource']['matches_expected'] is True
    assert state['authorize'][0]['resource']['corr'] == state['token'][0]['resource']['corr']
    if bad_resource:
        assert bad_resource not in json.dumps(evidence)


@pytest.mark.parametrize('change,error', [
    ({'client_id': 'unregistered'}, 'unauthorized_client'),
    ({'response_type': 'token'}, 'unsupported_response_type'),
    ({'code_challenge_method': 'plain'}, 'invalid_request'),
    ({'code_challenge': 'malformed'}, 'invalid_request'),
    ({'redirect_uri': 'http://127.0.0.1/callback#fragment'}, 'invalid_request'),
    ({'scope': 'other'}, 'invalid_scope'),
])
async def test_authorize_rejects_invalid_requests_then_control_succeeds(serving, change, error):
    assert authorization_error(await authorize(serving, **change)) == {'error': error}
    assert (await authorize(serving)).status_code == 302


async def test_callback_pins_only_after_success(serving):
    assert authorization_error(await authorize(serving, redirect_uri='http://127.0.0.1:9001/callback', response_type='token')) == {'error': 'unsupported_response_type'}
    assert (await authorize(serving)).status_code == 302
    assert (await authorize(serving, redirect_uri='http://127.0.0.1:9001/callback')).json() == {'error': 'invalid_request'}


@pytest.mark.parametrize('change,error', [
    ({'client_secret': 'changed'}, 'invalid_client'),
    ({'client_id': 'changed'}, 'invalid_client'),
    ({'grant_type': 'refresh_token'}, 'unsupported_grant_type'),
    ({'scope': 'other'}, 'invalid_scope'),
])
async def test_token_rejects_invalid_requests_then_control_succeeds(serving, change, error):
    assert (await token(serving, **change)).json() == {'error': error}
    assert (await token(serving)).status_code == 200


@pytest.mark.parametrize('change', [
    {'code_verifier': VERIFIER[:-1] + ('Y' if VERIFIER[-1] != 'Y' else 'X')}, {'code_verifier': ''},
    {'redirect_uri': 'http://127.0.0.1:9001/callback'}, {'code': 'unknown'},
])
async def test_code_redeeming_requires_pkce_code_and_exact_callback(serving, change):
    response = await authorize(serving)
    code = parse_qs(urlsplit(response.headers['location']).query)['code'][0]
    params = {'grant_type': 'authorization_code', 'code': code, 'code_verifier': VERIFIER,
              'redirect_uri': 'http://127.0.0.1:9000/callback?existing=ok', **change}
    assert (await token(serving, **params)).json() == {'error': 'invalid_grant'}
    response = await authorize(serving)
    params['code'] = parse_qs(urlsplit(response.headers['location']).query)['code'][0]
    params['code_verifier'] = VERIFIER
    params['redirect_uri'] = 'http://127.0.0.1:9000/callback?existing=ok'
    assert (await token(serving, **params)).status_code == 200


async def test_duplicate_parameters_media_type_methods_and_combined_auth(serving):
    host, _, _ = serving
    path = urlsplit(issuer_url(host.install)).path + '/token'
    params = token_params(host)
    body = urlencode(params) + '&resource=other'
    assert (await request(serving, 'issuer', path, method='POST', content=body,
        headers={'Content-Type': 'application/x-www-form-urlencoded'})).json() == {'error': 'invalid_request'}
    assert (await request(serving, 'issuer', path, method='POST', json=params)).json() == {'error': 'invalid_request'}
    assert (await request(serving, 'issuer', path)).status_code == 405
    assert (await request(serving, 'issuer', path, method='POST', data=params,
                         headers={'Authorization': 'Basic invalid'})).json() == {'error': 'invalid_request'}
    assert (await token(serving)).status_code == 200


async def test_codes_and_tokens_expire_and_runtime_closes(serving):
    host, _, _ = serving
    response = await authorize(serving)
    code = parse_qs(urlsplit(response.headers['location']).query)['code'][0]
    next(iter(host.oauth.codes.values())).expires = 0
    assert (await token(serving, grant_type='authorization_code', code=code, code_verifier=VERIFIER,
                        redirect_uri='http://127.0.0.1:9000/callback?existing=ok')).json() == {'error': 'invalid_grant'}
    access_token = (await token(serving)).json()['access_token']
    host.oauth.tokens[hashlib.sha256(access_token.encode()).digest()] = 0
    assert (await protected(serving, access_token)).status_code == 401
    assert (await token(serving)).status_code == 200
    host.oauth.close()
    assert not host.oauth.codes and not host.oauth.tokens and host.oauth.redirect_uri is None


def test_oauth_init_is_opt_in_and_stable(tmp_path):
    assert set(create_install()['origins']) == {'upstream', 'foreign'}
    install = create_install(oauth=True)
    assert set(install['origins']) == {'upstream', 'foreign', 'issuer'}
    path = tmp_path / 'install.json'
    runner = CliRunner()
    result = runner.invoke(main, ['gateway-fixtures', 'init', '--oauth', '--install-file', str(path)])
    assert result.exit_code == 0, result.output
    persisted = read_install(path)
    assert persisted['entries']['oauth']['client_id'] in result.output
    assert persisted['entries']['oauth']['client_secret'] in result.output
    assert runner.invoke(main, ['gateway-fixtures', 'sheet', '--install-file', str(path)]).exit_code == 0
    assert read_install(path) == persisted
    malformed = copy.deepcopy(install)
    malformed['entries']['oauth']['client_secret'] = 'not-an-install-canary'
    with pytest.raises(DefinitionError, match='canaries'):
        FixtureHost(malformed, control_token='generated-control')


@pytest.mark.parametrize('toggles', [
    {'issuer': {'iss': 'sometimes'}}, {'issuer': {'refresh_tokens': True}},
    {'upstream': {'prm': {'authorization_servers': ['unknown']}}},
    {'upstream': {'prm': {'authorization_servers': ['issuer'], 'extra': True}}},
    {'upstream': {'challenge': 'other'}},
])
def test_unknown_oauth_toggles_fail_closed(toggles):
    with pytest.raises(DefinitionError):
        load_registry(oauth=True).build_behaviors(toggles)


@pytest.mark.parametrize('iss_mode', ['always', 'never'])
async def test_authorization_error_redirect_preserves_state_and_iss(serving, iss_mode):
    host, client, auth = serving
    _, seq = await start_case(host, client, auth, toggles={'issuer': {'iss': iss_mode}})
    state = secrets.token_urlsafe(32)
    response = await authorize(serving, resource='https://resource.test/other', state=state)
    assert response.status_code == 302
    values = parse_qs(urlsplit(response.headers['location']).query)
    assert values['error'] == ['invalid_target']
    assert values['state'] == [state]
    assert values.get('iss') == ([issuer_url(host.install)] if iss_mode == 'always' else None)
    assert 'code' not in values
    assert host.oauth.redirect_uri is None
    evidence = await seal(host, client, auth, seq)
    assert not evidence['fixture']['state']['oauth'].get('codes_issued')
    assert_private(evidence, state)
