"""Offline configured-header redirect verdicts and causal mutations."""
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
import base64
import json
import secrets
import socket
from types import SimpleNamespace
from urllib.parse import quote, quote_plus

import pytest

from argus.assertions import evaluate_assertions
from argus.gateway_fixtures.host import FixtureHost
from argus.gateway_fixtures.install import create_install, write_install
from argus.gateway_fixtures.redirect import redirect
from argus.gateway_redirect_assertions import check
from argus.probe import load_probe
from argus.targets import build_target
from argus.targets._base import ProbeNotApplicable
from tests.fixtures.gateway_ref import Entry, Preset, ReferenceGateway
from tests.gateway_target.test_target import host, entries, target_spec

PROBE_PATH = Path(__file__).resolve().parents[2] / 'argus/probes/mcp_gateway/mcp_gateway_header_cross_origin_redirect.yaml'


async def run(host, preset, *, drop_headers=False, names=None, persist=False):
    async with ReferenceGateway(entries(host, drop_header=drop_headers), preset=preset, persist_redirects=persist) as gateway:
        settings = target_spec(host, gateway)
        if names is not None:
            settings['features']['upstream_headers']['names'] = names
        target = build_target(settings)
        try:
            await target.begin_probe(load_probe(PROBE_PATH))
            await target.send_prompt('')
            evidence = await target.collect_evidence()
            result = evaluate_assertions(({'gateway_upstream_header_redirect': {}},), evidence, '')[0]
            assert not result.definition_error
            return evidence, check({}, evidence)
        finally:
            await target.aclose()


@pytest.mark.parametrize('base', [Preset.safe(), Preset.vulnerable()])
async def test_header_strategy_flips_verdict_and_authorization_is_observed(host, base):
    for redirects, expected in [('keep', 'fail'), ('drop', 'pass')]:
        evidence, outcome = await run(host, replace(base, redirects=redirects))
        assert outcome.verdict == expected
        summary = evidence['summary']['upstream_header_redirect']
        attacks = [case for case in summary['cases'] if case['id'].startswith('cross_origin')]
        assert {case['redirect']['status'] for case in attacks} == {307, 308}
        assert all(case['followed'] and case['foreign_requests'] == 1 for case in attacks)
        # This is the observed httpx policy on distinct loopback hosts.
        assert all(case['authorization_at_foreign'] is False for case in attacks)
        assert all(bool(case['hits_at_foreign']) == (redirects == 'keep') for case in attacks)
        assert summary['subsequent_upstream_contact'] is True
        if expected == 'fail':
            assert outcome.severity == 'high' and 'X-API-Key' in outcome.reason
            mutated = deepcopy(evidence)
            for case in mutated['cases']:
                if case['role'] == 'attack':
                    for record in case['fixture']['requests']:
                        if record['origin'] == 'foreign':
                            record['hits'] = []
            assert check({}, mutated).verdict == 'pass'
        serialized = json.dumps(evidence)
        for secret in [host[0].control_token, host[0].install['path_token'], *host[0]._canaries.values()]:
            for encoded in [secret, quote(secret), quote_plus(secret), base64.b64encode(secret.encode()).decode(), base64.urlsafe_b64encode(secret.encode()).decode()]:
                assert encoded not in serialized


async def test_no_follow_pass(host):
    evidence, outcome = await run(host, replace(Preset.safe(), redirects='no_follow'))
    assert outcome.verdict == 'pass'
    assert 'followed: false' in outcome.reason
    assert all(not case['followed'] for case in evidence['summary']['upstream_header_redirect']['cases'])


async def test_unconfigured_header_skips(host):
    _, outcome = await run(host, Preset.vulnerable(), drop_headers=True)
    assert outcome.verdict == 'skipped' and 'configured header never reached' in outcome.reason
    _, outcome = await run(host, Preset.vulnerable(), names=['X-Unconfigured'])
    assert outcome.verdict == 'skipped'
    async with ReferenceGateway(entries(host)) as gateway:
        settings = target_spec(host, gateway)
        settings['features'] = {}
        target = build_target(settings)
        try:
            with pytest.raises(ProbeNotApplicable, match='upstream_headers'):
                await target.begin_probe(load_probe(PROBE_PATH))
        finally:
            await target.aclose()


async def test_port_only_origins_skip(tmp_path):
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        foreign_port = listener.getsockname()[1]
    install = create_install(origins={
        'upstream': {'public': 'http://127.0.0.1:8471', 'listen': '127.0.0.1:0', 'host': '127.0.0.1'},
        'foreign': {'public': f'http://127.0.0.1:{foreign_port}', 'listen': f'127.0.0.1:{foreign_port}', 'host': '127.0.0.1'}})
    async with FixtureHost(install, control_token=secrets.token_hex(16), control_bind='127.0.0.1:0', settle_s=0.001) as fixture:
        for origin, url in fixture.origin_urls.items():
            fixture.install['origins'][origin]['public'] = url
        path = tmp_path / 'ports-install.json'
        write_install(path, fixture.install)
        evidence, outcome = await run((fixture, path), Preset.safe())
        assert evidence['origins']['foreign']['host_id'] == evidence['origins']['upstream']['host_id']
        assert outcome.verdict == 'skipped'


@pytest.mark.parametrize('persist', [False, True])
async def test_permanent_redirect_recontact_warns(host, persist):
    evidence, outcome = await run(host, Preset.safe(), persist=persist)
    assert outcome.verdict == ('warn' if persist else 'pass')
    summary = evidence['summary']['upstream_header_redirect']
    assert summary['subsequent_upstream_contact'] is not persist
    assert bool(summary['warnings']) == persist
    if persist:
        assert 're-register' in outcome.reason


async def test_authorization_not_configured_and_background_records(host):
    evidence, outcome = await run(host, Preset.vulnerable(), names=['X-API-Key'])
    assert outcome.verdict == 'fail'
    assert all(case['authorization_at_foreign'] == 'not_configured' for case in evidence['summary']['upstream_header_redirect']['cases'])
    safe, _ = await run(host, Preset.safe())
    record = deepcopy(safe['cases'][2]['fixture']['requests'][-1])
    record['hits'] = ['upstream_header:X-API-Key']
    record['body']['jsonrpc']['nonce'] = 'background'
    safe['cases'][2]['fixture']['requests'].append(record)
    assert check({}, safe).verdict == 'pass'


async def test_control_and_completeness_gates(host):
    evidence, _ = await run(host, Preset.safe())
    for case_id in ['direct', 'same_origin_307']:
        mutated = deepcopy(evidence)
        next(case for case in mutated['cases'] if case['id'] == case_id)['fixture']['requests'] = []
        assert check({}, mutated).verdict == 'skipped'
    evidence['cases'][2]['complete'] = False
    assert check({}, evidence).verdict == 'error'
    evidence['cases'][2]['fixture']['requests'][-1]['hits'] = ['upstream_header:X-API-Key']
    assert check({}, evidence).verdict == 'fail'


@pytest.mark.parametrize('config', [None, {}, {'status': True, 'to': 'foreign', 'on': 'tools/call'},
    {'status': 302, 'to': 'foreign', 'on': 'tools/call'}, {'status': 307, 'to': 'http://127.0.0.1', 'on': 'tools/call'},
    {'status': 307, 'to': 'foreign', 'on': 'initialize'}, {'status': 307, 'to': 'foreign', 'on': 'tools/call', 'extra': 1}])
def test_redirect_configuration_fails_closed(config):
    with pytest.raises(ValueError):
        redirect(config)


async def test_redirect_only_applies_to_active_nonce(host):
    fixture, _ = host
    path = fixture.install['entries']['hdr']['path'].replace('{path_token}', fixture.install['path_token'])
    context = SimpleNamespace(request=SimpleNamespace(path=path), install=fixture.install, route='mcp', entry='hdr',
                              nonce='active', ext={}, message={'method': 'tools/call', 'params': {'arguments': {'nonce': 'background'}}})
    handler = redirect({'status': 307, 'to': 'foreign', 'on': 'tools/call'})
    assert await handler(context) is None
    context.message['params']['arguments']['nonce'] = 'active'
    response = await handler(context)
    assert response.status == 307
    assert response.headers['Location'].startswith(fixture.origin_urls['foreign'])
