"""Offline gateway adapter boundaries and nonce-correlated evidence."""
import json
import secrets
from types import SimpleNamespace

import httpx
import pytest
from click.testing import CliRunner

from argus.cli.cmd_gateway_fixtures import cmd_gateway_fixtures
from argus.cli.target_loader import TargetLoadError, check_target_spec, load_target_spec
from argus.gateway_fixtures.host import FixtureHost
from argus.gateway_fixtures.install import create_install, entry_url, write_install
from argus.runner import _send_failure
from argus.targets import build_target, kinds
from argus.targets._base import ProbeNotApplicable, TargetTransportError
from argus.targets.mcp_gateway import MCPGatewaySpec
from tests.fixtures.gateway_ref import Entry, Preset, ReferenceGateway


def recipe(**changes):
    return {'version': 1, 'requires': [], 'entries': ['plain', 'hdr'],
            'cases': [{'id': 'first', 'role': 'control', 'entry': 'plain', 'upstream': {}},
                      {'id': 'second', 'role': 'attack', 'entry': 'hdr', 'upstream': {}}],
            'drive': {'tool': 'echo', 'calls_per_case': 2}, **changes}


def probe(payload=None):
    return SimpleNamespace(id='gateway-test', scenario_payload=json.dumps(recipe() if payload is None else payload))


def spec():
    return {'kind': 'mcp_gateway', 'sandbox': True, 'gateway': {'url': 'http://127.0.0.1:1/mcp'},
            'fixtures': {'control_url': 'http://127.0.0.1:2', 'control_token': 'canary', 'install_file': 'install.json'}}


@pytest.fixture
async def host(tmp_path):
    install = create_install(origins={
        'upstream': {'public': 'http://127.0.0.1:8471', 'listen': '127.0.0.1:0', 'host': '127.0.0.1'},
        'foreign': {'public': 'http://127.0.0.2:8473', 'listen': '127.0.0.2:0', 'host': '127.0.0.2'}})
    async with FixtureHost(install, control_token=secrets.token_hex(16), control_bind='127.0.0.1:0', settle_s=0.001) as fixture:
        for origin, url in fixture.origin_urls.items():
            fixture.install['origins'][origin]['public'] = url
        path = tmp_path / 'install.json'
        write_install(path, fixture.install)
        yield fixture, path


def target_spec(host, gateway):
    fixture, path = host
    return {**spec(), 'gateway': {'url': gateway.url}, 'timeout_s': 2,
            'features': {'upstream_headers': {'names': ['X-API-Key', 'Authorization']}},
            'fixtures': {'control_url': fixture.control_url, 'control_token': fixture.control_token, 'install_file': str(path)}}


def entries(host, *, drop_header=False):
    fixture, _ = host
    return {name: Entry(entry_url(fixture.install, name), {} if drop_header else entry.get('headers', {}))
            for name, entry in fixture.install['entries'].items()}


@pytest.mark.parametrize('era', ['auto', '2025-11-25', '2025-06-18'])
async def test_mangled_discovery_nonces_and_count(host, era):
    async with ReferenceGateway(entries(host), preset=Preset.safe()) as gateway:
        settings = target_spec(host, gateway)
        settings['gateway']['protocol'] = era
        target = build_target(settings)
        try:
            await target.begin_probe(probe())
            text, _ = await target.send_prompt('this must never reach an upstream')
            evidence = await target.collect_evidence()
            assert json.loads(text) == evidence
            assert evidence['era'] == ('2025-11-25' if era == 'auto' else era)
            assert len(evidence['cases']) == 2
            nonces = []
            for case, entry in zip(evidence['cases'], ('plain', 'hdr')):
                assert case['complete'] and case['dropped'] == 0
                calls = case['client']['calls']
                assert len(calls) == 2 and {call['reply'] for call in calls} == {'result'}
                nonce = calls[0]['nonce']
                nonces.append(nonce)
                records = case['fixture']['requests']
                assert len(records) == 2
                assert all(r['entry'] == entry and r['body']['jsonrpc']['nonce'] == nonce for r in records)
            assert nonces[0] != nonces[1]
            assert evidence['interaction_count'] == 3 + 4 + 4
            assert host[0].lease_id is None and host[0].case is None
            await target.send_prompt('repeat')
            assert await target.collect_evidence() == evidence
            for value in [host[0].control_token, host[0].install['path_token'], *host[0]._canaries.values()]:
                assert value not in text
        finally:
            await target.aclose()


@pytest.mark.parametrize('field,value,match', [
    ('sandbox', None, 'sandbox: true|missing required fields.*sandbox'), ('features', {'unknown': {}}, 'unknown fixture feature'),
    ('gateway', {'url': 'http://127.0.0.1', 'protcol': 'auto'}, "unknown field 'protcol'.*Did you mean 'protocol'"),
    ('gateway', {'url': 'http://127.0.0.1', 'auth': {'token': 'a'}}, "unknown field 'token'"),
    ('registration', {'mode': 'hook'}, 'hook is reserved'), ('timeout_s', float('nan'), 'finite'),
])
def test_spec_validation(field, value, match):
    settings = spec()
    if value is None:
        settings.pop(field)
    else:
        settings[field] = value
    with pytest.raises(TargetLoadError, match=match):
        check_target_spec(settings)
    with pytest.raises(ValueError, match=match):
        MCPGatewaySpec(**settings)


def test_masked_env_unset_and_relative_install(monkeypatch, tmp_path):
    settings = spec()
    token = secrets.token_hex(24)
    settings['gateway']['auth'] = {'headers': {'Authorization': 'Bearer ${GW_CANARY}'}, 'cookies': {'session': '${GW_CANARY}'}}
    settings['fixtures']['control_token'] = '${FIXTURE_CANARY}'
    monkeypatch.setenv('GW_CANARY', token)
    monkeypatch.setenv('FIXTURE_CANARY', token + 'f')
    loaded, masked = check_target_spec(settings)
    assert loaded['gateway']['auth']['headers']['Authorization'] == 'Bearer ' + token
    assert masked == [token, token + 'f']
    monkeypatch.delenv('GW_CANARY')
    with pytest.raises(TargetLoadError, match="target.gateway.auth.headers.Authorization references environment variable 'GW_CANARY', which is not set"):
        check_target_spec(settings)
    path = tmp_path / 'target.json'
    path.write_text(json.dumps(spec()))
    assert load_target_spec(str(path))['fixtures']['install_file'] == str(tmp_path / 'install.json')
    assert kinds()['mcp_gateway'].sandbox_reason


@pytest.mark.parametrize('payload', ['{', '[]', '{"version": true}', json.dumps(recipe(drive={'tool': 'echo', 'calls_per_case': 0})), json.dumps(recipe(cases=[{'id': 'x', 'role': 'control', 'entry': 'plain', 'upstream': {'unknown': {}}}]))])
async def test_malformed_refused_before_teardown(payload):
    target = build_target(spec())
    target._lease_id = 'existing'
    try:
        with pytest.raises(ValueError):
            await target.begin_probe(SimpleNamespace(id='bad', scenario_payload=payload))
        assert target._lease_id == 'existing'
    finally:
        target._lease_id = None
        await target.aclose()


async def test_missing_entry_skips_and_releases(host):
    async with ReferenceGateway({'plain': entries(host)['plain']}) as gateway:
        target = build_target(target_spec(host, gateway))
        try:
            await target.begin_probe(probe())
            with pytest.raises(ProbeNotApplicable, match='entry not registered'):
                await target.send_prompt('')
            assert host[0].lease_id is None
        finally:
            await target.aclose()


async def test_gateway_401_is_error(host, monkeypatch):
    async with ReferenceGateway(entries(host)) as gateway:
        target = build_target(target_spec(host, gateway))
        from argus.targets import _gateway_client
        original = _gateway_client.target_client
        def unauthorized(*args, **kwargs):
            return original(*args, **kwargs, transport=httpx.MockTransport(lambda request: httpx.Response(401)))
        monkeypatch.setattr(_gateway_client, 'target_client', unauthorized)
        try:
            await target.begin_probe(probe())
            with pytest.raises(TargetTransportError) as raised:
                await target.send_prompt('')
            assert _send_failure(raised.value)[0] == 'error'
            assert host[0].lease_id is None
        finally:
            await target.aclose()


@pytest.mark.parametrize('drop_header', [False, True])
async def test_check_header_canary_mutation(host, drop_header):
    async with ReferenceGateway(entries(host, drop_header=drop_header)) as gateway:
        settings = target_spec(host, gateway)
        target = build_target(settings)
        try:
            messages = await target.check_registration()
            assert bool(messages) == drop_header
            if drop_header:
                assert 'entry hdr: X-API-Key canary never arrived' in messages
                assert 'entry hdr: Authorization canary never arrived' in messages
            # The CLI runs on its own event loop while the loopback services stay live.
            import asyncio
            result = await asyncio.to_thread(CliRunner().invoke, cmd_gateway_fixtures, ['check', '--target', json.dumps(settings)])
            assert result.exit_code == int(drop_header)
            assert ('canary never arrived' if drop_header else 'registration verified') in result.output
        finally:
            await target.aclose()


async def test_check_ignores_historical_canary_contacts(host):
    async with ReferenceGateway(entries(host)) as gateway:
        target = build_target(target_spec(host, gateway))
        try:
            assert await target.check_registration() == []
            assert 'upstream_header:X-API-Key' in host[0].seen['hdr']['hits']
            gateway.entries['hdr'] = Entry(gateway.entries['hdr'].url)
            assert 'entry hdr: X-API-Key canary never arrived' in await target.check_registration()
        finally:
            await target.aclose()


@pytest.mark.parametrize('passthrough', [False, True])
async def test_secret_watch_hmac_and_masked_evidence(host, passthrough):
    from dataclasses import replace
    token = 'argus-client-auth-' + secrets.token_hex(24)
    cookie = 'argus-client-cookie-' + secrets.token_hex(24)
    async with ReferenceGateway(entries(host), preset=replace(Preset.safe(), passthrough=passthrough)) as gateway:
        settings = target_spec(host, gateway)
        settings['gateway']['auth'] = {'headers': {'Authorization': 'Bearer ' + token}, 'cookies': {'session': cookie}}
        target = build_target(settings)
        control = target._control
        async def checked_control(method, path, **kwargs):
            if path == '/cases':
                assert token not in json.dumps(kwargs['json']) and cookie not in json.dumps(kwargs['json'])
                assert len(kwargs['json']['watch']['secrets']['cookie:session']) == 64
            return await control(method, path, **kwargs)
        target._control = checked_control
        try:
            await target.begin_probe(probe(recipe(drive={'tool': 'echo', 'calls_per_case': 1, 'client_canaries': True})))
            text, _ = await target.send_prompt('')
            evidence = await target.collect_evidence()
            hits = {hit for case in evidence['cases'] for record in case['fixture']['requests'] for hit in record['hits']}
            assert ('auth_header:Authorization' in hits) == passthrough
            assert ('auth_header:Authorization:payload' in hits) == passthrough
            assert ('cookie:session' in hits) == passthrough
            import base64
            from urllib.parse import quote, quote_plus
            for value in (token, cookie, *host[0]._canaries.values()):
                assert all(encoded not in text for encoded in (value, quote(value, safe=''), quote_plus(value), base64.b64encode(value.encode()).decode()))
        finally:
            await target.aclose()


async def test_background_requests_do_not_acquire_the_case_nonce(host, monkeypatch):
    from argus.targets._gateway_client import GatewayClient
    original = GatewayClient.call
    async def with_background(self, *args, **kwargs):
        async with httpx.AsyncClient(trust_env=False) as client:
            response = await client.post(self.gateway['url'], json={'jsonrpc': '2.0', 'id': 500, 'method': 'tools/call',
                'params': {'name': self.tools[(args[1], args[2])], 'arguments': {'nonce': 'unrelated-health-call'}}})
            assert response.status_code == 200
        return await original(self, *args, **kwargs)
    monkeypatch.setattr(GatewayClient, 'call', with_background)
    async with ReferenceGateway(entries(host)) as gateway:
        target = build_target(target_spec(host, gateway))
        try:
            await target.begin_probe(probe())
            await target.send_prompt('')
            evidence = await target.collect_evidence()
            assert evidence['interaction_count'] == 15
            for case in evidence['cases']:
                nonce = case['client']['calls'][0]['nonce']
                records = case['fixture']['requests']
                assert len(records) == 4
                assert sum(r['body']['jsonrpc'].get('nonce') == nonce for r in records) == 2
                assert sum('nonce' not in r['body']['jsonrpc'] for r in records) == 2
        finally:
            await target.aclose()


def test_gateway_initializer_writes_loadable_spec(tmp_path):
    from argus.cli.cmd_init import init_command
    settings = spec()
    path = tmp_path / 'target.json'
    result = CliRunner().invoke(init_command, ['--kind', 'mcp_gateway', '--no-workflow', '--output', str(path),
        '--set', 'gateway_json=' + json.dumps(settings['gateway']), '--set', 'fixtures_json=' + json.dumps(settings['fixtures'])])
    assert result.exit_code == 0, result.output
    loaded = load_target_spec(str(path))
    assert loaded['sandbox'] is True and loaded['gateway'] == settings['gateway']


def test_gateway_url_env_expands_before_validation(monkeypatch):
    settings = spec()
    settings['gateway']['url'] = '${GW_URL}'
    monkeypatch.setenv('GW_URL', 'http://127.0.0.1:3000/mcp')
    assert check_target_spec(settings)[0]['gateway']['url'] == 'http://127.0.0.1:3000/mcp'
    monkeypatch.setenv('GW_URL', 'file:///invalid')
    with pytest.raises(TargetLoadError, match='gateway.url must be an HTTP'):
        check_target_spec(settings)


async def test_discovery_uses_marker_and_paginated_opaque_names(monkeypatch):
    from argus.targets import _gateway_client
    observed = []
    def handle(request):
        message = json.loads(request.content)
        observed.append(message)
        if message['method'] == 'tools/list':
            cursor = message['params'].get('cursor')
            result = {'tools': [{'name': 'opaque-tool-two' if cursor else 'opaque-tool-one',
                                 'description': 'argus-fixture:fx-test:hdr echo' if cursor else 'argus-fixture:fx-test:plain echo'}]}
            if not cursor:
                result['nextCursor'] = 'page-2'
        else:
            result = {'content': [{'type': 'text', 'text': 'ok'}]}
        return httpx.Response(200, json={'jsonrpc': '2.0', 'id': message['id'], 'result': result})
    original = _gateway_client.target_client
    monkeypatch.setattr(_gateway_client, 'target_client', lambda *a, **kw: original(*a, **kw, transport=httpx.MockTransport(handle)))
    client = _gateway_client.GatewayClient({'url': 'http://127.0.0.1:1', 'protocol': '2025-11-25'}, 1)
    try:
        await client.discover('fx-test')
        assert client.tools == {('plain', 'echo'): 'opaque-tool-one', ('hdr', 'echo'): 'opaque-tool-two'}
        call = await client.call('fx-test', 'hdr', 'echo', 'case-nonce')
        assert call['reply'] == 'result' and call['nonce'] == 'case-nonce'
        assert observed[-1]['params']['name'] == 'opaque-tool-two'
        await client.discover('fx-other')
        assert client.tools == {}
    finally:
        await client.aclose()


async def test_reply_id_mismatch_is_refused(monkeypatch):
    from argus.targets import _gateway_client
    original = _gateway_client.target_client
    monkeypatch.setattr(_gateway_client, 'target_client', lambda *a, **kw: original(*a, **kw,
        transport=httpx.MockTransport(lambda r: httpx.Response(200, json={'jsonrpc': '2.0', 'id': 999, 'result': {}}))))
    client = _gateway_client.GatewayClient({'url': 'http://127.0.0.1:1', 'protocol': '2025-11-25'}, 1)
    try:
        with pytest.raises(TargetTransportError, match='malformed MCP response'):
            await client.rpc('tools/list')
    finally:
        await client.aclose()


async def test_prefix_discovery_fallback(host):
    async with ReferenceGateway(entries(host)) as gateway:
        settings = target_spec(host, gateway)
        settings['gateway']['tools'] = {'match': 'prefix', 'prefix': ''}
        target = build_target(settings)
        try:
            await target.begin_probe(probe())
            await target.send_prompt('')
            assert (await target.collect_evidence())['interaction_count'] == 11
        finally:
            await target.aclose()


async def test_unknown_tool_triggers_one_rediscovery(monkeypatch):
    from argus.targets import _gateway_client
    requests = []
    def handle(request):
        message = json.loads(request.content)
        requests.append(message)
        if message['method'] == 'tools/list':
            body = {'result': {'tools': [{'name': 'new-name', 'description': 'argus-fixture:fx-test:plain echo'}]}}
        elif len(requests) == 1:
            body = {'error': {'code': -32602, 'message': 'Unknown tool'}}
        else:
            body = {'result': {'content': []}}
        return httpx.Response(200, json={'jsonrpc': '2.0', 'id': message['id'], **body})
    original = _gateway_client.target_client
    monkeypatch.setattr(_gateway_client, 'target_client', lambda *a, **kw: original(*a, **kw, transport=httpx.MockTransport(handle)))
    client = _gateway_client.GatewayClient({'url': 'http://127.0.0.1:1', 'protocol': '2025-11-25'}, 1)
    client.tools = {('plain', 'echo'): 'old-name'}
    try:
        assert (await client.call('fx-test', 'plain', 'echo', 'case-nonce'))['reply'] == 'result'
        assert [request['method'] for request in requests] == ['tools/call', 'tools/list', 'tools/call']
        assert [request['params']['name'] for request in requests if request['method'] == 'tools/call'] == ['old-name', 'new-name']
    finally:
        await client.aclose()


async def test_paginated_discovery_stops_at_cap(monkeypatch):
    from argus.targets import _gateway_client
    original = _gateway_client.target_client
    def handle(request):
        message = json.loads(request.content)
        return httpx.Response(200, json={'jsonrpc': '2.0', 'id': message['id'], 'result': {'tools': [], 'nextCursor': 'again'}})
    monkeypatch.setattr(_gateway_client, 'target_client', lambda *a, **kw: original(*a, **kw, transport=httpx.MockTransport(handle)))
    client = _gateway_client.GatewayClient({'url': 'http://127.0.0.1:1', 'protocol': '2025-11-25'}, 1)
    try:
        with pytest.raises(TargetTransportError, match='page limit'):
            await client.discover('fx-test')
        assert client.exchanges == 20
    finally:
        await client.aclose()


async def test_gateway_respects_public_address_policy_and_releases(host, monkeypatch):
    from argus_transport.address_policy import TargetAddressPolicyError
    async with ReferenceGateway(entries(host)) as gateway:
        settings = target_spec(host, gateway)
        monkeypatch.setenv('ARGUS_TARGET_ADDRESS_POLICY', 'public_only')
        target = build_target(settings)
        try:
            await target.begin_probe(probe())
            with pytest.raises(TargetAddressPolicyError):
                await target.send_prompt('')
            assert host[0].lease_id is None
            assert host[0].seen['plain']['first'] is None
        finally:
            await target.aclose()


def test_gateway_plugin_feature_is_validated(monkeypatch):
    from argus.gateway_fixtures.registry import Registry
    from argus.targets import mcp_gateway
    registry = Registry()
    def validate(value):
        if value != {'mode': 'observe'}:
            raise ValueError('neutral feature requires observe mode')
    registry.add_feature('neutral', validate)
    monkeypatch.setattr(mcp_gateway, 'load_registry', lambda: registry)
    settings = spec()
    settings['features'] = {'neutral': {'mode': 'observe'}}
    assert check_target_spec(settings)[0]['features'] == settings['features']
    settings['features']['neutral']['mode'] = 'other'
    with pytest.raises(TargetLoadError, match='observe mode'):
        check_target_spec(settings)
