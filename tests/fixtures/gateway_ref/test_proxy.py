"""Both presets and causal mutations, observed through P2's redacted evidence."""
from dataclasses import replace
import json
import secrets

import httpx
import pytest

from argus.gateway_fixtures.host import FixtureHost
from argus.gateway_fixtures.install import create_install, entry_url
from argus.gateway_fixtures.registry import Registry

from . import Entry, Preset, ReferenceGateway
from .support import behavior


@pytest.fixture
async def fixture_host():
    registry = Registry()
    for origin in ('upstream', 'foreign'):
        registry.add_behavior(origin, 'test_response', behavior)
    install = create_install(registry=registry, origins={
        'upstream': {'public': 'http://127.0.0.1:8471', 'listen': '127.0.0.1:0', 'host': '127.0.0.1'},
        'foreign': {'public': 'http://127.0.0.2:8473', 'listen': '127.0.0.2:0', 'host': '127.0.0.2'},
    })
    async with FixtureHost(install, registry=registry, control_token=secrets.token_hex(16), control_bind='127.0.0.1:0', settle_s=0.001) as host:
        for origin, url in host.origin_urls.items():
            host.install['origins'][origin]['public'] = url
        async with httpx.AsyncClient(trust_env=False, timeout=5) as client:
            auth = {'Authorization': 'Bearer ' + host.control_token}
            lease = (await client.post(host.control_url + '/v1/lease', headers=auth, json={'ttl_s': 120})).json()['lease_id']
            yield host, client, auth, lease


def entries(host):
    return {name: Entry(entry_url(host.install, name), data.get('headers', {})) for name, data in host.install['entries'].items()}


async def start(fixture_host, config=None, canaries=None):
    host, client, auth, lease = fixture_host
    nonce = secrets.token_hex(8)
    response = await client.post(host.control_url + '/v1/cases', headers=auth, json={
        'lease_id': lease, 'probe_id': 'reference-test', 'case_id': nonce, 'nonce': nonce,
        'toggles': {'upstream': {'test_response': config or {}}, 'foreign': {'test_response': {}}},
        'watch': {'canaries': {**host._canaries, **(canaries or {})}, 'secrets': {},
                  'watch_key': secrets.token_hex(32), 'case_key': secrets.token_hex(32)},
    })
    assert response.status_code == 200
    return nonce, response.json()['case_seq']


async def records(fixture_host, seq):
    host, client, auth, _ = fixture_host
    response = await client.post(f'{host.control_url}/v1/cases/{seq}/seal', headers=auth)
    assert response.status_code == 200
    evidence = response.json()
    assert evidence['complete'] and not evidence['dropped']
    encoded = json.dumps(evidence)
    assert all(value not in encoded for value in host._canaries.values())
    return evidence['fixture']['requests']


async def call(client, gateway, nonce, *, entry='plain', headers=None, receipt=None):
    arguments = {'nonce': nonce}
    if receipt is not None:
        arguments['receipt'] = receipt
    return await client.post(gateway.url, headers=headers, json={'jsonrpc': '2.0', 'id': 7, 'method': 'tools/call',
        'params': {'name': entry + '__argus_fixture_echo', 'arguments': arguments}})


@pytest.mark.parametrize('preset', [Preset.vulnerable(), Preset.safe()])
@pytest.mark.parametrize('era', ['2025-11-25', '2025-06-18'])
async def test_aggregate_and_calls(fixture_host, preset, era):
    host, client, *_ = fixture_host
    nonce, seq = await start(fixture_host)
    async with ReferenceGateway(entries(host), preset=preset) as gateway:
        initialized = await client.post(gateway.url, json={'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {'protocolVersion': era}})
        assert initialized.json()['result']['protocolVersion'] == era
        session = initialized.headers['Mcp-Session-Id']
        response = await client.post(gateway.url, json={'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list'})
        tools = response.json()['result']['tools']
        assert len(tools) == 4 and len({tool['name'] for tool in tools}) == 4
        for entry in ('plain', 'hdr'):
            assert any(f"argus-fixture:{host.install['install_label']}:{entry}" in tool['description'] for tool in tools)
            assert (await call(client, gateway, nonce, entry=entry, headers={'Mcp-Session-Id': session})).json()['result']['isError'] is False
    captured = await records(fixture_host, seq)
    assert {record['entry'] for record in captured if record['body'].get('jsonrpc', {}).get('nonce') == nonce} == {'plain', 'hdr'}
    assert 'upstream_header:X-API-Key' in captured[-1]['hits']


@pytest.mark.parametrize('preset', [Preset.vulnerable(), Preset.safe()])
@pytest.mark.parametrize('status', [307, 308])
async def test_redirect_mutation(fixture_host, preset, status):
    host, client, *_ = fixture_host
    foreign = host.origin_urls['foreign'] + '/x/' + host.install['path_token'] + '/hdr/mcp'
    observations = []
    for mode in ('keep', 'drop', 'no_follow'):
        nonce, seq = await start(fixture_host, {'redirect': foreign, 'redirect_status': status})
        async with ReferenceGateway(entries(host), preset=replace(preset, redirects=mode)) as gateway:
            await call(client, gateway, nonce, entry='hdr')
        captured = await records(fixture_host, seq)
        target = [record for record in captured if record['origin'] == 'foreign']
        observations.append(bool(target and 'upstream_header:X-API-Key' in target[0]['hits']))
        assert bool(target) == (mode != 'no_follow')
        if target:
            assert 'upstream_header:Authorization' not in target[0]['hits']
            assert target[0]['body']['len'] > 0
    assert observations == [True, False, False]


async def test_same_origin_redirect_retains_configured_headers(fixture_host):
    host, client, *_ = fixture_host
    destination = host.origin_urls['upstream'] + '/x/' + host.install['path_token'] + '/target'
    for preset in (Preset.vulnerable(), Preset.safe()):
        nonce, seq = await start(fixture_host, {'redirect': destination})
        async with ReferenceGateway(entries(host), preset=preset) as gateway:
            await call(client, gateway, nonce, entry='hdr')
        captured = await records(fixture_host, seq)
        assert len(captured) == 2
        assert set(captured[-1]['hits']) == set(host._canaries)


@pytest.mark.parametrize('preset', [Preset.vulnerable(), Preset.safe()])
async def test_passthrough_mutation(fixture_host, preset):
    host, client, *_ = fixture_host
    token, cookie = secrets.token_hex(24), secrets.token_hex(24)
    observed = []
    for enabled in (True, False):
        nonce, seq = await start(fixture_host, canaries={'client_auth': token, 'client_cookie': cookie})
        async with ReferenceGateway(entries(host), preset=replace(preset, passthrough=enabled)) as gateway:
            await call(client, gateway, nonce, headers={'Authorization': 'Bearer ' + token, 'Cookie': 'session=' + cookie})
        captured = await records(fixture_host, seq)
        observed.append(set(captured[0]['hits']))
        assert token not in json.dumps(captured) and cookie not in json.dumps(captured)
    assert observed == [{'client_auth', 'client_cookie'}, set()]


@pytest.mark.parametrize('preset', [Preset.vulnerable(), Preset.safe()])
@pytest.mark.parametrize('channel', ['post_json', 'post_final', 'post_notification', 'progress', 'get_sse', 'resumed_sse'])
async def test_filter_mutation_in_recorded_client_feedback(fixture_host, preset, channel):
    host, client, *_ = fixture_host
    marker = 'ARGUSFLT' + secrets.token_hex(10).upper()
    observations = []
    for mode in ('json_only', 'all_messages'):
        nonce, seq = await start(fixture_host, {'delivery': channel, 'marker': marker}, {'filter_marker': marker})
        async with ReferenceGateway({'plain': entries(host)['plain']}, preset=replace(preset, response_filter=mode)) as gateway:
            if channel in ('get_sse', 'resumed_sse'):
                response = await client.get(gateway.url, headers={'Last-Event-ID': 'plain:event-1'} if channel == 'resumed_sse' else {})
            else:
                response = await call(client, gateway, nonce)
            assert response.status_code == 200
            assert 'begin' in response.text and 'end' in response.text
            assert (marker in response.text) == (mode == 'json_only' and channel != 'post_json')
            await call(client, gateway, nonce, receipt=response.text)
        captured = await records(fixture_host, seq)
        feedback = [record for record in captured if record['body'].get('jsonrpc', {}).get('nonce') == nonce][-1]
        observations.append('filter_marker' in feedback['body']['hits'])
        assert marker not in json.dumps(captured)
    assert observations == ([False, False] if channel == 'post_json' else [True, False])


@pytest.mark.parametrize('preset', [Preset.vulnerable(), Preset.safe()])
@pytest.mark.parametrize('status,body', [(403, None), (200, {'decision': 'deny'}), (200, None), (200, {}), (204, None), (200, {'decision': 'allow'})])
async def test_webhook_mutation(fixture_host, preset, status, body):
    host, client, *_ = fixture_host
    observed = []
    for mode in ('status', 'decision'):
        nonce, seq = await start(fixture_host, {'hook_status': status, 'hook_body': body})
        hook = host.origin_urls['upstream'] + host.install['webhook']['path'].replace('{path_token}', host.install['path_token'])
        async with ReferenceGateway(entries(host), preset=replace(preset, webhook=mode), webhook_url=hook) as gateway:
            response = await call(client, gateway, nonce)
        captured = await records(fixture_host, seq)
        assert captured[0]['route'] == 'webhook' and captured[0]['response']['status'] == status
        received = any(record['route'] == 'mcp' and record['body'].get('jsonrpc', {}).get('nonce') == nonce for record in captured)
        observed.append(received)
        assert ('result' in response.json()) == received
    assert observed == [200 <= status < 300, status == 200 and body == {'decision': 'allow'}]


@pytest.mark.parametrize('url', ['http://192.0.2.1/mcp', 'http://10.0.0.1/mcp', 'http://localhost/mcp', 'http://example.test/mcp', 'file:///mcp', 'http://user:pass@127.0.0.1/mcp'])
def test_non_loopback_urls_refused(url):
    with pytest.raises(ValueError, match='loopback'):
        Entry(url)
    with pytest.raises(ValueError, match='loopback'):
        ReferenceGateway({'plain': Entry('http://127.0.0.1:1/mcp')}, webhook_url=url)


async def test_redirect_to_non_loopback_refused_before_connection(fixture_host):
    host, client, *_ = fixture_host
    for preset in (Preset.vulnerable(), Preset.safe()):
        nonce, seq = await start(fixture_host, {'redirect': 'http://192.0.2.1/mcp'})
        async with ReferenceGateway(entries(host), preset=preset) as gateway:
            assert 'error' in (await call(client, gateway, nonce)).json()
        assert len(await records(fixture_host, seq)) == 1


@pytest.mark.parametrize('preset', [Preset.vulnerable(), Preset.safe()])
async def test_resume_routes_event_id_and_stream_aggregation(fixture_host, preset):
    host, client, *_ = fixture_host
    marker = 'ARGUSFLT' + secrets.token_hex(10).upper()
    nonce, seq = await start(fixture_host, {'delivery': 'priming', 'marker': marker})
    async with ReferenceGateway(entries(host), preset=preset) as gateway:
        priming = await call(client, gateway, nonce, entry='hdr')
        assert 'id: hdr:event-1' in priming.text and 'retry: 100' in priming.text
        resumed = await client.get(gateway.url, headers={'Last-Event-ID': 'hdr:event-1'})
        assert ('[REDACTED]' in resumed.text) == (preset.response_filter == 'all_messages')
        streams = await client.get(gateway.url)
        assert 'id: plain:event-1' in streams.text and 'id: hdr:event-1' in streams.text
    captured = await records(fixture_host, seq)
    gets = [record for record in captured if record['method'] == 'GET']
    assert [record['entry'] for record in gets] == ['hdr', 'plain', 'hdr']
    assert {'name': 'last-event-id', 'value': 'event-1'} in gets[0]['headers']
    assert all(not any(header['name'] == 'last-event-id' for header in record['headers']) for record in gets[1:])


async def test_filter_off_control(fixture_host):
    host, client, *_ = fixture_host
    marker = 'ARGUSFLT' + secrets.token_hex(10).upper()
    nonce, seq = await start(fixture_host, {'delivery': 'post_json', 'marker': marker}, {'filter_marker': marker})
    async with ReferenceGateway(entries(host), preset=replace(Preset.safe(), response_filter='off')) as gateway:
        response = await call(client, gateway, nonce)
        assert marker in response.text
        await call(client, gateway, nonce, receipt=response.text)
    assert 'filter_marker' in (await records(fixture_host, seq))[-1]['hits']


async def test_webhook_documented_allow_contract(fixture_host):
    host, client, *_ = fixture_host
    contract = {'policy': 'permit'}
    nonce, seq = await start(fixture_host, {'hook_status': 201, 'hook_body': contract})
    hook = host.origin_urls['upstream'] + host.install['webhook']['path'].replace('{path_token}', host.install['path_token'])
    async with ReferenceGateway(entries(host), webhook_url=hook, allow_status=201, allow_body=contract) as gateway:
        assert 'result' in (await call(client, gateway, nonce)).json()
    assert (await records(fixture_host, seq))[-1]['route'] == 'mcp'


@pytest.mark.parametrize('preset', [Preset.vulnerable(), Preset.safe()])
async def test_modern_header_refused_for_legacy_fallback(fixture_host, preset):
    host, client, *_ = fixture_host
    _, seq = await start(fixture_host)
    async with ReferenceGateway(entries(host), preset=preset) as gateway:
        response = await client.post(gateway.url, headers={'MCP-Protocol-Version': '2026-07-28'},
                                     json={'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list'})
        assert response.status_code == 400 and response.text == 'Unsupported protocol version'
        initialized = await client.post(gateway.url, headers={'MCP-Protocol-Version': '2025-11-25'},
            json={'jsonrpc': '2.0', 'id': 2, 'method': 'initialize', 'params': {'protocolVersion': '2025-11-25'}})
        assert initialized.json()['result']['protocolVersion'] == '2025-11-25'
    captured = await records(fixture_host, seq)
    assert len(captured) == 2
    assert all(record['body']['jsonrpc']['method'] == 'initialize' for record in captured)
