"""Modern and legacy counterparts share an endpoint without sharing a session."""
from copy import deepcopy
from dataclasses import replace
import json

import httpx
import pytest

from argus.gateway_filter_assertions import gateway_filter_delivery_path as check
from argus.gateway_fixtures.install import entry_url
from argus.targets._base import TargetTransportError
from argus.targets._gateway_client import GatewayClient
from tests.fixtures.gateway_ref import Preset, ReferenceGateway
from tests.gateway_target.test_target import host, entries
from tests.gateway_probes.test_filter import run, filter_recipe

MODERN = '2026-07-28'


@pytest.mark.parametrize('base', [Preset.safe(), Preset.vulnerable()])
async def test_modern_full_probe_mutation(host, base):
    for mode, expected in [('json_only', 'fail'), ('all_messages', 'pass'), ('off', 'skipped')]:
        evidence, outcome = await run(host, replace(base, response_filter=mode))
        assert evidence['era'] == MODERN
        assert outcome.verdict == expected
        paths = {p['path']: p for p in evidence['summary']['filter_delivery_paths']}
        for path in ('post_sse_resumed', 'get_stream_notification'):
            assert paths[path]['classification'] == 'absent'
            assert paths[path]['served_by_upstream'] is False
            assert paths[path]['client_channels'] == []
        mrtr = paths['mrtr_input_request']
        assert mrtr['served_by_upstream']
        assert mrtr['classification'] == ('redacted' if mode == 'all_messages' else 'raw')
        assert mrtr['client_channels'] == ['mrtr']
        assert all(r['method'] == 'POST' for c in evidence['cases'] for r in c['fixture']['requests'])
        for case in evidence['cases']:
            for record in case['fixture']['requests']:
                headers = {h['name']: h.get('value') for h in record['headers']}
                assert headers['mcp-protocol-version'] == MODERN
                assert headers['mcp-method'] == 'tools/call'
                assert headers['mcp-name'] == 'argus_fixture_emit'
                assert record['body']['jsonrpc']['protocol_version'] == MODERN


@pytest.mark.parametrize('base', [Preset.safe(), Preset.vulnerable()])
async def test_mrtr_isolated_mutations(host, base):
    for mode, expected in [('json_only', 'warn'), ('all_messages', 'pass')]:
        evidence, outcome = await run(host, replace(base, response_filter=mode),
                                      recipe=filter_recipe('inline_json', 'mrtr_input_request'))
        assert outcome.verdict == expected
        assert 'mrtr_input_request' in outcome.reason if mode == 'json_only' else True
        messages = evidence['cases'][1]['client']['calls'][0]['messages']
        assert messages[0]['kind'] == 'input_required' and messages[0]['channel'] == 'mrtr'
        mutated = deepcopy(evidence)
        mutated['cases'][1]['client']['calls'][0]['classification'] = 'redacted'
        assert check({}, mutated).verdict == 'pass'
        mutated['cases'][1]['client']['calls'][0]['classification'] = 'raw'
        assert check({}, mutated).verdict == 'warn'
        mutated['cases'][1]['fixture']['requests'] = []
        assert check({}, mutated).verdict == 'skipped'


@pytest.mark.parametrize('path', ['post_sse_resumed', 'get_stream_notification'])
async def test_modern_legacy_path_not_exercised(host, path):
    evidence, outcome = await run(host, Preset.safe(), recipe=filter_recipe('inline_json', path))
    assert outcome.verdict == 'skipped' and path in outcome.reason
    assert evidence['cases'][1]['fixture']['requests'] == []


@pytest.mark.parametrize('protocol', ['auto', MODERN, '2025-11-25', '2025-06-18'])
async def test_client_detects_dual_server(host, protocol):
    async with ReferenceGateway(entries(host)) as gateway:
        client = GatewayClient({'url': gateway.url, 'protocol': protocol}, 2)
        try:
            await client.initialize()
            assert client.era == (MODERN if protocol == 'auto' else protocol)
            assert (client.session is None) == (client.era == MODERN)
            await client.discover(host[0].install['install_label'])
            assert ('plain', 'echo') in client.tools
            if client.era == MODERN:
                async with httpx.AsyncClient(trust_env=False) as raw:
                    assert (await raw.get(gateway.url, headers={'MCP-Protocol-Version': MODERN})).status_code == 405
                    assert (await raw.get(entry_url(host[0].install, 'plain'), headers={'MCP-Protocol-Version': MODERN})).status_code == 405
        finally:
            await client.aclose()


@pytest.mark.parametrize('server_era', [MODERN, '2025-11-25', '2025-06-18'])
async def test_client_detects_single_era_server(host, server_era):
    async with ReferenceGateway(entries(host), protocol=server_era) as gateway:
        client = GatewayClient({'url': gateway.url}, 2)
        try:
            await client.initialize()
            assert client.era == (MODERN if server_era == MODERN else '2025-11-25')
            await client.discover(host[0].install['install_label'])
            assert ('hdr', 'emit') in client.tools
        finally:
            await client.aclose()


@pytest.mark.parametrize('upstream_era', [MODERN, '2025-11-25'])
async def test_reference_detects_upstream_era_and_caches_it(host, upstream_era):
    from tests.fixtures.gateway_ref import Entry
    async with ReferenceGateway(entries(host), protocol=upstream_era) as upstream:
        async with ReferenceGateway({'plain': Entry(upstream.url)}) as gateway:
            client = GatewayClient({'url': gateway.url}, 2)
            try:
                await client.initialize()
                await client.discover(host[0].install['install_label'])
                assert client.era == MODERN
                assert gateway.upstream_eras == {'plain': upstream_era}
                assert ('plain' in gateway.upstream_sessions) == (upstream_era != MODERN)
                observed = await client.call(host[0].install['install_label'], 'plain', 'echo', 'canary-nonce')
                assert observed['reply'] == 'result'
                assert gateway.upstream_eras == {'plain': upstream_era}
            finally:
                await client.aclose()


@pytest.mark.parametrize('code', [-32020, -32021, -32022])
async def test_modern_errors_never_trigger_legacy_initialization(code):
    methods = []
    def respond(request):
        message = json.loads(request.content)
        methods.append(message['method'])
        return httpx.Response(400, json={'jsonrpc': '2.0', 'id': message['id'],
            'error': {'code': code, 'message': 'Modern request rejected',
                      'data': {'supported': ['2099-01-01']}}})
    client = GatewayClient({'url': 'http://127.0.0.1:1/mcp'}, 1)
    await client.client.aclose()
    client.client = httpx.AsyncClient(transport=httpx.MockTransport(respond))
    try:
        with pytest.raises(TargetTransportError, match='modern MCP negotiation'):
            await client.initialize()
        assert client.era == MODERN
        assert methods == ['server/discover']
    finally:
        await client.aclose()


@pytest.mark.parametrize('body', [None, {'error': 'No session'}, {'jsonrpc': '2.0', 'id': 1,
    'error': {'code': -32600, 'message': 'Initialize first'}}])
async def test_unrecognized_400_falls_back_and_preserves_legacy_session(body):
    methods = []
    def respond(request):
        message = json.loads(request.content)
        methods.append(message['method'])
        if len(methods) == 1:
            return httpx.Response(400, json=body) if body is not None else httpx.Response(400)
        if message['method'] == 'initialize':
            return httpx.Response(200, headers={'Mcp-Session-Id': 'generated-session-canary'},
                json={'jsonrpc': '2.0', 'id': message['id'], 'result': {'protocolVersion': '2025-06-18'}})
        assert request.headers['Mcp-Session-Id'] == 'generated-session-canary'
        return httpx.Response(202)
    client = GatewayClient({'url': 'http://127.0.0.1:1/mcp'}, 1)
    await client.client.aclose()
    client.client = httpx.AsyncClient(transport=httpx.MockTransport(respond))
    try:
        await client.initialize()
        assert client.era == '2025-06-18'
        assert methods == ['server/discover', 'initialize', 'notifications/initialized']
    finally:
        await client.aclose()


@pytest.mark.parametrize('field', ['MCP-Protocol-Version', 'Mcp-Method', 'Mcp-Name'])
async def test_fixture_rejects_header_mismatch_and_missing_mirrors(host, field):
    from argus.gateway_fixtures.protocol import metadata, mirrored_headers
    message = {'jsonrpc': '2.0', 'id': 41, 'method': 'tools/call', 'params': {
        'name': 'argus_fixture_echo', 'arguments': {'nonce': 'canary-nonce'}, '_meta': metadata()}}
    headers = mirrored_headers(message)
    async with httpx.AsyncClient(trust_env=False) as client:
        url = entry_url(host[0].install, 'plain')
        good = await client.post(url, json=message, headers=headers)
        assert good.status_code == 200
        assert 'Mcp-Session-Id' not in good.headers
        for value in ('mismatch', None):
            changed = dict(headers)
            if value is None:
                changed.pop(field)
            else:
                changed[field] = value
            response = await client.post(url, json=message, headers=changed)
            assert response.status_code == 400
            assert response.json()['error']['code'] == -32020


async def test_unsupported_modern_version_and_required_metadata(host):
    from argus.gateway_fixtures.protocol import metadata, mirrored_headers, PREFIX
    message = {'jsonrpc': '2.0', 'id': 1, 'method': 'server/discover', 'params': {'_meta': metadata('2099-01-01')}}
    async with httpx.AsyncClient(trust_env=False) as client:
        url = entry_url(host[0].install, 'plain')
        response = await client.post(url, json=message, headers=mirrored_headers(message))
        assert response.status_code == 400
        assert response.json()['error']['code'] == -32022
        assert MODERN in response.json()['error']['data']['supported']
        message['params']['_meta'] = metadata()
        for key in (PREFIX + 'protocolVersion', PREFIX + 'clientCapabilities'):
            changed = deepcopy(message)
            changed['params']['_meta'].pop(key)
            response = await client.post(url, json=changed, headers=mirrored_headers(message))
            assert response.status_code == 400 and response.json()['error']['code'] == -32602


async def test_modern_stream_does_not_resume_or_accept_server_requests():
    methods = []
    def respond(request):
        methods.append(request.method)
        return httpx.Response(200, headers={'Content-Type': 'text/event-stream'},
            content=b'id: event-canary\nretry: 0\ndata:\n\n')
    client = GatewayClient({'url': 'http://127.0.0.1:1/mcp', 'protocol': MODERN}, 1)
    await client.client.aclose()
    client.client = httpx.AsyncClient(transport=httpx.MockTransport(respond))
    try:
        observation, _ = await client.rpc('tools/list', {})
        assert observation['reply'] == 'timeout' and methods == ['POST']
        with pytest.raises(TargetTransportError, match='server-initiated'):
            client.capture_message({'jsonrpc': '2.0', 'id': 2, 'method': 'elicitation/create', 'params': {}}, 'post_sse')
    finally:
        await client.aclose()


@pytest.mark.parametrize('value', ['plain', 'Hello, 世界', ' padded ', 'line\nbreak', '=?base64?literal?='])
def test_mirrored_name_encoding(value):
    from argus.gateway_fixtures.protocol import decode_header, header_value
    encoded = header_value(value)
    assert decode_header(encoded) == value
    assert encoded == value if value == 'plain' else encoded.startswith('=?base64?')
