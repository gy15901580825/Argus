"""Loopback URL elicitation consent, origin boundaries and session continuity."""
import asyncio
import base64
import copy
import hashlib
import json
import secrets
from pathlib import Path
from contextlib import asynccontextmanager
from types import SimpleNamespace
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx
import pytest
from aiohttp import web
from click.testing import CliRunner

from argus.cli.__main__ import main
from argus.gateway_fixtures.host import FixtureHost, _SafeRunner
from argus.gateway_fixtures.install import create_install, entry_url, read_install, write_install
from argus.gateway_fixtures.oauth import discovery_paths, issuer_url
from argus.gateway_consent import ConsentDriver
from argus.targets._gateway_client import GatewayClient
from argus.runner import _send_failure
from argus.targets import build_target
from argus.targets._base import ProbeNotApplicable, TargetTransportError
from tests.gateway_fixtures.test_oauth import installation, assert_private
from tests.gateway_fixtures.test_host import start_case, seal


@asynccontextmanager
async def mocked_consent(monkeypatch, handler, *, scheme='http', explicit_port=False, install=None):
    port = (':443' if scheme == 'https' else ':80') if explicit_port else ''
    install = install or create_install(oauth=True, origins={
        name: {'public': f'{scheme}://{alias}.argus.test{port}',
               'listen': f'0.0.0.0:{8471 + index}', 'host': alias + '.argus.test'}
        for index, (name, alias) in enumerate([('upstream', 'r'), ('foreign', 'e'), ('issuer', 'h')])
    })
    bearer, cookie = ('argus-canary-' + secrets.token_hex(16) for _ in range(2))
    config = {'url': f'{scheme}://gateway.argus.test{port}/mcp',
              'auth': {'headers': {'Authorization': 'Bearer ' + bearer}, 'cookies': {'gateway_user': cookie}}}
    def no_dns(*args, **kwargs):
        raise AssertionError('consent origin checks must not resolve DNS')
    monkeypatch.setattr('socket.getaddrinfo', no_dns)
    monkeypatch.setattr('argus.targets._gateway_client.target_client',
        lambda module, **kwargs: httpx.AsyncClient(transport=httpx.MockTransport(handler), **kwargs))
    gateway = GatewayClient(config, 2)
    driver = ConsentDriver(gateway, install, 'follow_url', 2)
    driver.begin_case(secrets.token_hex(16))
    try:
        yield driver, bearer, cookie
    finally:
        await gateway.aclose()


@pytest.mark.parametrize('scheme', ['http', 'https'])
async def test_configured_compose_origins_are_followed_without_dns(monkeypatch, scheme):
    contacted = []
    hosts = ['gateway.argus.test', 'r.argus.test', 'e.argus.test', 'h.argus.test', 'gateway.argus.test']
    rotated = 'argus-canary-rotated-' + secrets.token_hex(16)
    def respond(request):
        index = len(contacted)
        contacted.append(request.url.host)
        assert request.url.host == hosts[index]
        assert request.headers['X-Argus-Consent-Agent'] == driver.nonce
        if index in (0, 4):
            assert request.headers['Authorization'] == 'Bearer ' + bearer
            assert request.headers['Cookie'] == 'gateway_user=' + (cookie if index == 0 else rotated)
        else:
            assert 'Authorization' not in request.headers and 'Cookie' not in request.headers
        if index == 4:
            return httpx.Response(204)
        return httpx.Response(302, headers={
            'Location': f'{scheme}://{hosts[index + 1]}/authorize' if index < 3 else f'{scheme}://{hosts[4]}/callback?code=canary',
            **({'Set-Cookie': f'gateway_user={rotated}; Path=/'} if index == 0 else {})})
    async with mocked_consent(monkeypatch, respond, scheme=scheme) as (driver, bearer, cookie):
        await driver.open({'mode': 'url', 'elicitationId': 'placed-consent', 'message': 'Authorize fixture.',
                           'url': f'{scheme}://GATEWAY.ARGUS.TEST/connect'})
        assert contacted == hosts
        assert [hop['origin'] for hop in driver.hops] == ['gateway', 'upstream', 'foreign', 'issuer', 'gateway']
        assert [hop['status'] for hop in driver.hops] == [302, 302, 302, 302, 204]


@pytest.mark.parametrize('scheme', ['http', 'https'])
@pytest.mark.parametrize('explicit_port', [False, True])
@pytest.mark.parametrize('origin', ['gateway', 'issuer'])
async def test_consent_default_ports_normalize_both_ways(monkeypatch, scheme, explicit_port, origin):
    contacted = []
    def respond(request):
        contacted.append(request.url.host)
        return httpx.Response(204)
    async with mocked_consent(monkeypatch, respond, scheme=scheme, explicit_port=explicit_port) as (driver, _, _):
        host = 'gateway.argus.test' if origin == 'gateway' else 'h.argus.test'
        port = '' if explicit_port else (':443' if scheme == 'https' else ':80')
        await driver.follow(f'{scheme}://{host.upper()}{port}/authorize')
        assert contacted == [host] and driver.hops[0]['origin'] == origin


@pytest.mark.parametrize('host,port', [('gateway.argus.test', 8080), ('fixture.gateway.argus.test', 80)])
async def test_gateway_cookies_stay_on_exact_gateway_origin(monkeypatch, host, port):
    install = create_install(oauth=True, origins={
        name: {'public': f'http://{host}:{port + index}', 'listen': f'127.0.0.1:{port + index}', 'host': host}
        for index, name in enumerate(['upstream', 'foreign', 'issuer'])})
    contacted = []
    def respond(request):
        contacted.append(str(request.url))
        assert 'Cookie' not in request.headers and 'Authorization' not in request.headers
        assert request.headers['X-Argus-Consent-Agent'] == driver.nonce
        return httpx.Response(204)
    async with mocked_consent(monkeypatch, respond, install=install) as (driver, _, _):
        url = install['origins']['issuer']['public'] + '/authorize'
        await driver.follow(url)
        assert contacted == [url] and driver.hops[0]['origin'] == 'issuer'


@pytest.mark.parametrize('redirect', [False, True])
@pytest.mark.parametrize('destination', ['http://unlisted.argus.test/consent',
    'https://gateway.argus.test/consent', 'http://gateway.argus.test:8080/consent',
    'http://gateway.argus.test./consent', 'http://gateway.argus.test:0/consent'])
async def test_consent_unlisted_origin_refused_at_each_hop(monkeypatch, redirect, destination):
    contacted = []
    def respond(request):
        contacted.append(str(request.url))
        if request.url.path == '/start':
            return httpx.Response(302, headers={'Location': destination})
        return httpx.Response(204)
    async with mocked_consent(monkeypatch, respond) as (driver, _, _):
        start = 'http://gateway.argus.test/start' if redirect else destination
        with pytest.raises(TargetTransportError, match='consent.*origin'):
            await driver.follow(start)
        assert contacted == ([start] if redirect else [])
        assert len(driver.hops) == int(redirect)


@pytest.mark.parametrize('url', ['ftp://gateway.argus.test/consent', 'http://user@gateway.argus.test/consent',
    'http://gateway.argus.test/consent#fragment', 'http://gateway.argus.test:invalid/consent', '/consent'])
async def test_consent_still_refuses_malformed_urls_without_contact(monkeypatch, url):
    contacted = []
    def respond(request):
        contacted.append(str(request.url))
        return httpx.Response(204)
    async with mocked_consent(monkeypatch, respond) as (driver, _, _):
        with pytest.raises(TargetTransportError, match='consent.*HTTP'):
            await driver.follow(url)
        assert contacted == [] and driver.hops == []


@pytest.mark.parametrize('mode', ['compose', 'public'])
async def test_cli_placed_oauth_install_completes_consent_and_pins_callback(tmp_path, monkeypatch, mode):
    scheme = 'http' if mode == 'compose' else 'https'
    path = tmp_path / 'placed-install.json'
    command = ['gateway-fixtures', 'init', '--oauth', '--mode', mode, '--install-file', str(path)]
    if mode == 'public':
        for name, alias, port in [('upstream', 'r', 8471), ('foreign', 'e', 8473), ('issuer', 'h', 8472)]:
            command += ['--origin', f'{name}=https://{alias}.fixture.example:8443,0.0.0.0:{port},{alias}.fixture.example']
    result = CliRunner().invoke(main, command)
    assert result.exit_code == 0, result.output
    install = read_install(path)
    assert issuer_url(install) in result.output
    assert all(origin['listen'].startswith('0.0.0.0:') for origin in install['origins'].values())
    # Keep the placed URLs; only the test listeners move to ephemeral loopback ports.
    listening = copy.deepcopy(install)
    for origin in listening['origins'].values():
        origin['listen'] = '127.0.0.1:0'
    async with FixtureHost(listening, control_token=secrets.token_hex(16), control_bind='127.0.0.1:0', settle_s=0) as host:
        async with httpx.AsyncClient(trust_env=False, timeout=2) as local:
            auth = {'Authorization': 'Bearer ' + host.control_token}
            lease, seq = await start_case(host, local, auth)
            callback = f'{scheme}://gateway.argus.test/callback'
            verifier, state = secrets.token_urlsafe(48), secrets.token_urlsafe(32)
            challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
            params = {'client_id': install['entries']['oauth']['client_id'], 'response_type': 'code',
                      'redirect_uri': callback, 'resource': entry_url(install, 'oauth'), 'state': state,
                      'code_challenge': challenge, 'code_challenge_method': 'S256'}
            token_value, code_value = None, None
            async def respond(request):
                nonlocal token_value, code_value
                if request.url.host == 'gateway.argus.test':
                    assert request.headers['Authorization'] == 'Bearer ' + bearer
                    assert request.headers['Cookie'] == 'gateway_user=' + cookie
                    if request.url.path == '/connect':
                        return httpx.Response(302, headers={'Location': issuer_url(install) + '/authorize?' + urlencode(params)})
                    values = parse_qs(request.url.query.decode())
                    assert values['state'] == [state] and values['iss'] == [issuer_url(install)]
                    code_value = values['code'][0]
                    token = await respond(httpx.Request('POST', issuer_url(install) + '/token', data={
                        'grant_type': 'authorization_code', 'code': code_value, 'code_verifier': verifier,
                        'redirect_uri': callback, 'resource': entry_url(install, 'oauth'),
                        'client_id': install['entries']['oauth']['client_id'],
                        'client_secret': install['entries']['oauth']['client_secret']}))
                    assert token.status_code == 200
                    token_value = token.json()['access_token']
                    return httpx.Response(204)
                name = next(name for name, origin in install['origins'].items()
                            if request.url.host == urlsplit(origin['public']).hostname)
                destination = host.origin_urls[name] + request.url.raw_path.decode()
                response = await local.request(request.method, destination, content=request.content,
                                               headers=request.headers)
                return httpx.Response(response.status_code, headers=response.headers, content=response.content)
            async with mocked_consent(monkeypatch, respond, scheme=scheme, install=install) as (driver, bearer, cookie):
                driver.begin_case(host.case.nonce)
                metadata = await respond(httpx.Request('GET', install['origins']['issuer']['public'] + discovery_paths(install)[0]))
                assert metadata.json()['issuer'] == issuer_url(install)
                assert metadata.json()['authorization_endpoint'] == issuer_url(install) + '/authorize'
                await driver.open({'mode': 'url', 'elicitationId': 'placed', 'message': 'Authorize fixture.',
                                   'url': f'{scheme}://gateway.argus.test/connect'})
                assert [hop['origin'] for hop in driver.hops] == ['gateway', 'issuer', 'gateway']
                assert host.oauth.redirect_uri == callback
                changed = await respond(httpx.Request('GET', issuer_url(install) + '/authorize',
                                                      params={**params, 'redirect_uri': callback + '/changed'}))
                assert changed.json() == {'error': 'invalid_request'}
                assert host.oauth.redirect_uri == callback
                reply = await respond(httpx.Request('POST', entry_url(install, 'oauth'),
                    headers={'Authorization': 'Bearer ' + token_value, 'MCP-Protocol-Version': '2025-11-25'},
                    json={'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
                          'params': {'name': 'argus_fixture_echo', 'arguments': {'nonce': driver.nonce}}}))
                assert reply.status_code == 200 and reply.json()['result']['isError'] is False
            evidence = await seal(host, local, auth, seq)
            authorize = next(record for record in evidence['fixture']['requests'] if record['route'] == 'authorize')
            assert authorize['actor'] == 'argus_user_agent'
            assert_private(evidence, bearer, cookie, verifier, state, token_value, code_value,
                           install['entries']['oauth']['client_secret'])
            await local.delete(host.control_url + '/v1/lease/' + lease, headers=auth)


@asynccontextmanager
async def listener(handler):
    app = web.Application()
    app.router.add_route('*', '/{tail:.*}', handler)
    runner = _SafeRunner(app, access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', 0)
    await site.start()
    try:
        yield f'http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}'
    finally:
        await runner.cleanup()


class ConsentGateway:
    def __init__(self, host, *, delivery='error', destination=None, redirects=0, repeat=False, require_accept=False):
        self.host, self.delivery, self.destination = host, delivery, destination
        self.redirects, self.repeat = redirects, repeat
        self.require_accept = require_accept
        self.cookie = 'argus-canary-cookie-' + secrets.token_hex(16)
        self.rotated = 'argus-canary-cookie-' + secrets.token_hex(16)
        self.bearer = 'argus-canary-bearer-' + secrets.token_hex(16)
        self.session = 'argus-canary-session-' + secrets.token_hex(16)
        self.verifier, self.state = secrets.token_urlsafe(48), secrets.token_urlsafe(32)
        self.token = None
        self.calls = 0
        self.hops = []
        self.answer = asyncio.Event()
        self.connected = asyncio.Event()
        self.answer_value = None
        self.capabilities = None
        self.code = None

    def elicitation(self):
        return {'mode': 'url', 'elicitationId': 'consent-1', 'message': 'Authorize the fixture entry.',
                'url': self.destination or self.url + '/connect'}

    async def handle(self, request):
        if request.method == 'GET':
            self.hops.append(request.path)
            assert request.cookies.get('gateway_user') == (self.cookie if request.path == '/connect' else self.rotated)
            assert request.headers.get('Authorization') == 'Bearer ' + self.bearer
            assert request.headers.get('X-Argus-Consent-Agent') == self.host.case.nonce
            if request.path == '/connect' or request.path.startswith('/hop/'):
                hop = 0 if request.path == '/connect' else int(request.match_info['tail'].split('/')[-1])
                if hop < self.redirects:
                    location = self.url + f'/hop/{hop + 1}'
                else:
                    challenge = base64.urlsafe_b64encode(hashlib.sha256(self.verifier.encode()).digest()).decode().rstrip('=')
                    location = issuer_url(self.host.install) + '/authorize?' + urlencode({
                        'client_id': self.host.install['entries']['oauth']['client_id'], 'response_type': 'code',
                        'redirect_uri': self.url + '/callback', 'resource': entry_url(self.host.install, 'oauth'),
                        'state': self.state, 'code_challenge': challenge, 'code_challenge_method': 'S256'})
                response = web.Response(status=302, headers={'Location': location})
                response.set_cookie('gateway_user', self.rotated)
                return response
            values = parse_qs(request.query_string)
            assert values['state'] == [self.state]
            self.code = values['code'][0]
            token = await self.client.post(issuer_url(self.host.install) + '/token', data={
                'grant_type': 'authorization_code', 'code': self.code, 'code_verifier': self.verifier,
                'redirect_uri': self.url + '/callback', 'resource': entry_url(self.host.install, 'oauth'),
                'client_id': self.host.install['entries']['oauth']['client_id'],
                'client_secret': self.host.install['entries']['oauth']['client_secret']})
            assert token.status_code == 200
            self.token = token.json()['access_token']
            await self.upstream({'jsonrpc': '2.0', 'id': 90, 'method': 'initialize',
                                 'params': {'protocolVersion': '2025-11-25'}})
            self.connected.set()
            return web.Response(status=204)
        message = await request.json()
        if self.require_accept:
            assert request.headers.get('Authorization') == 'Bearer ' + self.bearer
            assert request.cookies.get('gateway_user') == (self.rotated if self.connected.is_set() else self.cookie)
            if message.get('method') not in ('server/discover', 'initialize'):
                assert request.headers.get('Mcp-Session-Id') == self.session
        if 'method' not in message:
            if self.require_accept and not {'application/json', 'text/event-stream'} <= set(request.headers.get('Accept', '').split(', ')):
                return web.Response(status=403, text='MCP Accept header required')
            self.answer_value = message
            self.answer.set()
            return web.Response(status=202)
        method = message['method']
        if self.delivery == 'mrtr':
            self.capabilities = message['params']['_meta']['io.modelcontextprotocol/clientCapabilities']
        if method == 'server/discover':
            if self.delivery != 'mrtr':
                return web.Response(status=400, text='Initialize first')
            return web.json_response({'jsonrpc': '2.0', 'id': message['id'],
                'result': {'resultType': 'complete', 'supportedVersions': ['2026-07-28'], 'capabilities': {}}})
        if method == 'notifications/initialized':
            return web.Response(status=202)
        if method == 'initialize':
            self.capabilities = message['params']['capabilities']
            result = {'protocolVersion': '2025-11-25', 'capabilities': {}, 'serverInfo': {'name': 'fixture', 'version': '1'}}
        elif method == 'tools/list':
            result = {'tools': [{'name': 'fixture_echo', 'description': f'argus-fixture:{self.host.install["install_label"]}:oauth echo'}]}
        else:
            self.calls += 1
            if not self.token or self.repeat:
                if self.delivery == 'mrtr':
                    return web.json_response({'jsonrpc': '2.0', 'id': message['id'], 'result': {
                        'resultType': 'input_required', 'requestState': 'consent-state',
                        'inputRequests': {'consent': {'method': 'elicitation/create', 'params': self.elicitation()}}}})
                if self.delivery == 'error':
                    return web.json_response({'jsonrpc': '2.0', 'id': message['id'], 'error': {
                        'code': -32042, 'message': 'Authorization required.', 'data': {'elicitations': [self.elicitation()]}}})
                stream = web.StreamResponse(headers={'Content-Type': 'text/event-stream'})
                await stream.prepare(request)
                await stream.write(('data: ' + json.dumps({'jsonrpc': '2.0', 'id': 'server-consent',
                    'method': 'elicitation/create', 'params': self.elicitation()}) + '\n\n').encode())
                await asyncio.wait_for(self.answer.wait(), 2)
                await asyncio.wait_for(self.connected.wait(), 2)
                response = await self.upstream(message)
                await stream.write(('data: ' + json.dumps(response) + '\n\n').encode())
                return stream
            return web.json_response(await self.upstream(message))
        return web.json_response({'jsonrpc': '2.0', 'id': message['id'], 'result': result},
            headers={'Mcp-Session-Id': self.session} if self.require_accept and method == 'initialize' else {})

    async def upstream(self, message):
        message = json.loads(json.dumps(message))
        if message['method'] == 'tools/call':
            message['params']['name'] = 'argus_fixture_echo'
            message['params']['_meta'] = {}
        response = await self.client.post(entry_url(self.host.install, 'oauth'), json=message,
            headers={'Authorization': 'Bearer ' + self.token, 'MCP-Protocol-Version': '2025-11-25'})
        assert response.status_code == 200
        return response.json()


@asynccontextmanager
async def running(tmp_path, *, mode='follow_url', steps=True, **kwargs):
    async with FixtureHost(installation(), control_token=secrets.token_hex(16), control_bind='127.0.0.1:0', settle_s=0.001) as host:
        for name, url in host.origin_urls.items():
            host.install['origins'][name]['public'] = url
        path = tmp_path / 'install.json'
        write_install(path, host.install)
        gateway = ConsentGateway(host, **kwargs)
        async with httpx.AsyncClient(trust_env=False, timeout=2) as client, listener(gateway.handle) as url:
            gateway.client, gateway.url = client, url
            settings = {'kind': 'mcp_gateway', 'sandbox': True, 'gateway': {'url': url + '/mcp',
                'auth': {'cookies': {'gateway_user': gateway.cookie}, 'headers': {'Authorization': 'Bearer ' + gateway.bearer}}},
                'fixtures': {'control_url': host.control_url, 'control_token': host.control_token, 'install_file': str(path)},
                'timeout_s': 2, 'case_window_s': 0.1,
                'features': {'static_oauth_client': {'grant': 'authorization_code', 'consent': mode, 'trigger': 'challenge'}}}
            target = build_target(settings)
            payload = {'version': 1, 'requires': ['static_oauth_client'], 'entries': ['oauth'],
                'cases': [{'id': 'baseline', 'role': 'control', 'entry': 'oauth', 'upstream': {'prm': {'authorization_servers': ['issuer']}}, 'issuer': {'iss': 'always'}}],
                'drive': {'tool': 'echo', 'calls_per_case': 1, **({'steps': ['consent']} if steps else {})}}
            try:
                await target.begin_probe(SimpleNamespace(id='consent-test', scenario_payload=json.dumps(payload)))
                yield target, gateway, host
            finally:
                await target.aclose()


@pytest.mark.parametrize('delivery', ['error', 'sse', 'mrtr'])
async def test_authorization_url_roundtrip_completes_case(tmp_path, delivery):
    async with running(tmp_path, delivery=delivery) as (target, gateway, host):
        text, _ = await target.send_prompt('')
        evidence = json.loads(text)
        case = evidence['cases'][0]
        assert case['complete'] and case['client']['calls'][0]['reply'] == 'result'
        assert gateway.hops == ['/connect', '/callback']
        assert [hop['origin'] for hop in case['client']['consent_hops']] == ['gateway', 'issuer', 'gateway']
        assert [hop['status'] for hop in case['client']['consent_hops']] == [302, 302, 204]
        assert gateway.capabilities['elicitation'] == ({'form': {}, 'url': {}} if delivery == 'mrtr' else {'url': {}})
        authorize = next(r for r in case['fixture']['requests'] if r['route'] == 'authorize')
        token = next(r for r in case['fixture']['requests'] if r['route'] == 'token')
        assert authorize['actor'] == 'argus_user_agent' and token['actor'] == 'gateway'
        assert all(h['name'] not in ('authorization', 'cookie') for h in authorize['headers'])
        assert_private(evidence, gateway.cookie, gateway.rotated, gateway.bearer, gateway.verifier, gateway.code,
                       gateway.state, gateway.token, host.install['entries']['oauth']['client_secret'])
        assert host.lease_id is None
        if delivery == 'sse':
            assert gateway.answer_value == {'jsonrpc': '2.0', 'id': 'server-consent', 'result': {'action': 'accept'}}


@pytest.mark.parametrize('redirect', [False, True])
async def test_non_fixture_origin_is_refused_without_contact(tmp_path, redirect):
    contacted = []
    async def other(request):
        contacted.append(request.path)
        return web.Response(status=204)
    async with listener(other) as url:
        async with running(tmp_path, destination=url + '/consent') as (target, gateway, host):
            if redirect:
                gateway.destination = gateway.url + '/connect'
                async def redirected(request):
                    return web.Response(status=302, headers={'Location': url + '/consent'})
                # A separate fixture listener makes the refusal occur after one allowed hop.
                async with listener(redirected) as allowed:
                    host.install['origins']['foreign']['public'] = allowed
                    path = Path(target.spec.fixtures['install_file'])
                    saved = json.loads(path.read_text())
                    saved['origins']['foreign']['public'] = allowed
                    saved['origins']['foreign']['host'] = '127.0.0.1'
                    path.write_text(json.dumps(saved))
                    gateway.destination = allowed + '/start'
                    with pytest.raises(TargetTransportError, match='consent.*origin'):
                        await target.send_prompt('')
            else:
                with pytest.raises(TargetTransportError, match='consent.*origin'):
                    await target.send_prompt('')
            assert contacted == []
            assert host.lease_id is None


@pytest.mark.parametrize('redirects,allowed', [(8, True), (9, False)])
async def test_redirect_chain_accepts_ten_and_refuses_eleventh(tmp_path, redirects, allowed):
    async with running(tmp_path, redirects=redirects) as (target, gateway, host):
        if allowed:
            await target.send_prompt('')
            assert (await target.collect_evidence())['cases'][0]['client']['calls'][0]['reply'] == 'result'
            assert len((await target.collect_evidence())['cases'][0]['client']['consent_hops']) == 11
        else:
            with pytest.raises(TargetTransportError, match='consent.*redirect'):
                await target.send_prompt('')
            assert '/callback' not in gateway.hops
            assert host.lease_id is None


async def test_manual_non_tty_reports_skipped_and_prints_instruction(tmp_path, monkeypatch, capsys):
    import io
    monkeypatch.setattr('sys.stdin', io.StringIO())
    async with running(tmp_path, mode='manual') as (target, gateway, host):
        with pytest.raises(ProbeNotApplicable) as raised:
            await asyncio.wait_for(target.send_prompt(''), 0.5)
        assert _send_failure(raised.value)[0] == 'skipped'
        output = capsys.readouterr().out
        assert gateway.url + '/connect' in output and 'Authorize the fixture entry.' in output
        assert gateway.hops == [] and host.lease_id is None


async def test_three_origin_install_selects_oauth_registry_without_feature(tmp_path):
    from argus.targets.mcp_gateway import MCPGatewaySpec, MCPGatewayTarget
    path = tmp_path / 'install.json'
    write_install(path, installation())
    target = MCPGatewayTarget(MCPGatewaySpec(sandbox=True, gateway={'url': 'http://127.0.0.1:1/mcp'},
        fixtures={'install_file': str(path), 'control_url': 'http://127.0.0.1:2', 'control_token': secrets.token_hex(16)}))
    try:
        payload = {'version': 1, 'requires': [], 'entries': ['oauth'],
            'cases': [{'id': 'baseline', 'role': 'control', 'entry': 'oauth', 'issuer': {'iss': 'never'}}],
            'drive': {'tool': 'echo', 'calls_per_case': 1}}
        await target.begin_probe(SimpleNamespace(id='registry-test', scenario_payload=json.dumps(payload)))
        assert 'issuer' in target.registry.origins
        assert list(target.registry.drive_steps) == ['consent']
    finally:
        await target.aclose()


async def test_consent_step_is_opt_in(tmp_path):
    async with running(tmp_path, steps=False) as (target, gateway, host):
        await target.send_prompt('')
        case = (await target.collect_evidence())['cases'][0]
        assert case['client']['calls'][0]['reply'] == 'jsonrpc_error'
        assert case['client']['consent_hops'] == []
        assert gateway.hops == []
        assert 'elicitation' not in gateway.capabilities


async def test_none_consent_mode_skips_required_authorization(tmp_path):
    async with running(tmp_path, mode='none') as (target, gateway, host):
        with pytest.raises(ProbeNotApplicable, match='requires consent'):
            await target.send_prompt('')
        assert gateway.hops == [] and host.lease_id is None


async def test_repeated_error_stops_after_one_consent_retry(tmp_path):
    async with running(tmp_path, repeat=True) as (target, gateway, host):
        with pytest.raises(ProbeNotApplicable, match='still requires authorization'):
            await target.send_prompt('')
        assert gateway.calls == 2 and gateway.hops == ['/connect', '/callback']
        assert host.lease_id is None


@pytest.mark.parametrize('field,value', [('mode', 'form'), ('elicitationId', None), ('message', None), ('url', 'ftp://127.0.0.1/a')])
async def test_malformed_elicitation_is_refused_before_navigation(tmp_path, field, value):
    async with running(tmp_path) as (target, gateway, host):
        original = gateway.elicitation
        gateway.elicitation = lambda: {**original(), field: value}
        with pytest.raises(TargetTransportError):
            await target.send_prompt('')
        assert gateway.hops == [] and host.lease_id is None


async def test_manual_tty_wait_is_bounded(tmp_path, monkeypatch):
    import io
    class TTY(io.StringIO):
        def isatty(self):
            return True
    monkeypatch.setattr('sys.stdin', TTY())
    monkeypatch.setattr('select.select', lambda *args: ([], [], []))
    async with running(tmp_path, mode='manual') as (target, gateway, host):
        target.spec.features['static_oauth_client']['consent'] = 'manual'
        with pytest.raises(ProbeNotApplicable, match='timed out'):
            await asyncio.wait_for(target.send_prompt(''), 3)
        assert gateway.hops == [] and host.lease_id is None


@pytest.mark.parametrize('changes', [
    {'steps': ['consent', 'consent']}, {'steps': ['missing']}, {'steps': 'consent'},
])
async def test_invalid_drive_step_refused_before_teardown(tmp_path, changes):
    async with running(tmp_path) as (target, gateway, host):
        from tests.gateway_target.test_target import recipe, probe
        target._lease_id = 'existing'
        try:
            with pytest.raises(ValueError):
                await target.begin_probe(probe(recipe(drive={'tool': 'echo', 'calls_per_case': 1, **changes})))
            assert target._lease_id == 'existing'
        finally:
            target._lease_id = None


async def test_url_elicitation_accept_precedes_navigation(tmp_path):
    async with running(tmp_path, delivery='sse') as (target, gateway, host):
        original = gateway.handle
        # The gateway requires the client's consent response before opening its session URL.
        async def requires_accept(request):
            if request.method == 'GET':
                assert gateway.answer.is_set()
            return await original(request)
        async with listener(requires_accept) as url:
            gateway.url = url
            target.spec.gateway['url'] = url + '/mcp'
            await target.send_prompt('')
            assert (await target.collect_evidence())['cases'][0]['client']['calls'][0]['reply'] == 'result'


async def test_manual_tty_user_can_finish_and_retry(tmp_path, monkeypatch):
    import io
    class TTY(io.StringIO):
        def isatty(self):
            return True
    tty = TTY('\n')
    monkeypatch.setattr('sys.stdin', tty)
    monkeypatch.setattr('select.select', lambda *args: ([tty], [], []))
    async with running(tmp_path, mode='manual') as (target, gateway, host):
        # Manual completion is external; the fake gateway returns a completed call on retry.
        original = gateway.handle
        async def completed(request):
            if request.method == 'POST':
                message = await request.json()
                if message.get('method') == 'tools/call' and gateway.calls:
                    return web.json_response({'jsonrpc': '2.0', 'id': message['id'], 'result': {'content': []}})
            return await original(request)
        async with listener(completed) as url:
            gateway.url = url
            target.spec.gateway['url'] = url + '/mcp'
            await target.send_prompt('')
            assert (await target.collect_evidence())['cases'][0]['client']['calls'][0]['reply'] == 'result'
            assert gateway.hops == []


async def test_navigation_policy_refusal_releases_lease(tmp_path):
    async with running(tmp_path) as (target, gateway, host):
        target.spec.gateway['url'] = target.spec.gateway['url'].replace('127.0.0.1', 'localhost')
        with pytest.raises(TargetTransportError, match='consent.*origin'):
            await target.send_prompt('')
        assert host.lease_id is None


@pytest.mark.parametrize('require_accept', [False, True])
async def test_consent_response_uses_mcp_accept_headers(tmp_path, require_accept):
    async with running(tmp_path, delivery='sse', require_accept=require_accept) as (target, gateway, host):
        await target.send_prompt('')
        evidence = await target.collect_evidence()
        assert evidence['cases'][0]['client']['calls'][0]['reply'] == 'result'
        assert gateway.answer_value['result']['action'] == 'accept'
        assert gateway.hops == ['/connect', '/callback']
        assert host.lease_id is None


async def test_consent_auth_refusal_keeps_redacted_body_and_fixture_record(tmp_path):
    async with running(tmp_path) as (target, gateway, host):
        original = gateway.handle
        async def refused(request):
            if request.path == '/callback':
                return web.Response(status=403, text='Rejected ' + request.query['code'] + ' ' + gateway.rotated)
            return await original(request)
        async with listener(refused) as url:
            gateway.url = url
            target.spec.gateway['url'] = url + '/mcp'
            with pytest.raises(TargetTransportError):
                await target.send_prompt('')
            evidence = await target.collect_evidence()
            failure = evidence['cases'][0]['client']['calls'][-1]['transport_error']
            assert failure['method'] == 'GET' and failure['path_class'] == 'auth' and failure['status'] == 403
            assert failure['body']['text'] == 'Rejected <redacted> <redacted>'
            assert any(r['route'] == 'authorize' for r in evidence['cases'][0]['fixture']['requests'])
            assert gateway.rotated not in json.dumps(evidence) and host.lease_id is None


@pytest.mark.parametrize('omit_accept', [False, True])
async def test_missing_consent_accept_mutation_changes_result(tmp_path, monkeypatch, omit_accept):
    if omit_accept:
        original = GatewayClient._headers
        def missing_accept(self, *args, **kwargs):
            headers = original(self, *args, **kwargs)
            del headers['Accept']
            return headers
        monkeypatch.setattr(GatewayClient, '_headers', missing_accept)
    async with running(tmp_path, delivery='sse', require_accept=True) as (target, gateway, host):
        if omit_accept:
            with pytest.raises(TargetTransportError):
                await target.send_prompt('')
            failure = (await target.collect_evidence())['cases'][0]['client']['calls'][-1]['transport_error']
            assert failure['status'] == 403 and failure['rpc_method'] == 'server_response'
            assert gateway.hops == []
        else:
            await target.send_prompt('')
            assert (await target.collect_evidence())['cases'][0]['client']['calls'][0]['reply'] == 'result'
        assert host.lease_id is None
