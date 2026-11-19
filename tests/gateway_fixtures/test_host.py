"""Offline fixture host conformance: httpx stands in for an MCP gateway."""
from __future__ import annotations

import asyncio
import json
import os
import secrets
import sys
from datetime import datetime, timedelta, timezone
from importlib.metadata import EntryPoint
from urllib.parse import urlsplit

import httpx
import pytest
from aiohttp import web
from click.testing import CliRunner
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from argus.cli.__main__ import main
from argus.gateway_fixtures.host import FixtureHost
from argus.gateway_fixtures.install import create_install, entry_url, read_install, write_install
from argus.gateway_fixtures.registry import DefinitionError, Registry, load_registry


def installation(*, shared=False, registry=None):
    return create_install(origins={
        'upstream': {'public': 'http://r.argus.test:8471', 'listen': '127.0.0.1:0', 'host': 'r.argus.test'},
        'foreign': {'public': 'http://e.argus.test:8473', 'listen': '127.0.0.1:0' if shared else '127.0.0.2:0', 'host': 'e.argus.test'},
    }, registry=registry)


@pytest.fixture
async def serving():
    token = secrets.token_urlsafe(24)
    async with FixtureHost(installation(), control_token=token, control_bind='127.0.0.1:0', settle_s=0.01) as host:
        async with httpx.AsyncClient(trust_env=False, timeout=3) as client:
            yield host, client, {'Authorization': 'Bearer ' + token}


async def start_case(host, client, auth, *, toggles=None, case_id='first', nonce='case-nonce', lease=None, canaries=None):
    if lease is None:
        result = await client.post(host.control_url + '/v1/lease', headers=auth, json={'ttl_s': 30})
        assert result.status_code == 200
        lease = result.json()['lease_id']
    result = await client.post(host.control_url + '/v1/cases', headers=auth, json={
        'lease_id': lease, 'probe_id': 'host-test', 'case_id': case_id, 'nonce': nonce, 'toggles': toggles or {},
        'watch': {'canaries': list(host._canaries) if canaries is None else canaries, 'secrets': {},
                  'watch_key': secrets.token_hex(32), 'case_key': secrets.token_hex(32)},
    })
    assert result.status_code == 200, result.text
    return lease, result.json()['case_seq']


async def seal(host, client, auth, seq):
    result = await client.post(f'{host.control_url}/v1/cases/{seq}/seal', headers=auth)
    assert result.status_code == 200, result.text
    return result.json()


async def rpc(host, client, method, *, entry='plain', nonce=None, headers=None, request_id=1):
    params = {'protocolVersion': '2025-06-18'} if method == 'initialize' else {}
    if method == 'tools/call':
        params = {'name': 'argus_fixture_echo', 'arguments': {'nonce': nonce or 'background-nonce'}}
    return await client.post(host.origin_urls['upstream'] + host.install['entries'][entry]['path'].replace('{path_token}', host.install['path_token']),
                             headers={'Host': 'r.argus.test:8471', **(headers or {})},
                             json={'jsonrpc': '2.0', 'id': request_id, 'method': method, 'params': params})


async def test_legacy_calls_record_nonce_case_and_canaries(serving):
    host, client, auth = serving
    lease, seq = await start_case(host, client, auth)
    response = await rpc(host, client, 'initialize')
    assert response.json()['result']['protocolVersion'] == '2025-06-18'
    tools = (await rpc(host, client, 'tools/list')).json()['result']['tools']
    assert {tool['name'] for tool in tools} == {'argus_fixture_echo', 'argus_fixture_emit'}
    assert all(f"argus-fixture:{host.install['install_label']}:plain" in tool['description'] for tool in tools)
    assert (await rpc(host, client, 'tools/call', nonce='case-nonce', entry='hdr',
                      headers=host.install['entries']['hdr']['headers'])).json()['result']['isError'] is False
    evidence = await seal(host, client, auth, seq)
    records = evidence['fixture']['requests']
    assert evidence['complete'] is True
    assert [record['seq'] for record in records] == [1, 2, 3]
    assert {record['case_id'] for record in records} == {'first'}
    assert [record['body']['jsonrpc']['method'] for record in records] == ['initialize', 'tools/list', 'tools/call']
    assert 'nonce' not in records[0]['body']['jsonrpc']
    assert records[2]['body']['jsonrpc']['nonce'] == 'case-nonce'
    assert records[2]['hits'] == ['upstream_header:Authorization', 'upstream_header:X-API-Key']
    assert records[2]['response'] == {'status': 200, 'behavior': 'upstream.idle'}
    assert host.install['path_token'] not in json.dumps(evidence)
    for canary in host._canaries.values():
        assert canary not in json.dumps(evidence)
    _, seq2 = await start_case(host, client, auth, lease=lease, case_id='second', nonce='different')
    await rpc(host, client, 'tools/call', nonce='case-nonce')
    await rpc(host, client, 'tools/call', nonce='different')
    next_records = (await seal(host, client, auth, seq2))['fixture']['requests']
    assert [record['seq'] for record in next_records] == [4, 5]
    assert 'nonce' not in next_records[0]['body']['jsonrpc']
    assert next_records[1]['body']['jsonrpc']['nonce'] == 'different'


async def test_token_required_on_every_control_route(serving):
    host, client, auth = serving
    for path in ('/v1/health', '/v1/seen', '/v1/lease', '/v1/cases', '/v1/cases/1/seal', '/v1/lease/anything'):
        assert (await client.get(host.control_url + path)).status_code == 401
        assert (await client.get(host.control_url + path, headers={'Authorization': 'Bearer changed'})).status_code == 401
    health = await client.get(host.control_url + '/v1/health', headers=auth)
    assert health.status_code == 200
    assert health.json()['eras'] == ['2026-07-28', '2025-11-25', '2025-06-18']
    assert host.control_token not in health.text


@pytest.mark.parametrize('flag,tls,allowed', [(False, False, False), (True, False, False), (False, True, False), (True, True, True)])
def test_remote_control_requires_explicit_flag_and_tls(flag, tls, allowed):
    install = installation()
    if tls:
        install['tls'] = {'cert': 'synthetic-cert.pem', 'key': 'synthetic-key.pem'}
    if allowed:
        FixtureHost(install, control_token='synthetic-token', control_bind='0.0.0.0:0', allow_remote_control=flag)
    else:
        with pytest.raises(DefinitionError, match='non-loopback'):
            FixtureHost(install, control_token='synthetic-token', control_bind='0.0.0.0:0', allow_remote_control=flag)


async def test_second_lease_refused_and_release_allows_next(serving):
    host, client, auth = serving
    lease, _ = await start_case(host, client, auth)
    response = await client.post(host.control_url + '/v1/lease', headers=auth, json={'ttl_s': 30})
    assert response.status_code == 409
    assert response.json()['expires_in_s'] > 0
    assert (await client.delete(host.control_url + '/v1/lease/wrong', headers=auth)).status_code == 409
    assert (await client.delete(host.control_url + '/v1/lease/' + lease, headers=auth)).status_code == 200
    assert host.case is None
    assert (await client.post(host.control_url + '/v1/lease', headers=auth, json={'ttl_s': 30})).status_code == 200


def register_test_plugin(registry):
    def factory(config):
        async def behavior(context):
            context.state['test.served'] = True
            context.ext['test'] = {'served': True}
            return web.json_response({'test': config['value']}, status=201)
        return behavior
    registry.add_behavior('upstream', 'test', factory)


async def test_entry_point_plugin_adds_behavior(monkeypatch):
    entry_point = EntryPoint(name='neutral-test', value=__name__ + ':register_test_plugin', group='argus.gateway_fixtures')
    monkeypatch.setattr('argus.gateway_fixtures.registry.metadata.entry_points', lambda *, group: [entry_point] if group == entry_point.group else [])
    registry = load_registry()
    assert registry.plugins == ['neutral-test']
    async with FixtureHost(installation(registry=registry), registry=registry, control_token='test-token', control_bind='127.0.0.1:0', settle_s=0) as host:
        async with httpx.AsyncClient(trust_env=False) as client:
            auth = {'Authorization': 'Bearer test-token'}
            lease, seq = await start_case(host, client, auth, toggles={'upstream': {'test': {'value': 'fixed'}}})
            result = await rpc(host, client, 'tools/call', nonce='case-nonce')
            assert result.status_code == 201 and result.json() == {'test': 'fixed'}
            evidence = await seal(host, client, auth, seq)
            assert evidence['fixture']['state'] == {'test.served': True}
            assert evidence['fixture']['requests'][0]['response']['behavior'] == 'upstream.test'
            assert evidence['fixture']['requests'][0]['ext'] == {'test': {'served': True}}
            assert (await rpc(host, client, 'tools/call')).status_code == 200
            await client.delete(host.control_url + '/v1/lease/' + lease, headers=auth)


async def test_unknown_behavior_is_definition_error(serving):
    host, client, auth = serving
    lease, _ = await start_case(host, client, auth)
    result = await client.post(host.control_url + '/v1/cases', headers=auth, json={
        'lease_id': lease, 'toggles': {'upstream': {'not_registered': {}}}})
    assert result.status_code == 400 and result.json() == {'error': 'definition_error'}
    assert host.case.case_id == 'first'
    with pytest.raises(DefinitionError, match='unknown fixture behaviour'):
        host.registry.build_behaviors({'upstream': {'not_registered': {}}})


@pytest.mark.parametrize('timeout', [False, True])
async def test_request_in_flight_at_seal_is_included(timeout):
    arrived, release = asyncio.Event(), asyncio.Event()
    def factory(config):
        async def behavior(context):
            arrived.set()
            await release.wait()
            return web.json_response({'done': True})
        return behavior
    registry = Registry()
    registry.add_behavior('upstream', 'hold', factory)
    async with FixtureHost(installation(registry=registry), registry=registry, control_token='test-token', control_bind='127.0.0.1:0',
                           settle_s=0.01, case_window_s=0.05 if timeout else 1) as host:
        async with httpx.AsyncClient(trust_env=False) as client:
            auth = {'Authorization': 'Bearer test-token'}
            _, seq = await start_case(host, client, auth, toggles={'upstream': {'hold': {}}})
            call = asyncio.create_task(rpc(host, client, 'tools/call', nonce='case-nonce'))
            await asyncio.wait_for(arrived.wait(), 1)
            sealing = asyncio.create_task(seal(host, client, auth, seq))
            if not timeout:
                await asyncio.sleep(0.03)
                assert not sealing.done()
                release.set()
                assert (await call).status_code == 200
            evidence = await sealing
            assert evidence['complete'] is not timeout
            assert evidence['fixture']['requests'][0]['body']['jsonrpc']['nonce'] == 'case-nonce'
            if timeout:
                with pytest.raises(httpx.RemoteProtocolError):
                    await call
            assert await seal(host, client, auth, seq) == evidence


async def test_settle_accepts_late_arrivals(serving):
    host, client, auth = serving
    host.settle_s = 0.08
    _, seq = await start_case(host, client, auth)
    sealing = asyncio.create_task(seal(host, client, auth, seq))
    await asyncio.sleep(0.02)
    await rpc(host, client, 'tools/call', nonce='case-nonce')
    assert len((await sealing)['fixture']['requests']) == 1


async def test_shared_host_routing_and_control_isolation():
    async with FixtureHost(installation(shared=True), control_token='test-token', control_bind='127.0.0.1:0', settle_s=0) as host:
        assert host.origin_urls['upstream'] == host.origin_urls['foreign']
        assert host.control_url != host.origin_urls['upstream']
        async with httpx.AsyncClient(trust_env=False) as client:
            auth = {'Authorization': 'Bearer test-token'}
            _, seq = await start_case(host, client, auth)
            url = host.origin_urls['upstream'] + '/x/' + host.install['path_token'] + '/unknown'
            assert (await client.get(url, headers={'Host': 'e.argus.test:8473'})).status_code == 404
            assert (await client.get(url, headers={'Host': 'unconfigured.test'})).status_code == 404
            assert (await client.get(url.replace(host.install['path_token'], 'changed'), headers={'Host': 'r.argus.test:8471'})).status_code == 404
            assert (await client.get(host.origin_urls['upstream'] + '/v1/health', headers={'Host': 'r.argus.test:8471', **auth})).status_code == 404
            records = (await seal(host, client, auth, seq))['fixture']['requests']
            assert len(records) == 1 and records[0]['origin'] == 'foreign'


async def test_idle_seen_is_bounded_and_lease_expires(serving):
    host, client, auth = serving
    await rpc(host, client, 'tools/list', entry='hdr', headers=host.install['entries']['hdr']['headers'])
    assert host.case is None and host.last_evidence is None
    seen = (await client.get(host.control_url + '/v1/seen', headers=auth)).json()
    assert seen['hdr']['methods'] == ['tools/list']
    assert seen['hdr']['hits'] == sorted(host._canaries)
    assert seen['hdr']['first'] == seen['hdr']['last']
    response = await client.post(host.control_url + '/v1/lease', headers=auth, json={'ttl_s': 0.05})
    lease, seq = await start_case(host, client, auth, lease=response.json()['lease_id'])
    await asyncio.sleep(0.1)
    assert host.lease_id is None and host.case is None
    assert (await rpc(host, client, 'tools/call')).status_code == 200
    assert (await client.post(host.control_url + '/v1/cases', headers=auth, json={'lease_id': lease})).status_code == 409


async def test_body_cap_and_request_cap_preserve_incompleteness(serving):
    host, client, auth = serving
    _, seq = await start_case(host, client, auth)
    host.case.recorder.max_requests = 1
    secret = host.install['entries']['hdr']['headers']['X-API-Key']
    url = host.origin_urls['upstream'] + host.install['entries']['hdr']['path'].replace('{path_token}', host.install['path_token'])
    response = await client.post(url, headers={'Host': 'r.argus.test:8471', 'Content-Type': 'application/json', 'X-API-Key': secret}, content=b'{' + b' ' * 65536)
    assert response.status_code == 413
    await rpc(host, client, 'tools/call')
    evidence = await seal(host, client, auth, seq)
    assert evidence['complete'] is False and evidence['dropped'] == 1
    assert evidence['fixture']['requests'][0]['hits'] == ['upstream_header:X-API-Key']


def test_init_install_permissions_stability_and_sheet(tmp_path):
    path = tmp_path / 'install.json'
    runner = CliRunner()
    result = runner.invoke(main, ['gateway-fixtures', 'init', '--install-file', str(path)])
    assert result.exit_code == 0, result.output
    assert path.stat().st_mode & 0o777 == 0o600
    original = path.read_bytes()
    install = read_install(path)
    assert entry_url(install, 'plain') in result.output
    assert install['entries']['hdr']['headers']['X-API-Key'] in result.output
    assert runner.invoke(main, ['gateway-fixtures', 'init', '--install-file', str(path)]).exit_code != 0
    assert path.read_bytes() == original
    sheet = runner.invoke(main, ['gateway-fixtures', 'sheet', '--install-file', str(path)])
    assert sheet.exit_code == 0
    assert result.output.endswith(sheet.output)


def test_plugin_registration_duplicates_fail_closed():
    registry = Registry()
    with pytest.raises(DefinitionError, match='duplicate'):
        registry.add_origin('upstream', {})
    with pytest.raises(DefinitionError, match='unknown fixture feature'):
        registry.validate_features({'unknown': {}})
    with pytest.raises(DefinitionError, match='unknown fixture drive step'):
        registry.validate_drive_steps(['unknown'])


def test_install_origin_and_entry_requirements():
    registry = Registry()
    registry.add_entry('test', '/u/{path_token}/test/mcp', lambda install: {'auth': 'none', 'sheet': ['Neutral test entry.']})
    install = installation(registry=registry)
    assert install['entries']['test']['auth'] == 'none'
    registry.add_origin('extra', {'https': True, 'symmetric_with': 'foreign'})
    with pytest.raises(DefinitionError, match='origins'):
        create_install(origins=install['origins'], registry=registry)


async def test_parser_errors_and_access_logs_never_contain_canary(serving, caplog):
    host, client, auth = serving
    canary = secrets.token_urlsafe(32)
    await rpc(host, client, 'tools/call', headers={'Authorization': 'Bearer ' + canary})
    address = urlsplit(host.origin_urls['upstream'])
    reader, writer = await asyncio.open_connection(address.hostname, address.port)
    try:
        writer.write(b'GET / HTTP/1.1\r\nHost: r.argus.test:8471\r\n' + canary.encode() + b'\r\n\r\n')
        await writer.drain()
        response = await asyncio.wait_for(reader.read(), 1)
        assert b'400 Bad Request' in response and b'request_rejected' in response
        assert canary.encode() not in response
        assert canary not in caplog.text
        assert not [record for record in caplog.records if record.name.startswith(('aiohttp', 'argus.gateway_fixtures.http'))]
    finally:
        writer.close()
        await writer.wait_closed()


async def test_body_read_timeout_is_incomplete_with_known_hits():
    install = installation()
    async with FixtureHost(install, control_token='test-token', control_bind='127.0.0.1:0', settle_s=0,
                           body_timeout_s=0.03) as host:
        async with httpx.AsyncClient(trust_env=False) as client:
            auth = {'Authorization': 'Bearer test-token'}
            _, seq = await start_case(host, client, auth)
            address = urlsplit(host.origin_urls['upstream'])
            reader, writer = await asyncio.open_connection(address.hostname, address.port)
            try:
                path = install['entries']['hdr']['path'].replace('{path_token}', install['path_token'])
                secret = install['entries']['hdr']['headers']['X-API-Key']
                writer.write(f'POST {path} HTTP/1.1\r\nHost: r.argus.test:8471\r\nContent-Type: application/json\r\nContent-Length: 100\r\nX-API-Key: {secret}\r\n\r\n{{'.encode())
                await writer.drain()
                assert b'413' in await asyncio.wait_for(reader.read(4096), 1)
                evidence = await seal(host, client, auth, seq)
                assert evidence['complete'] is False
                assert evidence['fixture']['requests'][0]['hits'] == ['upstream_header:X-API-Key']
                assert evidence['fixture']['requests'][0]['body']['complete'] is False
            finally:
                writer.close()
                await writer.wait_closed()


async def test_arrival_order_survives_out_of_order_body_reads(serving):
    host, client, auth = serving
    _, seq = await start_case(host, client, auth)
    yielded, release = asyncio.Event(), asyncio.Event()
    async def body():
        yield b'{"jsonrpc":"2.0",'
        yielded.set()
        await release.wait()
        yield b'"id":1,"method":"ping"}'
    url = host.origin_urls['upstream'] + host.install['entries']['plain']['path'].replace('{path_token}', host.install['path_token'])
    slow = asyncio.create_task(client.post(url, headers={'Host': 'r.argus.test:8471', 'Content-Type': 'application/json'}, content=body()))
    await asyncio.wait_for(yielded.wait(), 1)
    await rpc(host, client, 'tools/list')
    release.set()
    assert (await slow).status_code == 200
    records = (await seal(host, client, auth, seq))['fixture']['requests']
    assert [(record['seq'], record['body']['jsonrpc']['method']) for record in records] == [(1, 'ping'), (2, 'tools/list')]


@pytest.mark.parametrize('key', ['watch_key', 'case_key'])
async def test_empty_watch_keys_are_definition_errors(serving, key):
    host, client, auth = serving
    lease, _ = await start_case(host, client, auth)
    watch = {'canaries': [], 'secrets': {}, 'watch_key': secrets.token_hex(32), 'case_key': secrets.token_hex(32)}
    watch[key] = ''
    result = await client.post(host.control_url + '/v1/cases', headers=auth, json={
        'lease_id': lease, 'probe_id': 'test', 'case_id': 'next', 'nonce': 'next', 'toggles': {}, 'watch': watch})
    assert result.status_code == 400
    assert host.case.case_id == 'first'


async def test_cli_serve_stays_online_and_stops_on_signal(tmp_path):
    install_file = tmp_path / 'install.json'
    write_install(install_file, installation())
    token = secrets.token_urlsafe(24)
    process_env = {key: value for key, value in os.environ.items() if key not in {
        'ANTHROPIC_API_KEY', 'OPENAI_API_KEY', 'AZURE_OPENAI_API_KEY', 'AZURE_API_KEY'}}
    process_env['ARGUS_FIXTURE_TOKEN'] = token
    process = await asyncio.create_subprocess_exec(sys.executable, '-m', 'argus.cli', 'gateway-fixtures', 'serve',
                                                   '--install-file', str(install_file), '--control-bind', '127.0.0.1:0',
                                                   stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=process_env)
    try:
        line = (await asyncio.wait_for(process.stdout.readline(), 5)).decode()
        assert line.startswith('Fixtures serving; control API at '), line
        url = line.removeprefix('Fixtures serving; control API at ').strip().removesuffix('.')
        async with httpx.AsyncClient(trust_env=False) as client:
            assert (await client.get(url + '/v1/health', headers={'Authorization': 'Bearer ' + token})).status_code == 200
        assert process.returncode is None
    finally:
        if process.returncode is None:
            process.terminate()
        stdout, stderr = await asyncio.wait_for(process.communicate(), 5)
    assert process.returncode == 0 and not stderr
    assert token not in line + stdout.decode() + stderr.decode()


async def test_shutdown_during_expiry_seal_drops_watch_keys():
    arrived = asyncio.Event()
    def factory(config):
        async def handle(context):
            arrived.set()
            await asyncio.Event().wait()
        return handle
    registry = Registry()
    registry.add_behavior('upstream', 'hold', factory)
    async with FixtureHost(installation(registry=registry), registry=registry, control_token='test-token',
                           control_bind='127.0.0.1:0', settle_s=0, case_window_s=1) as host:
        async with httpx.AsyncClient(trust_env=False) as client:
            auth = {'Authorization': 'Bearer test-token'}
            response = await client.post(host.control_url + '/v1/lease', headers=auth, json={'ttl_s': 0.1})
            await start_case(host, client, auth, lease=response.json()['lease_id'], toggles={'upstream': {'hold': {}}})
            recorder = host.case.recorder
            call = asyncio.create_task(rpc(host, client, 'tools/call'))
            await asyncio.wait_for(arrived.wait(), 1)
            await asyncio.sleep(0.15)
            assert host.case is None and host.lease_id is not None
            await asyncio.wait_for(host.close(), 0.5)
            with pytest.raises(httpx.RemoteProtocolError):
                await call
            keys_cleared = recorder._case_key is None and recorder.matcher._watch_key is None
            assert keys_cleared
            assert host.lease_id is None and host.last_evidence is None


async def test_fixture_tls_keeps_default_loopback_control_http(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'r.argus.test')])
    now = datetime.now(timezone.utc)
    certificate = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
                   .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
                   .not_valid_after(now + timedelta(hours=1))
                   .add_extension(x509.SubjectAlternativeName([x509.DNSName('r.argus.test'), x509.DNSName('e.argus.test')]), critical=False)
                   .sign(key, hashes.SHA256()))
    cert_path, key_path = tmp_path / 'cert.pem', tmp_path / 'key.pem'
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    install = installation()
    for origin in install['origins'].values():
        origin['public'] = origin['public'].replace('http://', 'https://')
    install['tls'] = {'cert': str(cert_path), 'key': str(key_path)}
    async with FixtureHost(install, control_token='test-token', control_bind='127.0.0.1:0', settle_s=0) as host:
        assert host.control_url.startswith('http://')
        assert host.origin_urls['upstream'].startswith('https://')
        async with httpx.AsyncClient(trust_env=False, verify=False) as client:
            assert (await rpc(host, client, 'initialize')).status_code == 200
            assert (await client.get(host.control_url + '/v1/health', headers={'Authorization': 'Bearer test-token'})).status_code == 200


async def test_authorization_canary_matches_payload_without_scheme(serving):
    host, client, auth = serving
    _, seq = await start_case(host, client, auth)
    token = host.install['entries']['hdr']['headers']['Authorization'].partition(' ')[2]
    changed = token[:-1] + ('0' if token[-1] != '0' else '1')
    await rpc(host, client, 'tools/call', headers={'Cookie': 'observed=' + token})
    await rpc(host, client, 'tools/call', headers={'Cookie': 'observed=' + changed})
    evidence = await seal(host, client, auth, seq)
    assert evidence['fixture']['requests'][0]['hits'] == ['upstream_header:Authorization']
    assert evidence['fixture']['requests'][1]['hits'] == []
    assert token not in json.dumps(evidence) and changed not in json.dumps(evidence)
