"""Missing OAuth support skips before setup, while configured issuer failures error."""
import asyncio
import json
import secrets
import sys

from aiohttp import web
import pytest

from argus.cli.severity import incomplete_lines, run_exit_code
from argus.gateway_fixtures.host import FixtureHost
from argus.gateway_fixtures.install import entry_url, write_install
from argus.gateway_fixtures.oauth import issuer_url
from argus.local import run_local
from tests.fixtures.gateway_ref import Entry, Preset, ReferenceGateway
from tests.fixtures.gateway_ref.oauth import OAuthReferenceGateway, StaticClient
from tests.gateway_fixtures.test_oauth import installation
from tests.gateway_target.test_target import entries, host, target_spec
from tests.gateway_target.test_webhook import CONTRACT


OAUTH_IDS = {
    'mcp_gateway_upstream_as_binding',
    'mcp_gateway_upstream_as_binding_mixup_iss',
    'mcp_gateway_upstream_as_binding_mixup_no_iss',
}
NON_OAUTH_IDS = {
    'mcp_gateway_client_credential_passthrough',
    'mcp_gateway_filter_delivery_paths',
    'mcp_gateway_header_cross_origin_redirect',
    'mcp_gateway_webhook_decision',
}


@pytest.mark.parametrize('preset,want,exit_code', [
    (Preset.safe(), 'pass', 0), (Preset.vulnerable(), 'fail', 3),
])
@pytest.mark.parametrize('declare_oauth', [False, True])
async def test_cli_all_two_origin_install_skips_oauth_without_errors(host, tmp_path, preset, want, exit_code, declare_oauth):
    fixture, _ = host
    hook = fixture.origin_urls['upstream'] + fixture.install['webhook']['path'].replace('{path_token}', fixture.install['path_token'])
    async with ReferenceGateway(entries(host), preset=preset, webhook_url=hook) as gateway:
        settings = target_spec(host, gateway)
        settings['case_window_s'] = 0.1
        settings['gateway']['auth'] = {'headers': {'Authorization': 'Bearer ' + secrets.token_hex(24)}}
        settings['features'].update(response_filter={'action': 'redact'}, webhook=CONTRACT)
        if declare_oauth:
            settings['features']['static_oauth_client'] = {'grant': 'authorization_code', 'consent': 'none', 'trigger': 'challenge'}
        report = tmp_path / 'all.json'
        process = await asyncio.create_subprocess_exec(sys.executable, '-m', 'argus.cli', 'run',
            '--local', '--target', json.dumps(settings), '--probes', 'all',
            '--format', 'json', '--out', str(report), '--fail-on', 'high',
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        output, _ = await process.communicate()
        findings = json.loads(report.read_text())['findings']
        assert {f['probe_id'] for f in findings} == OAUTH_IDS | NON_OAUTH_IDS, output.decode()
        assert {f['verdict'] for f in findings if f['probe_id'] in NON_OAUTH_IDS} == {want}
        for finding in findings:
            if finding['probe_id'] in OAUTH_IDS:
                assert finding['verdict'] == 'skipped', finding['reasoning']
                assert 'this install has no OAuth issuer' in finding['reasoning']
                assert 'gateway-fixtures init --oauth' in finding['reasoning']
        assert incomplete_lines(findings) == []
        assert run_exit_code(findings, None, None) == 0
        assert process.returncode == exit_code, output.decode()
        assert fixture.lease_id is None


async def test_oauth_install_without_static_feature_skips_all_oauth_probes(tmp_path):
    path = tmp_path / 'install.json'
    write_install(path, installation())
    settings = {
        'kind': 'mcp_gateway', 'sandbox': True, 'gateway': {'url': 'http://127.0.0.1:1/mcp'},
        'fixtures': {'control_url': 'http://127.0.0.1:2', 'control_token': secrets.token_hex(16), 'install_file': str(path)},
    }
    findings = [event async for event in run_local(settings, sorted(OAUTH_IDS), env={}) if 'verdict' in event]
    assert {f['probe_id'] for f in findings} == OAUTH_IDS
    assert {f['verdict'] for f in findings} == {'skipped'}
    assert all('static_oauth_client' in f['reasoning'] for f in findings)
    assert run_exit_code(findings, None, None) == 0


async def test_oauth_install_with_broken_issuer_errors_for_all_oauth_probes(tmp_path):
    async def unavailable(request):
        return web.Response(status=503)

    app = web.Application()
    app.router.add_route('*', '/{tail:.*}', unavailable)
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.3', 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    try:
        async with FixtureHost(installation(), control_token=secrets.token_hex(16), control_bind='127.0.0.1:0', settle_s=0.001) as fixture:
            for name, url in fixture.origin_urls.items():
                fixture.install['origins'][name]['public'] = url
            fixture.install['origins']['issuer']['public'] = f'http://127.0.0.3:{port}'
            path = tmp_path / 'install.json'
            write_install(path, fixture.install)
            client = fixture.install['entries']['oauth']
            async with OAuthReferenceGateway({'oauth': Entry(entry_url(fixture.install, 'oauth'))},
                clients={'oauth': StaticClient(issuer_url(fixture.install), client['client_id'], client['client_secret'], 'authorization_code')}) as gateway:
                settings = {
                    'kind': 'mcp_gateway', 'sandbox': True, 'gateway': {'url': gateway.url},
                    'fixtures': {'control_url': fixture.control_url, 'control_token': fixture.control_token, 'install_file': str(path)},
                    'features': {'static_oauth_client': {'grant': 'authorization_code', 'consent': 'none', 'trigger': 'challenge'}},
                    'timeout_s': 2, 'case_window_s': 0.1,
                }
                findings = [event async for event in run_local(settings, sorted(OAUTH_IDS), env={}) if 'verdict' in event]
                assert {f['probe_id'] for f in findings} == OAUTH_IDS
                assert {f['verdict'] for f in findings} == {'error'}, findings
                assert run_exit_code(findings, None, None) == 1
                assert fixture.lease_id is None
    finally:
        await runner.cleanup()
