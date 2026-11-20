"""Post-challenge MCP refusals require manual upstream re-authorization."""
import asyncio
import io
import json
import secrets
from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest

from argus.gateway_consent import ConsentDriver
from argus.gateway_fixtures.host import FixtureHost
from argus.gateway_fixtures.install import entry_url, write_install
from argus.gateway_fixtures.oauth import issuer_url
from argus.gateway_oauth_assertions import gateway_upstream_as_binding
from argus.runner import _send_failure
from argus.targets import build_target
from argus.targets._base import ProbeNotApplicable, TargetTransportError
from tests.fixtures.gateway_ref import Entry
from tests.fixtures.gateway_ref.oauth import StaticClient
from tests.fixtures.gateway_ref.out_of_band import OutOfBandOAuthReferenceGateway
from tests.gateway_fixtures.test_oauth import assert_private, installation


REASON = ('the gateway requires out-of-band re-authorization after the challenge; '
          'rerun interactively with consent: manual')


def recipe(trigger='challenge'):
    upstream = {'prm': {'authorization_servers': ['issuer']}, 'challenge': 'invalid_token'}
    if trigger == 'metadata':
        upstream.pop('challenge')
    elif trigger == 'neither':
        upstream = {}
    return {'version': 1, 'requires': ['static_oauth_client'], 'entries': ['oauth'],
            'cases': [{'id': 'baseline_issuer', 'role': 'control', 'entry': 'oauth', 'upstream': upstream},
                      {'id': 'switch_to_foreign', 'role': 'attack', 'entry': 'oauth',
                       'upstream': {'prm': {'authorization_servers': ['foreign']}, 'challenge': 'invalid_token'},
                       'foreign': {'as_mode': 'mirror_authorize'}, 'issuer': {'iss': 'never'}}],
            'drive': {'tool': 'echo', 'calls_per_case': 1, 'steps': ['consent']}}


@asynccontextmanager
async def running(tmp_path, *, mode='follow_url', strategy='issuer', status=403, trigger='challenge', timeout_s=2):
    async with FixtureHost(installation(), control_token=secrets.token_hex(16),
                           control_bind='127.0.0.1:0', settle_s=0.001) as host:
        for name, url in host.origin_urls.items():
            host.install['origins'][name]['public'] = url
        path = tmp_path / 'install.json'
        write_install(path, host.install)
        client = host.install['entries']['oauth']
        async with OutOfBandOAuthReferenceGateway({'oauth': Entry(entry_url(host.install, 'oauth'))},
                clients={'oauth': StaticClient(issuer_url(host.install), client['client_id'],
                                              client['client_secret'], 'authorization_code')},
                strategy=strategy, refusal_status=status) as gateway:
            target = build_target({'kind': 'mcp_gateway', 'sandbox': True,
                'gateway': {'url': gateway.url, 'protocol': '2025-11-25'},
                'fixtures': {'control_url': host.control_url, 'control_token': host.control_token,
                             'install_file': str(path)},
                'features': {'static_oauth_client': {'grant': 'authorization_code', 'consent': mode, 'trigger': 'challenge'}},
                'timeout_s': timeout_s, 'case_window_s': 0.1})
            await target.begin_probe(SimpleNamespace(id='synthetic-reauth', scenario_payload=json.dumps(recipe(trigger))))
            try:
                yield target, gateway, host
            finally:
                await target.aclose()


@pytest.mark.parametrize('mode,tty', [('follow_url', True), ('none', True), ('follow_url', False), ('none', False), ('manual', False)])
@pytest.mark.parametrize('status', [401, 403])
async def test_unfollowable_refusal_skips_with_retained_evidence(tmp_path, monkeypatch, mode, tty, status):
    monkeypatch.setattr('sys.stdin.isatty', lambda: tty)
    async with running(tmp_path, mode=mode, status=status) as (target, gateway, host):
        with pytest.raises(ProbeNotApplicable, match='out-of-band') as raised:
            await target.send_prompt('')
        assert _send_failure(raised.value) == ('skipped', REASON)
        evidence = await target.collect_evidence()
        case = evidence['cases'][0]
        refusal = case['client']['calls'][0]['transport_error']
        assert refusal['rpc_method'] == 'tools/call' and refusal['status'] == status
        assert refusal['body']['kind'] == 'text' and 'authorization' in refusal['body']['text']
        assert case['not_exercised'] == REASON
        assert gateway.blocked_calls == 1 and gateway.reauthorizations == 0
        assert host.lease_id is None
        assert_private(evidence, host.install['entries']['oauth']['client_secret'])


@pytest.mark.parametrize('strategy,want', [('issuer', 'pass'), ('entry', 'fail')])
async def test_manual_reauthorization_proves_issuer_binding(tmp_path, monkeypatch, capsys, strategy, want):
    async with running(tmp_path, mode='manual', strategy=strategy) as (target, gateway, host):
        ready = False
        class Terminal(io.StringIO):
            def isatty(self):
                return True
            def readline(self):
                nonlocal ready
                ready = False
                return '\n'
        monkeypatch.setattr('sys.stdin', Terminal())
        monkeypatch.setattr('argus.gateway_consent.select.select', lambda *args: ([args[0][0]], [], []) if ready else ([], [], []))
        async def authorize():
            nonlocal ready
            for _ in range(2):
                while not gateway.pending:
                    await asyncio.sleep(0.01)
                await gateway.reauthorize('oauth')
                ready = True
                while ready:
                    await asyncio.sleep(0.01)
        authorizer = asyncio.create_task(authorize())
        try:
            await target.send_prompt('')
            await asyncio.wait_for(authorizer, 3)
        finally:
            authorizer.cancel()
            await asyncio.gather(authorizer, return_exceptions=True)
        evidence = await target.collect_evidence()
        outcome = gateway_upstream_as_binding({'mode': 'mirror_authorize'}, evidence)
        assert outcome.verdict == want
        assert gateway.reauthorizations == gateway.blocked_calls == 2
        for case in evidence['cases']:
            assert len(case['client']['calls']) == 2
            step = case['client']['manual_out_of_band'][0]
            assert step['completed'] is True
            assert 0 <= step['started_ms'] <= step['completed_ms'] <= 2000
            assert step['duration_ms'] == step['completed_ms'] - step['started_ms']
        tokens = evidence['summary']['upstream_as_binding']['cases'][1]['token']
        assert any(token['at'] == 'foreign' and token['client_secret_hit'] for token in tokens) is (strategy == 'entry')
        output = capsys.readouterr().out
        assert 'gateway\'s own interface' in output and 'connection/authorization page' in output and 'press Enter' in output
        assert_private(evidence, host.install['entries']['oauth']['client_id'], host.install['entries']['oauth']['client_secret'])


async def test_403_before_challenge_remains_transport_error(tmp_path, monkeypatch):
    async with running(tmp_path, trigger='neither') as (target, gateway, host):
        original = gateway._request
        async def refused(name, request, **kwargs):
            if kwargs.get('message', {}).get('method') == 'tools/call':
                import httpx
                return httpx.Response(403, text='Access refused.')
            return await original(name, request, **kwargs)
        monkeypatch.setattr(gateway, '_request', refused)
        with pytest.raises(TargetTransportError) as raised:
            await target.send_prompt('')
        assert _send_failure(raised.value)[0] == 'error'
        assert (await target.collect_evidence())['transport_error']['status'] == 403


@pytest.mark.parametrize('status', [500, 503])
async def test_post_challenge_server_failure_remains_error(tmp_path, status):
    async with running(tmp_path, status=status) as (target, gateway, host):
        with pytest.raises(TargetTransportError) as raised:
            await target.send_prompt('')
        assert _send_failure(raised.value)[0] == 'error'
        assert (await target.collect_evidence())['transport_error']['status'] == status


@pytest.mark.parametrize('signal', ['url', 'error_url', 'mrtr'])
async def test_auth_refusal_with_mcp_consent_signal_is_not_out_of_band(tmp_path, monkeypatch, signal):
    async with running(tmp_path) as (target, gateway, host):
        original = gateway._request
        async def response(name, request, **kwargs):
            message = kwargs.get('message', {})
            if message.get('method') != 'tools/call':
                return await original(name, request, **kwargs)
            elicitation = {'mode': 'url', 'elicitationId': 'synthetic', 'message': 'Authorize upstream.',
                           'url': gateway.url.removesuffix('/mcp') + '/authorize'}
            if signal == 'url':
                body = {'jsonrpc': '2.0', 'id': 7, 'method': 'elicitation/create', 'params': elicitation}
            elif signal == 'error_url':
                body = {'jsonrpc': '2.0', 'id': message['id'], 'error': {'code': -32042,
                        'message': 'Authorization required.', 'data': {'elicitations': [elicitation]}}}
            else:
                body = {'jsonrpc': '2.0', 'id': message['id'], 'result': {'resultType': 'input_required',
                        'inputRequests': {'authorize': {'method': 'elicitation/create', 'params': elicitation}}}}
            import httpx
            return httpx.Response(403, json=body)
        monkeypatch.setattr(gateway, '_request', response)
        with pytest.raises(TargetTransportError):
            await target.send_prompt('')
        assert (await target.collect_evidence())['transport_error']['consent_signal'] is True
        assert gateway.reauthorizations == 0


@pytest.mark.parametrize('ending', ['timeout', 'eof'])
async def test_manual_wait_is_bounded_and_retains_attempt(tmp_path, monkeypatch, ending):
    class Terminal(io.StringIO):
        def isatty(self):
            return True
    terminal = Terminal('')
    monkeypatch.setattr('sys.stdin', terminal)
    monkeypatch.setattr('argus.gateway_consent.select.select',
                        lambda *args: ([terminal], [], []) if ending == 'eof' else ([], [], []))
    async with running(tmp_path, mode='manual', timeout_s=0.2) as (target, gateway, host):
        with pytest.raises(ProbeNotApplicable, match='timed out|cancelled'):
            await asyncio.wait_for(target.send_prompt(''), 2)
        evidence = await target.collect_evidence()
        step = evidence['cases'][0]['client']['manual_out_of_band'][0]
        assert step['completed'] is False and step['duration_ms'] < 1000
        assert gateway.blocked_calls == 1 and gateway.reauthorizations == 0
        assert host.lease_id is None


async def test_removing_classification_restores_error(tmp_path, monkeypatch):
    monkeypatch.setattr(ConsentDriver, 'requires_out_of_band', lambda *args, **kwargs: False)
    async with running(tmp_path) as (target, gateway, host):
        with pytest.raises(TargetTransportError) as raised:
            await target.send_prompt('')
        assert _send_failure(raised.value)[0] == 'error'
        assert (await target.collect_evidence())['transport_error']['status'] == 403


async def test_metadata_change_without_explicit_challenge_can_require_reauthorization(tmp_path, monkeypatch):
    async with running(tmp_path, trigger='metadata') as (target, gateway, host):
        original = gateway._request
        async def invalidate(name, request, **kwargs):
            if kwargs.get('message', {}).get('method') == 'tools/call':
                gateway.tokens.clear()
            return await original(name, request, **kwargs)
        monkeypatch.setattr(gateway, '_request', invalidate)
        with pytest.raises(ProbeNotApplicable, match='out-of-band'):
            await target.send_prompt('')
        assert (await target.collect_evidence())['cases'][0]['client']['calls'][0]['transport_error']['status'] == 403


@pytest.mark.parametrize('probe_id', ['mcp_gateway_upstream_as_binding', 'mcp_gateway_upstream_as_binding_mixup_iss',
                                    'mcp_gateway_upstream_as_binding_mixup_no_iss'])
async def test_local_run_skips_issuer_binding_probe_with_evidence(tmp_path, probe_id):
    from dataclasses import asdict
    from argus.local import run_local
    async with running(tmp_path) as (target, gateway, host):
        settings = {'kind': 'mcp_gateway', **asdict(target.spec)}
        findings = [event async for event in run_local(settings, [probe_id], env={}) if 'verdict' in event]
        assert len(findings) == 1
        assert {finding['verdict'] for finding in findings} == {'skipped'}
        assert all(finding['reasoning'] == REASON for finding in findings)
        assert all(finding['evidence']['cases'][0]['client']['calls'][0]['transport_error']['status'] == 403
                   for finding in findings)
        assert host.lease_id is None


async def test_complete_long_text_refusal_skips_despite_export_truncation(tmp_path, monkeypatch):
    async with running(tmp_path) as (target, gateway, host):
        original = gateway._request
        async def refusal(name, request, **kwargs):
            if kwargs.get('message', {}).get('method') == 'tools/call':
                import httpx
                return httpx.Response(403, text='Authorization required. ' * 40)
            return await original(name, request, **kwargs)
        monkeypatch.setattr(gateway, '_request', refusal)
        with pytest.raises(ProbeNotApplicable, match='out-of-band'):
            await target.send_prompt('')
        body = (await target.collect_evidence())['cases'][0]['client']['calls'][0]['transport_error']['body']
        assert body['truncated'] is True
        assert len(body['text'].encode()) == 512
