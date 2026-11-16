"""Offline checks of target egress policy through real HTTP clients."""
import asyncio
from contextlib import asynccontextmanager

import pytest
from aiohttp import web

from argus.targets.openai_compat import OpenAICompatSpec, OpenAICompatTarget


@asynccontextmanager
async def server(handler):
    app = web.Application()
    app.router.add_route('*', '/{path:.*}', handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', 0)
    await site.start()
    try:
        yield f'http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}'
    finally:
        await runner.cleanup()


async def test_loopback_target_is_refused_when_enabled(monkeypatch):
    monkeypatch.setenv('ARGUS_TARGET_ADDRESS_POLICY', 'public_only')
    calls = []
    async def handle(request):
        calls.append(request.path)
        return web.json_response({'choices': [{'message': {'content': 'answer'}}]})
    async with server(handle) as url:
        target = OpenAICompatTarget(OpenAICompatSpec(endpoint_url=url, model='test'))
        with pytest.raises(Exception, match='target address not allowed by the address policy'):
            await target.send_prompt('hello')
    assert calls == []


async def test_loopback_target_works_by_default(monkeypatch):
    monkeypatch.delenv('ARGUS_TARGET_ADDRESS_POLICY', raising=False)
    async def handle(request):
        return web.json_response({'choices': [{'message': {'content': 'answer'}}]})
    async with server(handle) as url:
        target = OpenAICompatTarget(OpenAICompatSpec(endpoint_url=url, model='test'))
        text, _ = await target.send_prompt('hello')
        assert text == 'answer'


@pytest.fixture
def fake_dial(monkeypatch):
    """Keep all wire traffic on loopback, even when testing public DNS answers."""
    from httpcore._backends.anyio import AnyIOBackend
    from httpcore2._backends.anyio import AnyIOBackend as Backend2
    original = AnyIOBackend.connect_tcp
    connections = []
    async def connect(self, host, port, **kwargs):
        connections.append(host)
        return await original(self, '127.0.0.1', port, **kwargs)
    monkeypatch.setattr(AnyIOBackend, 'connect_tcp', connect)
    monkeypatch.setattr(Backend2, 'connect_tcp', connect)
    return connections


@pytest.mark.parametrize('address', [
    '127.0.0.1', '::1', '10.1.2.3', '172.16.2.3', '192.168.2.3',
    '169.254.169.254', '0.0.0.0', '::ffff:127.0.0.1', 'fc00::1', 'fd00::1',
    '100.64.0.1',
])
async def test_non_global_literals_never_connect(monkeypatch, fake_dial, address):
    monkeypatch.setenv('ARGUS_TARGET_ADDRESS_POLICY', 'public_only')
    async def handle(request):
        return web.json_response({'choices': [{'message': {'content': 'answer'}}]})
    async with server(handle) as local:
        host = f'[{address}]' if ':' in address else address
        url = local.replace('127.0.0.1', host)
        target = OpenAICompatTarget(OpenAICompatSpec(endpoint_url=url, model='test'))
        with pytest.raises(Exception, match='target address not allowed by the address policy') as exc:
            await target.send_prompt('hello')
        assert address not in str(exc.value)
    assert fake_dial == []


def fake_dns(monkeypatch, answers):
    import anyio
    import socket
    original = anyio.getaddrinfo
    calls = []
    async def resolve(host, port, **kwargs):
        if host == 'target.invalid':
            calls.append(host)
            ips = answers[min(len(calls)-1, len(answers)-1)]
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (ip, port)) for ip in ips]
        return await original(host, port, **kwargs)
    monkeypatch.setattr(anyio, 'getaddrinfo', resolve)
    return calls


async def test_rebinding_is_refused_at_connect_time(monkeypatch, fake_dial):
    from argus_transport.address_policy import resolve_addresses
    monkeypatch.setenv('ARGUS_TARGET_ADDRESS_POLICY', 'public_only')
    calls = fake_dns(monkeypatch, [['8.8.8.8'], ['10.1.2.3']])
    async def handle(request):
        return web.json_response({'choices': [{'message': {'content': 'answer'}}]})
    async with server(handle) as local:
        url = local.replace('127.0.0.1', 'target.invalid')
        port = int(local.rsplit(':', 1)[1])
        assert await resolve_addresses('target.invalid', port) == ['8.8.8.8']
        target = OpenAICompatTarget(OpenAICompatSpec(endpoint_url=url, model='test'))
        with pytest.raises(Exception, match='target address not allowed by the address policy'):
            await target.send_prompt('hello')
    assert len(calls) == 2
    assert fake_dial == []


async def test_mixed_dns_answers_are_refused(monkeypatch, fake_dial):
    monkeypatch.setenv('ARGUS_TARGET_ADDRESS_POLICY', 'public_only')
    fake_dns(monkeypatch, [['8.8.8.8', '10.1.2.3']])
    async def handle(request):
        return web.json_response({'choices': [{'message': {'content': 'answer'}}]})
    async with server(handle) as local:
        target = OpenAICompatTarget(OpenAICompatSpec(
            endpoint_url=local.replace('127.0.0.1', 'target.invalid'), model='test'))
        with pytest.raises(Exception, match='target address not allowed by the address policy'):
            await target.send_prompt('hello')
    assert fake_dial == []


async def test_public_address_is_pinned_with_original_host(monkeypatch, fake_dial):
    monkeypatch.setenv('ARGUS_TARGET_ADDRESS_POLICY', 'public_only')
    calls = fake_dns(monkeypatch, [['8.8.8.8'], ['10.1.2.3']])
    hosts = []
    async def handle(request):
        hosts.append(request.host)
        return web.json_response({'choices': [{'message': {'content': 'answer'}}]})
    async with server(handle) as local:
        url = local.replace('127.0.0.1', 'target.invalid')
        target = OpenAICompatTarget(OpenAICompatSpec(endpoint_url=url, model='test'))
        assert (await target.send_prompt('hello'))[0] == 'answer'
    assert fake_dial == ['8.8.8.8']
    assert len(calls) == 1
    assert hosts == [url.removeprefix('http://')]


async def test_redirect_hop_to_private_address_is_refused(monkeypatch, fake_dial):
    from argus.targets.anthropic_native import AnthropicNativeSpec, AnthropicNativeTarget
    monkeypatch.setenv('ARGUS_TARGET_ADDRESS_POLICY', 'public_only')
    fake_dns(monkeypatch, [['8.8.8.8']])
    calls = []
    async def handle(request):
        calls.append(request.path)
        raise web.HTTPTemporaryRedirect(location=local+'/private')
    async with server(handle) as local:
        monkeypatch.setenv('ANTHROPIC_BASE_URL', local.replace('127.0.0.1', 'target.invalid'))
        target = AnthropicNativeTarget(AnthropicNativeSpec(model='test', api_key='fake'))
        with pytest.raises(Exception, match='target address not allowed by the address policy'):
            await target.send_prompt('hello')
    # The SDK retries; every redirect is checked, and the private hop is never dialled.
    assert '/private' not in calls
    assert fake_dial and set(fake_dial) == {'8.8.8.8'}


async def test_retry_rechecks_dns(monkeypatch, fake_dial):
    from argus.targets.anthropic_native import AnthropicNativeSpec, AnthropicNativeTarget
    monkeypatch.setenv('ARGUS_TARGET_ADDRESS_POLICY', 'public_only')
    calls = fake_dns(monkeypatch, [['8.8.8.8'], ['10.1.2.3']])
    async def handle(request):
        return web.Response(status=503, headers={'Connection': 'close'})
    async with server(handle) as local:
        monkeypatch.setenv('ANTHROPIC_BASE_URL', local.replace('127.0.0.1', 'target.invalid'))
        target = AnthropicNativeTarget(AnthropicNativeSpec(model='test', api_key='fake'))
        with pytest.raises(Exception, match='target address not allowed by the address policy'):
            await target.send_prompt('hello')
    assert len(calls) == 2
    assert fake_dial == ['8.8.8.8']


KINDS = ['custom_http', 'custom_http_v1', 'custom_http_v2', 'openai_compat',
         'http_upload', 'mcp_server', 'vllm_server', 'a2a_server',
         'mcp_agent', 'payment_agent', 'a2a_agent', 'testbed_agent']


def target_for(kind, url):
    from argus.targets import build_target
    from test_transport_engine import spec_dict
    base = {'kind': kind}
    if kind in ('custom_http_v1', 'custom_http_v2'):
        transport = spec_dict(url)
        transport['version'] = int(kind[-1])
        return build_target({'kind': 'custom_http', 'transport': transport})
    if kind == 'custom_http':
        base.update(request_url=url, request_method='POST', request_body_template='{}', response_jsonpath='$.result')
    elif kind == 'openai_compat':
        base.update(endpoint_url=url, model='test')
    elif kind == 'http_upload':
        base.update(upload_url=url, render_url_jsonpath='$.url')
    elif kind.endswith('_agent'):
        base.update(testbed_url=url, sandbox=True, inner={
            'kind': 'openai_compat', 'endpoint_url': url, 'model': 'test'})
        if kind == 'testbed_agent':
            base['environment'] = 'mcp'
    else:
        base['url'] = url
    target = build_target(base)
    if kind == 'a2a_server':
        target._check = 'card_unsigned'
    return target


@pytest.mark.parametrize('kind', KINDS)
@pytest.mark.parametrize('enabled', [False, True])
async def test_every_http_target_real_path(monkeypatch, kind, enabled):
    from argus_transport import local_transport_mode
    monkeypatch.setenv('ARGUS_TARGET_ADDRESS_POLICY', 'public_only' if enabled else '')
    calls = []
    async def handle(request):
        calls.append(request.path)
        return web.json_response({
            'choices': [{'message': {'content': 'answer'}}], 'status': 'COMPLETED',
            'result': 'answer', 'version': '1.0.0', 'session_id': 'test',
            'mcp_url': 'http://example.invalid/mcp', 'merchant_url': 'http://example.invalid/pay',
            'a2a_url': 'http://example.invalid/a2a',
        })
    async with server(handle) as url:
        target = target_for(kind, url)
        with local_transport_mode():
            if enabled:
                with pytest.raises(Exception, match='target address not allowed by the address policy'):
                    await target.send_prompt('hello')
                assert calls == []
            else:
                text, _ = await target.send_prompt('hello')
                assert isinstance(text, str)
                assert calls


async def test_upload_response_followup_is_guarded(monkeypatch, fake_dial):
    from argus.targets.http_upload import HTTPUploadSpec, HTTPUploadTarget
    monkeypatch.setenv('ARGUS_TARGET_ADDRESS_POLICY', 'public_only')
    fake_dns(monkeypatch, [['8.8.8.8']])
    calls = []
    async def handle(request):
        calls.append(request.path)
        return web.json_response({'url': local+'/render'})
    async with server(handle) as local:
        target = HTTPUploadTarget(HTTPUploadSpec(
            upload_url=local.replace('127.0.0.1', 'target.invalid'), render_url_jsonpath='$.url'))
        with pytest.raises(Exception, match='target address not allowed by the address policy'):
            await target.send_prompt('hello')
    assert calls == ['/']
    assert fake_dial == ['8.8.8.8']


@pytest.mark.parametrize('enabled', [False, True])
async def test_scan_http_sdk_path(monkeypatch, enabled):
    from argus.mcp_scan.client import HttpServer, open_session, ConnectError
    from mcp_scan_harness import serve_http
    monkeypatch.setenv('ARGUS_TARGET_ADDRESS_POLICY', 'public_only' if enabled else '')
    with serve_http('basic') as url:
        if enabled:
            with pytest.raises(ConnectError, match='target address not allowed by the address policy') as exc:
                async with open_session(HttpServer(url), timeout_s=3):
                    pytest.fail('forbidden target connected')
            assert exc.value.code == 'address_policy'
        else:
            async with open_session(HttpServer(url), timeout_s=3) as session:
                tools, notes = await session.list_tools()
                assert tools and notes == []


async def test_grpc_target_refused(monkeypatch):
    from argus.targets.grpc import GRPCSpec, GRPCTarget
    monkeypatch.setenv('ARGUS_TARGET_ADDRESS_POLICY', 'public_only')
    target = GRPCTarget(GRPCSpec(endpoint='127.0.0.1:1', service_method='echo.Echo/Chat', tls=False))
    with pytest.raises(Exception, match='target address not allowed by the address policy'):
        await target.send_prompt('hello')


async def test_policy_error_is_reported_as_error(monkeypatch):
    from test_runner_target_failures import _run, _probe
    monkeypatch.setenv('ARGUS_TARGET_ADDRESS_POLICY', 'public_only')
    async def handle(request):
        return web.json_response({'choices': [{'message': {'content': 'answer'}}]})
    async with server(handle) as url:
        target = target_for('openai_compat', url)
        findings, judge = await _run(target, [_probe()])
    assert [f.verdict for f in findings] == ['error']
    assert 'target address not allowed by the address policy' in findings[0].reasoning
    assert judge.seen == []
    import json
    from dataclasses import asdict
    from argus.cli.run_json import render_json
    from argus.cli.reports import render_html
    run = {'id': 'test-run', 'status': 'incomplete', 'target_spec': {'kind': 'openai_compat', 'endpoint_url': url},
           'findings': [asdict(f) for f in findings]}
    record = json.loads(render_json(run))
    assert record['findings'][0]['verdict'] == 'error'
    assert 'target address not allowed by the address policy' in render_html(run)


def test_unknown_policy_stops_cli_startup(monkeypatch):
    from click.testing import CliRunner
    from argus.cli.__main__ import main
    monkeypatch.setenv('ARGUS_TARGET_ADDRESS_POLICY', 'typo')
    result = CliRunner().invoke(main, ['list-probes'])
    assert result.exit_code != 0
    assert 'ARGUS_TARGET_ADDRESS_POLICY' in result.output


async def test_unknown_policy_stops_server_startup(monkeypatch):
    import argus.server as server_module
    monkeypatch.setenv('ARGUS_TARGET_ADDRESS_POLICY', 'typo')
    with pytest.raises(ValueError, match='ARGUS_TARGET_ADDRESS_POLICY'):
        async with server_module._lifespan(server_module.app):
            pytest.fail('server started with invalid policy')


@pytest.mark.parametrize('enabled', [False, True])
async def test_native_target_loopback(monkeypatch, enabled):
    from argus.targets.anthropic_native import AnthropicNativeSpec, AnthropicNativeTarget
    monkeypatch.setenv('ARGUS_TARGET_ADDRESS_POLICY', 'public_only' if enabled else '')
    async def handle(request):
        return web.json_response({'id': 'test', 'type': 'message', 'role': 'assistant',
            'model': 'test', 'content': [{'type': 'text', 'text': 'answer'}],
            'stop_reason': 'end_turn', 'stop_sequence': None,
            'usage': {'input_tokens': 1, 'output_tokens': 1}})
    async with server(handle) as url:
        monkeypatch.setenv('ANTHROPIC_BASE_URL', url)
        target = AnthropicNativeTarget(AnthropicNativeSpec(model='test', api_key='fake'))
        if enabled:
            with pytest.raises(Exception, match='target address not allowed by the address policy'):
                await target.send_prompt('hello')
        else:
            assert (await target.send_prompt('hello'))[0] == 'answer'
            import gc
            gc.collect()
            await asyncio.sleep(0)


@pytest.mark.parametrize('enabled', [False, True])
async def test_browser_http_delivery(monkeypatch, enabled):
    from argus.browser_runner.target_agent_driver import TargetAgentDriver
    monkeypatch.setenv('ARGUS_TARGET_ADDRESS_POLICY', 'public_only' if enabled else '')
    async def handle(request):
        return web.json_response({'final_text': 'answer'})
    async with server(handle) as url:
        driver = TargetAgentDriver(agent_url=url, scenario_url='https://example.invalid/page', prompt='hello')
        if enabled:
            with pytest.raises(Exception, match='target address not allowed by the address policy'):
                await driver.run()
        else:
            assert (await driver.run()).response_text == 'answer'


@pytest.mark.parametrize('enabled', [False, True])
async def test_hosted_trap_control(monkeypatch, enabled):
    from types import SimpleNamespace
    from argus.targets.hosted_trap import HostedClient
    monkeypatch.setenv('ARGUS_TARGET_ADDRESS_POLICY', 'public_only' if enabled else '')
    monkeypatch.setenv('ARGUS_TEST_OWNER', 'fake')
    async def handle(request):
        return web.json_response({'ok': True})
    async with server(handle) as url:
        client = HostedClient(SimpleNamespace(service_url=url, owner_token_env='ARGUS_TEST_OWNER'))
        try:
            if enabled:
                with pytest.raises(Exception, match='target address not allowed by the address policy'):
                    await client._request('POST', '/v1/runs', json={})
            else:
                assert await client._request('POST', '/v1/runs', json={}) == {'ok': True}
        finally:
            await client._http.aclose()


@pytest.mark.parametrize('enabled', [False, True])
async def test_a2a_receiver_ingress(monkeypatch, enabled):
    from types import SimpleNamespace
    from argus.targets.a2a_agent import deliver_ingress
    monkeypatch.setenv('ARGUS_TARGET_ADDRESS_POLICY', 'public_only' if enabled else '')
    rows = []
    async def log(row):
        rows.append(row)
    async def handle(request):
        return web.json_response({'task': {'id': 't', 'status': {'state': 'completed'}}})
    async with server(handle) as url:
        spec = SimpleNamespace(receiver={'url': url}, timeout_s=3)
        delivery = {'message': {'messageId': 'm', 'role': 'user', 'parts': [{'text': 'hello'}]}}
        if enabled:
            with pytest.raises(Exception, match='target address not allowed by the address policy'):
                await deliver_ingress(spec, [delivery], log)
            assert rows == []
        else:
            await deliver_ingress(spec, [delivery], log)
            assert rows[0]['http_status'] == 200


@pytest.mark.parametrize('version', [1, 2])
async def test_poll_delivery_is_guarded(monkeypatch, fake_dial, version):
    from argus.targets import build_target
    from argus_transport import local_transport_mode
    from test_transport_poll import poll_dict
    monkeypatch.setenv('ARGUS_TARGET_ADDRESS_POLICY', 'public_only')
    fake_dns(monkeypatch, [['8.8.8.8']])
    loop = asyncio.get_running_loop()
    original = loop.getaddrinfo
    resolutions = []
    async def resolve(host, *args, **kwargs):
        if host == 'target.invalid':
            resolutions.append(host)
            return await original('8.8.8.8' if len(resolutions) == 1 else '10.1.2.3', *args, **kwargs)
        return await original(host, *args, **kwargs)
    monkeypatch.setattr(loop, 'getaddrinfo', resolve)
    calls = []
    async def handle(request):
        calls.append(request.path)
        return web.json_response({'run_id': 't', 'status': 'PENDING'}, status=202)
    async with server(handle) as local:
        spec = poll_dict(local.replace('127.0.0.1', 'target.invalid')+'/run')
        spec['version'] = version
        target = build_target({'kind': 'custom_http', 'transport': spec})
        with local_transport_mode():
            with pytest.raises(Exception, match='target address not allowed by the address policy'):
                await target.send_prompt('hello')
    assert calls == ['/run']
    assert len(resolutions) == 2
    assert fake_dial == ['8.8.8.8']


async def test_public_ipv4_mapped_address_can_connect(monkeypatch, fake_dial):
    monkeypatch.setenv('ARGUS_TARGET_ADDRESS_POLICY', 'public_only')
    async def handle(request):
        return web.json_response({'choices': [{'message': {'content': 'answer'}}]})
    async with server(handle) as local:
        target = target_for('openai_compat', local.replace('127.0.0.1', '[::ffff:8.8.8.8]'))
        assert (await target.send_prompt('hello'))[0] == 'answer'
    assert fake_dial == ['::ffff:8.8.8.8']


async def test_guard_ignores_environment_proxy(monkeypatch, fake_dial):
    monkeypatch.setenv('ARGUS_TARGET_ADDRESS_POLICY', 'public_only')
    monkeypatch.setenv('HTTP_PROXY', 'http://127.0.0.1:1')
    monkeypatch.setenv('ALL_PROXY', 'http://127.0.0.1:1')
    fake_dns(monkeypatch, [['8.8.8.8']])
    async def handle(request):
        return web.json_response({'choices': [{'message': {'content': 'answer'}}]})
    async with server(handle) as local:
        target = target_for('openai_compat', local.replace('127.0.0.1', 'target.invalid'))
        assert (await target.send_prompt('hello'))[0] == 'answer'
    assert fake_dial == ['8.8.8.8']


async def test_grpc_loopback_works_when_off(monkeypatch):
    from test_redteam_targets_grpc import test_grpc_adapter_against_in_memory_echo_servicer
    monkeypatch.setenv('ARGUS_TARGET_ADDRESS_POLICY', '')
    await test_grpc_adapter_against_in_memory_echo_servicer()


async def test_testbed_teardown_policy_refusal_is_an_error(monkeypatch):
    monkeypatch.setenv('ARGUS_TARGET_ADDRESS_POLICY', '')
    async def handle(request):
        return web.json_response({'session_id': 't'})
    async with server(handle) as local:
        target = target_for('mcp_agent', local)
        await target._open_session()
        monkeypatch.setenv('ARGUS_TARGET_ADDRESS_POLICY', 'public_only')
        with pytest.raises(Exception, match='target address not allowed by the address policy'):
            await target._close_session()


async def test_abort_refusal_is_not_hidden(monkeypatch, fake_dial):
    from test_transport_v2_abort import abort_spec, abort_app
    from transport_v2_fakes import serve
    from argus_transport.spec_v2 import TransportSpecV2
    from argus_transport.runtime_v2 import V2Run
    from argus_transport import ExecutionPolicy, TransportContext
    monkeypatch.setenv('ARGUS_TARGET_ADDRESS_POLICY', 'public_only')
    loop = asyncio.get_running_loop()
    original = loop.getaddrinfo
    resolutions = []
    async def resolve(host, *args, **kwargs):
        if host == 'target.invalid':
            resolutions.append(host)
            return await original('8.8.8.8' if len(resolutions) < 3 else '10.1.2.3', *args, **kwargs)
        return await original(host, *args, **kwargs)
    monkeypatch.setattr(loop, 'getaddrinfo', resolve)
    app = abort_app()
    async with serve(app) as local:
        data = abort_spec(local.replace('127.0.0.1', 'target.invalid')+'/run')
        data['delivery']['max_polls'] = 1
        spec = TransportSpecV2.from_dict(data)
        run = V2Run(spec, policy=ExecutionPolicy.local(spec))
        with pytest.raises(Exception, match='target address not allowed by the address policy'):
            await run.attempt(TransportContext(prompt='hello'))
    assert len(resolutions) == 3
    assert not any(call[1].endswith(':stop') for call in app.calls)


async def test_dns_failure_is_a_target_error(monkeypatch):
    import anyio
    import socket
    from test_runner_target_failures import _run, _probe
    monkeypatch.setenv('ARGUS_TARGET_ADDRESS_POLICY', 'public_only')
    async def resolve(*args, **kwargs):
        raise socket.gaierror('fake resolver failure')
    monkeypatch.setattr(anyio, 'getaddrinfo', resolve)
    findings, judge = await _run(target_for('openai_compat', 'http://target.invalid:1'), [_probe()])
    assert [f.verdict for f in findings] == ['error']
    assert judge.seen == []


async def test_scan_session_termination_refusal_is_reported(monkeypatch, fake_dial):
    from argus.mcp_scan.client import HttpServer, open_session, ConnectError
    monkeypatch.setenv('ARGUS_TARGET_ADDRESS_POLICY', 'public_only')
    fake_dns(monkeypatch, [['8.8.8.8']])
    calls = []
    async def handle(request):
        calls.append(request.method)
        headers = {'Connection': 'close', 'Mcp-Session-Id': 'test-session'}
        if request.method == 'GET':
            return web.Response(status=405, headers=headers)
        if request.method == 'DELETE':
            return web.Response(status=200, headers=headers)
        body = await request.json()
        if body['method'] == 'initialize':
            return web.json_response({'jsonrpc': '2.0', 'id': body['id'], 'result': {
                'protocolVersion': body['params']['protocolVersion'], 'capabilities': {},
                'serverInfo': {'name': 'fixture', 'version': '1.0'}}}, headers=headers)
        return web.Response(status=202, headers=headers)
    async with server(handle) as local:
        url = local.replace('127.0.0.1', 'target.invalid')
        with pytest.raises(ConnectError, match='target address not allowed by the address policy'):
            async with open_session(HttpServer(url), timeout_s=3):
                fake_dns(monkeypatch, [['10.1.2.3']])
    assert 'DELETE' not in calls
    assert fake_dial and set(fake_dial) == {'8.8.8.8'}


@pytest.mark.parametrize('retry_status', [200, 400])
async def test_native_retry_cannot_hide_a_policy_refusal(monkeypatch, fake_dial, retry_status):
    from argus.targets.anthropic_native import AnthropicNativeSpec, AnthropicNativeTarget
    monkeypatch.setenv('ARGUS_TARGET_ADDRESS_POLICY', 'public_only')
    fake_dns(monkeypatch, [['10.1.2.3'], ['8.8.8.8']])
    async def handle(request):
        if retry_status != 200:
            return web.json_response({'error': {'type': 'invalid_request_error', 'message': 'test'}}, status=retry_status)
        return web.json_response({'id': 'test', 'type': 'message', 'role': 'assistant',
            'model': 'test', 'content': [{'type': 'text', 'text': 'answer'}],
            'stop_reason': 'end_turn', 'stop_sequence': None,
            'usage': {'input_tokens': 1, 'output_tokens': 1}})
    async with server(handle) as local:
        monkeypatch.setenv('ANTHROPIC_BASE_URL', local.replace('127.0.0.1', 'target.invalid'))
        target = AnthropicNativeTarget(AnthropicNativeSpec(model='test', api_key='fake'))
        with pytest.raises(Exception, match='target address not allowed by the address policy'):
            await target.send_prompt('hello')
