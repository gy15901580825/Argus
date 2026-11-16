"""Offline regressions for construction, startup, and connect-time enforcement."""
import asyncio
import importlib.machinery
import sys
import types

import httpx
import pytest
from aiohttp import web

from argus_transport.address_policy import TargetAddressPolicyError, target_client
from test_target_address_policy import fake_dial, fake_dns, server


@pytest.fixture
def stub_playwright(monkeypatch):
    visited = []

    class Page:
        def is_closed(self):
            return False

        async def goto(self, url, **kwargs):
            visited.append(url)
            raise RuntimeError('stop after navigation')

    class Context:
        async def new_page(self):
            return Page()

        async def close(self):
            pass

    class Browser:
        async def new_context(self, **kwargs):
            return Context()

        async def close(self):
            pass

    class Chromium:
        async def launch(self, **kwargs):
            return Browser()

    class Playwright:
        chromium = Chromium()

        async def stop(self):
            pass

    class Starter:
        async def start(self):
            return Playwright()

    api = types.ModuleType('playwright.async_api')
    api.async_playwright = Starter
    api.Error = type('Error', (Exception,), {})
    api.TimeoutError = type('TimeoutError', (api.Error,), {})
    package = types.ModuleType('playwright')
    package.__spec__ = importlib.machinery.ModuleSpec('playwright', None)
    package.async_api = api
    monkeypatch.setitem(sys.modules, 'playwright', package)
    monkeypatch.setitem(sys.modules, 'playwright.async_api', api)
    return visited


def web_spec(kind):
    spec = {'kind': 'web_chat', 'url': 'http://169.254.169.254/',
            'input_selector': 'textarea', 'response_selector': 'pre'}
    if kind != 'web_chat':
        spec = {'kind': kind, 'testbed_url': 'http://127.0.0.1:1',
                'sandbox': True, 'inner': spec}
        if kind == 'testbed_agent':
            spec['environment'] = 'mcp'
    return spec


@pytest.mark.parametrize('kind', ['web_chat', 'mcp_agent', 'a2a_agent', 'payment_agent', 'testbed_agent'])
async def test_web_chat_refused_before_navigation(monkeypatch, stub_playwright, kind):
    from argus.targets import build_target
    monkeypatch.setenv('ARGUS_TARGET_ADDRESS_POLICY', 'public_only')
    with pytest.raises(TargetAddressPolicyError):
        target = build_target(web_spec(kind))
        # The old constructor succeeds; demonstrate its browser bypass offline.
        inner = getattr(target, '_inner', target)
        try:
            await inner.send_prompt('hello')
        finally:
            await inner.aclose()
    assert stub_playwright == []


async def test_web_chat_direct_constructor_refused(monkeypatch, stub_playwright):
    from argus.targets.web_chat import WebChatSpec, WebChatTarget
    monkeypatch.setenv('ARGUS_TARGET_ADDRESS_POLICY', 'public_only')
    with pytest.raises(TargetAddressPolicyError):
        WebChatTarget(WebChatSpec(**web_spec('web_chat')))
    assert stub_playwright == []


@pytest.mark.parametrize('kind', ['web_chat', 'testbed_agent'])
@pytest.mark.parametrize('route', ['preflight', 'run'])
async def test_web_chat_api_returns_target_error(monkeypatch, stub_playwright, kind, route):
    import argus.api as api
    from fastapi import HTTPException
    monkeypatch.setenv('ARGUS_TARGET_ADDRESS_POLICY', 'public_only')
    monkeypatch.setattr(api.llm, 'credential_error', lambda cfg: None)
    with pytest.raises(HTTPException) as caught:
        await getattr(api, route)(api.RunRequest(target=web_spec(kind)))
    assert caught.value.status_code == 422
    assert caught.value.detail == str(TargetAddressPolicyError())
    assert stub_playwright == []


async def test_web_chat_still_constructs_when_off(monkeypatch, stub_playwright):
    from argus.targets import build_target
    monkeypatch.delenv('ARGUS_TARGET_ADDRESS_POLICY', raising=False)
    target = build_target(web_spec('web_chat'))
    with pytest.raises(RuntimeError, match='stop after navigation'):
        await target.send_prompt('hello')
    await target.aclose()
    assert stub_playwright == ['http://169.254.169.254/']


@pytest.mark.parametrize('module_name', ['httpx', 'httpx2'])
@pytest.mark.parametrize('backend_state', ['absent', 'wrong_type', 'wrong_core'])
async def test_pool_backend_change_fails_closed(monkeypatch, module_name, backend_state):
    import importlib
    import httpcore
    import httpcore2
    module = importlib.import_module(module_name)
    original = module.AsyncHTTPTransport
    transports = []

    def changed_pool(**kwargs):
        transport = original(**kwargs)
        transports.append(transport)
        if backend_state == 'absent':
            del transport._pool._network_backend
        elif backend_state == 'wrong_type':
            transport._pool._network_backend = object()
        else:
            other = httpcore2 if module_name == 'httpx' else httpcore
            transport._pool._network_backend = other.AnyIOBackend()
        return transport

    monkeypatch.setenv('ARGUS_TARGET_ADDRESS_POLICY', 'public_only')
    monkeypatch.setattr(module, 'AsyncHTTPTransport', changed_pool)
    try:
        with pytest.raises(TargetAddressPolicyError):
            async with target_client(module):
                pass
    finally:
        for transport in transports:
            await transport.aclose()


@pytest.fixture
def neutralised_guard(monkeypatch):
    import argus_transport.address_policy as policy
    import httpcore
    import httpcore2
    monkeypatch.setenv('ARGUS_TARGET_ADDRESS_POLICY', 'public_only')
    attempted = []

    async def unchecked(host, port):
        return host

    async def connect(self, host, port, **kwargs):
        attempted.append((host, port))
        raise OSError('offline socket failure')

    monkeypatch.setattr(policy, 'checked_address', unchecked)
    monkeypatch.setattr(httpcore.AnyIOBackend, 'connect_tcp', connect)
    monkeypatch.setattr(httpcore2.AnyIOBackend, 'connect_tcp', connect)
    return attempted


def test_cli_self_check_refuses_neutralised_guard(neutralised_guard):
    from click.testing import CliRunner
    from argus.cli.__main__ import main
    result = CliRunner().invoke(main, ['list-probes'])
    assert result.exit_code != 0
    assert 'target address policy self-check failed' in result.output
    assert neutralised_guard == [('127.0.0.1', 9)]


async def test_server_self_check_refuses_neutralised_guard(neutralised_guard):
    import argus.server as server_module
    with pytest.raises(RuntimeError, match='target address policy self-check failed'):
        async with server_module._lifespan(server_module.app):
            pytest.fail('server started without address enforcement')
    assert neutralised_guard == [('127.0.0.1', 9)]


@pytest.mark.parametrize('address', [
    '64:ff9b::a9fe:a9fe', '64:ff9b::7f00:1', '::7f00:1', '::a9fe:a9fe',
    '::ffff:0:a9fe:a9fe', '224.0.0.1', 'ff0e::1',
])
async def test_embedded_private_and_multicast_never_dial(monkeypatch, fake_dial, address):
    monkeypatch.setenv('ARGUS_TARGET_ADDRESS_POLICY', 'public_only')
    host = f'[{address}]' if ':' in address else address
    async with target_client(timeout=1) as client:
        with pytest.raises(TargetAddressPolicyError):
            await client.get(f'http://{host}:9/')
    assert fake_dial == []


async def test_public_nat64_still_dials_checked_address(monkeypatch, fake_dial):
    monkeypatch.setenv('ARGUS_TARGET_ADDRESS_POLICY', 'public_only')

    async def handle(request):
        return web.Response(text='answer')

    async with server(handle) as local:
        async with target_client() as client:
            url = local.replace('127.0.0.1', '[64:ff9b::808:808]')
            assert (await client.get(url)).text == 'answer'
    assert fake_dial == ['64:ff9b::808:808']


@pytest.mark.parametrize('endpoint', [
    'unix:/tmp/x', 'unix:///tmp/x', 'unix-abstract:x', 'dns:///target.invalid:443',
    'dns://8.8.8.8/target:443', 'ipv4:127.0.0.1:1', 'ipv6:[::1]:1',
    'xds:///svc', 'vsock:3:50051', 'target.invalid', '8.8.8.8:99999',
    '[::1', 'user@8.8.8.8:443', '8.8.8.8:443#fragment',
])
async def test_grpc_endpoint_forms_are_policy_errors(monkeypatch, endpoint):
    from argus.targets.grpc import GRPCSpec, GRPCTarget
    import grpc
    monkeypatch.setenv('ARGUS_TARGET_ADDRESS_POLICY', 'public_only')

    def no_channel(*args, **kwargs):
        raise RuntimeError('unchecked endpoint reached channel construction')

    monkeypatch.setattr(grpc.aio, 'insecure_channel', no_channel)
    monkeypatch.setattr(grpc.aio, 'secure_channel', no_channel)
    target = GRPCTarget(GRPCSpec(endpoint=endpoint, service_method='echo.Echo/Chat', tls=False))
    with pytest.raises(TargetAddressPolicyError):
        await target.send_prompt('hello')


async def test_grpc_dns_uses_target_timeout(monkeypatch):
    import argus_transport.address_policy as policy
    from argus.targets.grpc import GRPCSpec, GRPCTarget
    monkeypatch.setenv('ARGUS_TARGET_ADDRESS_POLICY', 'public_only')

    async def blocked_dns(host, port):
        await asyncio.Event().wait()

    monkeypatch.setattr(policy, 'resolve_addresses', blocked_dns)
    target = GRPCTarget(GRPCSpec(endpoint='target.invalid:443', service_method='echo.Echo/Chat', timeout_s=.01))
    # The outer bound keeps the pre-fix test offline and finite; only the target
    # timeout should produce the named failure.
    with pytest.raises(TimeoutError, match='target connection timed out'):
        await asyncio.wait_for(target.send_prompt('hello'), .2)


async def test_cancellation_wins_over_abort_policy_refusal(monkeypatch, fake_dial):
    from test_transport_v2_abort import abort_spec
    from transport_v2_fakes import RecordingApp, serve
    from argus_transport import ExecutionPolicy, TransportContext
    from argus_transport.runtime_v2 import V2Run
    from argus_transport.spec_v2 import TransportSpecV2
    monkeypatch.setenv('ARGUS_TARGET_ADDRESS_POLICY', 'public_only')
    fake_dns(monkeypatch, [['8.8.8.8']])
    loop = asyncio.get_running_loop()
    original = loop.getaddrinfo
    refuse_abort = False

    async def resolve(host, *args, **kwargs):
        if host == 'target.invalid':
            host = '10.1.2.3' if refuse_abort else '8.8.8.8'
        return await original(host, *args, **kwargs)

    monkeypatch.setattr(loop, 'getaddrinfo', resolve)
    app = RecordingApp()
    poll_started, finish = asyncio.Event(), asyncio.Event()

    async def submit(request):
        return web.json_response({'run_id': 'job-1', 'status': 'PENDING'}, status=202)

    async def poll(request):
        poll_started.set()
        await finish.wait()
        return web.json_response({'run_id': 'job-1', 'status': 'PENDING'})

    app.route('POST', '/run', submit)
    app.route('GET', '/runs/{ident}', poll)
    async with serve(app) as local:
        spec = TransportSpecV2.from_dict(abort_spec(local.replace('127.0.0.1', 'target.invalid') + '/run'))
        run = V2Run(spec, policy=ExecutionPolicy.local(spec))
        task = asyncio.create_task(run.attempt(TransportContext(prompt='hello')))
        try:
            await asyncio.wait_for(poll_started.wait(), 3)
            refuse_abort = True
            task.cancel('operator stop')
            with pytest.raises(asyncio.CancelledError) as caught:
                await task
            assert caught.value.args == ('operator stop',)
            report = caught.value.transport_diagnostics['cleanup']
            assert report['aborts'][0]['failure_reason'] == 'address_policy'
            assert run.cleanup_report()['aborts'][0]['failure_reason'] == 'address_policy'
            assert not report['complete']
            assert not any(call[1].endswith(':stop') for call in app.calls)
        finally:
            finish.set()
            if not task.done():
                task.cancel()
            await run.close()


async def test_startup_self_check_blocks_without_dialing(monkeypatch, fake_dial):
    from argus_transport.address_policy import startup_self_check
    monkeypatch.setenv('ARGUS_TARGET_ADDRESS_POLICY', 'public_only')
    await startup_self_check()
    assert fake_dial == []


async def test_startup_self_check_is_inactive_when_off(monkeypatch):
    import argus_transport.address_policy as policy
    monkeypatch.delenv('ARGUS_TARGET_ADDRESS_POLICY', raising=False)

    def unexpected_client(**kwargs):
        pytest.fail('off-policy startup created a target client')

    monkeypatch.setattr(policy, 'target_client', unexpected_client)
    await policy.startup_self_check()


async def test_startup_self_check_refuses_unchecked_response(monkeypatch):
    import argus_transport.address_policy as policy
    monkeypatch.setenv('ARGUS_TARGET_ADDRESS_POLICY', 'public_only')
    requests = []

    def unchecked_response(request):
        requests.append(str(request.url))
        return httpx.Response(200)

    monkeypatch.setattr(policy, 'target_client', lambda **kwargs: httpx.AsyncClient(
        transport=httpx.MockTransport(unchecked_response)))
    with pytest.raises(RuntimeError, match='target address policy self-check failed'):
        await policy.startup_self_check()
    assert requests == ['http://127.0.0.1:9/']


async def test_pool_drift_refuses_server_startup(monkeypatch):
    import argus.server as server_module
    monkeypatch.setenv('ARGUS_TARGET_ADDRESS_POLICY', 'public_only')
    original = httpx.AsyncHTTPTransport
    transports = []

    def missing_backend(**kwargs):
        transport = original(**kwargs)
        del transport._pool._network_backend
        transports.append(transport)
        return transport

    monkeypatch.setattr(httpx, 'AsyncHTTPTransport', missing_backend)
    try:
        with pytest.raises(TargetAddressPolicyError):
            async with server_module._lifespan(server_module.app):
                pass
    finally:
        for transport in transports:
            await transport.aclose()
