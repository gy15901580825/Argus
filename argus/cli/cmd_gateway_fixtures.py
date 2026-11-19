"""Long-running gateway fixtures and their stable registration sheet."""
from __future__ import annotations

import asyncio
import signal

import click

from argus.gateway_fixtures.host import FixtureHost
from argus.gateway_fixtures.install import DEFAULT_INSTALL, create_install, read_install, registration_sheet, write_install
from argus.gateway_fixtures.registry import DefinitionError, load_registry


@click.group('gateway-fixtures')
def cmd_gateway_fixtures():
    """Host passive MCP fixtures for gateways you operate."""


@cmd_gateway_fixtures.command('init')
@click.option('--install-file', type=click.Path(dir_okay=False), default=DEFAULT_INSTALL, show_default=True)
@click.option('--mode', type=click.Choice(['local-hosts', 'local-ports', 'compose', 'public']), default='local-hosts', show_default=True)
@click.option('--origin', 'origin_specs', multiple=True, metavar='NAME=PUBLIC_URL,LISTEN,HOST',
              help='Override or add an origin. LISTEN is a numeric IP:port.')
@click.option('--oauth', is_flag=True, help='Add the OAuth issuer and protected entry in the selected placement mode.')
@click.option('--tls-cert', type=click.Path(dir_okay=False))
@click.option('--tls-key', type=click.Path(dir_okay=False))
def cmd_init(install_file, mode, origin_specs, tls_cert, tls_key, oauth):
    """Mint synthetic canaries once and print values to register."""
    try:
        if bool(tls_cert) != bool(tls_key):
            raise DefinitionError('TLS requires both --tls-cert and --tls-key')
        origins = {}
        if mode != 'public':
            for name, alias, port in [('upstream', 'r', 8471), ('foreign', 'e', 8473)] + ([('issuer', 'h', 8472)] if oauth else []):
                host = f'{alias}.argus.test' if mode == 'compose' else ({'foreign': '127.0.0.2', 'issuer': '127.0.0.3'}.get(name, '127.0.0.1') if mode == 'local-hosts' else '127.0.0.1')
                origins[name] = {'public': f"{'https' if tls_cert else 'http'}://{host}:{port}",
                                 'listen': f"{'0.0.0.0' if mode == 'compose' else host}:{port}", 'host': host}
        for spec in origin_specs:
            name, separator, values = spec.partition('=')
            fields = values.split(',')
            if not separator or len(fields) != 3:
                raise DefinitionError('--origin requires NAME=PUBLIC_URL,LISTEN,HOST')
            origins[name] = dict(zip(('public', 'listen', 'host'), fields))
        install = create_install(origins=origins, oauth=oauth, tls={'cert': tls_cert, 'key': tls_key} if tls_cert else None)
        write_install(install_file, install)
    except (ValueError, OSError, KeyError) as exc:
        raise click.ClickException(str(exc)) from None
    click.echo(f'Wrote {install_file} (mode 0600).')
    click.echo(registration_sheet(install))


@cmd_gateway_fixtures.command('sheet')
@click.option('--install-file', type=click.Path(dir_okay=False), default=DEFAULT_INSTALL, show_default=True)
def cmd_sheet(install_file):
    """Print the existing install's registration values."""
    try:
        click.echo(registration_sheet(read_install(install_file)))
    except (ValueError, OSError, KeyError) as exc:
        raise click.ClickException(str(exc)) from None


async def _serve(host):
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(signum, stop.set)
    try:
        async with host:
            click.echo(f'Fixtures serving; control API at {host.control_url}.')
            await stop.wait()
    finally:
        for signum in (signal.SIGINT, signal.SIGTERM):
            loop.remove_signal_handler(signum)


@cmd_gateway_fixtures.command('serve')
@click.option('--install-file', type=click.Path(dir_okay=False), default=DEFAULT_INSTALL, show_default=True)
@click.option('--control-bind', default='127.0.0.1:8470', show_default=True)
@click.option('--control-token', envvar='ARGUS_FIXTURE_TOKEN', required=True,
              help='Prefer ARGUS_FIXTURE_TOKEN so the token stays out of process arguments.')
@click.option('--allow-remote-control', is_flag=True, help='Permit a non-loopback control bind with install TLS.')
@click.option('--case-window-s', type=click.FloatRange(0, 3600), default=10.0, show_default=True)
def cmd_serve(install_file, control_bind, control_token, allow_remote_control, case_window_s):
    """Keep idle fixtures online during registration and between runs."""
    try:
        install = read_install(install_file)
        registry = load_registry(oauth='issuer' in install['origins'])
        host = FixtureHost(install, control_token=control_token,
                           control_bind=control_bind, allow_remote_control=allow_remote_control,
                           registry=registry, case_window_s=case_window_s)
        asyncio.run(_serve(host))
    except (ValueError, OSError, KeyError) as exc:
        raise click.ClickException(str(exc)) from None


async def _check_target(target):
    try:
        return await target.check_registration()
    finally:
        await target.aclose()


@cmd_gateway_fixtures.command('check')
@click.option('--target', 'target_arg', required=True, help='Sandboxed mcp_gateway target JSON or YAML.')
def cmd_check(target_arg):
    """Verify discovery and canary calls through the registered gateway."""
    from argus.cli.target_loader import load_target_spec
    from argus.targets import build_target
    from argus.targets._base import ProbeNotApplicable, TargetTransportError

    try:
        spec = load_target_spec(target_arg)
        if spec['kind'] != 'mcp_gateway':
            raise ValueError('gateway-fixtures check requires kind: mcp_gateway')
        messages = asyncio.run(_check_target(build_target(spec)))
    except (ValueError, OSError, KeyError, ProbeNotApplicable, TargetTransportError) as exc:
        raise click.ClickException(str(exc)) from None
    if messages:
        raise click.ClickException('\n'.join(messages))
    click.echo('Gateway registration verified: fixture tools and configured header canaries reached each entry.')
