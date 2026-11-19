"""Stable, synthetic registration values. No gateway credentials belong here."""
from __future__ import annotations

import ipaddress
import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from .registry import DefinitionError, Registry, load_registry

DEFAULT_INSTALL = 'argus-gateway-install.json'


def parse_listen(value: str) -> tuple[str, int]:
    parsed = urlsplit('http://' + value)
    try:
        port = parsed.port
        if not parsed.hostname or port is None or parsed.path or parsed.query or parsed.fragment:
            raise ValueError
        ipaddress.ip_address(parsed.hostname)
    except ValueError:
        raise DefinitionError('listen must be a numeric IP address and port') from None
    return parsed.hostname, port


def validate_install(install: dict, registry: Registry) -> None:
    if install.get('version') != 1:
        raise DefinitionError('unsupported fixture install version')
    token = install.get('path_token', '')
    if not isinstance(token, str) or len(token) < 22 or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-' for c in token):
        raise DefinitionError('path_token must contain at least 22 URL-safe characters')
    origins = install.get('origins', {})
    if set(origins) != set(registry.origins):
        raise DefinitionError('install origins do not match the loaded fixture origins')
    authorities = set()
    for name, origin in origins.items():
        parsed = urlsplit(origin['public'])
        if (parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username
                or parsed.password or parsed.path not in ('', '/') or parsed.query or parsed.fragment):
            raise DefinitionError(f'invalid public origin: {name}')
        try:
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        except ValueError:
            raise DefinitionError(f'invalid public port: {name}') from None
        if origin['host'].lower() != parsed.hostname.lower():
            raise DefinitionError(f'host must match the configured public hostname: {name}')
        authority = (parsed.hostname.lower(), port)
        if authority in authorities:
            raise DefinitionError('fixture origins must be distinct')
        authorities.add(authority)
        parse_listen(origin['listen'])
        requirements = registry.origins[name]
        if requirements.get('https') and parsed.scheme != 'https':
            raise DefinitionError(f'fixture origin requires HTTPS: {name}')
        other = requirements.get('symmetric_with')
        if other:
            peer = urlsplit(origins[other]['public'])
            def address_class(host):
                try:
                    address = ipaddress.ip_address(host)
                    return 'loopback' if address.is_loopback else 'private' if address.is_private else 'public'
                except ValueError:
                    return 'hostname'
            if (parsed.scheme, address_class(parsed.hostname), parsed.port is None) != (peer.scheme, address_class(peer.hostname), peer.port is None):
                raise DefinitionError(f'fixture origins must be symmetric: {name}, {other}')
    if 'issuer' in origins:
        if 'oauth' not in install.get('entries', {}):
            raise DefinitionError('issuer requires an OAuth entry')
        if any(not ipaddress.ip_address(parse_listen(origin['listen'])[0]).is_loopback for origin in origins.values()):
            raise DefinitionError('OAuth fixtures require loopback listeners')
        for field in ('client_id', 'client_secret'):
            value = install['entries']['oauth'].get(field)
            if not isinstance(value, str) or not value.startswith('argus-canary-') or len(value) < 32:
                raise DefinitionError('OAuth clients require install canaries')
    tls = install.get('tls')
    if tls is not None and (not tls.get('cert') or not tls.get('key')):
        raise DefinitionError('TLS requires both a certificate and key')
    for entry in install.get('entries', {}).values():
        path = entry.get('path', '').replace('{path_token}', token)
        if not path.startswith('/') or token not in path.split('/') or '?' in path or '#' in path:
            raise DefinitionError('entry paths must include the install path token')


def create_install(*, origins: dict | None = None, tls: dict | None = None,
                   registry: Registry | None = None, oauth: bool = False) -> dict:
    registry = registry or load_registry(oauth=oauth)
    if origins is None:
        origins = {
            'upstream': {'public': 'http://127.0.0.1:8471', 'listen': '127.0.0.1:8471', 'host': '127.0.0.1'},
            'foreign': {'public': 'http://127.0.0.2:8473', 'listen': '127.0.0.2:8473', 'host': '127.0.0.2'},
        }
        if 'issuer' in registry.origins:
            origins['issuer'] = {'public': 'http://127.0.0.3:8472', 'listen': '127.0.0.3:8472', 'host': '127.0.0.3'}
    install = {
        'version': 1, 'install_label': 'fx-' + secrets.token_hex(3),
        'path_token': secrets.token_urlsafe(16),
        'created_at': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        'origins': origins,
        'entries': {
            'plain': {'path': '/u/{path_token}/plain/mcp', 'auth': 'none'},
            'hdr': {'path': '/u/{path_token}/hdr/mcp', 'auth': 'headers', 'headers': {
                'X-API-Key': 'argus-canary-hdr-' + secrets.token_hex(16),
                'Authorization': 'Bearer argus-canary-auth-' + secrets.token_hex(16)}},
        },
        'webhook': {'path': '/w/{path_token}/hook'},
        'filter': {'pattern': 'ARGUSFLT[0-9A-F]{20}'}, 'plugins': {},
    }
    if tls:
        install['tls'] = tls
    for name, (path, sheet_fn) in registry.entries.items():
        if name in install['entries']:
            raise DefinitionError(f'duplicate fixture entry: {name}')
        install['entries'][name] = {**sheet_fn(install), 'path': path}
    validate_install(install, registry)
    return install


def write_install(path: str | Path, install: dict) -> None:
    # Refuse replacement: registration values must survive repeated init attempts.
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
        os.fchmod(stream.fileno(), 0o600)
        json.dump(install, stream, indent=2)
        stream.write('\n')


def read_install(path: str | Path, registry: Registry | None = None) -> dict:
    install = json.loads(Path(path).read_text(encoding='utf-8'))
    validate_install(install, registry or load_registry(oauth='issuer' in install.get('origins', {})))
    return install


def entry_url(install: dict, entry: str, origin: str = 'upstream') -> str:
    return install['origins'][origin]['public'].rstrip('/') + install['entries'][entry]['path'].replace('{path_token}', install['path_token'])


def registration_sheet(install: dict) -> str:
    lines = ['Register these in a non-production gateway or an isolated tenant.',
             'Use a dedicated test account; revoke its gateway token after testing.']
    for name, entry in install['entries'].items():
        lines.extend([f'Upstream argus-{name}', f'  URL: {entry_url(install, name)}', f"  Auth: {entry['auth']}"])
        for header, value in entry.get('headers', {}).items():
            lines.append(f'  {header}: {value}')
        for line in entry.get('sheet', []):
            lines.append('  ' + line)
    lines.append('Response filter: ' + install['filter']['pattern'])
    lines.append('Tool-call webhook: ' + install['origins']['upstream']['public'].rstrip('/') + install['webhook']['path'].replace('{path_token}', install['path_token']))
    lines.append('Next: argus-probe gateway-fixtures serve --install-file <install-file>')
    upstream, foreign = (urlsplit(install['origins'][name]['public']) for name in ('upstream', 'foreign'))
    if upstream.hostname == foreign.hostname:
        lines.append('Warning: upstream and foreign share a host; host-distinct redirect cases cannot run.')
    return '\n'.join(lines)
