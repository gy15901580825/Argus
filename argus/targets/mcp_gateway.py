"""Scripted gateway cases, attributed by nonce through passive fixtures."""
from __future__ import annotations

import asyncio
import copy
import hashlib
import hmac
import ipaddress
import json
import math
import re
import secrets
import time
from dataclasses import dataclass, field
from difflib import get_close_matches
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from argus.gateway_fixtures.install import read_install
from argus.gateway_fixtures.registry import load_registry
from argus.targets._base import KindInfo, ProbeNotApplicable, Target, TargetTransportError, Turn
from argus.targets._gateway_client import GatewayClient
from argus_transport.security import Redactor

SANDBOX_REASON = 'registers hostile upstream fixtures in a gateway'


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON field')
        result[key] = value
    return result


def _fields(value, allowed, required=(), *, path):
    if not isinstance(value, dict):
        raise ValueError(f'{path} must be an object')
    unknown = value.keys() - set(allowed)
    if unknown:
        messages = []
        for name in sorted(unknown, key=str):
            matches = get_close_matches(str(name), sorted(allowed), n=1)
            suggestion = f' Did you mean {matches[0]!r}?' if matches else ''
            messages.append(f'unknown field {name!r} for {path}.{suggestion}')
        raise ValueError(f"{' '.join(messages)} Valid fields: {', '.join(sorted(allowed))}")
    missing = set(required) - value.keys()
    if missing:
        raise ValueError(f'{path} missing required fields: {sorted(missing)}')


def _seconds(value, path, *, minimum=0, maximum=3600):
    if type(value) not in (int, float) or not math.isfinite(value) or not minimum <= value <= maximum:
        raise ValueError(f'{path} must be a finite number between {minimum} and {maximum}')


def _url(value, path):
    try:
        parsed = urlsplit(value)
        valid = parsed.scheme in ('http', 'https') and parsed.hostname and not parsed.username and not parsed.password and not parsed.fragment
        parsed.port
    except (ValueError, TypeError, AttributeError):
        valid = False
    if not valid:
        raise ValueError(f'{path} must be an HTTP(S) URL without userinfo or fragment')


def _strings(value, path):
    if not isinstance(value, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in value.items()):
        raise ValueError(f'{path} must map names to strings')


def _feature(name, value):
    if name == 'upstream_headers':
        _fields(value, {'names'}, {'names'}, path='features.upstream_headers')
        if not isinstance(value['names'], list) or not value['names'] or any(not isinstance(n, str) or not n for n in value['names']):
            raise ValueError('features.upstream_headers.names must be a nonempty list of header names')
    elif name == 'response_filter':
        _fields(value, {'action'}, {'action'}, path='features.response_filter')
        if value['action'] not in ('redact', 'block'):
            raise ValueError('features.response_filter.action must be redact or block')
    elif name == 'webhook':
        _fields(value, {'stage', 'decision', 'allow', 'deny'}, {'stage', 'allow', 'deny'}, path='features.webhook')
        if value['stage'] != 'pre_call':
            raise ValueError('features.webhook.stage must be pre_call')
        from argus.gateway_fixtures.webhook import validate_contract
        validate_contract(value)


@dataclass(frozen=True)
class MCPGatewaySpec:
    kind: str = 'mcp_gateway'
    sandbox: bool = False
    gateway: dict = field(default_factory=dict)
    fixtures: dict = field(default_factory=dict)
    features: dict = field(default_factory=dict)
    registration: dict = field(default_factory=lambda: {'mode': 'manual'})
    timeout_s: float = 30
    case_window_s: float = 10

    def __post_init__(self):
        if self.kind != 'mcp_gateway':
            raise ValueError("kind must be 'mcp_gateway'")
        if self.sandbox is not True:
            raise ValueError(f'mcp_gateway requires sandbox: true — this adapter {SANDBOX_REASON}; use a non-production gateway or an isolated tenant')
        _fields(self.gateway, {'url', 'protocol', 'auth', 'tools'}, {'url'}, path='gateway')
        _url(self.gateway['url'], 'gateway.url')
        if self.gateway.get('protocol', 'auto') not in ('auto', '2026-07-28', '2025-11-25', '2025-06-18'):
            raise ValueError('gateway.protocol must be auto, 2026-07-28, 2025-11-25 or 2025-06-18')
        auth = self.gateway.get('auth', {})
        _fields(auth, {'headers', 'cookies'}, path='gateway.auth')
        for name in ('headers', 'cookies'):
            _strings(auth.get(name, {}), f'gateway.auth.{name}')
        tools = self.gateway.get('tools', {})
        _fields(tools, {'match', 'prefix'}, path='gateway.tools')
        if tools.get('match', 'fixture_marker') not in ('fixture_marker', 'prefix') or not isinstance(tools.get('prefix', ''), str):
            raise ValueError('gateway.tools must use fixture_marker or prefix with a string prefix')
        _fields(self.fixtures, {'control_url', 'control_token', 'install_file'}, {'control_url', 'control_token', 'install_file'}, path='fixtures')
        _url(self.fixtures['control_url'], 'fixtures.control_url')
        for name in ('control_token', 'install_file'):
            if not isinstance(self.fixtures[name], str) or not self.fixtures[name]:
                raise ValueError(f'fixtures.{name} must be a nonempty string')
        _fields(self.registration, {'mode'}, path='registration')
        if self.registration.get('mode', 'manual') != 'manual':
            raise ValueError('registration.mode must be manual; hook is reserved')
        _seconds(self.timeout_s, 'timeout_s', minimum=0.01)
        _seconds(self.case_window_s, 'case_window_s')
        if not isinstance(self.features, dict):
            raise ValueError('features must be an object')
        registry = load_registry(oauth=True) if 'static_oauth_client' in self.features else load_registry()
        for name, value in self.features.items():
            if name in ('upstream_headers', 'response_filter', 'webhook'):
                _feature(name, value)
            else:
                registry.validate_features({name: value})


class MCPGatewayTarget(Target):
    compatible_classes = frozenset({'mcp_gateway'})
    kind_info = KindInfo(kind='mcp_gateway', required=frozenset({'gateway', 'fixtures', 'sandbox'}),
                         description='An MCP gateway connected to passive upstream fixtures', sandbox_reason=SANDBOX_REASON)

    def __init__(self, spec: MCPGatewaySpec):
        self.spec = spec
        oauth = 'static_oauth_client' in spec.features
        if Path(spec.fixtures['install_file']).is_file():
            oauth = 'issuer' in read_install(spec.fixtures['install_file'])['origins']
        self.registry = load_registry(oauth=True) if oauth else load_registry()
        self._oauth_challenged = False
        self._binding_assertion = None
        self._script = None
        self._probe_id = None
        self._evidence = {}
        self._lease_id = None
        self._control_client = httpx.AsyncClient(timeout=spec.timeout_s + spec.case_window_s + 1, trust_env=False,
            headers={'Authorization': 'Bearer ' + spec.fixtures['control_token']})
        self._gateway = None

    async def _control(self, method, path, **kwargs):
        try:
            response = await self._control_client.request(method, self.spec.fixtures['control_url'].rstrip('/') + '/v1' + path, **kwargs)
            if not response.is_success:
                reason = 'fixtures in use' if response.status_code == 409 and path == '/lease' else 'fixture control failed'
                raise TargetTransportError(f'{reason}: HTTP {response.status_code}')
            return response.json()
        except (httpx.HTTPError, ValueError):
            raise TargetTransportError('fixture control API unavailable or malformed') from None

    def _script_for(self, probe):
        try:
            raw = probe.scenario_payload
            if not isinstance(raw, str):
                raise ValueError
            script = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        except (ValueError, AttributeError, TypeError):
            raise ValueError('scenario.payload must be a valid JSON object; refusing to run an unstaged gateway') from None
        _fields(script, {'version', 'requires', 'entries', 'optional_entries', 'cases', 'drive', 'settle_s'}, {'version', 'requires', 'entries', 'cases', 'drive'}, path='scenario.payload')
        if type(script['version']) is not int or script['version'] != 1:
            raise ValueError('scenario.payload.version must be 1')
        for name in ('requires', 'entries'):
            if not isinstance(script[name], list) or any(not isinstance(v, str) or not v for v in script[name]):
                raise ValueError(f'scenario.payload.{name} must be a list of names')
        # OAuth recipes need their install and feature before behavior or consent setup.
        if 'static_oauth_client' in script['requires']:
            if 'issuer' not in self.registry.origins:
                raise ProbeNotApplicable('this install has no OAuth issuer; re-run gateway-fixtures init --oauth to test issuer binding')
            if 'static_oauth_client' not in self.spec.features:
                raise ProbeNotApplicable('target does not declare feature static_oauth_client')
        if not script['entries']:
            raise ValueError('scenario.payload.entries must not be empty')
        optional = script.get('optional_entries', [])
        if (not isinstance(optional, list) or any(not isinstance(v, str) or not v for v in optional)
                or len(set(optional)) != len(optional) or set(optional) & set(script['entries'])):
            raise ValueError('scenario.payload.optional_entries must contain distinct names outside entries')
        if not isinstance(script['cases'], list) or not 1 <= len(script['cases']) <= 100:
            raise ValueError('scenario.payload.cases must contain 1 to 100 cases')
        ids = set()
        for case in script['cases']:
            _fields(case, {'id', 'role', 'entry', 'calls_per_case', *self.registry.origins}, {'id', 'role', 'entry'}, path='scenario.payload.cases[]')
            if not isinstance(case['id'], str) or not re.fullmatch(r'[\w-]{1,120}', case['id']) or case['id'] in ids:
                raise ValueError('case ids must be distinct names of at most 120 characters')
            if 'calls_per_case' in case and (type(case['calls_per_case']) is not int or not 1 <= case['calls_per_case'] <= 20):
                raise ValueError('case calls_per_case must be between 1 and 20')
            ids.add(case['id'])
            if case['role'] not in ('control', 'attack') or case['entry'] not in [*script['entries'], *optional]:
                raise ValueError('case must declare control/attack role and a listed entry')
            self.registry.build_behaviors({origin: case[origin] for origin in self.registry.origins if origin in case})
        drive = script['drive']
        _fields(drive, {'tool', 'calls_per_case', 'client_canaries', 'steps', 'backoff_s', 'grant'}, {'tool', 'calls_per_case'}, path='scenario.payload.drive')
        if drive['tool'] not in ('echo', 'emit') or type(drive['calls_per_case']) is not int or not 1 <= drive['calls_per_case'] <= 20:
            raise ValueError('drive requires echo/emit and 1 to 20 calls_per_case')
        if drive.get('grant') not in (None, 'authorization_code'):
            raise ValueError('drive.grant must be authorization_code')
        backoff = drive.get('backoff_s', [])
        if not isinstance(backoff, list) or len(backoff) not in (0, drive['calls_per_case']):
            raise ValueError('drive.backoff_s must have one delay per call')
        if backoff and any(case['role'] == 'attack' and case.get('calls_per_case', drive['calls_per_case']) > len(backoff)
                           for case in script['cases']):
            raise ValueError('drive.backoff_s must cover every attack call')
        for delay in backoff:
            _seconds(delay, 'drive.backoff_s', maximum=30)
        if type(drive.get('client_canaries', False)) is not bool:
            raise ValueError('drive.client_canaries must be a boolean')
        steps = drive.get('steps', [])
        if not isinstance(steps, list) or any(not isinstance(step, str) for step in steps) or len(set(steps)) != len(steps):
            raise ValueError('drive.steps must contain distinct step names')
        self.registry.validate_drive_steps(steps)
        if 'consent' in steps and 'static_oauth_client' not in self.spec.features:
            raise ValueError('consent drive step requires features.static_oauth_client')
        if 'settle_s' in script:
            _seconds(script['settle_s'], 'scenario.payload.settle_s', maximum=self.spec.case_window_s)
        permanent = any(case.get('upstream', {}).get('redirect', {}).get('status') == 308 for case in script['cases'])
        if permanent and 'redirect_recontact' in ids:
            raise ValueError('redirect_recontact is reserved for the permanent redirect check')
        budget = sum(case.get('calls_per_case', drive['calls_per_case']) * self.spec.timeout_s + self.spec.case_window_s + 1 for case in script['cases'])
        if 'consent' in steps:
            budget += sum((10 + case.get('calls_per_case', drive['calls_per_case'])) * self.spec.timeout_s for case in script['cases'])
        if permanent:
            budget += drive['calls_per_case'] * self.spec.timeout_s + self.spec.case_window_s + 1
        budget += len(script['cases']) * sum(drive.get('backoff_s', []))
        if 10 + budget > 3600:
            raise ValueError('gateway recipe exceeds the one-hour fixture lease limit')
        return script

    async def begin_probe(self, probe):
        # Refused definitions must not tear down the caller's existing lease.
        script = self._script_for(probe)
        missing = set(script['requires']) - self.spec.features.keys()
        if missing:
            raise ProbeNotApplicable(f'target does not declare feature {sorted(missing)[0]}')
        grant = script['drive'].get('grant')
        if grant and self.spec.features.get('static_oauth_client', {}).get('grant') != grant:
            raise ProbeNotApplicable(f'probe requires static_oauth_client grant: {grant}')
        from argus.gateway_fixtures.webhook import NoDocumentedDeny, resolve_decision
        for case in script['cases']:
            decision = case.get('upstream', {}).get('decision')
            if decision is not None:
                try:
                    resolve_decision(decision, self.spec.features['webhook'])
                except NoDocumentedDeny as exc:
                    raise ProbeNotApplicable(str(exc)) from None
        await self._release()
        self._binding_assertion = next((entry['gateway_upstream_as_binding']
            for entry in getattr(probe, 'assertions', ()) if 'gateway_upstream_as_binding' in entry), None)
        self._script, self._probe_id, self._evidence = script, probe.id, {}

    async def _release(self):
        if self._lease_id:
            lease_id, self._lease_id = self._lease_id, None
            await self._control('DELETE', f'/lease/{lease_id}')

    async def aclose(self):
        try:
            await self._release()
        finally:
            if self._gateway:
                await self._gateway.aclose()
            await self._control_client.aclose()

    async def collect_evidence(self):
        return self._evidence

    async def send_prompt(self, prompt: str, history: tuple[Turn, ...] = ()):
        start = time.monotonic()
        if self._script is None:
            raise ValueError('begin_probe with a gateway recipe is required')
        if not self._evidence:
            await self._run()
        return json.dumps(self._evidence, sort_keys=True), (time.monotonic() - start) * 1000

    async def _run(self):
        install = read_install(self.spec.fixtures['install_file'], self.registry)
        health = await self._control('GET', '/health')
        if health.get('install_label') != install['install_label']:
            raise TargetTransportError('fixture host and install file do not match')
        script = self._script
        permanent = any(case.get('upstream', {}).get('redirect', {}).get('status') == 308 for case in script['cases'])
        budget = sum(case.get('calls_per_case', script['drive']['calls_per_case']) * self.spec.timeout_s + self.spec.case_window_s + 1 for case in script['cases'])
        if 'consent' in script['drive'].get('steps', []):
            budget += sum((10 + case.get('calls_per_case', script['drive']['calls_per_case'])) * self.spec.timeout_s for case in script['cases'])
        if permanent:
            budget += script['drive']['calls_per_case'] * self.spec.timeout_s + self.spec.case_window_s + 1
        ttl = min(3600, 10 + budget)
        self._lease_id = (await self._control('POST', '/lease', json={'ttl_s': ttl}))['lease_id']
        auth = self.spec.gateway.get('auth', {})
        credentials = {**{'auth_header:' + k: v for k, v in auth.get('headers', {}).items()},
                       **{'cookie:' + k: v for k, v in auth.get('cookies', {}).items()}}
        for name, value in list(credentials.items()):
            if name.startswith('auth_header:') and ' ' in value:
                credentials[name + ':payload'] = value.split(' ', 1)[1]
        canaries = {}
        for entry in install['entries'].values():
            for name, value in entry.get('headers', {}).items():
                canaries['upstream_header:' + name] = value.split(' ', 1)[1] if name.lower() == 'authorization' else value
        redactor = Redactor([*credentials.values(), *canaries.values(), self.spec.fixtures['control_token'], install['path_token'],
                             *[install['entries'].get('oauth', {}).get(key, '') for key in ('client_id', 'client_secret')]])
        origins = {}
        host_ids = {}
        for name, origin in install['origins'].items():
            parsed = urlsplit(origin['public'])
            try:
                address = ipaddress.ip_address(parsed.hostname)
                category = 'loopback' if address.is_loopback else 'public' if address.is_global else 'private'
            except ValueError:
                category = 'unknown'
            host_id = host_ids.setdefault(parsed.hostname, f'h{len(host_ids) + 1}')
            origins[name] = {'scheme': parsed.scheme, 'class': category, 'host_id': host_id}
        evidence = {'interaction_count': 0, 'install_label': install['install_label'], 'era': None,
                    'origins': origins, 'cases': [], 'summary': {}}
        if self.spec.features.get('webhook', {}).get('decision') == 'status':
            from argus.gateway_fixtures.webhook import status_sets
            evidence['webhook_contract'] = {'decision': 'status', **{
                name: sorted(statuses) for name, statuses in status_sets(self.spec.features['webhook']).items()}}
        if 'static_oauth_client' in self.spec.features:
            evidence['static_oauth_client'] = {
                'grant': self.spec.features['static_oauth_client']['grant'],
                'confidential': bool(install['entries'].get('oauth', {}).get('client_secret'))}
        if script['drive'].get('client_canaries'):
            evidence['client_credentials'] = [{'label': label, 'kind': 'secret'} for label in credentials if not label.endswith(':payload')]
            evidence['client_credentials'].append({'label': 'client_canary', 'kind': 'canary'})
        gateway = GatewayClient(self.spec.gateway, self.spec.timeout_s)
        self._gateway = gateway
        gateway.redactor = redactor
        self._evidence = evidence
        try:
            if ('consent' in script['drive'].get('steps', [])
                    or self._oauth_challenged and 'static_oauth_client' in self.spec.features):
                gateway.consent = self.registry.drive_steps['consent'](gateway, install,
                    self.spec.features['static_oauth_client']['consent'], self.spec.timeout_s)
            if gateway.consent:
                gateway.consent.begin_case(secrets.token_hex(16))
            for operation in (gateway.initialize, lambda: gateway.discover(install['install_label'])):
                try:
                    await operation()
                except TargetTransportError:
                    if not gateway.consent or not gateway.consent.requires_out_of_band(
                            {'entry': 'oauth'}, gateway.last_failure, run_challenged=self._oauth_challenged):
                        raise
                    startup = evidence.setdefault('startup', {'calls': []})
                    startup['calls'].append({'reply': 'transport_error', 'transport_error': gateway.last_failure})
                    try:
                        await gateway.consent.reauthorize('oauth')
                    finally:
                        startup['manual_out_of_band'] = list(gateway.consent.manual_out_of_band)
                    await operation()
            for entry in script['entries']:
                if (entry, script['drive']['tool']) not in gateway.tools:
                    raise ProbeNotApplicable(f'entry {entry}: entry not registered')
            evidence['era'] = gateway.era
            cases = list(script['cases'])
            permanent = next((case for case in reversed(cases) if case.get('upstream', {}).get('redirect', {}).get('status') == 308), None)
            if permanent:
                cases.append({'id': 'redirect_recontact', 'role': 'control', 'entry': permanent['entry'], 'upstream': {}})
            for case in cases:
                if case['entry'] in script.get('optional_entries', []) and (case['entry'], script['drive']['tool']) not in gateway.tools:
                    continue
                path = case.get('upstream', {}).get('delivery')
                if (gateway.era == '2026-07-28' and path in ('post_sse_resumed', 'get_stream_notification')
                        or gateway.era != '2026-07-28' and path == 'mrtr_input_request'):
                    evidence['cases'].append({'id': case['id'], 'entry': case['entry'], 'role': case['role'],
                        'delivery': path, 'complete': True, 'dropped': 0,
                        'client': {'calls': [], 'consent_hops': []}, 'fixture': {'requests': [], 'state': {}},
                        'not_exercised': 'delivery path does not belong to the negotiated era'})
                    continue
                nonce = secrets.token_hex(16)
                if gateway.consent:
                    gateway.consent.begin_case(nonce)
                watch_key = secrets.token_bytes(32)
                hashes = {name: hmac.new(watch_key, value.encode(), hashlib.sha256).hexdigest() for name, value in credentials.items() if value}
                if script['drive'].get('client_canaries') and gateway.session:
                    hashes['gateway_session_id'] = hmac.new(watch_key, gateway.session.encode(), hashlib.sha256).hexdigest()
                case_canaries = dict(canaries)
                headers, cookies = {}, {}
                if script['drive'].get('client_canaries'):
                    client_canary = 'argus-canary-client-' + secrets.token_hex(16)
                    headers['X-Argus-Client-Canary'] = client_canary
                    cookies['argus_client_canary'] = client_canary
                    case_canaries['client_canary'] = client_canary
                    redactor.add(client_canary)
                toggles = copy.deepcopy({o: case[o] for o in self.registry.origins if o in case})
                if 'decision' in toggles.get('upstream', {}):
                    from argus.gateway_fixtures.webhook import resolve_decision
                    toggles['upstream']['decision'] = resolve_decision(toggles['upstream']['decision'], self.spec.features['webhook'])
                opened = await self._control('POST', '/cases', json={'lease_id': self._lease_id, 'probe_id': self._probe_id,
                    'case_id': case['id'], 'nonce': nonce, 'toggles': toggles,
                    'watch': {'canaries': case_canaries, 'secrets': hashes, 'watch_key': watch_key.hex(), 'case_key': secrets.token_hex(32)}})
                if gateway.consent and (toggles.get('upstream', {}).get('challenge') == 'invalid_token'
                                        or 'prm' in toggles.get('upstream', {})):
                    self._oauth_challenged = True
                calls = []
                failure = None
                try:
                    for attempt in range(case.get('calls_per_case', script['drive']['calls_per_case'])):
                        backoff = script['drive'].get('backoff_s', [])
                        if case['role'] == 'attack' and backoff:
                            await asyncio.sleep(backoff[attempt])
                        try:
                            call = await gateway.call(install['install_label'], case['entry'], script['drive']['tool'], nonce,
                                                      headers=headers, cookies=cookies, path=case.get('upstream', {}).get('delivery'))
                        except TargetTransportError:
                            if not gateway.consent or not gateway.consent.requires_out_of_band(case, gateway.last_failure, run_challenged=self._oauth_challenged):
                                raise
                            calls.append({'nonce': nonce, 'reply': 'transport_error', 'transport_error': gateway.last_failure})
                            await gateway.consent.reauthorize(case['entry'])
                            call = await gateway.call(install['install_label'], case['entry'], script['drive']['tool'], nonce,
                                                      headers=headers, cookies=cookies, path=case.get('upstream', {}).get('delivery'))
                        calls.append(call)
                    if script.get('settle_s'):
                        await asyncio.sleep(script['settle_s'])
                except TargetTransportError as exc:
                    failure = exc
                    calls.append({'nonce': nonce, 'reply': 'transport_error',
                                  'transport_error': gateway.last_failure or gateway.failure_context('POST', gateway.gateway['url'])})
                except ProbeNotApplicable as exc:
                    failure = exc
                finally:
                    sealed = await self._control('POST', f"/cases/{opened['case_seq']}/seal")
                requests = sealed['fixture']['requests']
                if 'delivery' in case.get('upstream', {}):
                    markers = {record.get('ext', {}).get('delivery', {}).get('marker') for record in requests
                               if record.get('body', {}).get('jsonrpc', {}).get('nonce') == nonce
                               or (record.get('method') == 'GET'
                                   and record.get('ext', {}).get('delivery', {}).get('nonce') == nonce)}
                    for call in calls:
                        if markers.intersection(call.get('markers', [])):
                            call['classification'] = 'raw'
                evidence['cases'].append({'id': case['id'], 'entry': case['entry'], 'role': case['role'], 'complete': sealed['complete'],
                    'dropped': sealed['dropped'], 'client': {'calls': calls, 'consent_hops': list(gateway.consent.hops) if gateway.consent else []}, 'fixture': sealed['fixture']})
                if gateway.consent and gateway.consent.manual_out_of_band:
                    evidence['cases'][-1]['client']['manual_out_of_band'] = list(gateway.consent.manual_out_of_band)
                if isinstance(failure, ProbeNotApplicable):
                    evidence['cases'][-1]['not_exercised'] = str(failure)
                if 'static_oauth_client' in self.spec.features:
                    evidence['cases'][-1]['oauth'] = {'as_metadata_fetched': {
                        origin: sum(record.get('actor') == 'gateway' and record.get('origin') == origin
                                    and 'as_metadata_fetched' in record.get('ext', {}).get('oauth', {})
                                    for record in requests) for origin in ('issuer', 'foreign')}}
                if 'redirect' in case.get('upstream', {}):
                    evidence['cases'][-1]['redirect'] = {key: case['upstream']['redirect'][key] for key in ('status', 'to')}
                if 'delivery' in case.get('upstream', {}):
                    evidence['cases'][-1]['delivery'] = case['upstream']['delivery']
                evidence['interaction_count'] += sum(r.get('actor') == 'gateway' for r in requests)
                if failure:
                    if (case['role'] == 'attack' and self._binding_assertion is not None
                            and any(call.get('reply') == 'transport_error' for call in calls)):
                        from argus.gateway_oauth_assertions import gateway_upstream_as_binding
                        evidence['transport_error'] = gateway.last_failure or gateway.failure_context('POST', gateway.gateway['url'])
                        if gateway_upstream_as_binding(self._binding_assertion, evidence).verdict == 'fail':
                            break
                    raise failure
            if any('redirect' in case.get('upstream', {}) for case in script['cases']):
                from argus.gateway_redirect_assertions import summarize

                evidence['summary']['upstream_header_redirect'] = summarize(evidence, self.spec.features.get('upstream_headers', {}).get('names', []))
        except TargetTransportError:
            evidence['transport_error'] = gateway.last_failure or gateway.failure_context('POST', gateway.gateway['url'])
            raise
        finally:
            evidence['interaction_count'] += gateway.exchanges
            self._evidence = redactor.clean(evidence)
            try:
                await self._release()
            finally:
                await gateway.aclose()
                self._gateway = None

    async def check_registration(self):
        install = read_install(self.spec.fixtures['install_file'], self.registry)
        from types import SimpleNamespace

        entries = list(install['entries'])
        recipe = {'version': 1, 'requires': [], 'entries': entries,
                  'cases': [{'id': 'check-' + name, 'role': 'control', 'entry': name, 'upstream': {}} for name in entries],
                  'drive': {'tool': 'echo', 'calls_per_case': 1}}
        await self.begin_probe(SimpleNamespace(id='gateway-registration-check', scenario_payload=json.dumps(recipe)))
        await self.send_prompt('')
        messages = []
        for name, case in zip(entries, self._evidence['cases']):
            nonce = case['client']['calls'][0]['nonce']
            records = [r for r in case['fixture']['requests'] if r.get('actor') == 'gateway' and r.get('entry') == name
                       and r.get('body', {}).get('jsonrpc', {}).get('nonce') == nonce]
            if not records:
                messages.append(f'entry {name}: the gateway never connected for the canary call')
            if any(call['reply'] != 'result' for call in case['client']['calls']):
                messages.append(f'entry {name}: gateway canary call failed')
            if not case['complete']:
                messages.append(f'entry {name}: fixture evidence is incomplete')
            hits = {hit for record in records for hit in record['hits']}
            configured = {header.lower() for header in self.spec.features.get('upstream_headers', {}).get('names', [])}
            for header in install['entries'][name].get('headers', {}):
                if header.lower() in configured and 'upstream_header:' + header not in hits:
                    messages.append(f'entry {name}: {header} canary never arrived')
        return messages
