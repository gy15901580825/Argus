"""Synthetic OAuth refusal, foreign authorize and cross-probe recovery regressions."""
import asyncio
import copy
import io
import json
from dataclasses import replace

import httpx
import pytest

from argus.gateway_consent import ConsentDriver
from argus.probe import load_probe
from argus.runner import Runner
from tests.gateway_probes.test_as_binding import PROBES, _ExplodingJudge, captured, record, verdict
from tests.gateway_target.test_out_of_band import running


def terminal(monkeypatch):
    ready = [False]
    class Terminal(io.StringIO):
        def isatty(self):
            return True
        def readline(self):
            ready[0] = False
            return '\n'
    monkeypatch.setattr('sys.stdin', Terminal())
    monkeypatch.setattr('argus.gateway_consent.select.select',
                        lambda *args: ([args[0][0]], [], []) if ready[0] else ([], [], []))
    return ready


@pytest.mark.parametrize('variant', ['', '_mixup_iss', '_mixup_no_iss'])
@pytest.mark.parametrize('strategy,want', [('entry', 'fail'), ('issuer', 'error')])
async def test_positive_exposure_precedes_post_exchange_403(tmp_path, monkeypatch, variant, strategy, want):
    async with running(tmp_path, mode='manual', strategy=strategy) as (target, gateway, host):
        probe = load_probe(PROBES / ('mcp_gateway_upstream_as_binding' + variant + '.yaml'))
        script = json.loads(probe.scenario_payload)
        script['drive']['calls_per_case'] = 1
        script['drive']['backoff_s'] = [0]
        # Include the baseline revocation, just as the bundled control does.
        probe = replace(probe, scenario_payload=json.dumps(script))
        original = gateway._request
        async def refused_after_exchange(name, request, **kwargs):
            if gateway.authorization_errors:
                return httpx.Response(403, text='Upstream authorization is required.')
            return await original(name, request, **kwargs)
        monkeypatch.setattr(gateway, '_request', refused_after_exchange)
        ready = terminal(monkeypatch)
        async def authorize():
            for _ in range(2):
                while not gateway.pending:
                    await asyncio.sleep(0.001)
                await gateway.reauthorize('oauth')
                ready[0] = True
                while ready[0]:
                    await asyncio.sleep(0.001)
        task = asyncio.create_task(authorize())
        try:
            runner = Runner(target, _ExplodingJudge(), PROBES.parents[1] / 'rubrics')
            finding, = [finding async for finding in runner.run_probe(probe)]
            assert finding.verdict == want, finding.reasoning
            evidence = finding.evidence
            assert evidence['transport_error']['status'] == 403
            assert evidence['cases'][-1]['complete'] is True
            if want == 'fail':
                assert finding.severity == 'high'
                tokens = [r for r in evidence['cases'][-1]['fixture']['requests'] if r['origin'] == 'foreign' and r['route'] == 'token']
                assert any(r['ext']['oauth']['token']['client_secret_hit'] for r in tokens)
                changed = copy.deepcopy(evidence)
                changed['cases'][-1]['fixture']['requests'] = [r for r in changed['cases'][-1]['fixture']['requests'] if r['origin'] != 'foreign']
                assert verdict(changed, 'mirror_authorize' if variant else 'own')[0] == 'error'
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


@pytest.mark.parametrize('mode', ['own', 'mirror_authorize'])
@pytest.mark.parametrize('actor', ['unknown', 'operator_browser', 'script', 'argus_user_agent', 'gateway'])
def test_authorize_id_counts_for_every_carrier(mode, actor):
    evidence = captured()
    forwarded = record('foreign', 'authorize', {'authorize': {'client_id_hit': True}}, actor=actor)
    evidence['cases'][-1]['fixture']['requests'].append(forwarded)
    status, result = verdict(evidence, mode)
    assert status == 'fail' and result.severity == 'medium'
    forwarded['ext']['oauth']['authorize']['client_id_hit'] = False
    assert verdict(evidence, mode)[0] == 'pass'
    forwarded.update(route='token', ext={'oauth': {'token': {'client_id_hit': True}}})
    assert verdict(evidence, mode)[0] == ('fail' if actor == 'gateway' else 'pass')


@pytest.mark.parametrize('mode', ['own', 'mirror_authorize'])
@pytest.mark.parametrize('hit,severity', [('client_secret_hit', 'high'), ('client_id_hit', 'medium')])
def test_credential_exposure_applies_to_every_variant(mode, hit, severity):
    evidence = captured()
    token = record('foreign', 'token', {'token': {hit: True}})
    evidence['cases'][-1]['fixture']['requests'].append(token)
    evidence['transport_error'] = {'status': 403}
    status, outcome = verdict(evidence, mode)
    assert status == 'fail' and outcome.severity == severity
    token['ext']['oauth']['token'][hit] = False
    assert verdict(evidence, mode)[0] == 'error'


@pytest.mark.parametrize('oauth_probe', [True, False])
@pytest.mark.parametrize('strategy', ['issuer', 'entry'])
@pytest.mark.parametrize('method', ['initialize', 'tools/list'])
@pytest.mark.parametrize('mode', ['manual', 'none', 'follow_url'])
async def test_probe_two_recovers_discovery_refusal_after_prior_challenge(tmp_path, monkeypatch, method, mode, strategy, oauth_probe):
    from tests.fixtures.gateway_ref.out_of_band import ReauthorizationRequired
    from types import SimpleNamespace
    from argus.targets._base import ProbeNotApplicable
    async with running(tmp_path, mode=mode, strategy=strategy) as (target, gateway, host):
        monkeypatch.setattr('sys.stdin.isatty', lambda: False)
        with pytest.raises(ProbeNotApplicable):
            await target.send_prompt('')
        if method == 'tools/list':
            await gateway.reauthorize('oauth')
        blocked = [True]
        attempts = []
        original = gateway._request
        async def discovery_refusal(name, request, **kwargs):
            message = kwargs.get('message', {})
            if name == 'oauth' and message.get('method') == method:
                attempts.append(blocked[0])
                if blocked[0]:
                    raise ReauthorizationRequired
            return await original(name, request, **kwargs)
        monkeypatch.setattr(gateway, '_request', discovery_refusal)
        script = {'version': 1, 'requires': ['static_oauth_client'], 'entries': ['oauth'],
                  'cases': [{'id': 'recovered', 'role': 'control', 'entry': 'oauth', 'upstream': {}}],
                  'drive': {'tool': 'echo', 'calls_per_case': 1, 'steps': ['consent']}}
        if not oauth_probe:
            from tests.fixtures.gateway_ref import Entry
            from argus.gateway_fixtures.install import entry_url
            gateway.entries['plain'] = Entry(entry_url(host.install, 'plain'))
            script['requires'] = []
            script['entries'] = ['plain']
            script['cases'][0]['entry'] = 'plain'
            script['drive']['steps'] = []
        await target.begin_probe(SimpleNamespace(id='second-probe', scenario_payload=json.dumps(script)))
        ready = terminal(monkeypatch)
        async def authorize():
            while target._gateway is None or not target._gateway.consent.manual_out_of_band:
                await asyncio.sleep(0.001)
            if gateway.pending:
                await gateway.reauthorize('oauth')
            blocked[0] = False
            ready[0] = True
        task = asyncio.create_task(authorize()) if mode == 'manual' else None
        try:
            if mode == 'manual':
                await target.send_prompt('')
                evidence = await target.collect_evidence()
                assert attempts == [True, False]
                assert evidence['startup']['manual_out_of_band'][0]['completed'] is True
                assert evidence['startup']['calls'][0]['transport_error']['rpc_method'] == method
                assert evidence['cases'][0]['client']['calls'][-1]['reply'] == 'result'
            else:
                with pytest.raises(ProbeNotApplicable, match='out-of-band'):
                    await target.send_prompt('')
                assert attempts == [True]
        finally:
            if task:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)


@pytest.mark.parametrize('method', ['initialize', 'tools/list', 'tools/call'])
@pytest.mark.parametrize('prior', [True, False])
def test_discovery_classification_requires_oauth_challenge(method, prior):
    from types import SimpleNamespace
    driver = ConsentDriver(SimpleNamespace(gateway={'url': 'http://127.0.0.1:1/mcp'},
        last_failure_body_complete=True), {'origins': {}}, 'none', 1)
    failure = {'method': 'POST', 'path_class': 'mcp', 'rpc_method': method, 'status': 403}
    assert driver.requires_out_of_band({'entry': 'oauth'}, failure, run_challenged=prior) is prior
    assert not driver.requires_out_of_band({'entry': 'plain'}, failure, run_challenged=prior)


@pytest.mark.parametrize('mode', ['own', 'mirror_authorize'])
def test_correlated_h_code_without_credentials_precedes_error(mode):
    evidence = captured()
    evidence['transport_error'] = {'status': 403}
    records = evidence['cases'][-1]['fixture']['requests']
    records.append(record('issuer', 'authorize', {'codes_issued': {
        'by': 'issuer', 'corr': 'synthetic-code', 'verifier_s256': 'synthetic-challenge'}}))
    token = record('foreign', 'token', {'token': {'code': {'corr': 'synthetic-code'},
                                               'verifier_s256': 'synthetic-challenge'}})
    records.append(token)
    status, result = verdict(evidence, mode)
    assert status == 'fail' and result.severity == 'high'
    token['ext']['oauth']['token']['verifier_s256'] = 'different-challenge'
    assert verdict(evidence, mode)[0] == 'error'


@pytest.mark.parametrize('mode', ['none', 'follow_url'])
@pytest.mark.parametrize('strategy,want', [('entry', 'fail'), ('issuer', 'skipped')])
async def test_positive_exposure_precedes_nonmanual_refusal_skip(tmp_path, monkeypatch, mode, strategy, want):
    from tests.fixtures.gateway_ref.oauth import OAuthError, OAuthReferenceGateway
    from tests.fixtures.gateway_ref.out_of_band import ReauthorizationRequired
    async with running(tmp_path, mode=mode, strategy=strategy) as (target, gateway, host):
        async def authenticate(name, challenge):
            try:
                await OAuthReferenceGateway._authenticate(gateway, name, challenge)
            except OAuthError:
                raise ReauthorizationRequired
        monkeypatch.setattr(gateway, '_authenticate', authenticate)
        probe = load_probe(PROBES / 'mcp_gateway_upstream_as_binding.yaml')
        script = json.loads(probe.scenario_payload)
        script['drive']['backoff_s'] = [0, 0, 0]
        probe = replace(probe, scenario_payload=json.dumps(script))
        runner = Runner(target, _ExplodingJudge(), PROBES.parents[1] / 'rubrics')
        finding, = [finding async for finding in runner.run_probe(probe)]
        assert finding.verdict == want, finding.reasoning
        if want == 'fail':
            assert finding.severity == 'high'
            assert finding.evidence['transport_error']['status'] == 403


@pytest.mark.parametrize('mode', ['own', 'mirror_authorize'])
def test_code_alone_does_not_override_transport_error(mode):
    evidence = captured()
    evidence['transport_error'] = {'status': 403}
    records = evidence['cases'][-1]['fixture']['requests']
    records.append(record('issuer', 'authorize', {'codes_issued': {
        'by': 'issuer', 'corr': 'synthetic-code', 'verifier_s256': 'synthetic-challenge'}}))
    records.append(record('foreign', 'token', {'token': {'code': {'corr': 'synthetic-code'}}}))
    assert verdict(evidence, mode)[0] == 'error'
    evidence.pop('transport_error')
    assert verdict(evidence, mode)[0] == 'fail'


async def test_plain_case_recovery_prompts_for_oauth_entry(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from argus.targets._base import ProbeNotApplicable
    from argus.gateway_fixtures.install import entry_url
    from tests.fixtures.gateway_ref import Entry
    from tests.fixtures.gateway_ref.out_of_band import ReauthorizationRequired
    async with running(tmp_path, mode='manual') as (target, gateway, host):
        monkeypatch.setattr('sys.stdin.isatty', lambda: False)
        with pytest.raises(ProbeNotApplicable):
            await target.send_prompt('')
        await gateway.reauthorize('oauth')
        gateway.entries['plain'] = Entry(entry_url(host.install, 'plain'))
        blocked = [True]
        original = gateway._request
        async def refuse_call(name, request, **kwargs):
            if name == 'plain' and kwargs.get('message', {}).get('method') == 'tools/call' and blocked[0]:
                raise ReauthorizationRequired
            return await original(name, request, **kwargs)
        monkeypatch.setattr(gateway, '_request', refuse_call)
        entries = []
        manual = ConsentDriver.reauthorize
        async def reauthorize(driver, entry):
            entries.append(entry)
            blocked[0] = False
            await manual(driver, entry)
        monkeypatch.setattr(ConsentDriver, 'reauthorize', reauthorize)
        ready = terminal(monkeypatch)
        ready[0] = True
        script = {'version': 1, 'requires': [], 'entries': ['plain'],
                  'cases': [{'id': 'plain-call', 'role': 'control', 'entry': 'plain', 'upstream': {}}],
                  'drive': {'tool': 'echo', 'calls_per_case': 1}}
        await target.begin_probe(SimpleNamespace(id='plain-after-oauth', scenario_payload=json.dumps(script)))
        await target.send_prompt('')
        assert entries == ['oauth']
        case, = (await target.collect_evidence())['cases']
        assert case['client']['manual_out_of_band'][0]['completed'] is True
        assert case['client']['calls'][-1]['reply'] == 'result'


async def test_shared_recovery_lease_survives_manual_wait(tmp_path, monkeypatch):
    import time
    from types import SimpleNamespace
    from argus.targets._base import ProbeNotApplicable
    from argus.gateway_fixtures.install import entry_url
    from tests.fixtures.gateway_ref import Entry
    from tests.fixtures.gateway_ref.out_of_band import ReauthorizationRequired
    async with running(tmp_path, mode='manual', timeout_s=60) as (target, gateway, host):
        monkeypatch.setattr('sys.stdin.isatty', lambda: False)
        with pytest.raises(ProbeNotApplicable):
            await target.send_prompt('')
        await gateway.reauthorize('oauth')
        gateway.entries['plain'] = Entry(entry_url(host.install, 'plain'))
        elapsed = [0]
        monkeypatch.setattr('argus.gateway_fixtures.host.time',
                            SimpleNamespace(monotonic=lambda: time.monotonic() + elapsed[0], time=time.time))
        blocked = [True]
        original = gateway._request
        async def refuse_call(name, request, **kwargs):
            if name == 'plain' and kwargs.get('message', {}).get('method') == 'tools/call' and blocked[0]:
                raise ReauthorizationRequired
            return await original(name, request, **kwargs)
        monkeypatch.setattr(gateway, '_request', refuse_call)
        manual = ConsentDriver.reauthorize
        async def reauthorize(driver, entry):
            # Advance only the fixture clock for a slow refusal and manual wait.
            elapsed[0] += 90
            blocked[0] = False
            await manual(driver, entry)
        monkeypatch.setattr(ConsentDriver, 'reauthorize', reauthorize)
        ready = terminal(monkeypatch)
        ready[0] = True
        script = {'version': 1, 'requires': [], 'entries': ['plain'],
                  'cases': [{'id': 'wait-and-retry', 'role': 'control', 'entry': 'plain', 'upstream': {}}],
                  'drive': {'tool': 'echo', 'calls_per_case': 1}}
        await target.begin_probe(SimpleNamespace(id='plain-recovery-wait', scenario_payload=json.dumps(script)))
        await target.send_prompt('')
        case, = (await target.collect_evidence())['cases']
        assert case['complete'] is True and case['client']['calls'][-1]['reply'] == 'result'
