"""Webhook decision mutations through the shipped fixture and probe."""
import copy
import json
from dataclasses import replace
from pathlib import Path

import httpx
import pytest

from argus.assertions import evaluate_assertions
from argus.gateway_fixtures.webhook import decision, resolve_decision
from argus.gateway_webhook import decide
from argus.probe import load_probe
from argus.targets import build_target
from argus.targets._base import ProbeNotApplicable
from tests.fixtures.gateway_ref import Preset, ReferenceGateway
from tests.gateway_target.test_target import entries, host, target_spec

PROBE = Path(__file__).resolve().parents[2] / 'argus/probes/mcp_gateway/mcp_gateway_webhook_decision.yaml'
CONTRACT = {'stage': 'pre_call', 'allow': {'status': 200, 'body': {'decision': 'allow'}},
            'deny': {'status': 200, 'body': {'decision': 'deny'}}}


async def run(host, preset, *, wired=True, cache_allow=False, contract=None, mutate=None, gateway_type=ReferenceGateway):
    fixture, _ = host
    contract = contract or CONTRACT
    hook_url = fixture.origin_urls['upstream'] + fixture.install['webhook']['path'].replace('{path_token}', fixture.install['path_token'])
    async with gateway_type(entries(host), preset=preset, webhook_url=hook_url if wired else None,
                                allow_status=contract['allow']['status'], allow_body=contract['allow']['body'],
                                cache_allow=cache_allow) as gateway:
        settings = target_spec(host, gateway)
        settings['features'] = {'webhook': contract}
        target = build_target(settings)
        probe = load_probe(PROBE)
        if mutate:
            payload = json.loads(probe.scenario_payload)
            mutate(payload)
            probe = replace(probe, scenario_payload=json.dumps(payload))
        try:
            await target.begin_probe(probe)
            text, _ = await target.send_prompt('')
            evidence = await target.collect_evidence()
            outcome = decide({}, evidence)
            results = evaluate_assertions(probe.assertions, evidence, text)
            assert len(results) == 1
            assert results[0].passed == (outcome.verdict == 'pass')
            return outcome, evidence
        finally:
            await target.aclose()


@pytest.mark.parametrize('preset', [Preset.safe(), Preset.vulnerable()])
@pytest.mark.parametrize('cache_allow', [False, True])
async def test_status_toggle_flips_verdict(host, preset, cache_allow):
    vulnerable, evidence = await run(host, replace(preset, webhook='status'), cache_allow=cache_allow)
    safe, safe_evidence = await run(host, replace(preset, webhook='decision'), cache_allow=cache_allow)
    assert vulnerable.verdict == 'fail' and vulnerable.severity == 'medium'
    assert 'deny_2xx_documented' in vulnerable.reason
    assert safe.verdict == 'pass'
    assert evidence['summary']['webhook']['deny_2xx_documented']['upstream_received']
    assert not safe_evidence['summary']['webhook']['deny_2xx_documented']['upstream_received']
    assert [case['id'] for case in evidence['cases']][-1] == 'allow'
    assert len(safe_evidence['cases'][2]['client']['calls']) == 2
    assert safe_evidence['summary']['webhook']['malformed_2xx']['webhook_status_sent'] == [200, 200]
    nonces = [case['client']['calls'][0]['nonce'] for case in evidence['cases']]
    assert len(set(nonces)) == 5
    mutated = copy.deepcopy(evidence)
    for case in mutated['cases']:
        if case['role'] == 'attack':
            case['fixture']['requests'] = [r for r in case['fixture']['requests'] if r['route'] != 'mcp']
    assert decide({}, mutated).verdict == ('skipped' if cache_allow else 'pass')


async def test_unwired_and_audit_controls_skip(host):
    assert (await run(host, Preset.safe(), wired=False))[0].verdict == 'skipped'
    def allow_non2xx(payload):
        payload['cases'][0]['upstream']['decision'] = {'documented': 'allow'}
    outcome, _ = await run(host, Preset.safe(), mutate=allow_non2xx)
    assert outcome.verdict == 'skipped' and 'deny_non2xx' in outcome.reason


@pytest.mark.parametrize('deny_status', [200, 201, 403])
async def test_custom_documented_contract(host, deny_status):
    contract = {'stage': 'pre_call', 'allow': {'status': 201, 'body': {'authorized': True}},
                'deny': {'status': deny_status, 'body': {'authorized': False}}}
    safe, evidence = await run(host, Preset.safe(), contract=contract)
    vulnerable, _ = await run(host, Preset.vulnerable(), contract=contract)
    assert safe.verdict == 'pass' and vulnerable.verdict == 'fail'
    assert evidence['summary']['webhook']['allow']['webhook_status_sent'] == [201]
    assert evidence['summary']['webhook']['deny_2xx_documented']['webhook_status_sent'] == [deny_status if 200 <= deny_status < 300 else 200]


async def test_ambiguous_only_warn_and_incomplete_gate(host):
    _, evidence = await run(host, Preset.vulnerable())
    documented = evidence['cases'][1]
    documented['fixture']['requests'] = [r for r in documented['fixture']['requests'] if r['route'] != 'mcp']
    assert decide({}, evidence).verdict == 'warn'
    for case in evidence['cases']:
        if case['role'] == 'attack':
            case['fixture']['requests'] = [r for r in case['fixture']['requests'] if r['route'] != 'mcp']
    evidence['cases'][0]['complete'] = False
    assert decide({}, evidence).verdict == 'error'
    evidence['cases'][0]['complete'] = True
    assert decide({}, evidence).verdict == 'pass'
    evidence['cases'][1]['fixture']['requests'] = []
    evidence['cases'][2]['fixture']['requests'] = []
    evidence['cases'][3]['fixture']['requests'] = []
    assert decide({}, evidence).verdict == 'skipped'


async def test_missing_feature_and_malformed_recipe_refused(host):
    async with ReferenceGateway(entries(host)) as gateway:
        target = build_target(target_spec(host, gateway))
        try:
            with pytest.raises(ProbeNotApplicable, match='webhook'):
                await target.begin_probe(load_probe(PROBE))
            probe = load_probe(PROBE)
            payload = json.loads(probe.scenario_payload)
            payload['cases'][2]['calls_per_case'] = True
            with pytest.raises(ValueError, match='calls_per_case'):
                await target.begin_probe(replace(probe, scenario_payload=json.dumps(payload)))
        finally:
            await target.aclose()


async def test_webhook_idle_and_body_privacy(host):
    fixture, _ = host
    url = fixture.origin_urls['upstream'] + fixture.install['webhook']['path'].replace('{path_token}', fixture.install['path_token'])
    async with httpx.AsyncClient(trust_env=False) as client:
        assert (await client.post(url, json={'identity': 'synthetic-id'})).json() == {'decision': 'allow'}
    _, evidence = await run(host, Preset.safe())
    for case in evidence['cases']:
        for record in case['fixture']['requests']:
            if record['route'] == 'webhook':
                assert 'jsonrpc' not in record['body']
                assert record['ext']['webhook']['nonce_correlated']
    for value in [fixture.control_token, fixture.install['path_token'], *fixture._canaries.values()]:
        assert value not in json.dumps(evidence)


@pytest.mark.parametrize('config', [None, {}, {'status': True}, {'status': 200, 'extra': 1},
                                    {'documented': 'unknown'}, {'status': 200, 'body': float('nan')},
                                    {'responses': []}, {'responses': [{'responses': [{'status': 200}]}]}, {'status': 200, 'body': 'x' * 65537}])
def test_decision_invalid_definition(config):
    with pytest.raises((ValueError, TypeError)):
        decision(config)


def test_decision_resolution_does_not_mutate_contract():
    original = copy.deepcopy(CONTRACT)
    assert resolve_decision({'documented': 'deny', 'status': 200}, CONTRACT)['body'] == {'decision': 'deny'}
    assert CONTRACT == original


async def test_allow_first_cache_cannot_satisfy_deny_control(host):
    def allow_first(payload):
        payload['cases'].insert(0, payload['cases'].pop())
    for preset in (Preset.safe(), Preset.vulnerable()):
        outcome, evidence = await run(host, preset, cache_allow=True, mutate=allow_first)
        assert outcome.verdict == 'skipped' and 'deny_non2xx' in outcome.reason
        assert evidence['summary']['webhook']['deny_non2xx']['upstream_received']


async def test_background_hook_contact_does_not_satisfy_controls(host):
    _, evidence = await run(host, Preset.safe())
    for case in evidence['cases']:
        for record in case['fixture']['requests']:
            if record['route'] == 'webhook':
                record['ext']['webhook']['nonce_correlated'] = False
    assert decide({}, evidence).verdict == 'skipped'


async def test_gateway_webhook_envelope_and_identity_privacy(host):
    class WrappedWebhook(ReferenceGateway):
        change_nonce = False

        async def _webhook_allowed(self, message):
            wrapped = copy.deepcopy(message)
            if self.change_nonce:
                wrapped['params']['arguments']['nonce'] = 'unrelated-nonce'
            response = await self.client.post(self.webhook_url, json={
                'request': wrapped, 'identity': 'argus-synthetic-webhook-identity'})
            if self.preset.webhook == 'status':
                return 200 <= response.status_code < 300
            try:
                return response.json() == self.allow_body and response.status_code == self.allow_status
            except ValueError:
                return False

    for preset, expected in ((Preset.safe(), 'pass'), (Preset.vulnerable(), 'fail')):
        outcome, evidence = await run(host, preset, gateway_type=WrappedWebhook)
        assert outcome.verdict == expected
        assert 'argus-synthetic-webhook-identity' not in json.dumps(evidence)
    WrappedWebhook.change_nonce = True
    assert (await run(host, Preset.safe(), gateway_type=WrappedWebhook))[0].verdict == 'skipped'


async def test_case_call_override_and_redirect_recontact_share_lease_budget(host):
    from tests.gateway_target.test_target import probe, recipe

    async with ReferenceGateway(entries(host)) as gateway:
        settings = target_spec(host, gateway)
        settings.update(timeout_s=178, case_window_s=0)
        target = build_target(settings)
        payload = recipe(drive={'tool': 'echo', 'calls_per_case': 1})
        payload['cases'][0]['calls_per_case'] = 19
        payload['cases'][1]['upstream'] = {
            'redirect': {'status': 308, 'to': 'foreign', 'on': 'tools/call'}}
        try:
            with pytest.raises(ValueError, match='one-hour fixture lease'):
                await target.begin_probe(probe(payload))
            payload['cases'][1]['upstream']['redirect']['status'] = 307
            await target.begin_probe(probe(payload))
        finally:
            await target.aclose()
