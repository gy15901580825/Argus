"""Offline filter delivery paths, controls, and causal mutations."""
import base64
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import quote, quote_plus

import httpx
import pytest

from argus.assertions import evaluate_assertions
from argus.gateway_filter_assertions import capture, classify, gateway_filter_delivery_path as check
from argus.gateway_fixtures.delivery import CURRENT_PATHS, delivery
from argus.probe import load_probe
from argus.targets import build_target
from argus.targets._base import ProbeNotApplicable, TargetTransportError
from argus.targets._gateway_client import GatewayClient
from tests.fixtures.gateway_ref import Preset, ReferenceGateway
from tests.gateway_target.test_target import host, entries, target_spec

PROBE_PATH = Path(__file__).resolve().parents[2] / 'argus/probes/mcp_gateway/mcp_gateway_filter_delivery_paths.yaml'


class SideChannelGateway(ReferenceGateway):
    async def _relay(self, request, responses):
        # Keep the final result filtered while bypassing only notification messages.
        original = self.preset
        self.preset = replace(original, response_filter='all_messages')
        try:
            self._bypass = original.response_filter == 'json_only'
            return await super()._relay(request, responses)
        finally:
            self.preset = original

    def _json(self, value):
        if getattr(self, '_bypass', False) and value.get('method', '').startswith('notifications/'):
            return json.dumps(value).encode()
        return super()._json(value)


class WrapperStrippingGateway(ReferenceGateway):
    def _json(self, value):
        encoded = json.dumps(value)
        if 'argus-path=post_sse_final' in encoded:
            content = value['result']['content'][0]['text']
            value['result']['content'][0]['text'] = content.split(' begin ')[1].split(' end')[0]
            return json.dumps(value).encode()
        return super()._json(value)


class BlockingGateway(ReferenceGateway):
    def _json(self, value):
        if 'argus-path=' in json.dumps(value) and 'id' in value:
            return json.dumps({'jsonrpc': '2.0', 'id': value['id'], 'error': {'code': -32000, 'message': 'Filter blocked'}}).encode()
        return super()._json(value)


async def run(host, preset, *, gateway_type=ReferenceGateway, protocol='auto', recipe=None):
    async with gateway_type(entries(host), preset=preset) as gateway:
        settings = target_spec(host, gateway)
        settings['features']['response_filter'] = {'action': 'redact'}
        settings['gateway']['protocol'] = protocol
        target = build_target(settings)
        try:
            probe = load_probe(PROBE_PATH)
            await target.begin_probe(probe if recipe is None else SimpleNamespace(id=probe.id, scenario_payload=json.dumps(recipe)))
            await target.send_prompt('')
            evidence = await target.collect_evidence()
            results = evaluate_assertions(({'gateway_filter_delivery_path': {}},), evidence, '')
            assert not results[0].definition_error
            return evidence, check({}, evidence)
        finally:
            await target.aclose()


@pytest.mark.parametrize('base', [Preset.safe(), Preset.vulnerable()])
@pytest.mark.parametrize('protocol', ['2025-11-25', '2025-06-18'])
async def test_filter_toggle_flips_same_result_verdict(host, base, protocol):
    for mode, expected in [('json_only', 'fail'), ('all_messages', 'pass'), ('off', 'skipped')]:
        evidence, outcome = await run(host, replace(base, response_filter=mode), protocol=protocol)
        assert outcome.verdict == expected
        paths = evidence['summary']['filter_delivery_paths']
        assert [p['path'] for p in paths] == list(CURRENT_PATHS)
        assert all(p['served_by_upstream'] and p['era'] == protocol for p in paths)
        assert paths[0]['classification'] == ('raw' if mode == 'off' else 'redacted')
        assert all(p['classification'] == ('redacted' if mode == 'all_messages' else 'raw') for p in paths[1:])
        assert paths[0]['upstream_channel'] == 'post_json'
        assert all(p['upstream_channel'] == 'post_sse' for p in paths[1:])
        assert all(p['client_channels'] == [p['upstream_channel']] for p in paths)
        messages = evidence['cases'][2]['client']['calls'][0]['messages']
        assert [m['kind'] for m in messages] == ['notifications/message', 'result']
        progress = evidence['cases'][3]['client']['calls'][0]['messages']
        assert [m['kind'] for m in progress] == ['notifications/progress', 'result']
        if expected == 'fail':
            assert outcome.severity == 'medium' and 'post_sse_final' in outcome.reason
            mutated = deepcopy(evidence)
            for case in mutated['cases'][1:]:
                case['client']['calls'][0]['classification'] = 'redacted'
            assert check({}, mutated).verdict == 'pass'
        serialized = json.dumps(evidence)
        for secret in [host[0].control_token, host[0].install['path_token'], *host[0]._canaries.values()]:
            for encoded in [secret, quote(secret), quote_plus(secret), base64.b64encode(secret.encode()).decode()]:
                assert encoded not in serialized


@pytest.mark.parametrize('base', [Preset.safe(), Preset.vulnerable()])
async def test_side_channel_only_toggle_warns(host, base):
    for mode, expected in [('json_only', 'warn'), ('all_messages', 'pass')]:
        evidence, outcome = await run(host, replace(base, response_filter=mode), gateway_type=SideChannelGateway)
        assert outcome.verdict == expected
        paths = evidence['summary']['filter_delivery_paths']
        assert paths[1]['classification'] == 'redacted'
        assert paths[2]['classification'] == ('raw' if expected == 'warn' else 'redacted')
        if expected == 'warn':
            assert 'post_sse_notification' in outcome.reason and 'progress_message' in outcome.reason
            evidence['cases'][2]['client']['calls'][0]['classification'] = 'absent'
            evidence['cases'][3]['client']['calls'][0]['classification'] = 'absent'
            assert check({}, evidence).verdict == 'pass'


async def test_control_and_exercise_gates_mutate(host):
    evidence, _ = await run(host, Preset.safe())
    mutated = deepcopy(evidence)
    mutated['cases'][0]['client']['calls'][0]['classification'] = 'raw'
    assert check({}, mutated).verdict == 'skipped'
    mutated['cases'][0]['client']['calls'][0]['classification'] = 'absent'
    assert check({}, mutated).verdict == 'error'
    mutated = deepcopy(evidence)
    for case in mutated['cases'][1:]:
        case['fixture']['requests'][0]['body']['jsonrpc']['nonce'] = 'background'
    assert check({}, mutated).verdict == 'skipped'
    mutated['cases'][1]['fixture']['requests'] = deepcopy(evidence['cases'][1]['fixture']['requests'])
    assert check({}, mutated).verdict == 'pass'
    mutated['cases'][1]['complete'] = False
    assert check({}, mutated).verdict == 'error'
    mutated['cases'][1]['client']['calls'][0]['classification'] = 'raw'
    assert check({}, mutated).verdict == 'fail'
    mutated['cases'][1]['client']['calls'][0]['status'] = 401
    assert check({}, mutated).verdict == 'error'


async def test_unserved_or_unattributed_paths_cannot_fail(host):
    evidence, _ = await run(host, Preset.vulnerable())
    for case in evidence['cases'][1:]:
        for record in case['fixture']['requests']:
            record['ext'] = {}
    assert check({}, evidence).verdict == 'skipped'


async def test_marker_survives_wrapper_removal(host):
    evidence, outcome = await run(host, Preset.safe(), gateway_type=WrapperStrippingGateway)
    assert outcome.verdict == 'fail' and 'post_sse_final' in outcome.reason
    call = evidence['cases'][1]['client']['calls'][0]
    assert not call['messages'][0]['classifications'] and call['classification'] == 'raw'
    _, outcome = await run(host, Preset.safe())
    assert outcome.verdict == 'pass'


async def test_blocking_control_and_final_pass(host):
    evidence, outcome = await run(host, Preset.safe(), gateway_type=BlockingGateway)
    assert outcome.verdict == 'pass'
    assert all(p['classification'] == 'blocked' for p in evidence['summary']['filter_delivery_paths'][:2])
    evidence['cases'] = evidence['cases'][1:]
    assert check({}, evidence).verdict == 'skipped'


async def test_missing_feature_and_entry_skip(host):
    async with ReferenceGateway({'hdr': entries(host)['hdr']}) as gateway:
        settings = target_spec(host, gateway)
        target = build_target(settings)
        try:
            with pytest.raises(ProbeNotApplicable, match='response_filter'):
                await target.begin_probe(load_probe(PROBE_PATH))
        finally:
            await target.aclose()
        settings['features']['response_filter'] = {'action': 'redact'}
        target = build_target(settings)
        try:
            await target.begin_probe(load_probe(PROBE_PATH))
            with pytest.raises(ProbeNotApplicable, match='entry not registered'):
                await target.send_prompt('')
            assert host[0].lease_id is None
        finally:
            await target.aclose()


@pytest.mark.parametrize('path', ['post_sse_resumed', 'get_stream_notification', 'unknown', {}, None])
def test_legacy_and_unknown_delivery_definitions_refused(path):
    with pytest.raises(ValueError):
        delivery(path)


@pytest.mark.parametrize('channel', ['post_json', 'post_sse', 'get_sse', 'resumed_sse', 'listen_sse', 'mrtr'])
def test_channel_capture_seam(channel):
    text = 'argus-path=post_sse_final begin ARGUSFLT0123456789ABCDEF0123 end'
    raw = capture({'jsonrpc': '2.0', 'result': {'content': [{'text': text}]}}, channel)
    assert raw['channel'] == channel and classify([raw], 'post_sse_final') == 'raw'
    redacted = capture({'jsonrpc': '2.0', 'result': {'content': [{'text': text.replace('ARGUSFLT0123456789ABCDEF0123', '[REDACTED]')}]}}, channel)
    assert classify([redacted], 'post_sse_final') == 'redacted'
    assert classify([raw], 'progress_message') == 'absent'
    assert classify([], 'post_sse_final', {'error': {'code': -32000}}) == 'blocked'
    assert classify([], 'post_sse_final', {'result': {'isError': True}}) == 'blocked'
    assert classify([], 'post_sse_final', {'result': {'content': []}}) == 'blocked'


@pytest.mark.parametrize('value,evidence', [({'unexpected': True}, {}), ({}, {}), ({}, {'cases': []}), ({}, {'cases': [None]})])
def test_malformed_assertion_refused(value, evidence):
    assert check(value, evidence).verdict == 'error'


async def test_sse_fragmentation_preserves_all_messages_and_masks_content():
    marker = 'ARGUSFLT0123456789ABCDEF0123'
    frames = [{'jsonrpc': '2.0', 'method': 'notifications/message', 'params': {'data': f'argus-path=progress_message begin {marker} end', 'credential': 'generated-canary'}},
              {'jsonrpc': '2.0', 'id': 1, 'result': {'content': [{'text': 'ok'}]}}]
    encoded = ''.join('data: ' + json.dumps(frame) + '\r\n\r\n' for frame in frames).encode()

    class Chunks(httpx.AsyncByteStream):
        async def __aiter__(self):
            for byte in encoded:
                yield bytes([byte])

    client = GatewayClient({'url': 'http://127.0.0.1:1/mcp', 'protocol': '2025-11-25'}, 1)
    await client.client.aclose()
    client.client = httpx.AsyncClient(transport=httpx.MockTransport(lambda _: httpx.Response(200, headers={'content-type': 'text/event-stream'}, stream=Chunks())))
    try:
        observed, body = await client.rpc('tools/call', {})
        assert body['id'] == 1
        assert len(observed['messages']) == 2
        assert classify(observed['messages'], 'progress_message', body) == 'raw'
        assert 'generated-canary' not in json.dumps(observed)
    finally:
        await client.aclose()


async def test_notification_before_timeout_is_captured():
    frame = {'jsonrpc': '2.0', 'method': 'notifications/progress',
             'params': {'message': 'argus-path=progress_message begin ARGUSFLT0123456789ABCDEF0123 end'}}

    class TimeoutStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield ('data: ' + json.dumps(frame) + '\n\n').encode()
            raise httpx.ReadTimeout('synthetic timeout')

    client = GatewayClient({'url': 'http://127.0.0.1:1/mcp', 'protocol': '2025-11-25'}, 1)
    await client.client.aclose()
    client.client = httpx.AsyncClient(transport=httpx.MockTransport(lambda _: httpx.Response(200, headers={'content-type': 'text/event-stream'}, stream=TimeoutStream())))
    try:
        observation, body = await client.rpc('tools/call', {})
        assert body is None and observation['reply'] == 'timeout'
        assert observation['channels'] == ['post_sse']
        assert classify(observation['messages'], 'progress_message') == 'raw'
    finally:
        await client.aclose()
