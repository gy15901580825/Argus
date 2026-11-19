"""Failed gateway exchanges preserve sealed observations without credential values."""
import asyncio
import json
import secrets
from dataclasses import replace

import pytest
from aiohttp import web

from argus.cli.run_json import scrub_run
from argus.probe import load_probe
from argus.runner import Runner
from argus.targets import build_target
from tests.fixtures.gateway_ref import ReferenceGateway
from tests.gateway_target.test_target import host, entries, target_spec
from tests.gateway_target.test_passthrough_probe import PROBE, _ExplodingJudge


class RefusingGateway(ReferenceGateway):
    def __init__(self, *args, refuse=True, json_error=True, refuse_method=None, slow_error=False, **kwargs):
        super().__init__(*args, **kwargs)
        self.refuse, self.json_error = refuse, json_error
        self.calls = 0
        self.refuse_method = refuse_method
        self.slow_error = slow_error
        self.secret = 'argus-canary-response-' + secrets.token_hex(16)

    async def _handle(self, request):
        response = await super()._handle(request)
        message = await request.json()
        if self.refuse_method == message.get('method'):
            return web.Response(status=403, text='Refused ' + self.secret)
        if message.get('method') == 'tools/call':
            self.calls += 1
            if self.refuse and self.calls == 2:
                if self.slow_error:
                    refusal = web.StreamResponse(status=403, headers={'Content-Type': 'text/plain'})
                    await refusal.prepare(request)
                    await refusal.write(('Rejected ' + self.secret).encode())
                    await asyncio.sleep(0.5)
                    return refusal
                if self.json_error is None:
                    return web.Response(status=200, text='Malformed ' + self.secret)
                if self.json_error:
                    return web.json_response({'jsonrpc': '2.0', 'id': message['id'], 'error': {
                        'code': -32001, 'message': 'Refused ' + self.secret, 'data': {'hidden': self.secret}}}, status=403)
                return web.Response(status=403, text='Refused ' + self.secret + ' ' + 'x' * 900)
        return response


@pytest.mark.parametrize('refuse', [False, True])
@pytest.mark.parametrize('json_error', [False, True])
async def test_runner_keeps_failed_case_and_redacted_response(host, refuse, json_error):
    async with RefusingGateway(entries(host), refuse=refuse, json_error=json_error) as gateway:
        settings = target_spec(host, gateway)
        settings['gateway']['auth'] = {'headers': {'X-API-Key': gateway.secret}}
        target = build_target(settings)
        try:
            probe = load_probe(PROBE)
            recipe = json.loads(probe.scenario_payload)
            recipe['drive']['calls_per_case'] = 2
            probe = replace(probe, scenario_payload=json.dumps(recipe))
            finding, = [f async for f in Runner(target, _ExplodingJudge(), PROBE.parents[2] / 'rubrics').run_probe(probe)]
            assert finding.verdict == ('error' if refuse else 'pass'), finding.reasoning
            evidence = finding.evidence
            assert evidence and evidence['interaction_count'] > 0
            assert host[0].lease_id is None and host[0].case is None
            exported = scrub_run({'target_spec': settings, 'findings': [{'evidence': evidence}]})
            assert gateway.secret not in json.dumps(exported)
            if refuse:
                case = evidence['cases'][-1]
                assert len(case['fixture']['requests']) == 2
                assert case['client']['calls'][0]['reply'] == 'result'
                failed = case['client']['calls'][-1]
                assert failed['reply'] == 'transport_error'
                failure = failed['transport_error']
                assert failure['method'] == 'POST' and failure['path_class'] == 'mcp'
                assert failure['status'] == 403
                body = failure['body']
                if json_error:
                    assert body['kind'] == 'jsonrpc_error' and body['code'] == -32001
                    assert body['message'].startswith('Refused <redacted>')
                    assert 'data' not in body
                else:
                    assert body['kind'] == 'text' and body['truncated']
                    assert len(body['text'].encode()) <= 512
            else:
                assert all(call['reply'] == 'result' for case in evidence['cases'] for call in case['client']['calls'])

        finally:
            await target.aclose()


def test_export_preserves_header_names_and_masks_values():
    secret = 'argus-canary-export-' + secrets.token_hex(16)
    settings = {'kind': 'mcp_gateway', 'features': {'upstream_headers': {'names': ['X-API-Key', 'Authorization']}},
                'gateway': {'auth': {'headers': {'X-API-Key': secret, 'Authorization': 'Bearer ' + secret}}}}
    evidence = {'configured_headers': ['X-API-Key', 'Authorization'],
                'hits': ['upstream_header:X-API-Key', 'auth_header:Authorization'], 'reflected_value': secret}
    exported = scrub_run({'target_spec': settings, 'findings': [{'evidence': evidence}]})
    assert exported['target_spec']['features']['upstream_headers']['names'] == ['X-API-Key', 'Authorization']
    assert exported['findings'][0]['evidence']['configured_headers'] == ['X-API-Key', 'Authorization']
    assert exported['findings'][0]['evidence']['hits'] == ['upstream_header:X-API-Key', 'auth_header:Authorization']
    assert secret not in json.dumps(exported)


@pytest.mark.parametrize('method', ['initialize', 'notifications/initialized', 'tools/list'])
async def test_negotiation_refusal_retains_request_evidence(host, method):
    async with RefusingGateway(entries(host), refuse_method=method) as gateway:
        settings = target_spec(host, gateway)
        settings['gateway'].update(protocol='2025-11-25', auth={'headers': {'X-API-Key': gateway.secret}})
        target = build_target(settings)
        try:
            finding, = [f async for f in Runner(target, _ExplodingJudge(), PROBE.parents[2] / 'rubrics').run_probe(load_probe(PROBE))]
            assert finding.verdict == 'error'
            failure = finding.evidence['transport_error']
            assert failure['method'] == 'POST' and failure['rpc_method'] == method
            assert failure['status'] == 403 and failure['path_class'] == 'mcp'
            assert gateway.secret not in json.dumps(finding.evidence)
            assert host[0].lease_id is None
        finally:
            await target.aclose()


async def test_malformed_success_response_keeps_redacted_body(host):
    async with RefusingGateway(entries(host), json_error=None) as gateway:
        settings = target_spec(host, gateway)
        settings['gateway']['auth'] = {'headers': {'X-API-Key': gateway.secret}}
        target = build_target(settings)
        try:
            finding, = [f async for f in Runner(target, _ExplodingJudge(), PROBE.parents[2] / 'rubrics').run_probe(load_probe(PROBE))]
            assert finding.verdict == 'error'
            failure = finding.evidence['cases'][-1]['client']['calls'][-1]['transport_error']
            assert failure['status'] == 200 and failure['body']['text'] == 'Malformed <redacted>'
            assert finding.evidence['cases'][-1]['fixture']['requests']
            assert gateway.secret not in json.dumps(finding.evidence)
        finally:
            await target.aclose()


async def test_slow_refusal_body_still_produces_error_with_partial_evidence(host):
    async with RefusingGateway(entries(host), slow_error=True) as gateway:
        settings = target_spec(host, gateway)
        settings['timeout_s'] = 0.15
        settings['gateway']['auth'] = {'headers': {'X-API-Key': gateway.secret}}
        target = build_target(settings)
        try:
            finding, = [f async for f in Runner(target, _ExplodingJudge(), PROBE.parents[2] / 'rubrics').run_probe(load_probe(PROBE))]
            assert finding.verdict == 'error'
            failure = finding.evidence['cases'][-1]['client']['calls'][-1]['transport_error']
            assert failure['status'] == 403 and failure['body']['truncated']
            assert failure['body']['text'] == 'Rejected <redacted>'
            assert finding.evidence['cases'][-1]['fixture']['requests']
        finally:
            await target.aclose()
