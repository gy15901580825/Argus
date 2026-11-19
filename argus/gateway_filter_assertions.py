"""Classify filter observations and decide delivery-path conformance."""
import json
import re

from argus.world_assertions import AssertionOutcome

MARKER = re.compile(r'ARGUSFLT[0-9A-F]{20}')
WRAPPER = re.compile(r'argus-path=([\w-]+) begin (.*?) end', re.DOTALL)
SAME_RESULT_PATHS = frozenset({'post_sse_final', 'post_sse_resumed'})
DELIVERY_PATHS = frozenset({'inline_json', *SAME_RESULT_PATHS, 'post_sse_notification', 'progress_message',
                          'get_stream_notification', 'mrtr_input_request'})


def capture(message, channel):
    classifications = []
    for path, content in WRAPPER.findall(json.dumps(message)):
        if path in DELIVERY_PATHS:
            classifications.append({'path': path, 'classification': 'raw' if MARKER.search(content) else 'redacted'})
    kind = message.get('method', 'error' if 'error' in message else 'result')
    if kind not in ('result', 'error', 'notifications/message', 'notifications/progress'):
        kind = 'server_request' if 'id' in message else 'notification'
    return {'channel': channel, 'kind': kind,
            'classifications': classifications}


def classify(messages, path, reply=None):
    observed = [item['classification'] for message in messages for item in message['classifications'] if item['path'] == path]
    for classification in ('raw', 'redacted'):
        if classification in observed:
            return classification
    if reply and ('error' in reply or isinstance(reply.get('result'), dict)
                  and (reply['result'].get('isError') is True or reply['result'].get('content') == []
                       or reply['result'].get('content') == [{'type': 'text', 'text': ''}])):
        return 'blocked'
    return 'absent'


def gateway_filter_delivery_path(value, evidence):
    if value != {}:
        return AssertionOutcome('error', 'gateway filter assertion expects an empty object')
    try:
        return _decide(evidence)
    except (KeyError, TypeError, AttributeError, ValueError):
        return AssertionOutcome('error', 'gateway filter evidence is malformed')


def _decide(evidence):
    cases = evidence['cases']
    if not isinstance(cases, list) or not cases:
        return AssertionOutcome('error', 'gateway filter evidence has no cases')
    paths, controls, attacks = [], [], []
    incomplete = False
    for case in cases:
        path = case['delivery']
        if case['role'] not in ('control', 'attack') or not isinstance(path, str):
            raise ValueError
        calls = case['client']['calls']
        if any(call.get('status') in (401, 403) for call in calls):
            return AssertionOutcome('error', 'gateway client authentication failed')
        nonces = {call['nonce'] for call in calls}
        served = [record['ext']['delivery'] for record in case['fixture']['requests']
                  if record.get('actor') == 'gateway' and record.get('entry') == case['entry']
                  and record.get('body', {}).get('jsonrpc', {}).get('nonce') in nonces
                  and record.get('ext', {}).get('delivery', {}).get('path') == path
                  and record['ext']['delivery'].get('served_by_upstream') is True]
        classifications = [call['classification'] for call in calls]
        if any(c not in ('raw', 'redacted', 'blocked', 'absent') for c in classifications):
            raise ValueError
        classification = next((c for c in ('raw', 'redacted', 'blocked') if c in classifications), 'absent')
        observation = {'path': path, 'era': evidence['era'], 'served_by_upstream': bool(served),
                       'upstream_channel': served[0]['upstream_channel'] if served else None,
                       'client_channels': sorted({channel for call in calls for channel in call['channels']}),
                       'classification': classification}
        paths.append(observation)
        (controls if case['role'] == 'control' else attacks).append(observation)
        incomplete |= case.get('complete') is not True or case.get('dropped', 0) != 0
        incomplete |= any(record.get('body', {}).get('complete') is False for record in case['fixture']['requests'])
    evidence.setdefault('summary', {})['filter_delivery_paths'] = paths
    if not controls or not any(c['path'] == 'inline_json' for c in controls):
        return AssertionOutcome('skipped', 'gateway filter probe has no inline JSON control')
    for control in controls:
        if control['classification'] == 'absent':
            return AssertionOutcome('error', 'basic filter control call failed: ' + control['path'])
        if control['classification'] == 'raw':
            return AssertionOutcome('skipped', 'the filter is not active on the inline JSON path; check the rule')
        if not control['served_by_upstream']:
            return AssertionOutcome('skipped', 'control did not reach the upstream: ' + control['path'])
    exercised = [attack for attack in attacks if attack['served_by_upstream']]
    if not exercised:
        return AssertionOutcome('skipped', 'not exercised: no non-control delivery path was served')
    raw = [attack['path'] for attack in exercised if attack['classification'] == 'raw']
    failures = sorted(set(raw) & SAME_RESULT_PATHS)
    if failures:
        return AssertionOutcome('fail', 'response filter bypass on same-result path: ' + ', '.join(failures), 'medium')
    if raw:
        return AssertionOutcome('warn', 'content reached the client unfiltered through a side channel: ' + ', '.join(sorted(set(raw))))
    if incomplete:
        return AssertionOutcome('error', 'incomplete gateway evidence cannot establish a filter pass')
    return AssertionOutcome('pass', 'exercised delivery paths exposed no raw filter marker')
