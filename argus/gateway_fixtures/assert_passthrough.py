"""Decide client credential passthrough using redacted fixture hit labels."""
from argus.world_assertions import AssertionOutcome


def _secret(label):
    return label.startswith(('auth_header:', 'cookie:'))


def gateway_no_client_credential_upstream(value, evidence):
    if value != {}:
        return AssertionOutcome('error', 'gateway credential assertion expects an empty object')
    try:
        return _decide(evidence)
    except (KeyError, TypeError, AttributeError):
        return AssertionOutcome('error', 'gateway credential evidence is malformed')


def _decide(evidence):
    cases = evidence['cases']
    if not isinstance(cases, list) or not cases:
        return AssertionOutcome('error', 'gateway credential evidence has no cases')
    exercised, attacks, failures, canaries, webhook, forwarded, sessions = set(), [], [], set(), set(), set(), set()
    failed_controls = []
    incomplete = False
    credentials = evidence.get('client_credentials', [])
    client_headers = {c['label'].split(':', 1)[1].lower() for c in credentials if c['label'].startswith('auth_header:')}
    if any(c['label'].startswith('cookie:') or c['label'] == 'client_canary' for c in credentials):
        client_headers.add('cookie')
    client_headers.update({'x-argus-client-canary', 'mcp-session-id'})
    for case in cases:
        if case['role'] not in ('control', 'attack'):
            return AssertionOutcome('error', 'gateway credential case has an invalid role')
        calls = case['client']['calls']
        if any(call.get('status') in (401, 403) for call in calls):
            return AssertionOutcome('error', 'gateway client authentication failed')
        nonces = {call['nonce'] for call in calls if isinstance(call['nonce'], str) and call['nonce']}
        contacted = set()
        incomplete |= case.get('complete') is not True or case.get('dropped', 0) != 0
        for request in case['fixture']['requests']:
            incomplete |= request.get('body', {}).get('complete') is False
            if request.get('actor') != 'gateway':
                continue
            hits = request['hits']
            if not isinstance(hits, list) or any(not isinstance(label, str) for label in hits):
                return AssertionOutcome('error', 'gateway request hit labels are malformed')
            secrets = {label.removesuffix(':payload') for label in hits if _secret(label)}
            if request['origin'] == 'upstream' and request['route'] == 'webhook':
                webhook.update(secrets)
                continue
            correlated = request.get('body', {}).get('jsonrpc', {}).get('nonce') in nonces
            upstream_call = request['origin'] == 'upstream' and request['route'] == 'mcp' and correlated
            # Foreign fixture routes exist only for the active case; idle noise is excluded.
            foreign = request['origin'] == 'foreign' and (correlated or request['route'] != 'other')
            if upstream_call:
                entry = request['entry']
                contacted.add(entry)
                exercised.add(entry)
                forwarded.update(h['name'].lower() for h in request.get('headers', []) if h['name'].lower() in client_headers)
                if 'gateway_session_id' in hits:
                    sessions.add(entry)
            if upstream_call or foreign:
                failures.extend((label, request.get('entry') or case.get('entry', 'unknown')) for label in secrets)
                if 'client_canary' in hits and upstream_call:
                    canaries.add(request['entry'])
        if case['role'] == 'control' and not contacted:
            failed_controls.append(case['id'])
        if case['role'] == 'attack' and contacted:
            attacks.append(case['id'])
    evidence.setdefault('summary', {}).update({
        'client_credentials': credentials, 'entries_exercised': sorted(exercised),
        'credential_hits': [{'label': label, 'entry': entry} for label, entry in sorted(set(failures))],
        'canary_entries': sorted(canaries), 'forwarded_client_header_names': sorted(forwarded),
        'gateway_session_id_forwarded_entries': sorted(sessions),
        'webhook_received_client_credential': sorted(webhook),
    })
    if failed_controls:
        return AssertionOutcome('skipped', 'control did not reach the upstream: ' + ', '.join(failed_controls))
    if not any(c['role'] == 'control' for c in cases):
        return AssertionOutcome('skipped', 'gateway credential probe has no control case')
    if not attacks:
        return AssertionOutcome('skipped', 'not exercised: no attack nonce call reached an upstream entry')
    if failures:
        return AssertionOutcome('fail', 'client credential reached an upstream: ' + ', '.join(
            f'{label} at entry {entry}' for label, entry in sorted(set(failures))), 'high')
    if canaries:
        return AssertionOutcome('warn', 'the gateway forwards arbitrary client headers or cookies upstream')
    if incomplete:
        return AssertionOutcome('error', 'incomplete gateway evidence cannot establish a credential miss')
    return AssertionOutcome('pass', 'exercised entries received no client credential or canary hits')
