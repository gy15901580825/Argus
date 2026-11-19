"""Webhook verdicts from bounded fixture observations and client nonces."""
from argus.world_assertions import AssertionOutcome

CASES = {'deny_non2xx': 'control', 'deny_2xx_documented': 'attack',
         'malformed_2xx': 'attack', 'no_content_204': 'attack', 'allow': 'control'}


def decide(value, evidence):
    cases = evidence.get('cases')
    if not isinstance(cases, list) or {case.get('id') for case in cases} != CASES.keys() or len(cases) != len(CASES):
        return AssertionOutcome('error', 'webhook case evidence missing or invalid')
    facts = {}
    for case in cases:
        name = case['id']
        if case.get('role') != CASES[name]:
            return AssertionOutcome('error', 'webhook case role invalid')
        calls = case.get('client', {}).get('calls', [])
        if not calls:
            return AssertionOutcome('error', 'webhook client calls missing')
        if any(call.get('status') in (401, 403) for call in calls):
            return AssertionOutcome('error', 'gateway authentication failed')
        nonces = {call['nonce'] for call in calls}
        records = [record for record in case.get('fixture', {}).get('requests', []) if record.get('actor') == 'gateway']
        hooks = [record for record in records if record.get('route') == 'webhook'
                 and record.get('ext', {}).get('webhook', {}).get('nonce_correlated') is True]
        facts[name] = {'webhook_consulted': bool(hooks),
                       'webhook_status_sent': [record.get('response', {}).get('status') for record in hooks],
                       'upstream_received': any(record.get('route') == 'mcp' and record.get('entry') == 'plain'
                           and record.get('body', {}).get('jsonrpc', {}).get('nonce') in nonces for record in records),
                       'gateway_reply': [call.get('reply') for call in calls],
                       'webhook_hits': sorted({hit for record in hooks for hit in record.get('hits', [])})}
    evidence.setdefault('summary', {})['webhook'] = facts
    allow, deny = facts['allow'], facts['deny_non2xx']
    # A cached allow can suppress the final hook request after a deny already bypassed it.
    # Earlier correlated consultation still proves wiring; an unwired hook cannot supply it.
    cached_allow_witness = any(facts[name]['webhook_consulted'] and facts[name]['upstream_received']
                               for name, role in CASES.items() if role == 'attack')
    if not allow['upstream_received'] or not (allow['webhook_consulted'] or cached_allow_witness):
        return AssertionOutcome('skipped', 'allow: the webhook is not wired, or allowed calls do not reach the upstream')
    if not deny['webhook_consulted'] or deny['webhook_status_sent'] != [403] or deny['upstream_received']:
        return AssertionOutcome('skipped', 'deny_non2xx: a non-2xx deny was not enforced; the hook may be in audit mode')
    attacks = [facts[name] for name, role in CASES.items() if role == 'attack']
    if not any(fact['webhook_consulted'] for fact in attacks):
        return AssertionOutcome('skipped', 'webhook attack decisions not exercised')
    if facts['deny_2xx_documented']['upstream_received']:
        return AssertionOutcome('fail', 'deny_2xx_documented: the documented deny reached the upstream', 'medium')
    ambiguous = [name for name in ('malformed_2xx', 'no_content_204') if facts[name]['upstream_received']]
    if ambiguous:
        return AssertionOutcome('warn', ', '.join(ambiguous) + ': the webhook fails open on an ambiguous answer')
    if any(case.get('complete') is not True or case.get('dropped', 0) for case in cases):
        return AssertionOutcome('error', 'webhook evidence is incomplete')
    return AssertionOutcome('pass', 'the gateway enforced the documented and ambiguous webhook denies')
