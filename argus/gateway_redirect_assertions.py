"""Configured upstream header redirects, decided from nonce-correlated records."""
from argus.world_assertions import AssertionOutcome


def records(case):
    nonces = {call.get('nonce') for call in case.get('client', {}).get('calls', [])} - {None}
    return [record for record in case.get('fixture', {}).get('requests', [])
            if record.get('actor') == 'gateway'
            and record.get('body', {}).get('jsonrpc', {}).get('nonce') in nonces]


def configured_hit(hit, names):
    return (hit.startswith('upstream_header:') and hit.split(':', 1)[1].lower() in names
            or hit == 'upstream_authorization' and 'authorization' in names)


def summarize(evidence, configured_headers):
    names = {name.lower() for name in configured_headers}
    cases = []
    for case in evidence.get('cases', []):
        captured = records(case)
        foreign = [r for r in captured if r.get('origin') == 'foreign']
        hits = sorted({hit for r in foreign for hit in r.get('hits', []) if configured_hit(hit, names)})
        redirect = case.get('redirect')
        cases.append({'id': case['id'], 'redirect': redirect,
                      'followed': any(r.get('route') == 'redirect_target' for r in captured),
                      'foreign_requests': len(foreign), 'hits_at_foreign': hits,
                      'authorization_at_foreign': (any(hit.lower() in ('upstream_header:authorization', 'upstream_authorization')
                                                       for hit in hits) if 'authorization' in names else 'not_configured'),
                      'gateway_reply': [call.get('reply') for call in case.get('client', {}).get('calls', [])]})
    subsequent = next((any(r.get('origin') == 'upstream' and r.get('route') == 'mcp' for r in records(case))
                       for case in evidence.get('cases', []) if case['id'] == 'redirect_recontact'), None)
    return {'configured_headers': configured_headers, 'cases': cases, 'subsequent_upstream_contact': subsequent,
            'warnings': ([] if subsequent is not False else ['Permanent redirect persisted; re-register the hdr upstream entry.'])}


def check(value, evidence):
    names = evidence.get('summary', {}).get('upstream_header_redirect', {}).get('configured_headers', [])
    if not names:
        return AssertionOutcome('skipped', 'configured upstream header feature is not declared')
    origins = evidence.get('origins', {})
    upstream, foreign = origins.get('upstream', {}), origins.get('foreign', {})
    if not upstream.get('host_id') or not foreign.get('host_id'):
        return AssertionOutcome('error', 'fixture origin evidence is missing')
    if upstream['host_id'] == foreign['host_id']:
        return AssertionOutcome('skipped', 'fixture origins share a host; port-only origins do not exercise header removal')
    cases = {case['id']: case for case in evidence.get('cases', [])}
    if not {'direct', 'same_origin_307', 'cross_origin_307', 'cross_origin_308'} <= cases.keys():
        return AssertionOutcome('error', 'redirect case evidence is missing')
    summary = summarize(evidence, names)
    evidence.setdefault('summary', {})['upstream_header_redirect'] = summary
    lower_names = {name.lower() for name in names}
    direct = records(cases['direct'])
    if not any(r.get('origin') == 'upstream' and r.get('route') == 'mcp'
               and any(configured_hit(hit, lower_names) for hit in r.get('hits', [])) for r in direct):
        return AssertionOutcome('skipped', 'configured header never reached the upstream; check the hdr registration')
    same = records(cases['same_origin_307'])
    if not any(r.get('origin') == 'upstream' and r.get('ext', {}).get('redirect', {}).get('to') == 'same_origin' for r in same):
        return AssertionOutcome('skipped', 'same_origin_307 control did not serve its redirect')
    moved = [r for r in same if r.get('route') == 'redirect_target' and r.get('origin') == 'upstream']
    if moved and not any(configured_hit(hit, lower_names) for r in moved for hit in r.get('hits', [])):
        return AssertionOutcome('skipped', 'same_origin_307 control did not retain a configured header')
    attacks = [case for case in evidence['cases'] if case.get('role') == 'attack']
    if not any(r.get('ext', {}).get('redirect', {}).get('to') == 'foreign' for case in attacks for r in records(case)):
        return AssertionOutcome('skipped', 'cross-origin redirect was not exercised')
    findings = [fact for fact in summary['cases'] if fact['id'] in {case['id'] for case in attacks} and fact['hits_at_foreign']]
    if findings:
        reason = '; '.join(f"HTTP {fact['redirect']['status']}: {', '.join(fact['hits_at_foreign'])} reached the foreign origin" for fact in findings)
        if summary['warnings']:
            reason += '; ' + summary['warnings'][0]
        return AssertionOutcome('fail', reason, 'high')
    if any(not case.get('complete') or case.get('dropped', 0) for case in evidence['cases']):
        return AssertionOutcome('error', 'redirect evidence is incomplete')
    if summary['warnings']:
        return AssertionOutcome('warn', summary['warnings'][0])
    if not moved and not any(fact['foreign_requests'] for fact in summary['cases']):
        return AssertionOutcome('pass', 'the gateway does not follow upstream redirects; followed: false')
    return AssertionOutcome('pass', 'configured upstream headers did not reach the foreign origin')
