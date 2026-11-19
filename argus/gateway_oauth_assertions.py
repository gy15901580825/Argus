"""MCP Authorization Server Binding checks from sealed fixture request records."""
from argus.world_assertions import AssertionOutcome


def _records(case, *, gateway_only=True):
    return [record for record in case['fixture']['requests']
            if record.get('entry') == 'oauth'
            and (not gateway_only or record.get('actor') == 'gateway')]


def _events(records, name, origin=None):
    return [record['ext']['oauth'][name] for record in records
            if (origin is None or record.get('origin') == origin)
            and name in record.get('ext', {}).get('oauth', {})]


def _summary(case):
    gateway = _records(case)
    all_records = _records(case, gateway_only=False)
    codes = _events(all_records, 'codes_issued', 'issuer')
    tokens = []
    for record in gateway:
        if record.get('route') != 'token':
            continue
        event = record.get('ext', {}).get('oauth', {}).get('token', {})
        token = {**event, 'at': record['origin']}
        token['client_id_hit'] = event.get('client_id_hit') is True or 'static_client_id' in record.get('hits', [])
        token['client_secret_hit'] = event.get('client_secret_hit') is True or 'static_client_secret' in record.get('hits', [])
        issued = next((code for code in codes if code.get('corr') and code['corr'] == event.get('code', {}).get('corr')), None)
        token['code_issued_by'] = 'issuer' if issued else None
        token['verifier_matches_challenge_from'] = ('issuer' if issued and token.get('verifier_s256')
            and token['verifier_s256'] == issued.get('verifier_s256') else None)
        tokens.append(token)
    return {'id': case['id'], 'prm_served': _events(gateway, 'prm_served', 'upstream'),
            'as_metadata_fetched': {origin: max(len(_events(gateway, 'as_metadata_fetched', origin)),
                case.get('oauth', {}).get('as_metadata_fetched', {}).get(origin, 0)) for origin in ('issuer', 'foreign')},
            'authorize': _events(all_records, 'authorize'), 'codes_issued': codes, 'token': tokens,
            'h_sent_iss': any(code.get('h_sent_iss') is True for code in codes),
            'h_authorize_static_client_id': any(event.get('client_id_hit') is True for event in _events(all_records, 'authorize', 'issuer')),
            'registered_at_foreign': any(record.get('origin') == 'foreign' and record.get('route') == 'register'
                                         for record in gateway)}


def gateway_upstream_as_binding(value, evidence):
    mode = value.get('mode', 'own') if isinstance(value, dict) else None
    if mode not in ('own', 'mirror_authorize'):
        return AssertionOutcome('error', 'unknown authorization-server binding mode')
    cases = evidence.get('cases')
    if (not isinstance(cases, list) or not cases
            or any(not isinstance(case, dict) or not isinstance(case.get('fixture'), dict)
                   or not isinstance(case['fixture'].get('requests'), list)
                   or any(not isinstance(record, dict) for record in case['fixture']['requests']) for case in cases)):
        return AssertionOutcome('error', 'authorization-server binding case evidence is missing or malformed')
    controls = [case for case in cases if case.get('role') == 'control']
    attacks = [case for case in cases if case.get('role') == 'attack']
    if not controls or not attacks:
        return AssertionOutcome('error', 'authorization-server binding requires control and attack cases')
    facts = [_summary(case) for case in cases]
    evidence.setdefault('summary', {})['upstream_as_binding'] = {'foreign_as_mode': mode, 'cases': facts}
    confidential = evidence.get('static_oauth_client', {}).get('confidential', True)
    for case in controls:
        records = _records(case)
        tokens = _events(records, 'token', 'issuer')
        nonces = {call.get('nonce') for call in case.get('client', {}).get('calls', [])} - {None}
        if (not any(token.get('client_id_hit') is True and (not confidential or token.get('client_secret_hit') is True) for token in tokens)
                or not any(record.get('origin') == 'upstream' and record.get('route') == 'mcp'
                           and record.get('ext', {}).get('oauth', {}).get('token_valid') is True
                           and record.get('body', {}).get('jsonrpc', {}).get('method') == 'tools/call'
                           and record.get('body', {}).get('jsonrpc', {}).get('nonce') in nonces for record in records)):
            return AssertionOutcome('skipped', f"{case['id']}: the gateway did not use static client credentials at the configured authorization server and complete an upstream call")
    exercised = []
    for case, fact in zip(cases, facts):
        if case not in attacks:
            continue
        contact = (any(event.get('as') == 'foreign' for event in fact['prm_served']) if mode == 'own'
                   else fact['as_metadata_fetched']['foreign'] > 0)
        if contact:
            exercised.append((case, fact))
    if not exercised:
        step = ('never re-read protected resource metadata after the 401; restart the gateway or use trigger: manual_restart'
                if mode == 'own' else 'never fetched foreign authorization-server metadata after the switch')
        return AssertionOutcome('skipped', 'the gateway ' + step)
    findings = []
    for case, fact in exercised:
        foreign_tokens = [token for token in fact['token'] if token['at'] == 'foreign']
        if mode == 'own':
            if any(token['client_secret_hit'] for token in foreign_tokens):
                findings.append(('high', f"{case['id']}: client_secret_hit at foreign token endpoint violates MCP 2026-07-28 Authorization Server Binding"))
            elif (any(token['client_id_hit'] for token in foreign_tokens)
                  or any(record.get('origin') == 'foreign' and record.get('route') == 'authorize'
                         and ('static_client_id' in record.get('hits', []) or record.get('ext', {}).get('oauth', {}).get('authorize', {}).get('client_id_hit') is True)
                         for record in _records(case))):
                findings.append(('medium', f"{case['id']}: client_id_hit at foreign authorization server violates MCP 2026-07-28 Authorization Server Binding"))
        else:
            for token in foreign_tokens:
                if token['code_issued_by'] == 'issuer' and (token['verifier_matches_challenge_from'] == 'issuer' or not token.get('verifier_s256')):
                    detail = 'verifier_s256 matches the challenge for that code' if token.get('verifier_s256') else 'without a PKCE verifier'
                    findings.append(('high', f"{case['id']}: H-issued code reached foreign token endpoint; {detail} (MCP Mix-Up Attacks; RFC 9207)"))
    if findings:
        severity = 'high' if any(severity == 'high' for severity, _ in findings) else 'medium'
        return AssertionOutcome('fail', '; '.join(reason for _, reason in findings), severity)
    if any(not case.get('complete') or case.get('dropped', 0)
           or any(record.get('body', {}).get('complete') is False for record in case['fixture']['requests']) for case in cases):
        return AssertionOutcome('error', 'authorization-server binding evidence is incomplete')
    if len(exercised) != len(attacks):
        return AssertionOutcome('skipped', 'an authorization-server binding attack case was not exercised')
    return AssertionOutcome('pass', 'exercised authorization-server change did not expose the credentials or correlated H code at the foreign server')
