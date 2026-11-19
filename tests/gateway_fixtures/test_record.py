"""Generated credentials exercise matching and evidence privacy together."""
import base64
import hashlib
import hmac
import json
import random
import string
from urllib.parse import quote, quote_plus

import pytest

from argus.gateway_fixtures.match import WatchMatcher
from argus.gateway_fixtures.record import BODY_MAX, RequestRecorder


def recorder(canaries=None, secrets=None, *, case_key=b'c' * 32, **kwargs):
    return RequestRecorder(
        case_id='case', case_key=case_key,
        matcher=WatchMatcher(canaries or {}, secrets or {}, watch_key=b'w' * 32),
        path_token='install-token', nonce='case-nonce', **kwargs,
    )


def request(rec, **kwargs):
    return rec.record(origin='upstream', route='mcp', entry='hdr',
                      method='POST', path='/u/install-token/hdr/mcp', **kwargs)


def encodings(value):
    return [value, quote(value, safe=''), quote_plus(value, safe=''),
            quote(quote(value, safe=''), safe=''),
            quote(quote(quote(value, safe=''), safe=''), safe=''),
            base64.b64encode(value.encode()).decode(),
            base64.urlsafe_b64encode(value.encode()).decode().rstrip('='),
            ''.join(f'\\u{ord(char):04x}' for char in value)]


def test_generated_credentials_never_enter_evidence():
    rng = random.Random(83267)
    alphabet = string.ascii_letters + string.digits + '/+ =?&'
    for _ in range(200):
        canary = 'canary-' + ''.join(rng.choices(alphabet, k=40))
        secret = 'secret-' + ''.join(rng.choices(alphabet, k=40))
        verifier = ''.join(rng.choices(string.ascii_letters + string.digits + '-._~', k=64))
        secret_digest = hmac.new(b'w' * 32, secret.encode(), hashlib.sha256).hexdigest()
        rec = recorder({'synthetic': canary}, {'external': secret_digest})
        oauth_request = request(rec, headers=[('Content-Type', 'application/x-www-form-urlencoded')],
            body=('client_secret=' + quote(secret, safe='') + '&code=' + quote(canary, safe='')
                  + '&code_verifier=' + verifier).encode())
        oauth_request['ext']['oauth'] = {
            'code': rec.oauth_observation(canary),
            'verifier': rec.oauth_observation(verifier, verifier=True),
            'challenge': rec.oauth_observation(base64.urlsafe_b64encode(secret.encode()).decode().rstrip('='), challenge=True),
        }
        expected = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode('ascii')).digest()).decode().rstrip('=')
        assert oauth_request['ext']['oauth']['verifier']['verifier_s256'] == expected
        assert oauth_request['ext']['oauth']['code']['hits'] == ['synthetic']
        assert len(oauth_request['ext']['oauth']['code']['corr']) == 16
        for credential in (canary, secret, verifier):
            for variant in encodings(credential):
                assert variant not in json.dumps(oauth_request)
        for encode in (lambda x: x, lambda x: quote(x, safe=''),
                       lambda x: quote(quote(x, safe=''), safe=''),
                       lambda x: base64.b64encode(x.encode()).decode()):
            left, right = encode(canary), encode(secret)
            basic = base64.b64encode(f'{canary}:{secret}'.encode()).decode()
            for args in (
                {'headers': [('X-Key', left), ('Authorization', f'Bearer {right}')]},
                {'headers': [('Cookie', f'left={quote(left, safe="")}; right={quote(right, safe="")}')]},
                {'headers': [('Authorization', f'Basic {basic}')]},
                {'query': f'left={quote(left, safe="")}&right={quote(right, safe="")}'},
                {'headers': [('Content-Type', 'application/x-www-form-urlencoded')],
                 'body': f'left={quote(left, safe="")}&right={quote(right, safe="")}'.encode()},
                {'headers': [('Content-Type', 'application/json')],
                 'body': json.dumps({'left': left, 'nested': [right]}).encode()},
            ):
                evidence = request(rec, **args)
                assert evidence['hits'] == ['external', 'synthetic']
                if args.get('body'):
                    assert evidence['body']['hits'] == ['external', 'synthetic']
                serialized = json.dumps(evidence)
                for credential in (canary, secret):
                    for variant in encodings(credential):
                        assert variant not in serialized
                assert canary not in repr(rec.records) and secret not in repr(rec.records)
            # Each iteration is a separate case with a bounded number of records.
            rec.seal()
            rec = recorder({'synthetic': canary}, {'external': secret_digest})


@pytest.mark.parametrize('encoder', [lambda x: x, lambda x: quote(x, safe=''),
    lambda x: quote_plus(x, safe=''), lambda x: quote(quote(x, safe=''), safe=''),
    lambda x: quote(quote(quote(x, safe=''), safe=''), safe=''),
    lambda x: base64.b64encode(x.encode()).decode(),
    lambda x: base64.urlsafe_b64encode(x.encode()).decode().rstrip('='),
    lambda x: ''.join(f'\\u{ord(c):04x}' for c in x)])
def test_decodings_and_one_character_mutation(encoder):
    value = 'generated-canary/with+space 0123456789'
    digest = hmac.new(b'w' * 32, value.encode(), hashlib.sha256).hexdigest()
    watch = WatchMatcher({'canary': value}, {'secret': digest}, watch_key=b'w' * 32)
    assert watch.match(encoder(value)).hits == ['canary', 'secret']
    assert watch.match(encoder(value)).complete is True
    assert watch.match(encoder(value[:-1] + 'X')).hits == []
    assert watch.match('prefix' + value + 'suffix').hits == ['canary']


def test_capture_policy_and_correlation():
    rec = recorder()
    body = json.dumps({'jsonrpc': '2.0', 'id': 7, 'method': 'tools/call',
        'params': {'name': 'argus_fixture_echo', 'arguments': {'nonce': 'case-nonce',
        'private': 'do-not-copy'}, '_meta': {'protocolVersion': '2026-07-28'}}}).encode()
    evidence = request(rec, headers=[('Content-Type', 'application/json'),
        ('User-Agent', 'a' * 200), ('Mcp-Session-Id', 'same-value'),
        ('Authorization', 'Bearer same-value'), ('Cookie', 'a=same-value')], body=body,
        query='state=same-value&grant_type=client_credentials', peer='127.0.0.1', t_ms=10)
    headers = {header['name']: header for header in evidence['headers']}
    assert headers['content-type']['value'] == 'application/json'
    assert len(headers['user-agent']['value']) == 120
    assert 'value' not in headers['mcp-session-id']
    assert headers['authorization']['scheme'] == 'Bearer'
    assert evidence['path'] == '/u/{path_token}/hdr/mcp'
    assert evidence['peer_class'] == 'loopback'
    assert evidence['query'][0]['corr'] == headers['mcp-session-id']['corr']
    other = request(recorder(case_key=b'd' * 32), query='state=same-value')
    assert other['query'][0]['corr'] != evidence['query'][0]['corr']
    assert len(other['query'][0]['corr']) == 16
    assert evidence['body']['jsonrpc'] == {'jsonrpc': '2.0', 'id': 7,
        'method': 'tools/call', 'tool': 'argus_fixture_echo', 'nonce': 'case-nonce',
        'protocol_version': '2026-07-28'}
    assert 'do-not-copy' not in json.dumps(evidence)
    assert request(rec)['seq'] == evidence['seq'] + 1


def test_multipart_candidates_and_safe_fields():
    value = 'generated-multipart-secret-12345678'
    digest = hmac.new(b'w' * 32, value.encode(), hashlib.sha256).hexdigest()
    rec = recorder({'canary': value}, {'secret': digest})
    body = f'--boundary\r\nContent-Disposition: form-data; name="field"\r\n\r\n{value}\r\n--boundary--\r\n'.encode()
    result = request(rec, headers=[('Content-Type', 'multipart/form-data; boundary=boundary')], body=body)
    assert result['hits'] == ['canary', 'secret']
    assert value not in json.dumps(result)
    for header in ('User-Agent', 'Content-Type', 'Mcp-Name', 'Authorization'):
        result = request(rec, headers=[(header, value)])
        assert value not in json.dumps(result)


def test_webhooks_and_untrusted_envelope_are_structure_only():
    rec = recorder()
    body = b'{"jsonrpc":"secret","id":"secret","method":"secret","params":{"name":"secret","arguments":{"nonce":"secret"}}}'
    result = request(rec, headers=[('Content-Type', 'application/json')], body=body)
    assert result['body']['jsonrpc'] == {}
    assert 'secret' not in json.dumps(result)
    result = rec.record(origin='upstream', route='webhook', method='POST', path='/w/install-token/hook',
        headers=[('Content-Type', 'application/json')], body=b'{"id":7,"method":"tools/call"}')
    assert 'jsonrpc' not in result['body']


def test_bounds_keep_positive_hits_and_reject_complete_misses():
    value = 'generated-bound-canary-12345678'
    rec = recorder({'canary': value})
    result = request(rec, body=value.encode() + b'x' * BODY_MAX)
    assert result['hits'] == ['canary']
    assert result['body']['len'] == BODY_MAX + len(value)
    assert result['body']['complete'] is False
    assert rec.complete is False
    result = request(recorder(), body=b'', body_complete=False)
    assert result['body']['complete'] is False
    capped = recorder(max_requests=1)
    assert request(capped) is not None
    assert request(capped) is None
    assert capped.dropped == 1 and capped.complete is False
    sealed = capped.seal()
    assert sealed['complete'] is False and sealed['dropped'] == 1
    with pytest.raises(RuntimeError, match='sealed'):
        request(capped)


def test_excess_decode_depth_and_json_depth_are_incomplete():
    deep_url = '%2525252541'
    assert request(recorder(), query='field=' + deep_url)['body']['complete'] is False
    nested = b'[' * 80 + b'"leaf"' + b']' * 80
    assert request(recorder(), headers=[('Content-Type', 'application/json')], body=nested)['body']['complete'] is False


def test_repeated_hits_are_preserved_per_location():
    value = 'generated-repeat-secret-123456789'
    digest = hmac.new(b'w' * 32, value.encode(), hashlib.sha256).hexdigest()
    rec = recorder({'canary': value}, {'secret': digest})
    result = request(rec, headers=[('Cookie', 'token=' + value), ('Content-Type', 'application/json')],
                     body=json.dumps({'token': value}).encode())
    assert result['headers'][0]['hits'] == ['canary', 'secret']
    assert result['body']['hits'] == ['canary', 'secret']
    assert result['hits'] == ['canary', 'secret']


def test_malformed_envelope_and_unicode_do_not_crash():
    body = b'{"method":[],"params":{"name":[],"arguments":{"nonce":[]}},"private":"\\ud800"}'
    result = request(recorder(), headers=[('Content-Type', 'application/json')], body=body)
    assert result['body']['jsonrpc'] == {}
    assert 'private' in result['body']['shape']['properties']


def test_request_key_and_path_watch_values_are_redacted():
    value = 'generated-key-canary-123456789'
    rec = recorder({'canary': value})
    result = rec.record(origin='upstream', route='mcp', method='POST', path='/' + value,
                        headers=[('Content-Type', 'application/json')],
                        body=json.dumps({value: value}).encode(), query=value + '=' + value)
    assert value not in json.dumps(result)
    assert result['hits'] == ['canary']


@pytest.mark.parametrize('args', [
    {'headers': [('X-Key', 'x' * (BODY_MAX + 1))]},
    {'query': 'value=' + 'x' * BODY_MAX},
    {'headers': [('X-Key', 'x')] * 129},
])
def test_other_capture_bounds_are_incomplete(args):
    assert request(recorder(), **args)['body']['complete'] is False


def test_seal_releases_secret_state_and_tracks_inflight_timeout():
    value = 'generated-seal-canary-12345678'
    rec = recorder({'canary': value})
    request(rec)
    evidence = rec.seal(complete=False)
    assert evidence['complete'] is False
    assert rec._case_key is None and rec.matcher._watch_key is None
    assert not rec.matcher._canaries
    with pytest.raises(RuntimeError, match='sealed'):
        rec.matcher.match(value)


def test_path_matches_across_segments_and_unicode_surrogates():
    value = 'generated-path/canary-123456789'
    result = recorder({'canary': value}).record(origin='upstream', route='mcp', method='POST', path='/' + value)
    assert result['hits'] == ['canary']
    assert value not in json.dumps(result)
    watch = WatchMatcher({'canary': 'generated-😀-123456789'}, {}, watch_key=b'w' * 32)
    assert watch.match(r'generated-\ud83d\ude00-123456789').hits == ['canary']


def test_quoted_cookie_is_a_semantic_secret_candidate():
    value = 'generated-cookie;secret-123456789'
    digest = hmac.new(b'w' * 32, value.encode(), hashlib.sha256).hexdigest()
    result = request(recorder(secrets={'secret': digest}), headers=[('Cookie', 'token="' + value + '"')])
    assert result['hits'] == ['secret']
    assert result['headers'][0]['hits'] == ['secret']
    assert value not in json.dumps(result)


def test_nested_multipart_string_field_is_a_secret_candidate():
    value = 'generated-nested-secret-123456789'
    digest = hmac.new(b'w' * 32, value.encode(), hashlib.sha256).hexdigest()
    body = ('--outer\r\nContent-Disposition: form-data; name="nested"\r\n'
            'Content-Type: multipart/mixed; boundary=inner\r\n\r\n'
            '--inner\r\nContent-Disposition: attachment; name="token"\r\n\r\n' + value +
            '\r\n--inner--\r\n--outer--\r\n').encode()
    result = request(recorder(secrets={'secret': digest}),
        headers=[('Content-Type', 'multipart/form-data; boundary=outer')], body=body)
    assert result['body']['hits'] == ['secret']
    assert result['body']['complete'] is True
    assert value not in json.dumps(result)


def test_authorization_without_scheme_never_preserves_a_bare_token():
    value = 'unwatched-generated-token'
    result = request(recorder(), headers=[('Authorization', value)])
    assert 'scheme' not in result['headers'][0]
    assert value not in json.dumps(result)
    result = request(recorder(), headers=[('Authorization', 'Bearer ' + value)])
    assert result['headers'][0]['scheme'] == 'Bearer'
    assert value not in json.dumps(result)


def test_basic_decodes_even_a_short_payload():
    rng = random.Random(83267)
    username, password = map(str, rng.sample(range(10), 2))
    def digest(value):
        return hmac.new(b'w' * 32, value.encode(), hashlib.sha256).hexdigest()
    watch = WatchMatcher({'canary': username + ':' + password},
        {'username': digest(username), 'password': digest(password)}, watch_key=b'w' * 32)
    encoded = base64.b64encode((username + ':' + password).encode()).decode()
    assert len(encoded) < 8
    basic = 'Basic ' + encoded
    for candidate in (basic, quote(basic, safe=''), quote(quote(basic, safe=''), safe='')):
        assert watch.match(candidate).hits == ['canary', 'password', 'username']
    changed = str((int(password) + 1) % 10)
    encoded = base64.b64encode((username + ':' + changed).encode()).decode()
    assert watch.match('Basic ' + encoded).hits == ['username']


def test_external_secret_field_names_do_not_count_as_credential_hits():
    value = 'generated-field-123456789'
    changed = value[:-1] + '0'
    digest = hmac.new(b'w' * 32, value.encode(), hashlib.sha256).hexdigest()
    for args in (
        {'headers': [(value, changed)]},
        {'query': value + '=' + changed},
        {'headers': [('Content-Type', 'application/json')],
         'body': json.dumps({value: changed}).encode()},
    ):
        result = request(recorder(secrets={'external': digest}), **args)
        assert result['hits'] == []
        assert value not in json.dumps(result)


def test_raw_structure_is_not_an_external_secret_candidate():
    query = 'field=generated-value'
    body = json.dumps({'field': 'generated-value'}).encode()
    for value, args in ((query, {'query': query}),
        (body.decode(), {'headers': [('Content-Type', 'application/json')], 'body': body})):
        digest = hmac.new(b'w' * 32, value.encode(), hashlib.sha256).hexdigest()
        result = request(recorder(secrets={'external': digest}), **args)
        assert result['hits'] == []


def test_numeric_envelope_metadata_is_not_a_string_secret_candidate():
    value = '721123456789456789'
    digest = hmac.new(b'w' * 32, value.encode(), hashlib.sha256).hexdigest()
    result = request(recorder(secrets={'external': digest}),
        headers=[('Content-Type', 'application/json')], body=json.dumps({'id': int(value)}).encode())
    assert result['hits'] == []
    assert value not in json.dumps(result)


def test_header_names_match_before_case_normalization():
    value = 'generated-field-AaBb123456789'
    result = request(recorder({'canary': value}), headers=[(value, 'other')])
    assert result['hits'] == ['canary']
    assert value.lower() not in json.dumps(result)
    digest = hmac.new(b'w' * 32, value.encode(), hashlib.sha256).hexdigest()
    result = request(recorder(secrets={'external': digest}), headers=[(value, 'other')])
    assert result['hits'] == []
    assert value.lower() not in json.dumps(result)


def test_path_canary_matches_before_install_token_masking():
    result = request(recorder({'canary': 'install-token'}))
    assert result['hits'] == ['canary']
    assert 'install-token' not in json.dumps(result)


def test_absent_body_is_complete_despite_json_content_type():
    result = recorder().record(origin='upstream', route='mcp', method='GET',
        path='/u/install-token/hdr/mcp', headers=[('Content-Type', 'application/json')])
    assert result['body']['complete'] is True
    assert result['body']['len'] == 0
    assert result['body']['hits'] == []


@pytest.mark.parametrize('scheme', ['Bearer', 'Basic'])
def test_public_auth_scheme_does_not_count_as_a_secret_candidate(scheme):
    digest = hmac.new(b'w' * 32, scheme.encode(), hashlib.sha256).hexdigest()
    changed = scheme[:-1] + 'X'
    credential = changed if scheme == 'Bearer' else base64.b64encode(('generated-user:' + changed).encode()).decode()
    result = request(recorder(secrets={'external': digest}),
        headers=[('Authorization', scheme + ' ' + credential)])
    assert result['hits'] == []
    assert scheme not in json.dumps(result)


def test_invalid_unicode_cannot_match_a_replacement_character_secret():
    value = 'generated-invalid-unicode-?'
    digest = hmac.new(b'w' * 32, value.encode(), hashlib.sha256).hexdigest()
    watch = WatchMatcher({'canary': value}, {'external': digest}, watch_key=b'w' * 32)
    result = watch.match(value[:-1] + '\ud800')
    assert result.hits == []
    assert result.complete is False
    body = json.dumps({'value': value[:-1] + '\ud800'}).encode()
    captured = request(recorder({'canary': value}, {'external': digest}),
        headers=[('Content-Type', 'application/json')], body=body)
    assert captured['hits'] == []
    assert captured['body']['complete'] is False


def test_oauth_s256_known_answer_and_seal_gate():
    rec = recorder()
    verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
    challenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'
    assert rec.oauth_observation(verifier, verifier=True)['verifier_s256'] == challenge
    assert rec.oauth_observation(challenge, challenge=True)['verifier_s256'] == challenge
    assert 'verifier_s256' not in rec.oauth_observation('malformed', verifier=True)
    assert 'verifier_s256' not in rec.oauth_observation('malformed', challenge=True)
    rec.seal()
    with pytest.raises(RuntimeError, match='sealed'):
        rec.oauth_observation(verifier, verifier=True)


def test_watched_challenge_never_enters_evidence_verbatim():
    value = 'A' * 43
    rec = recorder({'synthetic': value})
    observation = rec.oauth_observation(value, challenge=True)
    assert observation['hits'] == ['synthetic']
    assert 'verifier_s256' not in observation
    assert value not in json.dumps(observation)
