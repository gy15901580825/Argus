"""Pure verdicts over A2A response facts, never error-message prose."""
from typing import Literal
Outcome = Literal['pass', 'fail', 'warn', 'skipped', 'error']
_DECIDERS = {}

def decide(name: str, evidence: dict) -> tuple[Outcome, str]:
    if name != evidence.get('check'):
        return 'error', 'evidence check does not match assertion'
    precondition = evidence.get('precondition', {})
    if 'error' in precondition:
        return 'error', precondition['error']
    if 'skip' in precondition:
        return 'skipped', precondition['skip']
    if name not in _DECIDERS:
        return 'error', 'no decider for '+name
    try:
        return _DECIDERS[name](evidence)
    except (ValueError, TypeError, KeyError) as exc:
        return 'error', str(exc)


def classify_auth(ex: dict, codes: frozenset[int]):
    if ex.get('outcome') == 'success':
        return 'auth_required' if ex.get('task_state') == 'TASK_STATE_AUTH_REQUIRED' else 'accepted'
    if ex.get('http_status') in (401, 403):
        return 'rejected'
    if ex.get('outcome') == 'jsonrpc_error' and ex.get('jsonrpc_code') in codes:
        return 'rejected'
    return 'undetermined'


def _record(evidence, step):
    records = evidence.get('exchanges')
    if not isinstance(records, list):
        raise ValueError('incomplete evidence: exchanges are missing')
    record = next((ex for ex in records if isinstance(ex, dict) and ex.get('step') == step), None)
    if record is None or record.get('outcome') not in {'success', 'jsonrpc_error', 'http_error', 'undecodable', 'transport_error'}:
        raise ValueError('incomplete evidence: missing '+step)
    return record


def _observed(ex):
    if ex.get('outcome') == 'jsonrpc_error':
        return f"JSON-RPC error {ex.get('jsonrpc_code')}"
    if ex.get('outcome') in ('transport_error', 'undecodable'):
        return ex['outcome']
    return f"HTTP {ex.get('http_status')}"


def _auth_codes(evidence):
    codes = evidence.get('config', {}).get('jsonrpc_auth_error_codes', {})
    return frozenset(codes.get('authentication', [])) | frozenset(codes.get('authorization', []))


def _authentication(evidence):
    control = _record(evidence, 'control_send')
    if control['outcome'] != 'success':
        return 'error', 'clean_control_failed: legal SendMessage did not succeed ('+_observed(control)+')'
    attack = _record(evidence, 'attack_send')
    classification = classify_auth(attack, _auth_codes(evidence))
    request = 'an unauthenticated request' if evidence['check'] == 'unauthenticated_task' else 'a request with forged credentials'
    if classification == 'accepted':
        action = 'created a task' if attack.get('result_kind') == 'task' else 'returned an agent message'
        return 'fail', f'accepted {request} and {action}'
    if classification == 'auth_required':
        return 'warn', 'did not reject at the authentication layer: returned a task in TASK_STATE_AUTH_REQUIRED, which the spec reserves for authenticated callers'
    if classification == 'rejected':
        mapping = " per the target's declared jsonrpc_auth_error_codes" if attack.get('outcome') == 'jsonrpc_error' and attack.get('http_status') not in (401, 403) else ''
        return 'pass', f'rejected {request} ({_observed(attack)}){mapping}'
    return 'error', 'could not confirm an authentication-layer rejection: '+_observed(attack)

_DECIDERS.update(unauthenticated_task=_authentication, invalid_credentials=_authentication)
