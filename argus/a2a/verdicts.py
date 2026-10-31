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


def classify_authz(ex: dict, authorization_codes: frozenset[int]):
    if ex.get('outcome') == 'success':
        return 'accepted'
    if ex.get('http_status') in (401, 403, 404):
        return 'rejected'
    if ex.get('outcome') == 'jsonrpc_error' and (ex.get('jsonrpc_code') == -32001 or ex.get('jsonrpc_code') in authorization_codes):
        return 'rejected'
    return 'undetermined'


def _authorization_attempt(attack, codes):
    classification = classify_authz(attack, codes)
    if classification == 'accepted':
        return 'fail', "violated the target's declared authorization boundary: the second client's operation succeeded"
    if classification == 'rejected':
        mapping = " per the target's declared jsonrpc_auth_error_codes" if attack.get('jsonrpc_code') in codes else ''
        return 'pass', 'rejected the second client ('+_observed(attack)+')'+mapping
    return 'error', 'could not confirm an authorization rejection: '+_observed(attack)


def _cancel_subcheck(evidence, control, attack, codes):
    from argus.a2a.protocol import TERMINAL_STATES
    if control.get('task_state') in TERMINAL_STATES:
        return 'skipped', 'task finished before it could be canceled'
    canceled = _record(evidence, 'control_a_cancel')
    if canceled['outcome'] != 'success':
        recheck = _record(evidence, 'control_a_recheck')
        if recheck['outcome'] == 'success' and recheck.get('task_state') in TERMINAL_STATES:
            return 'skipped', 'task finished before it could be canceled'
        return 'error', 'clean_control_failed: the first client could not cancel its own task'
    recent = next((ex for ex in reversed(evidence['exchanges']) if ex.get('step') in ('control_a_get', 'attack_a_send') and ex.get('outcome') == 'success'), attack)
    if recent.get('task_state') in TERMINAL_STATES:
        return 'skipped', 'task finished before it could be canceled'
    canceled = _record(evidence, 'attack_b_cancel')
    classification = classify_authz(canceled, codes)
    if classification != 'rejected':
        return _authorization_attempt(canceled, codes)
    viewed = _record(evidence, 'attack_a_view')
    if viewed['outcome'] != 'success':
        return 'error', 'could not re-check the task after the rejected cancel'
    if viewed.get('task_state') == 'TASK_STATE_CANCELED':
        return 'warn', "cancel anomaly: the server rejected the second client's cancel, but the first client then saw TASK_STATE_CANCELED; cause undetermined, not attributed to the second client"
    return 'pass', 'rejected the second client cancel ('+_observed(canceled)+'); the first client did not see TASK_STATE_CANCELED'


def _cross_client(evidence):
    controls = []
    for step in ('control_a_send', 'control_b_send', 'attack_a_send'):
        ex = _record(evidence, step)
        controls.append(ex)
        if ex['outcome'] != 'success':
            return 'error', 'clean_control_failed: '+step+' did not succeed ('+_observed(ex)+')'
    declared = evidence.get('config', {}).get('forbidden_on_primary_tasks', [])
    codes = frozenset(evidence.get('config', {}).get('jsonrpc_auth_error_codes', {}).get('authorization', []))
    subchecks = []
    reasons = []
    for op in ('get', 'list', 'cancel'):
        if op not in declared:
            reasons.append(op+': skipped (not declared in forbidden_on_primary_tasks)')
            continue
        try:
            if op == 'get':
                control = _record(evidence, 'control_a_get')
                result = ('error', 'clean_control_failed: the first client could not read its own task') if control['outcome'] != 'success' else _authorization_attempt(_record(evidence, 'attack_b_get'), codes)
            elif op == 'list':
                control = _record(evidence, 'control_a_list')
                if control['outcome'] != 'success' or control.get('detail', {}).get('list_has_primary_task') is not True:
                    result = 'error', 'clean_control_failed: the first client list did not show its task'
                else:
                    attack = _record(evidence, 'attack_b_list')
                    if attack['outcome'] != 'success':
                        result = 'error', 'the second client ListTasks did not succeed ('+_observed(attack)+')'
                    elif attack.get('detail', {}).get('list_has_primary_task') is True:
                        result = 'fail', "violated the target's declared authorization boundary: the second client list showed the first client's task"
                    elif attack.get('detail', {}).get('list_has_primary_task') is False:
                        result = 'pass', "the second client list did not show the first client's task or marker"
                    else:
                        result = 'error', 'incomplete evidence: list task visibility is missing'
            else:
                result = _cancel_subcheck(evidence, controls[0], controls[2], codes)
        except ValueError as exc:
            result = 'error', str(exc)
        subchecks.append(result[0])
        reasons.append(f'{op}: {result[0]} ({result[1]})')
    outcome = next((value for value in ('fail', 'error', 'warn') if value in subchecks), 'skipped' if not subchecks or all(v == 'skipped' for v in subchecks) else 'pass')
    return outcome, '; '.join(reasons)

_DECIDERS['cross_client_task'] = _cross_client
