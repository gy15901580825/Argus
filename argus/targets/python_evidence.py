from __future__ import annotations

import functools
import json
import math
from types import MappingProxyType

from argus.assertions import _CHECKS, requires_observations, validate_observations
from argus.world_assertions import Undecided
from argus.targets._base import TargetTransportError

PYTHON_EVIDENCE_VERSION = 1
MAX_EVIDENCE_BYTES = 256 * 1024
MAX_EVIDENCE_DEPTH = 16
MAX_EVIDENCE_NODES = 65536
EVIDENCE_KEYS_V1 = frozenset({
    'authorizations', 'expected_payee', 'tool_calls', 'shadow_tool_names', 'canary',
    'attacker_addresses', 'canary_hits', 'trap_requests', 'hosted', 'server_info',
    'foreign_origin_initialized', 'cors_allow_origin', 'cors_allows_foreign_origin',
    'unauthenticated_initialized', 'tools', 'server_version', 'canaries',
    'elicitations', 'memory_writes', 'approvals', 'executions', 'protected_writes',
    'resource_hashes', 'stop_notice', 'report', 'interaction_count',
    'interaction_count_by_session',
})


def _mapping_error(reason):
    return TargetTransportError(f'mapping_error: {reason}')


def validate_python_evidence(value: object) -> dict:
    if type(value) is not dict:
        raise _mapping_error('evidence_not_dict')
    for key in value:
        if type(key) is not str:
            raise _mapping_error('evidence_key_type')
        if key not in EVIDENCE_KEYS_V1:
            raise _mapping_error('evidence_unknown_keys')
    ancestors = set()
    nodes = 0
    size = 0

    def charge(amount):
        nonlocal size
        size += amount
        if size > MAX_EVIDENCE_BYTES:
            raise _mapping_error('evidence_too_large')

    def string_size(text):
        if len(text) > MAX_EVIDENCE_BYTES - size:
            raise _mapping_error('evidence_too_large')
        charge(2)
        for char in text:
            point = ord(char)
            if 0xD800 <= point <= 0xDFFF:
                raise _mapping_error('evidence_encoding')
            if char in '\"\\\b\f\n\r\t':
                charge(2)
            elif point < 32:
                charge(6)
            else:
                charge(1 if point < 128 else 2 if point < 2048 else 3 if point < 65536 else 4)

    def visit(item, depth):
        nonlocal nodes
        nodes += 1
        if nodes > MAX_EVIDENCE_NODES:
            raise _mapping_error('evidence_work_limit')
        kind = type(item)
        if kind in (dict, list):
            if id(item) in ancestors:
                raise _mapping_error('evidence_cycle')
            if depth > MAX_EVIDENCE_DEPTH:
                raise _mapping_error('evidence_depth')
            charge(2 + max(0, len(item) - 1))
            ancestors.add(id(item))
            try:
                if kind is dict:
                    for key, child in item.items():
                        if type(key) is not str:
                            raise _mapping_error('evidence_key_type')
                        visit(key, depth + 1)
                        charge(1)
                        visit(child, depth + 1)
                else:
                    for child in item:
                        visit(child, depth + 1)
            finally:
                ancestors.remove(id(item))
        elif kind is str:
            string_size(item)
        elif kind is float:
            if not math.isfinite(item):
                raise _mapping_error('evidence_nonfinite_number')
            charge(len(repr(item)))
        elif kind is int:
            if item.bit_length() > MAX_EVIDENCE_BYTES * 4:
                raise _mapping_error('evidence_too_large')
            try:
                charge(len(str(item)))
            except ValueError:
                raise _mapping_error('evidence_encoding') from None
        elif kind is bool:
            charge(4 if item else 5)
        elif item is None:
            charge(4)
        else:
            raise _mapping_error('evidence_value_type')

    visit(value, 0)
    try:
        encoded = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(',', ':')).encode('utf-8')
    except (UnicodeError, ValueError, OverflowError):
        raise _mapping_error('evidence_encoding') from None
    if len(encoded) > MAX_EVIDENCE_BYTES:
        raise _mapping_error('evidence_too_large')
    return json.loads(encoded)


def accumulate_python_evidence(previous: dict, current: dict) -> dict:
    merged = dict(previous)
    for key, item in current.items():
        if key not in merged:
            merged[key] = item
        elif type(merged[key]) is list and type(item) is list:
            merged[key] = merged[key] + item
        elif json.dumps(merged[key], sort_keys=True) != json.dumps(item, sort_keys=True):
            raise _mapping_error('evidence_conflict')
    return validate_python_evidence(merged)


def evaluate_python_assertions(assertions, evidence, response_text, prompt_index=None, *, context=None):
    from argus.assertions import AssertionResult, evaluate_assertions

    results = []
    for entry in assertions:
        for name, value in entry.items():
            try:
                results.extend(evaluate_assertions(({name: value},), evidence, response_text, prompt_index, context=context))
            except (TypeError, KeyError, ValueError) as exc:
                results.append(AssertionResult(
                    name=name, passed=False, error=True,
                    reason=f'mapping_error: evidence_assertion_error: {name}: {type(exc).__name__}',
                ))
    return results


def _declare(name, fields, records=None, enabled=None):
    original = _CHECKS[name]
    existing = getattr(original, 'observation_requirements', None)
    if existing is not None:
        fields = {**fields, **dict(existing.fields)}
        enabled = existing.enabled if existing.enabled is not None else enabled
        records = {**{key: dict(shape) for key, shape in existing.records}, **(records or {})}
    item_types = {'canaries': str, 'attacker_addresses': str, 'shadow_tool_names': str, 'cors_allow_origin': str}
    items = {key: expected for key, expected in item_types.items() if key in fields}
    if existing is not None:
        items = {**items, **dict(existing.items)}
    optional = {'hosted': dict} if name in {'no_trap_request', 'no_canary_in_trap_requests'} else {}
    if existing is not None:
        optional = {**optional, **dict(existing.optional)}
    nested = dict(existing.nested) if existing is not None else {}
    if name == 'no_canary_in_mcp_requests':
        nested['canary_hits'] = _CANARY_HIT
    if name == 'no_action_after_denial':
        nested['executions'] = _EXECUTION_LINK
    if name == 'report_matches_record':
        nested['report'] = _REPORT_ACTIONS
    check = functools.partial(original)
    return requires_observations(fields, records=records, items=items, optional=optional, nested=nested, enabled=enabled)(check)


_TOOL = {'tool': str}
_ARGS = {'tool': str, 'arguments': dict}
_AUTH = {'amount': (str, int), 'asset': str, 'payee': str}
_NOTICE = (dict, type(None))
_CONTENT = (dict, list, str, int, float, bool, type(None))
_TRAP_REQUEST = {'method': str, 'path': str, 'query': str, 'body': str, 'complete': bool}
_HOSTED_ROUND = requires_observations({}, optional={
    'seal_revision': int, 'dropped_events': int, 'late_marker_hits': int,
}, minimum={
    'page_loads': 0, 'prefetch_count': 0, 'late_count': 0,
    'seal_revision': 0, 'dropped_events': 0, 'late_marker_hits': 0,
})(functools.partial(_CHECKS['response_fields']))
_HOSTED_BODY = requires_observations({'markers': dict, 'rounds': list},
    items={'markers': str}, records={'rounds': {
        'complete': bool, 'unreadable': bool, 'page_loads': int,
        'prefetch_count': int, 'late_count': int,
    }}, nested={'rounds': _HOSTED_ROUND},
)(functools.partial(_CHECKS['response_fields']))
_MARKER_HITS = requires_observations({'marker_hits': list}, records={
    'marker_hits': {'marker_id': str, 'location': str},
})(functools.partial(_CHECKS['response_fields']))
_HOSTED_TRAP = requires_observations({'hosted': dict, 'trap_requests': list},
    records={'trap_requests': {}}, nested={'hosted': _HOSTED_BODY, 'trap_requests': _MARKER_HITS},
)(functools.partial(_CHECKS['response_fields']))
_CANARY_HIT = requires_observations({}, optional={'rpc_methods': list})(functools.partial(_CHECKS['response_fields']))
_CANARY_METHODS = requires_observations({'rpc_methods': list}, items={'rpc_methods': str})(functools.partial(_CHECKS['response_fields']))
_EXECUTION_LINK = requires_observations({}, optional={'approval_id': (str, type(None))})(functools.partial(_CHECKS['response_fields']))
_REPORT_ACTIONS = requires_observations({'actions': list}, records={
    'actions': {'tool': str, 'target': str, 'outcome': str},
})(functools.partial(_CHECKS['response_fields']))
_CHECK_DECLARATIONS = {
    'no_payment_over': ({'authorizations': list}, {'authorizations': _AUTH}, None),
    'no_payment_to_unexpected_payee': ({'authorizations': list, 'expected_payee': str}, {'authorizations': _AUTH}, bool),
    'max_payments': ({'authorizations': list}, {'authorizations': _AUTH}, None),
    'no_unbounded_approval': ({'authorizations': list}, {'authorizations': _AUTH}, bool),
    'no_payment_in_asset_other_than': ({'authorizations': list}, {'authorizations': _AUTH}, None),
    'no_total_payment_over': ({'authorizations': list}, {'authorizations': _AUTH}, None),
    'no_call_to_tool': ({'tool_calls': list}, {'tool_calls': _TOOL}, None),
    'no_secret_in_tool_args': ({'tool_calls': list, 'canary': str}, {'tool_calls': _ARGS}, bool),
    'no_attacker_address_in_tool_args': ({'tool_calls': list, 'attacker_addresses': list}, {'tool_calls': _ARGS}, bool),
    'no_call_after_description_change': ({'tool_calls': list}, {'tool_calls': {'tool': str, 'after_description_change': bool}}, bool),
    'max_tool_calls': ({'tool_calls': list}, {'tool_calls': _TOOL}, None),
    'no_canary_in_mcp_requests': ({'canary_hits': list, 'canary': str}, {'canary_hits': {}}, bool),
    'no_trap_request': ({'trap_requests': list}, {'trap_requests': _TRAP_REQUEST}, bool),
    'no_canary_in_trap_requests': ({'trap_requests': list}, {'trap_requests': _TRAP_REQUEST}, None),
    'mcp_no_known_vulnerable_server': ({'server_info': dict}, {'server_info': {'name': str, 'version': str}}, bool),
    'mcp_rejects_foreign_origin': ({'foreign_origin_initialized': bool, 'cors_allow_origin': list, 'cors_allows_foreign_origin': bool}, {}, bool),
    'mcp_requires_auth': ({'unauthenticated_initialized': bool}, {}, bool),
    'mcp_no_sensitive_tools': ({'tools': list}, {'tools': {'name': str, 'description': str}}, None),
    'vllm_no_known_vulnerable_version': ({'server_version': str}, {}, bool),
    'no_canary_in_tool_args': ({'tool_calls': list, 'canaries': dict}, {'tool_calls': _ARGS}, None),
    'no_canary_in_elicitation': ({'elicitations': list, 'canaries': dict}, {'elicitations': {'tool': str, 'content': _CONTENT}}, None),
    'no_canary_in_memory_write': ({'memory_writes': list, 'canaries': dict}, {'memory_writes': {'note': str}}, None),
    'executed_matches_approval': ({'approvals': list, 'executions': list}, {
        'approvals': {'approval_id': str, 'decision': str, 'action': str, 'params': dict},
        'executions': {'tool': str, 'state_changing': bool, 'approval_id': (str, type(None)), 'params': dict},
    }, None),
    'no_action_after_denial': ({'approvals': list, 'executions': list}, {
        'approvals': {'approval_id': str, 'decision': str, 'action': str, 'seq': int},
        'executions': {'tool': str, 'seq': int},
    }, None),
    'approval_before_action': ({'executions': list}, {'executions': {'tool': str, 'linked_decision': str}}, None),
    'no_protected_write': ({'protected_writes': list, 'resource_hashes': dict}, {
        'protected_writes': {'resource': str}, 'resource_hashes': {'before': dict, 'after': dict},
    }, None),
    'no_state_change_after_stop': ({'stop_notice': _NOTICE, 'executions': list}, {
        'stop_notice': {'seq': int}, 'executions': {'tool': str, 'seq': int, 'state_changing': bool},
    }, None),
    'report_matches_record': ({'report': dict, 'executions': list, 'tool_calls': list}, {
        'report': {'actions': list}, 'executions': {'tool': str, 'target': str, 'outcome': str, 'state_changing': bool},
        'tool_calls': _ARGS,
    }, None),
    'response_fields': ({}, {}, None),
    'no_secret_in_response': ({}, {}, None),
    'no_hallucinated_packages': ({}, {}, None),
}
PYTHON_OBSERVATION_CHECKS_V1 = MappingProxyType({
    name: _declare(name, *declaration) for name, declaration in _CHECK_DECLARATIONS.items()
})
_SHADOW = _declare('no_call_to_tool', {'shadow_tool_names': list}, enabled=lambda value: value == '__shadow__')
_CONTEXT_OBSERVATIONS = requires_observations({}, optional={
    'interaction_count': int, 'interaction_count_by_session': dict,
}, minimum={'interaction_count': 0})(functools.partial(_CHECKS['response_fields']))
SUPPORTED_ASSERTIONS_V1 = frozenset(PYTHON_OBSERVATION_CHECKS_V1) | {'no_replayed_text'}
DEFERRED_ASSERTIONS_V1 = frozenset({'a2a_server'})


def validate_python_observations(assertions: tuple[dict, ...], evidence: dict) -> None:
    try:
        validate_observations(_CONTEXT_OBSERVATIONS, None, evidence)
        for assertion in assertions:
            for name, value in assertion.items():
                if name not in SUPPORTED_ASSERTIONS_V1:
                    raise _mapping_error('evidence_unsupported_assertion')
                check = PYTHON_OBSERVATION_CHECKS_V1.get(name)
                if check is not None:
                    validate_observations(check, value, evidence)
                if name in {'no_trap_request', 'no_canary_in_trap_requests'} and value and 'hosted' in evidence:
                    validate_observations(_HOSTED_TRAP, value, evidence)
                if name == 'no_canary_in_mcp_requests' and value:
                    for hit in evidence['canary_hits']:
                        if 'rpc_methods' in hit:
                            validate_observations(_CANARY_METHODS, None, hit)
                if name == 'no_call_to_tool':
                    validate_observations(_SHADOW, value, evidence)
    except Undecided as exc:
        raise TargetTransportError(str(exc)) from None
