"""Request flows that record evidence for pure A2A verdicts."""
from __future__ import annotations
from typing import Literal, TYPE_CHECKING
from argus.a2a.client import A2AClient, MutationNotAllowed
from argus.a2a.protocol import parse_card
if TYPE_CHECKING:
    from argus.targets.a2a_server import A2AServerSpec

CheckName = Literal['unauthenticated_task', 'invalid_credentials', 'cross_client_task', 'extended_card_auth', 'card_unsigned', 'push_private_callback']
ALL_CHECKS = ('unauthenticated_task', 'invalid_credentials', 'cross_client_task', 'extended_card_auth', 'card_unsigned', 'push_private_callback')
_FLOWS = {}

async def run_check(name: CheckName, client: A2AClient, spec: A2AServerSpec) -> dict:
    evidence = {'check': name, 'card': {}, 'precondition': {}, 'config': {'forbidden_on_primary_tasks': sorted(spec.forbidden_on_primary_tasks), 'push_callback_policy': spec.push_callback_policy,
                'jsonrpc_auth_error_codes': {'authentication': sorted(spec.authentication_codes), 'authorization': sorted(spec.authorization_codes)}}}
    status, doc = await client.fetch_card()
    evidence['card']['status'] = status
    if status == 404:
        legacy = await client.fetch_legacy_card_status()
        evidence['precondition'] = {'skip': 'server publishes only an A2A 0.3 Agent Card'} if legacy is not None and 200 <= legacy < 300 else {'error': f'no Agent Card at {spec.url}'}
    elif status is None or not 200 <= status < 300:
        evidence['precondition'] = {'error': f'could not fetch Agent Card (HTTP {status})'}
    else:
        try:
            facts = parse_card(doc)
        except ValueError as exc:
            evidence['precondition'] = {'error': str(exc)}
        else:
            evidence['card'].update(facts.to_dict())
            unavailable = facts.unavailable
            if unavailable == 'a2a_0_3_only':
                evidence['precondition'] = {'skip': 'server publishes only an A2A 0.3 Agent Card'}
            elif unavailable == 'no_interfaces':
                evidence['precondition'] = {'error': 'Agent Card has no A2A 1.0 supportedInterfaces'}
            elif facts.interface is None and name != 'card_unsigned':
                evidence['precondition'] = {'skip': 'unsupported binding '+unavailable.split(':', 1)[-1]}
            elif name in _FLOWS:
                try:
                    await _FLOWS[name](evidence, client, spec, facts)
                except MutationNotAllowed:
                    evidence['precondition'] = {'error': 'internal: a state-changing request was attempted with allow_send false'}
    evidence.update(interaction_count=client.interaction_count, state_changing_requests=client.state_changing_requests, exchanges=[ex.to_dict() for ex in client.exchanges])
    return evidence
