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


def _auth_precondition(evidence, facts):
    if facts.auth == 'anonymous':
        evidence['precondition'] = {'skip': 'Card allows anonymous access'}
    elif facts.auth == 'malformed':
        evidence['precondition'] = {'error': 'Agent Card authentication requirements are malformed'}
    return bool(evidence['precondition'])


def _send_precondition(evidence, spec):
    if spec.allow_send is not True:
        evidence['precondition'] = {'skip': 'allow_send is not true; SendMessage changes server state'}
        return True
    return False


async def _authentication(evidence, client, spec, facts):
    from argus.a2a.protocol import message_request
    if _auth_precondition(evidence, facts) or _send_precondition(evidence, spec):
        return
    control = await client.call('control_send', 'SendMessage', message_request(return_immediately=False), 'primary', iface=facts.interface)
    if control.outcome != 'success':
        return
    principal = 'none' if evidence['check'] == 'unauthenticated_task' else 'forged'
    await client.call('attack_send', 'SendMessage', message_request(return_immediately=False), principal, iface=facts.interface)

_FLOWS.update(unauthenticated_task=_authentication, invalid_credentials=_authentication)


async def _cross_client(evidence, client, spec, facts):
    import secrets
    from argus.a2a.protocol import message_request, TERMINAL_STATES
    if spec.second_client is None:
        evidence['precondition'] = {'skip': 'no second_client configured'}
        return
    if not spec.forbidden_on_primary_tasks:
        evidence['precondition'] = {'skip': 'no authorization boundary declared (second_client.forbidden_on_primary_tasks is empty)'}
        return
    if {(k.lower(), v) for k, v in spec.primary_headers} == {(k.lower(), v) for k, v in spec.second_headers}:
        evidence['precondition'] = {'error': 'second_client.headers are identical to credentials.headers; the two principals cannot be told apart'}
        return
    if _send_precondition(evidence, spec):
        return
    iface = facts.interface
    control = await client.call('control_a_send', 'SendMessage', message_request(return_immediately=True), 'primary', iface=iface)
    if control.outcome != 'success':
        return
    if control.result_kind == 'message':
        evidence['precondition'] = {'skip': 'server answered with a Message; there is no task to test'}
        return
    second = await client.call('control_b_send', 'SendMessage', message_request(return_immediately=True), 'second', iface=iface)
    if second.outcome != 'success':
        return
    marker = secrets.token_hex(16)
    evidence['marker'] = marker
    attack = await client.call('attack_a_send', 'SendMessage', message_request(return_immediately=True, marker=marker), 'primary', iface=iface)
    if attack.outcome != 'success':
        return
    if attack.result_kind == 'message':
        evidence['precondition'] = {'skip': 'server answered with a Message; there is no task to test'}
        return
    task_id = attack.task_id
    state = attack.task_state
    if 'get' in spec.forbidden_on_primary_tasks:
        get = await client.call('control_a_get', 'GetTask', {'id': task_id}, 'primary', iface=iface)
        if get.outcome == 'success':
            state = get.task_state
            await client.call('attack_b_get', 'GetTask', {'id': task_id}, 'second', iface=iface)
    if 'list' in spec.forbidden_on_primary_tasks:
        listed = await client.call('control_a_list', 'ListTasks', {'pageSize': 100}, 'primary', iface=iface, detail={'list_has_primary_task': [task_id, marker]})
        if listed.outcome == 'success' and listed.detail.get('list_has_primary_task') is True:
            await client.call('attack_b_list', 'ListTasks', {'pageSize': 100}, 'second', iface=iface, detail={'list_has_primary_task': [task_id, marker]})
    if 'cancel' in spec.forbidden_on_primary_tasks and control.task_state not in TERMINAL_STATES:
        canceled = await client.call('control_a_cancel', 'CancelTask', {'id': control.task_id}, 'primary', iface=iface)
        if canceled.outcome != 'success':
            await client.call('control_a_recheck', 'GetTask', {'id': control.task_id}, 'primary', iface=iface)
        elif state not in TERMINAL_STATES:
            await client.call('attack_b_cancel', 'CancelTask', {'id': task_id}, 'second', iface=iface)
            viewed = await client.call('attack_a_view', 'GetTask', {'id': task_id}, 'primary', iface=iface)
            if viewed.outcome == 'success':
                state = viewed.task_state
    if state not in TERMINAL_STATES:
        await client.call('cleanup_cancel', 'CancelTask', {'id': task_id}, 'primary', iface=iface)

_FLOWS['cross_client_task'] = _cross_client


async def _extended_card(evidence, client, spec, facts):
    if not facts.extended_card:
        evidence['precondition'] = {'skip': 'Card does not declare capabilities.extendedAgentCard'}
        return
    if _auth_precondition(evidence, facts):
        return
    control = await client.call('control_extended_card', 'GetExtendedAgentCard', {}, 'primary', iface=facts.interface)
    if control.outcome == 'success':
        await client.call('attack_extended_card', 'GetExtendedAgentCard', {}, 'none', iface=facts.interface)


async def _card_unsigned(evidence, client, spec, facts):
    pass

_FLOWS.update(extended_card_auth=_extended_card, card_unsigned=_card_unsigned)

PRIVATE_CALLBACK_URLS = (
    'http://127.0.0.1:9/argus-callback', 'http://localhost:9/argus-callback',
    'http://10.0.0.1:9/argus-callback', 'http://172.16.0.1:9/argus-callback',
    'http://192.168.0.1:9/argus-callback', 'http://169.254.169.254:9/argus-callback',
)


async def _push_private_callback(evidence, client, spec, facts):
    import secrets
    from argus.a2a.protocol import message_request, TERMINAL_STATES
    if not facts.push_notifications:
        evidence['precondition'] = {'skip': 'Card does not declare capabilities.pushNotifications'}
        return
    if _send_precondition(evidence, spec):
        return
    iface = facts.interface
    task = await client.call('control_send', 'SendMessage', message_request(return_immediately=True), 'primary', iface=iface)
    if task.outcome != 'success':
        return
    if task.result_kind == 'message':
        evidence['precondition'] = {'skip': 'server answered with a Message; there is no task to register a callback on'}
        return
    if task.task_state in TERMINAL_STATES:
        evidence['precondition'] = {'skip': 'task finished; there is no unfinished task to register a callback on'}
        return
    configs = []
    config_id = 'argus-ctrl-'+secrets.token_hex(8)
    control = await client.call('control_register', 'CreateTaskPushNotificationConfig', {'taskId': task.task_id, 'id': config_id, 'url': spec.push_control_url}, 'primary', iface=iface, detail={'callback_url': spec.push_control_url, 'config_id': config_id})
    if control.outcome == 'success':
        configs.append(control.detail['config_id'])
        for index, url in enumerate(PRIVATE_CALLBACK_URLS):
            config_id = f'argus-atk-{index}-'+secrets.token_hex(8)
            attack = await client.call('attack_register', 'CreateTaskPushNotificationConfig', {'taskId': task.task_id, 'id': config_id, 'url': url}, 'primary', iface=iface, detail={'callback_url': url, 'config_id': config_id})
            if attack.outcome == 'success':
                configs.append(attack.detail['config_id'])
    for config_id in configs:
        await client.call('cleanup_delete', 'DeleteTaskPushNotificationConfig', {'taskId': task.task_id, 'id': config_id}, 'primary', iface=iface, detail={'config_id': config_id})
    await client.call('cleanup_cancel', 'CancelTask', {'id': task.task_id}, 'primary', iface=iface)

_FLOWS['push_private_callback'] = _push_private_callback
