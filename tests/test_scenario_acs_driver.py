from datetime import timedelta
from uuid import uuid4

import pytest
from pydantic import SecretStr

from argus.scenarios.credentials import AccessToken
from argus.scenarios.models import BudgetSpec, ObjectSpec, now
from argus.scenarios.runtime import Budget, NotReady, ObjectRegistry, RunContext
import argus_drivers_acs as acs


class Provider:
    async def access_token(self, ref, scopes):
        return AccessToken(value=SecretStr('fake-acs-connection'), expires_at=now() + timedelta(hours=1), scopes=frozenset(scopes))


def context(tmp_path):
    run_id = str(uuid4())
    return RunContext(run_id=run_id, organization_id=str(uuid4()), scenario_id='local-acs',
                      connections={'operator': 'op', 'observer': 'obs'}, target_identity='observer@example.invalid',
                      allowed_ops=frozenset({'acs_email.send_seed'}), budget=Budget(BudgetSpec()),
                      registry=ObjectRegistry(tmp_path, run_id), group='test')


@pytest.fixture
def sdk(monkeypatch):
    from azure.communication.email.aio import EmailClient
    calls = []
    failure = []
    observed_intent = []

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def begin_send(self, message):
            calls.append(message)
            if observed_intent:
                observed_intent[0]()
            return self

        async def result(self):
            if failure:
                raise failure[0]
            return {'id': 'delivery-ledger-id', 'status': 'Succeeded'}

    monkeypatch.setattr(EmailClient, 'from_connection_string', lambda value: Client())
    monkeypatch.setattr(acs.time, 'monotonic', lambda: 100.0)
    acs._sends.clear()
    yield calls, failure, observed_intent
    acs._sends.clear()


def driver():
    return acs.ACSEmailDriver({'sender': 'test@fixture.azurecomm.net'}, Provider())


async def test_local_acs_rejects_unsupported_observation(tmp_path):
    ctx, local = context(tmp_path), driver()
    for call in [lambda: local.readiness(ctx, None), lambda: local.snapshot(ctx, None), lambda: local.collect(ctx, None, {})]:
        with pytest.raises(NotReady, match='does not support'):
            await call()


async def test_local_acs_persists_intent_before_send_and_reuses_acceptance(tmp_path, sdk):
    calls, _, observed_intent = sdk
    ctx, local = context(tmp_path), driver()

    def assert_intent():
        records = ObjectRegistry(tmp_path, ctx.run_id).records.values()
        assert any(record.external_id == 'pending-send' for record in records)

    observed_intent.append(assert_intent)
    spec = ObjectSpec(driver='acs_email', op='send_seed', content='controlled seed')
    result = await local.prepare(ctx, 'seed', spec)
    ctx.registry.save(result)
    assert result.external_id == 'delivery-ledger-id'
    assert calls[0]['recipients']['to'] == [{'address': ctx.target_identity}]
    assert calls[0]['headers']['X-Argus-Marker'] == ctx.marker('seed')
    assert ctx.marker('seed') in calls[0]['content']['plainText']
    assert (await local.prepare(ctx, 'seed', spec)).external_id == result.external_id
    assert len(calls) == 1


async def test_local_acs_uncertain_result_cannot_resend(tmp_path, sdk):
    calls, failure, _ = sdk
    failure.append(RuntimeError('controlled transport uncertainty'))
    ctx, local = context(tmp_path), driver()
    spec = ObjectSpec(driver='acs_email', op='send_seed', content='controlled seed')
    with pytest.raises(RuntimeError):
        await local.prepare(ctx, 'seed', spec)
    with pytest.raises(NotReady, match='do not resend'):
        await local.prepare(ctx, 'seed', spec)
    assert len(calls) == 1
    assert next(iter(ObjectRegistry(tmp_path, ctx.run_id).records.values())).external_id == 'pending-send'


@pytest.mark.parametrize('prior', [[100.0] * 5, [0.0] * 10])
async def test_local_acs_quota_stops_before_external_send(tmp_path, sdk, prior):
    calls, _, _ = sdk
    acs._sends.extend(prior)
    ctx = context(tmp_path)
    with pytest.raises(NotReady, match='quota exhausted'):
        await driver().prepare(ctx, 'seed', ObjectSpec(driver='acs_email', op='send_seed'))
    assert calls == []
    assert not ctx.registry.records
    assert ctx.budget.counts['third_party_calls'] == 0
