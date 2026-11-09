import importlib
from types import SimpleNamespace

import pytest

from argus.targets.browser_use import BrowserUseSpec, BrowserUseTarget
from argus_transport import TransportContext
from argus_transport.security import Redactor
from test_transport_lifecycle import lifecycle_dict, recording_lifecycle, deletes
from test_transport_v2_engine import runtime
from transport_v2_fakes import serve
from test_transport_browser import browser_spec


@pytest.mark.asyncio
@pytest.mark.parametrize('status', [204, 500])
async def test_actual_v2run_live_and_final_reports_validate(status):
    app = recording_lifecycle(undo_status=status)
    async with serve(app) as origin:
        run = runtime(lifecycle_dict(origin, attempt=False))
        await run.attempt(TransportContext(prompt='benign task'))
        before = run.cleanup_report()
        assert before['complete'] is False
        await run.close()
        final = run.cleanup_report()
        assert final['complete'] is (status == 204)
        assert deletes(app) == ['/v1/sources/source-one']
        validate = importlib.import_module('argus_transport.cleanup').validate_cleanup_report
        assert validate(before) == before
        assert validate(final) == final
        assert run.cleanup_report() == final


@pytest.mark.asyncio
@pytest.mark.parametrize('failed', [False, True])
async def test_actual_hosted_browser_reports_validate_after_close(failed):
    browser = BrowserUseTarget(BrowserUseSpec(transport=browser_spec('http://127.0.0.1:1/run'), scenario_kind='ui_phishing', trap_mode='hosted', hosted={
        'service_url': 'http://127.0.0.1:1', 'owner_token_env': 'GENERIC_OWNER'}))
    calls = []
    class Client:
        redactor = Redactor(())
        async def delete_run(self, run):
            calls.append(run.run_id)
            if failed:
                error = RuntimeError('generic deletion failed')
                error.status = 503
                raise error
            return 204
        async def aclose(self):
            calls.append('close')
    browser._hosted_client = Client()
    browser._hosted_runs = [SimpleNamespace(run_id='run-one')]
    await browser.aclose()
    final = browser.cleanup_report()
    await browser.aclose()
    assert calls == ['run-one', 'close']
    assert final['complete'] is not failed
    assert final['done'] == (0 if failed else 1)
    assert final['leftover'] == []
    validate = importlib.import_module('argus_transport.cleanup').validate_cleanup_report
    assert validate(final) == final
    assert browser.cleanup_report() == final


def test_browser_local_none_and_hosted_zero_run_object():
    from dataclasses import replace
    browser = BrowserUseTarget(BrowserUseSpec(transport=browser_spec('http://127.0.0.1:1/run'),
        scenario_kind='ui_phishing', trap_mode='hosted', hosted={
            'service_url': 'http://127.0.0.1:1', 'owner_token_env': 'GENERIC_OWNER'}))
    validate = importlib.import_module('argus_transport.cleanup').validate_cleanup_report
    assert validate(browser.cleanup_report()) == {
        'complete': True, 'done': 0, 'open': [], 'stop_reason': None, 'leftover': []}
    local = BrowserUseTarget(replace(browser.spec, trap_mode='local', hosted=None))
    assert validate(local.cleanup_report()) is None
