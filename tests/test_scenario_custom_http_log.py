import httpx
import respx

from argus.targets.custom_http import CustomHTTPSpec, CustomHTTPTarget


@respx.mock
async def test_custom_http_preserves_real_run_record_and_dry_run_flag():
    target = CustomHTTPTarget(CustomHTTPSpec(kind="custom_http", request_url="https://target.invalid/chat", request_body_template='{"prompt": {{ prompt | tojson }} }',
                                           response_jsonpath="$.text", session_id_jsonpath="$.session_id", run_id_jsonpath="$.run_id", run_log_jsonpath="$.run_log"))
    respx.post("https://target.invalid/chat").mock(return_value=httpx.Response(200, json={"text": "answer", "session_id": "session", "run_id": "target-run",
                                                                                      "run_log": {"is_dry_run": True, "events": [{"operation": "read", "status": "intent"}]}}))
    assert (await target.send_prompt("task"))[0] == "answer"
    log = target.last_run_log()
    assert log.session_id == "session"
    assert log.run_id == "target-run"
    assert log.is_dry_run
    await target.begin_probe(None)
    assert target.last_run_log() is None
