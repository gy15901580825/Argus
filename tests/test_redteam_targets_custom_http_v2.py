import asyncio
import json

import pytest
from aiohttp import web

from argus.targets._base import TargetBlockedError, TargetTransportError, Turn
from argus.targets.custom_http import CustomHTTPSpec, CustomHTTPTarget
from argus_transport import local_transport_mode
from test_transport_engine import spec_dict
from transport_v2_fakes import RecordingApp, serve


def target(data):
    data["version"] = 2
    return CustomHTTPTarget(CustomHTTPSpec(transport=data))


def test_v2_session_none_has_no_history_support():
    assert target(spec_dict()).supports_history is False


@pytest.mark.parametrize("failure", ["http", "timeout"])
async def test_v2_failure_maps_like_v1(failure):
    app = RecordingApp()

    async def failed(request):
        if failure == "timeout":
            await asyncio.sleep(0.05)
        return web.Response(status=500)

    app.route("POST", "/run", failed)
    async with serve(app) as origin:
        data = spec_dict(origin + "/run")
        if failure == "timeout":
            data["timeout"] = {"total_deadline_s": 0.01, "read_s": 0.01}
        instance = target(data)
        with local_transport_mode():
            if failure == "http":
                with pytest.raises(TargetTransportError, match="^target_error: http_error$"):
                    await instance.send_prompt("ping")
            else:
                with pytest.raises(TimeoutError):
                    await instance.send_prompt("ping")
        evidence = (await instance.collect_evidence())["transport"]
        assert evidence["outcome"] == ("target_error" if failure == "http" else "timed_out")
        assert len(app.calls) == 1


async def test_v2_mapped_refusal_retains_transport_evidence():
    app = RecordingApp()

    async def refused(request):
        return web.json_response({"error": {"code": "POLICY_REFUSAL"}}, status=403)

    app.route("POST", "/run", refused)
    async with serve(app) as origin:
        instance = target(spec_dict(origin + "/run"))
        with local_transport_mode():
            with pytest.raises(TargetBlockedError) as caught:
                await instance.send_prompt("ping")
        assert caught.value.transport_metadata == {
            "outcome": "blocked", "http_status": 403,
            "matched_rule_id": "policy_refusal", "reason_code": "target_refusal",
            "origin": "mapped_body_rule",
        }
        assert (await instance.collect_evidence())["transport"] == caught.value.transport_metadata


async def test_v2_server_session_continues_and_resets_for_new_probe():
    app = RecordingApp()

    async def completed(request):
        return web.json_response({"status": "COMPLETED", "result": "done", "session_id": "session-1"})

    app.route("POST", "/run", completed)
    async with serve(app) as origin:
        data = spec_dict(origin + "/run")
        data["session"] = {"mode": "server_returned", "id_path": "$.session_id"}
        data["response"]["metadata"] = {"session_id": {"path": "$.session_id", "required": True}}
        data["request"]["body"]["json"]["session"] = {"context": "session_id", "missing": "omit"}
        instance = target(data)
        assert instance.supports_history is True
        with local_transport_mode():
            assert (await instance.send_prompt("first"))[0] == "done"
            assert (await instance.send_prompt("second", (Turn("user", "first"),)))[0] == "done"
            await instance.begin_probe(None)
            assert (await instance.send_prompt("third"))[0] == "done"
        assert [json.loads(call[3]) for call in app.calls] == [
            {"goal": "first"}, {"goal": "second", "session": "session-1"}, {"goal": "third"}
        ]
