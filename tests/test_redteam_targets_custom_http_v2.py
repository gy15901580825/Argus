import asyncio
import json

import httpx
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
async def test_v2_failure_maps_like_v1(failure, monkeypatch):
    app = RecordingApp()
    response_release = asyncio.Event()

    if failure == "timeout":
        class DelayedClient(httpx.AsyncClient):
            async def __aenter__(self):
                await asyncio.sleep(0.05)
                return await super().__aenter__()

        monkeypatch.setattr("argus_transport.engine_v2.httpx.AsyncClient", DelayedClient)

    async def failed(request):
        if failure == "timeout":
            await response_release.wait()
        return web.Response(status=500)

    app.route("POST", "/run", failed)
    async with serve(app) as origin:
        data = spec_dict(origin + "/run")
        if failure == "timeout":
            data["timeout"] = {"total_deadline_s": 5, "read_s": 0.1}
        instance = target(data)
        try:
            with local_transport_mode():
                if failure == "http":
                    with pytest.raises(TargetTransportError, match="^target_error: http_error$"):
                        await instance.send_prompt("ping")
                else:
                    with pytest.raises(TimeoutError):
                        await instance.send_prompt("ping")
        finally:
            response_release.set()
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


async def required_material_prompt_only(tmp_path, startup="provision"):
    from pathlib import Path
    from dataclasses import replace
    from argus.probe import load_probe
    from argus.runner import Runner
    from test_probe_indirect import probe_data, write_probe
    from test_runner_material import StubJudge
    from test_transport_provision import provision_app, provision_dict

    app = provision_app()
    async with serve(app) as origin:
        if startup == 'provision':
            data = provision_dict(origin)
        else:
            from test_transport_lifecycle import lifecycle_dict
            data = lifecycle_dict(origin, attempt=False)
        data['request']['body']['json']['document'] = {'base64': {'context': 'material'}}
        instance = target(data)
        probe = replace(load_probe(write_probe(tmp_path, probe_data())), indirect=())
        runner = Runner(target=instance, judge=StubJudge(), rubrics_dir=Path(__file__).parents[1] / 'argus/rubrics')
        with local_transport_mode():
            findings = [finding async for finding in runner.run_probe(probe)]
            await instance.aclose()
        return findings, app.calls


@pytest.mark.parametrize('startup', ['provision', 'run'])
async def test_required_material_skips_probe_without_indirect(tmp_path, startup):
    findings, calls = await required_material_prompt_only(tmp_path, startup)
    assert [finding.verdict for finding in findings] == ['skipped']
    assert calls == []


async def test_required_material_skip_reason_names_indirect(tmp_path):
    findings, calls = await required_material_prompt_only(tmp_path)
    assert 'requires material' in findings[0].reasoning
    assert 'indirect' in findings[0].reasoning
    assert calls == []


async def test_optional_material_runs_prompt_only():
    app = RecordingApp()
    async def completed(request):
        return web.json_response({'status': 'COMPLETED', 'result': 'done'})
    app.route('POST', '/run', completed)
    app.route('POST', '/upload', completed)
    async with serve(app) as origin:
        data = spec_dict(origin + '/run')
        data['lifecycle'] = {'attempt': [{'id': 'upload', 'if_present': 'material',
            'request': {'url': origin + '/upload', 'body': {'json': {'document': {'context': 'material'}}}},
            'expect': {'http_status': [200]}}]}
        instance = target(data)
        assert instance.material_channel is True
        with local_transport_mode():
            await instance.begin_probe(None)
            assert (await instance.send_prompt('Read the sample.'))[0] == 'done'
            await instance.aclose()
        assert [(call[0], call[1]) for call in app.calls] == [('POST', '/run')]


async def test_base64_encodes_utf8_material():
    import base64
    app = RecordingApp()
    async def completed(request):
        return web.json_response({'status': 'COMPLETED', 'result': 'done'})
    app.route('POST', '/run', completed)
    async with serve(app) as origin:
        data = spec_dict(origin + '/run')
        data['request']['body']['json']['document'] = {'base64': {'context': 'material'}}
        instance = target(data)
        with local_transport_mode():
            assert (await instance.send_prompt('Read the sample.', material='Résumé sample.'))[0] == 'done'
            await instance.aclose()
        assert base64.b64decode(json.loads(app.calls[0][3])['document']).decode('utf-8') == 'Résumé sample.'


@pytest.mark.parametrize('owner', ['query', 'multipart', 'concat', 'base64'])
async def test_optional_material_omission_works_through_public_target(owner):
    app = RecordingApp()
    async def completed(request):
        return web.json_response({'status': 'COMPLETED', 'result': 'done'})
    app.route('POST', '/run', completed)
    async with serve(app) as origin:
        data = spec_dict(origin + '/run')
        expression = {'context': 'material', 'missing': 'omit'}
        if owner == 'query':
            data['request']['query'] = {'document': {'base64': expression}}
        elif owner == 'multipart':
            data['request']['body'] = {'multipart': {'file': {'filename': {'literal': 'sample.txt'},
                'content_type': 'text/plain', 'content': {'concat': [{'literal': 'sample'}, expression]}}}}
        else:
            expression = {'base64': expression} if owner == 'base64' else {'concat': [{'literal': 'sample'}, expression]}
            data['request']['body']['json']['document'] = expression
        instance = target(data)
        assert instance.material_channel is True
        with local_transport_mode():
            await instance.begin_probe(None)
            assert (await instance.send_prompt('Read the sample.'))[0] == 'done'
            await instance.aclose()
        assert app.calls[0][1] == '/run'
        assert b'Content-Disposition' not in app.calls[0][3]
        if owner != 'multipart':
            assert json.loads(app.calls[0][3]) == {'goal': 'Read the sample.'}
