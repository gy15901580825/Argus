import asyncio
import json

import pytest
from aiohttp import web
from click.testing import CliRunner

from argus.cli.__main__ import main
from test_transport_engine import spec_dict
from test_transport_poll import poll_dict
from transport_v2_fakes import RecordingApp, serve


def target_file(tmp_path, transport, *, kind="custom_http"):
    path = tmp_path / "target-v2.json"
    spec = {"kind": kind, "transport": transport}
    if kind == "browser_use":
        spec["scenario_kind"] = "dom_injection"
    path.write_text(json.dumps(spec))
    return path


async def invoke(path, *options):
    return await asyncio.to_thread(
        CliRunner().invoke,
        main,
        ["validate-target", "--target", str(path), *options],
    )


async def completed(request):
    return web.json_response({"status": "COMPLETED", "result": "done"})


async def test_v2_offline_sends_nothing_and_lists_bindings(tmp_path, monkeypatch):
    monkeypatch.delenv("UNSET_AUTOMATION_REF", raising=False)
    app = RecordingApp()
    app.route("POST", "/automations/{ref}", completed)
    async with serve(app) as origin:
        data = spec_dict(origin + "/automations/{automation_id}")
        data["version"] = 2
        data["let"] = {
            "run": {
                "automation_id": {"env": "UNSET_AUTOMATION_REF"},
                "source_name": {"generate": "uuid4"},
            },
            "attempt": {"ref": {"generate": "uuid4"}},
        }
        data["request"]["query"] = {"page_size": {"literal": 10}}
        result = await invoke(target_file(tmp_path, data), "--offline")
        assert result.exit_code == 0, result.output
        assert result.output.splitlines() == [
            "spec.transport.version: 2 OK",
            "request.method: POST",
            "request.url: <configured endpoint>",
            'request.placeholders: ["automation_id"]',
            'request.query: ["page_size"]',
            'let.run: ["automation_id", "source_name"]',
            'let.attempt: ["ref"]',
            "requests.submit=0 requests.poll=0 requests.retry=0",
        ]
        assert app.calls == []


async def test_v2_offline_omits_empty_binding_lists(tmp_path):
    data = spec_dict()
    data["version"] = 2
    result = await invoke(target_file(tmp_path, data))
    assert result.exit_code == 0, result.output
    assert result.output.splitlines() == [
        "spec.transport.version: 2 OK",
        "request.method: POST",
        "request.url: <configured endpoint>",
        "requests.submit=0 requests.poll=0 requests.retry=0",
    ]


@pytest.mark.parametrize("poll", [False, True])
async def test_v2_execute_counts_requests(tmp_path, poll):
    app = RecordingApp()

    async def accepted(request):
        return web.json_response({"status": "PENDING", "run_id": "job-1"}, status=202)

    async def polled(request):
        if len(app.calls) == 2:
            return web.json_response({"status": "RUNNING"})
        return await completed(request)

    app.route("POST", "/run", accepted if poll else completed)
    app.route("GET", "/runs/{ref}", polled)
    async with serve(app) as origin:
        data = (poll_dict if poll else spec_dict)(origin + "/run")
        data["version"] = 2
        result = await invoke(target_file(tmp_path, data), "--execute")
        assert result.exit_code == 0, result.output
        assert result.output.splitlines() == [
            "HTTP.status: 200",
            "outcome.selected: completed -> succeeded",
            f"requests.submit=1 requests.poll={2 if poll else 0} requests.retry=0",
        ]
        assert [call[:2] for call in app.calls] == (
            [("POST", "/run"), ("GET", "/runs/job-1"), ("GET", "/runs/job-1")]
            if poll else [("POST", "/run")]
        )
        assert json.loads(app.calls[0][3]) == {"goal": "ping"}


async def test_endpoint_override_rewrites_every_v2_request_origin(tmp_path):
    app = RecordingApp()

    async def accepted(request):
        return web.json_response({"status": "PENDING", "run_id": "job-2"}, status=202)

    app.route("POST", "/run", accepted)
    app.route("GET", "/runs/{ref}", completed)
    async with serve(app) as origin:
        data = poll_dict("https://api.vendor-a.example.test/run")
        data["version"] = 2
        data["delivery"]["request"]["query"] = {"page_size": {"literal": 3}}
        result = await invoke(
            target_file(tmp_path, data), "--execute", "--endpoint-override", origin
        )
        assert result.exit_code == 0, result.output
        assert [call[:2] for call in app.calls] == [
            ("POST", "/run"), ("GET", "/runs/job-2?page_size=3")
        ]
        assert "requests.submit=1 requests.poll=1 requests.retry=0" in result.output


async def test_v2_endpoint_override_requires_origin_only(tmp_path):
    data = spec_dict("https://api.vendor-a.example.test/run")
    data["version"] = 2
    result = await invoke(
        target_file(tmp_path, data), "--execute", "--endpoint-override", "http://127.0.0.1:1/run"
    )
    assert result.exit_code != 0
    assert "takes an origin" in result.output


@pytest.mark.parametrize("option", ["sample", "with_scenario", "scenario_url"])
async def test_v2_rejects_v1_only_options(tmp_path, option):
    data = spec_dict()
    data["version"] = 2
    sample = tmp_path / "sample.json"
    sample.write_text("{}")
    options = {
        "sample": ["--offline", "--sample-response", str(sample)],
        "with_scenario": ["--execute", "--with-scenario"],
        "scenario_url": ["--execute", "--scenario-url", "http://127.0.0.1:1/neutral"],
    }
    result = await invoke(target_file(tmp_path, data), *options[option])
    assert result.exit_code == 2
    assert "this option supports version 1 transports only" in result.output


@pytest.mark.parametrize("version", [2, 2.0, "2", True])
async def test_browser_v2_remains_rejected(tmp_path, version):
    data = spec_dict()
    data["version"] = version
    result = await invoke(target_file(tmp_path, data, kind="browser_use"), "--offline")
    assert result.exit_code != 0
    assert "spec.transport.version: 2 OK" not in result.output


@pytest.mark.parametrize("version", [2.0, "2", True])
async def test_custom_http_v2_requires_exact_integer_version(tmp_path, version):
    data = spec_dict()
    data["version"] = version
    result = await invoke(target_file(tmp_path, data), "--offline")
    assert result.exit_code != 0
    assert "spec.transport.version: 2 OK" not in result.output


async def test_v2_execute_reports_failure_without_response_body(tmp_path):
    app = RecordingApp()

    async def failed(request):
        return web.Response(status=500, text="private-response-data")

    app.route("POST", "/run", failed)
    async with serve(app) as origin:
        data = spec_dict(origin + "/run")
        data["version"] = 2
        result = await invoke(target_file(tmp_path, data), "--execute")
        assert result.exit_code == 1
        assert "HTTP.status: 500" in result.output
        assert "requests.submit=1 requests.poll=0 requests.retry=0" in result.output
        assert "transport.http_error: target_error" in result.output
        assert "private-response-data" not in result.output


async def test_v2_execute_rejects_invalid_run_log(tmp_path):
    app = RecordingApp()

    async def completed_with_invalid_log(request):
        return web.json_response({"status": "COMPLETED", "result": "done", "events": [123]})

    app.route("POST", "/run", completed_with_invalid_log)
    async with serve(app) as origin:
        data = spec_dict(origin + "/run")
        data["version"] = 2
        data["response"]["metadata"] = {"run_log": {"path": "$.events", "required": True}}
        result = await invoke(target_file(tmp_path, data), "--execute")
        assert result.exit_code == 1
        assert "outcome.selected: completed -> target_error" in result.output
        assert "transport.mapping_error: target_error" in result.output


@pytest.mark.parametrize("offline", [False, True])
@pytest.mark.parametrize("owner", ["poll_query", "run", "attempt"])
async def test_v2_cli_rejects_browser_context_before_requests(tmp_path, offline, owner):
    app = RecordingApp()

    async def accepted(request):
        return web.json_response({"status": "PENDING", "run_id": "job-1"}, status=202)

    app.route("POST", "/run", accepted)
    app.route("GET", "/runs/{ref}", completed)
    async with serve(app) as origin:
        data = poll_dict(origin + "/run")
        data["version"] = 2
        expression = {"context": "scenario_url"}
        if owner == "poll_query":
            data["delivery"]["request"]["query"] = {"scenario": expression}
        else:
            expression["missing"] = "omit"
            data["let"] = {owner: {"ref": expression}}
        result = await invoke(target_file(tmp_path, data), "--offline" if offline else "--execute")
        assert result.exit_code == 1
        assert "target spec invalid: ValueError" in result.output
        assert app.calls == []


async def test_v2_cli_accepts_opaque_context_shaped_literal(tmp_path):
    data = spec_dict()
    data["version"] = 2
    data["request"]["body"] = {
        "json": {"context": {"literal": {"context": "scenario_url"}}}
    }
    result = await invoke(target_file(tmp_path, data), "--offline")
    assert result.exit_code == 0, result.output
    assert "requests.submit=0 requests.poll=0 requests.retry=0" in result.output


async def test_endpoint_override_rewrites_lifecycle_and_undo_origins(tmp_path):
    from test_transport_lifecycle import lifecycle_dict, recording_lifecycle
    app = recording_lifecycle()
    async def accepted(request):
        return web.json_response({'status': 'PENDING', 'run_id': 'job-2'}, status=202)
    app.route('POST', '/submit', accepted)
    app.route('GET', '/runs/{ref}', completed)
    async with serve(app) as origin:
        data = lifecycle_dict('https://api.vendor-a.example.test')
        polling = poll_dict('https://api.vendor-a.example.test/run')
        data['delivery'] = polling['delivery']
        data['request']['url'] = 'https://api.vendor-a.example.test/submit'
        data['delivery']['request']['query'] = {'page_size': {'literal': 3}}
        result = await invoke(target_file(tmp_path, data), '--execute', '--endpoint-override', origin)
        assert result.exit_code == 0, result.output
        assert [call[:2] for call in app.calls] == [
            ('POST', '/v1/sources'), ('POST', '/v1/messages'), ('POST', '/submit'),
            ('GET', '/runs/job-2?page_size=3'),
            ('DELETE', '/v1/messages?remoteId=local-ref&sourceId=source-one'),
            ('DELETE', '/v1/sources/source-one'),
        ]
        assert 'requests.submit=1 requests.poll=1 requests.retry=0 requests.setup=2 requests.cleanup=2' in result.output


async def test_v2_execute_closes_run_after_failed_submit(tmp_path):
    from test_transport_lifecycle import lifecycle_dict, recording_lifecycle
    app = recording_lifecycle()
    async def failed(request):
        return web.Response(status=500)
    app.route('POST', '/submit', failed)
    async with serve(app) as origin:
        data = lifecycle_dict(origin)
        data['request']['url'] = origin + '/submit'
        result = await invoke(target_file(tmp_path, data), '--execute')
        assert result.exit_code == 1
        assert [call[1] for call in app.calls if call[0] == 'DELETE'] == [
            '/v1/messages?remoteId=local-ref&sourceId=source-one', '/v1/sources/source-one',
        ]
        assert 'requests.setup=2 requests.cleanup=2' in result.output


async def test_offline_prints_checklist_with_zero_requests(tmp_path):
    from test_transport_provision import provision_app, provision_dict
    app = provision_app()
    async with serve(app) as origin:
        data = provision_dict(origin)
        result = await invoke(target_file(tmp_path, data), '--offline')
        assert result.exit_code == 0, result.output
        assert 'provision.manual (shown when a find step matches nothing):' in result.output
        assert '[ ] Build the example.' in result.output
        assert '[ ] Exactly one item in $.automations has $.display_name = Example (skipped when $EXAMPLE_AUTOMATION_ID is set)' in result.output
        assert app.calls == []


async def test_execute_reports_provision_count(tmp_path, monkeypatch):
    from test_transport_provision import provision_app, provision_dict
    monkeypatch.delenv('EXAMPLE_AUTOMATION_ID', raising=False)
    app = provision_app()
    async with serve(app) as origin:
        result = await invoke(target_file(tmp_path, provision_dict(origin)), '--execute')
        assert result.exit_code == 0, result.output
        assert 'requests.provision=3' in result.output
        assert [call[0] for call in app.calls] == ['GET', 'GET', 'GET', 'POST']


async def test_execute_sends_neutral_sample_material(tmp_path):
    import base64
    app = RecordingApp()
    app.route('POST', '/run', completed)
    async with serve(app) as origin:
        data = spec_dict(origin + '/run')
        data['version'] = 2
        data['request']['body']['json']['document'] = {'base64': {'context': 'material'}}
        result = await invoke(target_file(tmp_path, data), '--execute')
        assert result.exit_code == 0, result.output
        assert json.loads(app.calls[0][3]) == {'goal': 'ping', 'document': base64.b64encode(b'Argus validation sample.').decode('ascii')}


async def test_endpoint_override_rewrites_provision_and_confirmation(tmp_path, monkeypatch):
    from test_transport_provision import provision_app, provision_dict
    monkeypatch.delenv('EXAMPLE_AUTOMATION_ID', raising=False)
    app = provision_app()
    async def created(request):
        return web.json_response({'name': 'files/sample.txt'}, status=201)
    async def unexpected(request):
        return web.Response(status=500)
    async def gone(request):
        return web.Response(status=404)
    app.route('POST', '/upload', created)
    app.route('DELETE', '/files/{ref}', unexpected)
    app.route('GET', '/files/{ref}/metadata', gone)
    async with serve(app) as origin:
        configured = 'https://api.vendor-a.example.test'
        data = provision_dict(configured)
        data['lifecycle']['run'] = [{'id': 'upload',
            'request': {'url': configured + '/upload', 'body': {'none': True}},
            'expect': {'http_status': [201]},
            'capture': {'file_id': {'path': '$.name', 'expect_prefix': {'literal': 'files/'}, 'last_segment': True}},
            'undo': {'request': {'method': 'DELETE', 'url': configured + '/files/{file_id}'},
                'expect': {'http_status': [204]}, 'confirm': {'request': {'method': 'GET',
                    'url': configured + '/files/{file_id}/metadata'}, 'gone_status': [404]}}}]
        result = await invoke(target_file(tmp_path, data), '--execute', '--endpoint-override', origin)
        assert result.exit_code == 0, result.output
        assert [call[:2] for call in app.calls] == [
            ('GET', '/organizations'), ('GET', '/organizations/o1/workspaces'),
            ('GET', '/organizations/o1/workspaces/w1/automations'), ('POST', '/upload'),
            ('POST', '/automations/a1:invoke'), ('DELETE', '/files/sample.txt'), ('GET', '/files/sample.txt/metadata')]
        assert 'requests.setup=1 requests.cleanup=2 requests.provision=3' in result.output


async def test_execute_not_provisioned_prints_checklist_and_final_counts(tmp_path, monkeypatch):
    from test_transport_provision import provision_app, provision_dict
    monkeypatch.delenv('EXAMPLE_AUTOMATION_ID', raising=False)
    app = provision_app(count=0)
    async with serve(app) as origin:
        result = await invoke(target_file(tmp_path, provision_dict(origin)), '--execute')
        assert result.exit_code == 1
        assert 'NOT PROVISIONED:' in result.output
        assert 'Build the example or supply its ID.' in result.output
        assert 'requests.submit=0 requests.poll=0 requests.retry=0 requests.provision=3' in result.output
        assert 'Configured cleanup remained enabled.' in result.output
        assert len(app.calls) == 3


@pytest.mark.parametrize('undo', [False, True], ids=['informational', 'unconfirmed'])
async def test_execute_reports_leftover_and_cleanup_completeness(tmp_path, undo):
    from test_transport_v2_local_run import resource_run_dict
    app = RecordingApp()
    async def created(request):
        return web.json_response({'name': 'files/sample.txt'}, status=201)
    async def unexpected(request):
        return web.Response(status=500)
    app.route('POST', '/v1/sources', created)
    app.route('POST', '/run', completed)
    app.route('DELETE', '/v1/sources/{ref}', unexpected)
    async with serve(app) as origin:
        data = resource_run_dict(origin, undo=undo)
        data['budget'] = {'cleanup_reserve': 1}
        result = await invoke(target_file(tmp_path, data), '--execute')
        assert result.exit_code == int(undo), result.output
        assert 'Target resources left on the target: 1 item(s).' in result.output
        assert '[ ] files/sample.txt' in result.output
        assert ('Target cleanup incomplete' in result.output) is undo
        assert f'requests.setup=1 requests.cleanup={int(undo)}' in result.output


async def test_execute_cleanup_stop_still_reports_final_counts(tmp_path):
    from test_transport_v2_local_run import resource_run_dict
    app = RecordingApp()
    async def created(request):
        return web.json_response({'name': 'files/sample.txt'}, status=201)
    async def stopped(request):
        return web.Response(status=429)
    app.route('POST', '/v1/sources', created)
    app.route('POST', '/run', completed)
    app.route('DELETE', '/v1/sources/{ref}', stopped)
    async with serve(app) as origin:
        result = await invoke(target_file(tmp_path, resource_run_dict(origin, undo=True)), '--execute')
        assert result.exit_code == 1
        assert 'Target stopped the run: stop_on_status. No further request was sent, cleanup included.' in result.output
        assert 'requests.setup=1 requests.cleanup=1' in result.output
        assert '[ ] files/sample.txt' in result.output
        assert [call[0] for call in app.calls] == ['POST', 'POST', 'DELETE']


@pytest.mark.parametrize('reason', ['request_budget', 'setup_failed_run'])
async def test_execute_startup_stop_keeps_cleanup_enabled(tmp_path, reason):
    from test_transport_lifecycle import lifecycle_dict, recording_lifecycle
    app = recording_lifecycle()
    async def failed(request):
        return web.Response(status=500)
    app.route('GET', '/startup-check', failed)
    async with serve(app) as origin:
        data = lifecycle_dict(origin, attempt=False)
        if reason == 'request_budget':
            data['budget'] = {'max_requests': 1}
        else:
            data['lifecycle']['run'].append({'id': 'check', 'request': {'method': 'GET',
                'url': origin + '/startup-check'}, 'expect': {'http_status': [200]}})
        result = await invoke(target_file(tmp_path, data), '--execute')
        assert result.exit_code == 1
        assert f'Target stopped the run: {reason}' in result.output
        assert 'Configured cleanup remained enabled.' in result.output
        assert 'No further request was sent, cleanup included.' not in result.output
        assert 'requests.submit=0 requests.poll=0 requests.retry=0 requests.setup=' in result.output
        assert 'requests.cleanup=1' in result.output
        assert app.calls[-1][:2] == ('DELETE', '/v1/sources/source-one')


def test_browser_v2_transport_rejection_precedes_sample_response_options(tmp_path):
    sample = tmp_path / "sample.json"
    sample.write_text('{}')
    result = CliRunner().invoke(main, [
        "validate-target", "--target",
        str(target_file(tmp_path, {"version": 2}, kind="browser_use")),
        "--offline", "--sample-response", str(sample),
    ])
    assert result.exit_code == 1, result.output
    assert result.output == "Error: target spec invalid: ValueError: Invalid transport fields\n"
    assert "this option supports version 1 transports only" not in result.output
