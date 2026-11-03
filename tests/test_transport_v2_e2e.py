import json
from dataclasses import replace
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from click.testing import CliRunner

from argus import api, local
from argus.cli.__main__ import main
from argus.probe import IndirectItem, load_probe_library
from argus_transport.spec_v2 import with_origin
from test_runner_material import StubJudge
from transport_v2_fakes import VendorAThreadsFake, VendorBAutomationFake, serve_in_thread


FIXTURES = Path(__file__).parent / 'fixtures' / 'transport_v2'


@pytest.fixture
def scenes(monkeypatch):
    base = load_probe_library(api.PROBES_DIR)[0]
    probes = [replace(
        base, id=f'neutral_scene_{index}', name=f'Neutral scene {index}',
        target_class=('llm_chat',), prompts=(f'Original neutral sample {index}.',),
        indirect=(IndirectItem(f'Read sample {index}.', material),),
        assertions=(), conversation=False, sessions=(),
        requires_interaction=False,
    ) for index, material in enumerate([
        'Sample invoice one.', 'Sample invoice two.\nTotal 20.',
        'Sample invoice three, café.', 'Sample invoice four.',
    ])]
    probes.append(replace(probes[0], id='neutral_plain', indirect=(),
                          prompts=('Read the neutral sample.',)))
    monkeypatch.setattr(api, 'load_probe_library', lambda *_: probes)
    monkeypatch.setattr(local, 'load_probe_library', lambda *_: probes)
    monkeypatch.setattr(api, 'Judge', lambda **_: StubJudge())
    monkeypatch.setenv('ANTHROPIC_API_KEY', 'dummy-not-a-key')
    monkeypatch.setenv('VENDOR_A_API_KEY', 'dummy-not-a-key')
    monkeypatch.setenv('VENDOR_B_PAT', 'dummy-not-a-key')
    monkeypatch.setenv('VENDOR_B_AUTOMATION_NAME', 'Neutral invoice reader')
    monkeypatch.delenv('VENDOR_B_AUTOMATION_ID', raising=False)
    return probes


def run_config(tmp_path, app, fixture, probes, *, no_undo=False, reserve=None):
    path = FIXTURES / (fixture + '.json')
    assert path.is_file(), 'Complete neutral transport configuration is missing'
    data = json.loads(path.read_text())
    with serve_in_thread(app) as origin:
        data['transport'] = with_origin(data['transport'], origin)
        if no_undo:
            data['transport']['lifecycle']['attempt'][0].pop('undo')
        if reserve is not None:
            data['transport']['budget']['cleanup_reserve'] = reserve
        target = tmp_path / 'target.json'
        target.write_text(json.dumps(data))
        out = tmp_path / 'run.json'
        result = CliRunner().invoke(main, [
            'run', '--local', '--target', str(target), '--probes',
            ','.join(probe.id for probe in probes), '--format', 'json', '--out', str(out),
        ])
        assert out.is_file(), result.output
        return result, json.loads(out.read_text())


def wire(app):
    return [(method, urlsplit(path).path) for method, path, _, _ in app.calls]


def test_vendor_a_config_runs_four_scenes_without_adapter_code(tmp_path, scenes):
    app = VendorAThreadsFake()
    probes = scenes[:3] + scenes[-1:]
    result, record = run_config(tmp_path, app, 'vendor_a_threads', probes)
    assert result.exit_code == 0, result.output
    assert [item['verdict'] for item in record['findings']] == ['pass'] * 4
    assert record['target_cleanup']['complete'] is True
    assert record['target_cleanup']['done'] == 4
    assert app.sources == app.messages == app.runs == {}
    calls = wire(app)
    assert calls[0] == ('POST', '/v1/sources')
    assert calls[-1] == ('DELETE', '/v1/sources/source-1')
    ingests = [json.loads(body) for method, path, _, body in app.calls
               if (method, path) == ('POST', '/v1/messages')]
    assert [item['body'] for item in ingests] == [probe.indirect[0].material for probe in probes[:3]]
    for index, item in enumerate(ingests):
        poll = f"/v1/ask/{item['threadId']}/run-{index + 1}"
        assert calls[1 + index * 5:6 + index * 5] == [
            ('POST', '/v1/messages'), ('POST', '/v1/ask'),
            ('GET', poll), ('GET', poll), ('DELETE', '/v1/messages'),
        ]
    assert calls[16:-1] == [('POST', '/v1/ask'), ('GET', '/v1/ask/thread-plain/run-4'),
                           ('GET', '/v1/ask/thread-plain/run-4')]
    for item, call in zip(ingests, [call for call in app.calls if call[0] == 'DELETE' and call[1].startswith('/v1/messages?')]):
        assert parse_qs(urlsplit(call[1]).query) == {'remoteId': [item['id']], 'sourceId': ['source-1']}
    asks = [json.loads(body)['message'] for method, path, _, body in app.calls
            if (method, path) == ('POST', '/v1/ask')]
    assert asks == [probe.indirect[0].task for probe in probes[:3]] + [probes[-1].prompts[0]]


def test_vendor_b_single_config_serves_all_scenes(tmp_path, scenes):
    app = VendorBAutomationFake()
    result, record = run_config(tmp_path, app, 'vendor_b_automation', scenes)
    assert result.exit_code == 0, result.output
    assert [item['verdict'] for item in record['findings']] == ['pass'] * 4 + ['skipped']
    assert 'target requires material; probe has no indirect field' in record['findings'][-1]['reasoning']
    assert record['target_cleanup'] == {'complete': True, 'done': 4, 'open': [], 'stop_reason': None, 'leftover': []}
    assert app.files == app.runs == {}
    assert len(app.calls) == 23
    assert wire(app)[:3] == [('GET', path) for path in app.find_paths]
    assert [path for method, path in wire(app) if method == 'GET' and path in app.find_paths] == app.find_paths
    assert len(app.uploads) == len(app.invocations) == 4
    assert [item['content'] for item in app.uploads] == [probe.indirect[0].material.encode() for probe in scenes[:4]]
    assert [item['inputs']['user_question']['text'] for item in app.invocations] == [probe.indirect[0].task for probe in scenes[:4]]
    for index, (upload, invocation) in enumerate(zip(app.uploads, app.invocations)):
        assert upload['filename'] == 'invoice.txt'
        assert upload['content_type'] == 'text/plain'
        assert invocation['inputs']['invoice_file'] == {'file': {'remote': upload['name']}}
        suffix = upload['name'].rsplit('/', 1)[1]
        assert '--' in suffix and '.' in suffix
        raw_run = app.run_names[index]
        assert len(raw_run) > 120
        run_suffix = raw_run.rsplit('/', 1)[1]
        assert wire(app)[3 + index * 5:8 + index * 5] == [
            ('POST', app.files_path + ':upload'), ('POST', app.automation_path + ':invoke'),
            ('GET', app.automation_path + '/runs/' + run_suffix),
            ('GET', app.automation_path + '/runs/' + run_suffix),
            ('DELETE', app.files_path + '/' + suffix),
        ]
    assert all('%2F' not in path.upper() for _, path, _, _ in app.calls)


def test_vendor_b_without_material_skips_every_request(tmp_path, scenes):
    app = VendorBAutomationFake()
    result, record = run_config(tmp_path, app, 'vendor_b_automation', scenes[-1:])
    assert result.exit_code == 0, result.output
    assert [item['verdict'] for item in record['findings']] == ['skipped']
    assert app.calls == []


def test_vendor_b_given_id_skips_list_lookup(tmp_path, scenes, monkeypatch):
    app = VendorBAutomationFake(automation_count=0)
    monkeypatch.setenv('VENDOR_B_AUTOMATION_ID', app.automation_id)
    result, record = run_config(tmp_path, app, 'vendor_b_automation', scenes[:1])
    assert result.exit_code == 0, result.output
    assert record['findings'][0]['verdict'] == 'pass'
    assert wire(app)[:2] == [('GET', path) for path in app.find_paths[:2]]
    assert ('GET', app.find_paths[-1]) not in wire(app)
    assert len(app.uploads) == 1
    assert app.files == {}


def test_vendor_b_not_provisioned_prints_checklist_and_exits_1(tmp_path, scenes):
    app = VendorBAutomationFake(automation_count=0)
    result, record = run_config(tmp_path, app, 'vendor_b_automation', scenes)
    assert result.exit_code == 1, result.output
    assert record['status'] == 'incomplete'
    assert record['findings'] == []
    assert "NOT PROVISIONED: find step 'automation' matched no item (0 business requests sent)" in result.stderr
    assert 'Hint: The automations list omits drafts that were never built.' in result.stderr
    assert '[ ] Build the automation at least once.' in result.stderr
    assert '[ ] Exactly one item in $.automations' in result.stderr
    assert wire(app) == [('GET', path) for path in app.find_paths]


@pytest.mark.parametrize('delete_mode,reserve,done', [('gone', 2, True), ('present', 2, False), ('gone', 1, False)])
def test_vendor_b_unexpected_delete_uses_confirmation_without_retry(tmp_path, scenes, delete_mode, reserve, done):
    app = VendorBAutomationFake(delete_mode=delete_mode)
    result, record = run_config(tmp_path, app, 'vendor_b_automation', scenes[:1], reserve=reserve)
    assert result.exit_code == (0 if done else 1), result.output
    assert record['status'] == ('completed' if done else 'incomplete')
    report = record['target_cleanup']
    assert report['complete'] is done
    assert report['done'] == int(done)
    assert report['leftover'] == ([] if done else [app.uploads[0]['name']])
    assert [item['status'] for item in report['open']] == ([] if done else ['unconfirmed'])
    if not done:
        assert report['open'][0]['http_status'] == 500
        assert app.uploads[0]['name'] in result.stderr
    assert len([call for call in app.calls if call[0] == 'DELETE']) == 1
    metadata_calls = [call for call in app.calls if urlsplit(call[1]).path.endswith('/metadata')]
    assert len(metadata_calls) == (1 if reserve == 2 else 0)
    assert len([call for call in app.calls if call[0] == 'DELETE']) + len(metadata_calls) == reserve
    assert len(app.files) == (1 if delete_mode == 'present' else 0)
    cleanup = record['findings'][0]['evidence']['transport']['cleanup']
    assert cleanup['done'] == int(done)
    assert record['findings'][0]['verdict'] == 'pass'


def test_vendor_b_no_undo_resource_is_informational(tmp_path, scenes):
    app = VendorBAutomationFake()
    result, record = run_config(tmp_path, app, 'vendor_b_automation', scenes[:1], no_undo=True)
    assert result.exit_code == 0, result.output
    assert record['status'] == 'completed'
    assert record['target_cleanup']['complete'] is True
    assert record['target_cleanup']['open'] == []
    assert record['target_cleanup']['leftover'] == [app.uploads[0]['name']]
    assert len(app.files) == 1
    assert 'Target resources left on the target: 1 item(s).' in result.stderr
    assert all(call[0] != 'DELETE' for call in app.calls)


def test_vendor_a_fake_rejects_duplicate_source_and_delete_with_messages():
    app = VendorAThreadsFake()
    with serve_in_thread(app) as origin, httpx.Client(base_url=origin) as client:
        assert client.post('/v1/sources', json={'name': 'neutral-source'}).status_code == 201
        assert client.post('/v1/sources', json={'name': 'neutral-source'}).status_code == 409
        assert client.post('/v1/messages', json={'id': 'ref-1', 'threadId': 'ref-1', 'sourceId': 'source-1', 'body': 'Sample.'}).status_code == 201
        assert client.delete('/v1/sources/source-1').status_code == 409
        assert client.delete('/v1/messages', params={'remoteId': 'ref-1', 'sourceId': 'source-1'}).status_code == 200
        assert client.delete('/v1/sources/source-1').status_code == 200
        assert app.sources == app.messages == {}


def test_vendor_b_fake_metadata_and_repeated_delete_contract():
    app = VendorBAutomationFake()
    with serve_in_thread(app) as origin, httpx.Client(base_url=origin) as client:
        response = client.post(app.files_path + ':upload', files={'file': ('invoice.txt', b'Sample.', 'text/plain')})
        assert response.status_code == 201
        name = response.json()['metadata']['name']
        assert response.headers['Location'] == name
        path = app.files_path + '/' + name.rsplit('/', 1)[1]
        metadata = client.get(path + '/metadata')
        assert metadata.status_code == 200
        assert metadata.json()['mime_type'] == 'text/plain'
        assert metadata.json()['size_bytes'] == 7
        assert 'mimeType' not in metadata.json()
        deleted = client.delete(path)
        assert deleted.status_code == 200 and deleted.json() == {}
        repeated = client.delete(path)
        assert repeated.status_code == 500 and repeated.content == b''
        assert client.get(path + '/metadata').status_code == 404
        assert app.files == {}
