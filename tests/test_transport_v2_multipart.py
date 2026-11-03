import json

import pytest
from aiohttp import web

from argus_transport.spec_v2 import TransportSpecV2
from test_transport_v2_engine import completed, runtime, v2_dict
from transport_v2_fakes import RecordingApp, serve


def multipart_data(origin, filename='sample.txt', content='Sample é document.'):
    data = v2_dict(origin + '/run')
    data['request']['body'] = {'multipart': {'file': {
        'filename': {'literal': filename}, 'content_type': 'text/plain',
        'content': {'literal': content}}}}
    return data


@pytest.mark.parametrize('method', ['POST', 'PUT'])
async def test_multipart_wire_framing_uses_actual_boundary(method):
    from argus_transport.spec_v2 import TransportContextV2
    app = RecordingApp()
    app.route(method, '/run', completed)
    async with serve(app) as origin:
        data = multipart_data(origin)
        data['request']['method'] = method
        result = await runtime(data).attempt(TransportContextV2(prompt='Read the sample.'))
        assert result.response_text == 'done'
        _, _, headers, body = app.calls[0]
        boundary = headers['Content-Type'].split('boundary=')[1].encode('ascii')
        assert body == (b'--' + boundary + b'\r\nContent-Disposition: form-data; name="file"; filename="sample.txt"\r\n'
                        b'Content-Type: text/plain\r\n\r\n' + 'Sample é document.'.encode() + b'\r\n--' + boundary + b'--\r\n')


@pytest.mark.parametrize('filename,content', [('', 'x'), ('a\r.txt', 'x'), ('a\n.txt', 'x'),
    ('a\0.txt', 'x'), ('a".txt', 'x'), (2, 'x'), ('sample.txt', 2), ('sample.txt', 'é' * 524289)], ids=['empty', 'cr', 'lf', 'nul', 'quote', 'filename-type', 'content-type', 'byte-overflow'])
async def test_multipart_invalid_values_emit_no_request(filename, content):
    from argus_transport.spec_v2 import TransportContextV2
    app = RecordingApp()
    app.route('POST', '/run', completed)
    async with serve(app) as origin:
        result = await runtime(multipart_data(origin, filename, content)).attempt(TransportContextV2(prompt='Read'))
        assert result.reason_code.value == 'binding_error'
        assert app.calls == []


async def test_multipart_content_byte_limit_inclusive():
    from argus_transport.spec_v2 import TransportContextV2
    app = RecordingApp()
    app.app._client_max_size = 2 * 1048576
    app.route('POST', '/run', completed)
    async with serve(app) as origin:
        result = await runtime(multipart_data(origin, content='é' * 524288)).attempt(TransportContextV2(prompt='Read'))
        assert result.response_text == 'done'
        assert len(app.calls) == 1


@pytest.mark.parametrize('expression,want', [({'context': 'material'}, 'required'),
    ({'context': 'material', 'missing': 'omit'}, 'optional'),
    ({'base64': {'context': 'material', 'missing': 'omit'}}, 'optional'),
    ({'concat': [{'literal': 'x'}, {'context': 'material', 'missing': 'omit'}]}, 'optional'),
    ({'object': {'doc': {'context': 'material', 'missing': 'omit'}}}, 'optional')])
def test_material_binding_matches_nested_omission(expression, want):
    from argus_transport.spec_v2 import material_binding
    data = v2_dict('http://127.0.0.1:1/run')
    data['request']['body'] = {'json': {'doc': expression}}
    assert material_binding(TransportSpecV2.from_dict(data)) == want


async def test_nested_omission_skips_base64_and_concat_without_material():
    from argus_transport.spec_v2 import TransportContextV2
    app = RecordingApp()
    app.route('POST', '/run', completed)
    async with serve(app) as origin:
        data = v2_dict(origin + '/run')
        data['request']['body'] = {'json': {
            'encoded': {'base64': {'context': 'material', 'missing': 'omit'}},
            'joined': {'concat': [{'literal': 'x'}, {'context': 'material', 'missing': 'omit'}]}}}
        assert (await runtime(data).attempt(TransportContextV2(prompt='Read'))).response_text == 'done'
        assert json.loads(app.calls[0][3]) == {}


@pytest.mark.parametrize('location', ['query', 'multipart', 'guard', 'confirm'])
def test_material_binding_visits_every_request_owner(location):
    from argus_transport.spec_v2 import material_binding
    data = v2_dict('http://127.0.0.1:1/run')
    if location == 'query':
        data['request']['query'] = {'doc': {'context': 'material'}}
        want = 'required'
    elif location == 'multipart':
        data['request']['body'] = {'multipart': {'file': {'filename': {'literal': 'sample.txt'},
            'content_type': 'text/plain', 'content': {'context': 'material', 'missing': 'omit'}}}}
        want = 'optional'
    else:
        step = {'id': 'sample_step', 'request': {'url': 'http://127.0.0.1:1/setup', 'body': {'json': {}}},
                'expect': {'http_status': [200]}}
        if location == 'guard':
            step['if_present'] = 'material'
            step['request']['body']['json']['doc'] = {'context': 'material'}
            want = 'optional'
        else:
            step['undo'] = {'request': {'method': 'DELETE', 'url': 'http://127.0.0.1:1/item'},
                'expect': {'http_status': [204]}, 'confirm': {'request': {'method': 'GET',
                'url': 'http://127.0.0.1:1/item', 'query': {'doc': {'context': 'material'}}}, 'gone_status': [404]}}
            want = 'required'
        data['lifecycle'] = {'attempt': [step]}
    assert material_binding(TransportSpecV2.from_dict(data)) == want


async def test_omitted_material_skips_multipart_part_and_query():
    from argus_transport.spec_v2 import TransportContextV2
    app = RecordingApp()
    app.route('POST', '/run', completed)
    async with serve(app) as origin:
        data = multipart_data(origin)
        data['request']['query'] = {'doc': {'base64': {'context': 'material', 'missing': 'omit'}}}
        data['request']['body']['multipart']['file']['content'] = {'context': 'material', 'missing': 'omit'}
        assert (await runtime(data).attempt(TransportContextV2(prompt='Read'))).response_text == 'done'
        assert app.calls[0][1] == '/run'
        assert b'Content-Disposition' not in app.calls[0][3]


async def test_multipart_material_content_is_utf8_and_never_a_file_reference(tmp_path):
    from argus_transport.spec_v2 import TransportContextV2
    sample = tmp_path / 'sample.txt'
    sample.write_text('Local file content.')
    app = RecordingApp()
    app.route('POST', '/run', completed)
    async with serve(app) as origin:
        data = multipart_data(origin)
        part = data['request']['body']['multipart']['file']
        part['content'] = {'context': 'material'}
        for material in ('Sample é document.', str(sample)):
            result = await runtime(data).attempt(TransportContextV2(prompt='Read', material=material))
            assert result.response_text == 'done'
            assert material.encode('utf-8') in app.calls[-1][3]
            assert b'Local file content.' not in app.calls[-1][3]
