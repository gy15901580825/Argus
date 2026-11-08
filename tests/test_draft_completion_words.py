import json

import pytest

from argus.drafting.draft import choose_without_model, compile_draft
from test_draft_async import async_document, catalog_for, poll_schema, scenario
from test_draft_verify_local import verify


@pytest.mark.parametrize('word', ['executing', 'stopping', 'awaiting_guidance'])
async def test_documented_progress_word_keeps_polling(tmp_path, word):
    doc = async_document(result={'type': 'string'})
    poll_schema(doc)['properties']['status']['enum'].append(word)
    catalog = catalog_for(tmp_path, doc)
    spec = compile_draft(catalog, choose_without_model(catalog)).spec
    raw = json.loads(scenario(tmp_path).read_text())
    raw['operations'][1]['replies'][0]['body']['status'] = word
    result = await verify(spec, raw)
    assert result.as_dict()['execution']['outcome'] == 'succeeded', result.as_dict()
    assert result.as_dict()['execution']['requests']['poll'] == 2
    assert not any(g.code == 'poll_status_unclassified' and word in g.why for g in compile_draft(catalog, choose_without_model(catalog)).gaps)


async def test_documented_stopped_is_a_failure_rule(tmp_path):
    doc = async_document(result={'type': 'string'})
    poll_schema(doc)['properties']['status']['enum'].append('stopped')
    catalog = catalog_for(tmp_path, doc)
    artifact = compile_draft(catalog, choose_without_model(catalog))
    assert not any(g.code == 'poll_status_unclassified' and 'stopped' in g.why for g in artifact.gaps)
    raw = json.loads(scenario(tmp_path).read_text())
    raw['operations'][1]['calls'] = {'min': 1, 'max': 1}
    raw['operations'][1]['replies'] = [{'status': 200, 'body': {'status': 'stopped'}, 'effects': []}]
    raw['expect'].update(outcome='target_error', reply=None)
    result = await verify(artifact.spec, raw)
    assert result.as_dict()['execution']['outcome'] == 'target_error', result.as_dict()
