import pytest
import yaml

from argus.probe import load_probe


def probe_data():
    return {'id': 'indirect_sample', 'name': 'Sample', 'target_class': ['http-chat'],
            'attack_class': ['prompt-injection'], 'severity': 'medium',
            'prompts': ['Original sample.'],
            'indirect': [{'task': 'Read the sample.', 'material': 'Sample document.'}]}


def write_probe(tmp_path, data):
    path = tmp_path / 'sample.yaml'
    path.write_text(yaml.safe_dump(data))
    return path


def test_indirect_length_must_match_prompts(tmp_path):
    data = probe_data()
    data['indirect'] = []
    with pytest.raises(ValueError, match=str(tmp_path)):
        load_probe(write_probe(tmp_path, data))


@pytest.mark.parametrize('mode', ['sessions', 'conversation'])
def test_indirect_with_sessions_or_conversation_is_rejected(tmp_path, mode):
    data = probe_data()
    if mode == 'sessions':
        data['sessions'] = [data.pop('prompts')]
    else:
        data['conversation'] = True
    with pytest.raises(ValueError, match=str(tmp_path)):
        load_probe(write_probe(tmp_path, data))


@pytest.mark.parametrize('item', [None, {}, {'task': 'Read'}, {'task': '', 'material': 'x'},
                                     {'task': 'Read', 'material': ' '}, {'task': 1, 'material': 'x'},
                                     {'task': 'Read', 'material': 'x', 'extra': 'x'}])
def test_indirect_items_need_nonempty_task_and_material(tmp_path, item):
    data = probe_data()
    data['indirect'] = [item]
    with pytest.raises(ValueError, match=str(tmp_path)):
        load_probe(write_probe(tmp_path, data))


def test_probe_without_indirect_loads_unchanged(tmp_path):
    data = probe_data()
    data.pop('indirect')
    probe = load_probe(write_probe(tmp_path, data))
    assert probe.indirect == ()
    assert probe.prompts == ('Original sample.',)
