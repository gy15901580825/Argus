from copy import deepcopy

import pytest
import yaml

from argus.probe import load_probe
from test_agentic_mapping_data import ROOT, mapper
from test_probe_indirect import B_CLASS_IDS
import test_probe_content_urls as content_urls


@pytest.mark.parametrize('probe_id', sorted(B_CLASS_IDS))
@pytest.mark.parametrize('field', ['task', 'material'])
def test_indirect_evidence_changes_require_mapping_review(tmp_path, probe_id, field):
    module = mapper()
    source = next(path for path in module.probe_files(ROOT) if path.stem == probe_id)
    data = yaml.safe_load(source.read_text())
    original = deepcopy(data)
    path = tmp_path / 'argus' / 'probes' / source.name
    path.parent.mkdir(parents=True)
    path.write_text(source.read_text())
    reviewed = module.check(tmp_path) == []
    assert reviewed, f'{probe_id} unchanged evidence must be approved'

    item = data['indirect'][0]
    if field == 'task':
        item[field] = 'Describe the provided source.'
    else:
        item[field] = item[field][1:]
        valid_substring = bool(item[field].strip()) and item[field] in data['prompts'][0]
        strict_substring = len(item[field]) < len(data['prompts'][0])
        assert valid_substring and strict_substring, f'{probe_id} material mutation must remain valid'
    changed = item[field] != original['indirect'][0][field]
    preserved = {key: value for key, value in data.items() if key != 'indirect'} == {
        key: value for key, value in original.items() if key != 'indirect'
    }
    assert changed and preserved, f'{probe_id} must change only indirect evidence'
    path.write_text(yaml.safe_dump(data, allow_unicode=True))
    loaded = load_probe(path)
    accepted = bool(loaded.indirect)
    assert accepted, f'{probe_id} changed evidence must remain a valid probe'
    rejected = any('evidence changed' in issue for issue in module.check(tmp_path))
    assert rejected, f'{probe_id} {field} changes must require mapping review'


def test_repo_asset_paths_are_stable_unique_and_keep_distinct_paths():
    prefix = 'https://raw.githubusercontent.com/gy15901580825/Argus/main/'
    text = f'{prefix}probe-content/first.md. {prefix}probe-content/second.md; {prefix}probe-content/first.md'
    assert content_urls._raw_paths(text) == ['probe-content/first.md', 'probe-content/second.md']


def test_ambient_asset_guard_rejects_a_distinct_reference(tmp_path, monkeypatch):
    prefix = 'https://raw.githubusercontent.com/gy15901580825/Argus/main/'
    path = tmp_path / 'ambient_persuasion_url_fetch.yaml'
    path.write_text(f'{prefix}probe-content/ambient-persuasion.md\n{prefix}probe-content/other.md\n')
    monkeypatch.setattr(content_urls, 'PROBES_DIR', tmp_path)
    with pytest.raises(AssertionError):
        content_urls.test_ambient_persuasion_url_fetch_points_at_repo_hosted_content()


def test_repo_asset_guard_rejects_missing_distinct_reference(tmp_path, monkeypatch):
    prefix = 'https://raw.githubusercontent.com/gy15901580825/Argus/main/'
    probes = tmp_path / 'argus' / 'probes'
    probes.mkdir(parents=True)
    assets = tmp_path / 'probe-content'
    assets.mkdir()
    (assets / 'present.md').write_text('Available source.')
    (probes / 'sample.yaml').write_text(
        f'{prefix}probe-content/present.md\n{prefix}probe-content/present.md\n'
        f'{prefix}probe-content/missing.md\n'
    )
    monkeypatch.setattr(content_urls, 'REPO_ROOT', tmp_path)
    monkeypatch.setattr(content_urls, 'PROBES_DIR', probes)
    with pytest.raises(AssertionError, match='missing.md'):
        content_urls.test_every_repo_hosted_probe_url_names_a_committed_file()
