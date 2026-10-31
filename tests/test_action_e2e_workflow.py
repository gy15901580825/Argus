import json
from pathlib import Path
import yaml

ROOT = Path(__file__).parents[1]

def workflow():
    return yaml.safe_load((ROOT / '.github/workflows/action-e2e.yml').read_text())

def action(job):
    return next(s for s in job['steps'] if s.get('uses') == './.argus-probe-action')

def test_released_target_json_has_no_new_fields():
    assert set(json.loads((ROOT / '.github/argus-e2e/mcp-target.json').read_text())) == {'kind', 'testbed_url', 'sandbox', 'inner'}

def test_source_target_json_carries_token_placeholder():
    old = json.loads((ROOT / '.github/argus-e2e/mcp-target.json').read_text())
    new = json.loads((ROOT / '.github/argus-e2e/mcp-target-source.json').read_text())
    assert new.pop('control_token') == '${ARGUS_TESTBED_TOKEN}'
    assert new == old

def test_released_client_job_resolves_version_from_selected_action():
    job = workflow()['jobs']['released-client']
    version = next(s for s in job['steps'] if s.get('id') == 'version')
    assert '.argus-probe-action/action.yml' in version['run']
    assert 'argus-version' in version['run']
    assert 'git ls-remote --exit-code --tags' in version['run']
    assert action(job)['with']['argus-version'] == '${{ steps.version.outputs.version }}'
    fixture = next(s for s in job['steps'] if s.get('with', {}).get('path') == '.release-fixture')
    assert fixture['with']['ref'] == 'v${{ steps.version.outputs.version }}'
    setup = next(s for s in job['steps'] if s.get('id') == 'fixture')
    assert 'mcp-target-source.json' in setup['run'] and 'mcp-target.json' in setup['run']
    assert action(job)['with']['target'] == '${{ steps.fixture.outputs.target }}'

def test_pr_source_job_installs_pr_source():
    job = workflow()['jobs']['pr-source']
    assert action(job)['with']['install-spec'] == '.[local]'
    assert action(job)['with']['target'] == '.github/argus-e2e/mcp-target-source.json'

def test_both_jobs_keep_the_gate_checks():
    for job in workflow()['jobs'].values():
        check = next(s for s in job['steps'] if s.get('name') == 'Expect the gate to trip')['run']
        assert 'test "$EXIT_CODE" = "3"' in check
        assert 'test "$OUTCOME" = "failure"' in check
        assert '== 12' in check
        assert action(job)['with']['fail-on'] == 'high'
        assert action(job)['with']['upload-sarif'] == 'false'
        assert action(job)['continue-on-error'] is True

def test_workflow_triggers_on_source_changes():
    doc = workflow()
    paths = doc.get('on', doc.get(True))['pull_request']['paths']
    assert 'argus/**' in paths and 'pyproject.toml' in paths
