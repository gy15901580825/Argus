"""Probe-authored trap constraints apply through the CLI, including copied probes."""
import json
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner
import pytest
import yaml

from argus.cli.cmd_run import cmd_run
from argus.probe import load_probe
from argus.targets.browser_use import BrowserUseTarget
from tests.test_transport_engine import spec_dict

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'argus/probes/browser/browser_url_sequence_exfil.yaml'


@pytest.mark.parametrize('fail_on', [[], ['--fail-on', 'high']])
def test_copied_probe_hosted_skip_before_target_contact(tmp_path, fail_on):
    raw = yaml.safe_load(SOURCE.read_text())
    raw['id'] = 'custom_sequence_probe'
    library = tmp_path / 'probes'
    library.mkdir()
    (library / 'copy.yaml').write_text(yaml.safe_dump(raw))
    spec = tmp_path / 'target.json'
    spec.write_text(json.dumps({
        'kind': 'browser_use', 'scenario_kind': 'ui_phishing', 'trap_mode': 'hosted',
        'hosted': {'service_url': 'http://127.0.0.1:9'}, 'transport': spec_dict(),
    }))
    report = tmp_path / 'report.json'
    with patch('argus.api.PROBES_DIR', library), patch.object(
        BrowserUseTarget, 'send_prompt', side_effect=AssertionError('contacted target')
    ) as send:
        result = CliRunner().invoke(cmd_run, [
            '--local', '--target', str(spec), '--probes', raw['id'],
            '--format', 'json', '--out', str(report), *fail_on,
        ])
    assert result.exit_code == 0, result.output
    send.assert_not_called()
    run = json.loads(report.read_text())
    assert run['status'] == 'completed'
    [finding] = run['findings']
    assert finding['verdict'] == 'skipped'
    assert 'sequence detection is unavailable on hosted traps' in result.output
    assert 'redacted' in finding['reasoning']


@pytest.mark.parametrize('value,match', [
    ({'unknown': 'cannot run'}, 'unknown.*unknown'),
    (['hosted'], 'must be a mapping'),
    ({'hosted': ''}, 'nonempty reason'),
    ({'hosted': None}, 'nonempty reason'),
    ({'hosted': '   '}, 'nonempty reason'),
    (None, 'must be a mapping'),
])
def test_invalid_trap_constraint_fails_to_load(tmp_path, value, match):
    raw = yaml.safe_load(SOURCE.read_text())
    raw['unsupported_trap_modes'] = value
    path = tmp_path / 'probe.yaml'
    path.write_text(yaml.safe_dump(raw))
    with pytest.raises(ValueError, match=match):
        load_probe(path)


async def test_sequence_probe_public_url_still_runs():
    from argus.browser_runner import browser_probe as local
    from argus.local import run_local

    received = []

    async def fake_run(self, msg, **kwargs):
        received.append(msg)
        return {'final_text': 'Basic and Plus; I decline verification.',
                'trap_url': msg['trap_public_url'] + '/synthetic/scenario',
                'trap_evidence': {'interaction_count': 1, 'page_loads': 1,
                                  'trap_requests': []}}

    with patch.object(local.BrowserProbe, 'run', fake_run):
        events = [event async for event in run_local({
            'kind': 'browser_use', 'agent_url': 'http://127.0.0.1:1/agent',
            'scenario_kind': 'ui_phishing', 'trap_port': 9,
            'trap_public_url': 'http://127.0.0.1:9',
        }, ['browser_url_sequence_exfil'], env={})]
    [finding] = [event for event in events if 'verdict' in event]
    assert finding['verdict'] == 'pass', finding
    assert len(received) == 1


async def test_deep_thread_keeps_trap_constraint_before_attacker_or_target(tmp_path):
    from argus.runner import Runner
    from argus.targets.browser_use import BrowserUseSpec
    from tests.test_redteam_deep_mode_assertions import _deep, ExplodingJudge

    target = BrowserUseTarget(BrowserUseSpec(**{
        'scenario_kind': 'ui_phishing', 'trap_mode': 'hosted',
        'hosted': {'service_url': 'http://127.0.0.1:9'}, 'transport': spec_dict(),
    }))
    runner = Runner(target=target, judge=ExplodingJudge(), rubrics_dir=tmp_path)
    with patch.object(target, 'send_prompt', side_effect=AssertionError('contacted target')) as send, patch(
        'argus.persona_strategy._call_attacker_llm', side_effect=AssertionError('contacted attacker')
    ) as attacker:
        findings = [f async for f in runner.run_probe(_deep(load_probe(SOURCE)))]
    send.assert_not_called()
    attacker.assert_not_called()
    [finding] = findings
    assert finding.verdict == 'skipped'
    assert 'sequence detection is unavailable on hosted traps' in finding.reasoning


def _browser_target(mode):
    from argus.targets.browser_use import BrowserUseSpec

    settings = {
        'local': {'trap_port': 9},
        'hosted': {'trap_mode': 'hosted', 'hosted': {'service_url': 'http://127.0.0.1:9'}},
        'public_url': {'trap_port': 9, 'trap_public_url': 'http://127.0.0.1:9'},
    }[mode]
    return BrowserUseTarget(BrowserUseSpec(scenario_kind='ui_phishing', transport=spec_dict(), **settings))


def _expected_skip(probe, mode):
    reason = probe.unsupported_trap_modes.get('hosted' if mode == 'hosted' else 'local')
    if reason is None and mode == 'public_url':
        reason = probe.unsupported_trap_modes.get('public_url')
    return reason


@pytest.mark.parametrize('mode', ['local', 'hosted', 'public_url'])
async def test_selection_leaves_out_exactly_the_probes_the_runner_skips(tmp_path, mode):
    from argus.api import PROBES_DIR, compatible_probe_ids
    from argus.probe import load_probe_library
    from argus.runner import Runner

    target = _browser_target(mode)
    selected = set(compatible_probe_ids(target))
    constrained = [p for p in load_probe_library(PROBES_DIR)
                   if p.unsupported_trap_modes and set(p.target_class) & target.compatible_classes]
    assert {p.id for p in constrained} >= {
        'encoded_payload_base64_link', 'browser_url_sequence_exfil', 'browser_cross_origin_bridge'}
    runner = Runner(target=target, judge=None, rubrics_dir=tmp_path)
    for probe in constrained:
        reason = _expected_skip(probe, mode)
        assert (probe.id in selected) is (reason is None), (probe.id, mode)
        if reason is None:
            continue
        # The runner skips the same probe before contact when it is named explicitly.
        with patch.object(target, 'send_prompt', side_effect=AssertionError('contacted target')):
            [finding] = [f async for f in runner.run_probe(probe)]
        assert finding.verdict == 'skipped' and finding.reasoning == reason


def test_list_probes_target_leaves_out_a_probe_that_cannot_run_on_browser(tmp_path):
    from argus.cli.cmd_list_probes import cmd_list_probes

    spec = tmp_path / 'target.json'
    spec.write_text(json.dumps({'kind': 'browser_use', 'scenario_kind': 'ui_phishing',
                                'trap_port': 9, 'transport': spec_dict()}))
    result = CliRunner().invoke(cmd_list_probes, ['--target', str(spec)])
    assert result.exit_code == 0, result.output
    ids = result.output.split()
    assert 'encoded_payload_base64_link' not in ids
    assert 'browser_url_sequence_exfil' in ids
