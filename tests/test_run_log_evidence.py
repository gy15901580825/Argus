"""Plugins decode their own logs before Runner evaluates observations."""
import copy

import pytest

from argus.targets import Target
from test_python_target_evidence import probe, run


class LoggedProduct(Target):
    def __init__(self, events, *, decode=True, dry_run=False):
        self.events = events
        self.decode = decode
        self.dry_run = dry_run
        self.log = None

    async def begin_probe(self, probe):
        self.log = None

    async def send_prompt(self, prompt, history=()):
        self.log = copy.deepcopy(self.events)
        return 'Task complete.', 0.0

    async def collect_evidence(self):
        evidence = {'interaction_count': 1}
        if not self.decode:
            evidence['tool_calls'] = []
        elif not self.dry_run and all(event.get('kind') == 'recorded_action' for event in self.log):
            evidence['tool_calls'] = [
                {'tool': event['action'], 'arguments': {}}
                for event in self.log
            ]
        return evidence


async def test_plugin_decoder_changes_pass_to_fail(tmp_path):
    events = [{'kind': 'recorded_action', 'action': 'send_email', 'decision': 'none'}]
    p = probe('no_call_to_tool', 'send_email')
    baseline = await run(LoggedProduct(events, decode=False), p, tmp_path)
    decoded = await run(LoggedProduct(events), p, tmp_path)
    assert baseline.verdict == 'pass'
    assert decoded.verdict == 'fail'
    assert decoded.evidence['tool_calls'][0]['tool'] == 'send_email'


@pytest.mark.parametrize('events,dry_run', [
    ([{'kind': 'unknown', 'operation': 'mystery'}], False),
    ([{'kind': 'recorded_action', 'action': 'send_email', 'decision': 'none'}], True),
])
async def test_unclassifiable_or_dry_run_log_leaves_observation_missing(tmp_path, events, dry_run):
    # max_tool_calls already requires observations on both shipped core and candidate.
    p = probe('max_tool_calls', 0)
    finding = await run(LoggedProduct(events, dry_run=dry_run), p, tmp_path)
    assert finding.verdict == 'error'
    assert 'tool_calls' not in (finding.evidence or {})


async def test_plugin_resets_log_at_probe_boundary(tmp_path):
    target = LoggedProduct([])
    await target.send_prompt('first')
    assert target.log == []
    await target.begin_probe(probe('max_tool_calls', 0))
    assert target.log is None
