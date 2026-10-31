import pytest
from argus import assertions
from argus.runner import Runner
from tests.test_redteam_runner_assertions import _Target, _ExplodingJudge, _probe


def test_outcome_checks_map_to_assertion_results(monkeypatch):
    monkeypatch.setitem(assertions._OUTCOME_CHECKS, 't_outcome', lambda v, e: (v, f'said {v}'))
    got = {v: assertions.evaluate_assertions(({'t_outcome': v},), {}, '')[0] for v in ('pass', 'fail', 'warn', 'skipped', 'error')}
    assert (got['pass'].passed, got['pass'].verdict, got['pass'].error) == (True, None, False)
    assert (got['fail'].passed, got['fail'].verdict, got['fail'].error) == (False, None, False)
    assert (got['warn'].passed, got['warn'].verdict, got['warn'].error) == (False, 'warn', False)
    assert (got['skipped'].passed, got['skipped'].verdict, got['skipped'].error) == (False, 'skipped', False)
    assert got['error'].error and not got['error'].passed


def test_unknown_outcome_is_an_error(monkeypatch):
    monkeypatch.setitem(assertions._OUTCOME_CHECKS, 't_outcome', lambda v, e: ('maybe', 'x'))
    assert assertions.evaluate_assertions(({'t_outcome': True},), {}, '')[0].error


async def _run_outcomes(monkeypatch, tmp_path, values):
    monkeypatch.setitem(assertions._OUTCOME_CHECKS, 't_outcome', lambda v, e: (v, f'said {v}'))
    evidence = {'interaction_count': 1}
    runner = Runner(target=_Target(evidence), judge=_ExplodingJudge(), rubrics_dir=tmp_path)
    findings = [f async for f in runner.run_probe(_probe(assertions=tuple({'t_outcome': v} for v in values)))]
    assert len(findings) == 1 and findings[0].evidence == evidence
    return findings[0]


async def test_warn_outcome_yields_warn_with_probe_severity(monkeypatch, tmp_path):
    finding = await _run_outcomes(monkeypatch, tmp_path, ['warn'])
    assert (finding.verdict, finding.severity) == ('warn', 'critical')


async def test_all_skipped_outcomes_yield_skipped(monkeypatch, tmp_path):
    finding = await _run_outcomes(monkeypatch, tmp_path, ['skipped', 'skipped'])
    assert (finding.verdict, finding.severity) == ('skipped', 'info')


async def test_skipped_plus_pass_yields_pass(monkeypatch, tmp_path):
    finding = await _run_outcomes(monkeypatch, tmp_path, ['skipped', 'pass'])
    assert (finding.verdict, finding.severity) == ('pass', 'info')


@pytest.mark.parametrize('values,want,severity', [(['fail', 'warn'], 'fail', 'critical'), (['error', 'fail'], 'error', 'info')])
async def test_fail_beats_warn_and_error_beats_fail(monkeypatch, tmp_path, values, want, severity):
    finding = await _run_outcomes(monkeypatch, tmp_path, values)
    assert (finding.verdict, finding.severity) == (want, severity)


async def test_zero_interaction_still_errors_before_outcomes(monkeypatch, tmp_path):
    monkeypatch.setitem(assertions._OUTCOME_CHECKS, 't_outcome', lambda v, e: ('skipped', 'not available'))
    runner = Runner(target=_Target({'interaction_count': 0}), judge=_ExplodingJudge(), rubrics_dir=tmp_path)
    findings = [f async for f in runner.run_probe(_probe(assertions=({'t_outcome': True},)))]
    assert findings[0].verdict == 'error'
