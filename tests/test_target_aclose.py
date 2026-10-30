"""_run_probes releases the target exactly once, however the run ends."""

from dataclasses import replace
from unittest.mock import patch

import pytest

from argus import api
from argus.cost_meter import CostExceededError
from argus.probe import load_probe_library
from argus.runner import skipped_finding
from argus.targets._base import Target

PROBE_IDS = [p.id for p in load_probe_library(api.PROBES_DIR)[:2]]


class _ClosingTarget(Target):
    def __init__(self):
        self.closed = 0

    async def send_prompt(self, prompt, history=()):
        return "ok", 1.0

    async def aclose(self):
        self.closed += 1


def _runner(raise_exc=None):
    """A Runner stand-in: one pass finding per probe, or `raise_exc` from the first."""

    class _Runner:
        def __init__(self, **kw):
            pass

        async def run_probe(self, probe):
            if raise_exc is not None:
                raise raise_exc
            yield replace(skipped_finding(probe, "ok"), verdict="pass")

    return _Runner


async def _drive(runner, consume, target=None):
    target = target or _ClosingTarget()
    req = api.RunRequest(target={"kind": "openai_compat"}, probe_ids=PROBE_IDS)
    with patch("argus.api.build_target", lambda spec: target), patch("argus.api.Runner", runner):
        await consume(api._run_probes(req, "k"))
    return target


async def test_base_target_aclose_is_a_no_op():
    class _Plain(Target):
        async def send_prompt(self, prompt, history=()):
            return "ok", 1.0

    assert await _Plain().aclose() is None


async def test_closed_once_after_a_normal_run():
    async def consume(gen):
        assert len([e async for e in gen]) == len(PROBE_IDS)

    assert (await _drive(_runner(), consume)).closed == 1


async def test_closed_once_when_the_consumer_stops_early():
    async def consume(gen):
        await gen.__anext__()
        await gen.aclose()

    assert (await _drive(_runner(), consume)).closed == 1


async def test_closed_once_when_a_probe_raises():
    async def consume(gen):
        with pytest.raises(RuntimeError, match="boom"):
            async for _ in gen:
                pass

    assert (await _drive(_runner(RuntimeError("boom")), consume)).closed == 1


async def test_closed_once_when_the_cost_cap_is_re_raised():
    async def consume(gen):
        with pytest.raises(CostExceededError):
            async for _ in gen:
                pass

    assert (await _drive(_runner(CostExceededError("cap")), consume)).closed == 1


async def test_a_duck_typed_target_without_aclose_still_completes():
    # Plugin targets need not subclass Target, so they may have no aclose at all.
    class _Duck:
        compatible_classes = frozenset()
        supports_history = False

        async def send_prompt(self, prompt, history=()):
            return "ok", 1.0

    async def consume(gen):
        assert len([e async for e in gen]) == len(PROBE_IDS)

    await _drive(_runner(), consume, target=_Duck())
