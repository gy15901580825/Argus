"""Pins the POST /redteam/run stream to docs/reference/run-stream.md.

Every frame the real endpoint emits must match an entry in the doc's machine-readable frame list,
so a new frame type, event name or field cannot ship undocumented.
"""
import json
import re
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI

from argus import api, cost_meter, llm
from argus.cost_meter import CostMeter
from argus.probe import Probe, ProbeMappings

DOC = Path(__file__).resolve().parents[1] / "docs" / "reference" / "run-stream.md"
DOC_NAME = "docs/reference/run-stream.md"
ATTACKER = "You are a red-team attacker"
CLEANUP = {"complete": True, "done": 1, "open": [], "stop_reason": None, "leftover": []}
BLOCK = {"provider": "azure", "model": "test-model", "categories": ["jailbreak"], "fallback": None}


def load_contract() -> dict:
    text = DOC.read_text()
    section = text.split("## Machine-readable frame list", 1)[1]
    block = re.search(r"```json\n(.*?)\n```", section, re.S).group(1)
    return json.loads(block)


CONTRACT = load_contract()

_TYPES = {
    "string": lambda v: isinstance(v, str),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    "boolean": lambda v: isinstance(v, bool),
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
    "null": lambda v: v is None,
}


class ContractViolation(AssertionError):
    pass


def _fail(where: str, message: str):
    raise ContractViolation(f"{where}: {message}. Update {DOC_NAME} (frame tables and machine-readable frame list).")


def _resolve(spec):
    if isinstance(spec, str) and spec.startswith("$"):
        return CONTRACT["shared"][spec[1:]]
    return spec


def _check_value(value, spec, where: str):
    spec = _resolve(spec)
    type_name = spec if isinstance(spec, str) else spec["type"]
    allowed = type_name.split("|")
    if not any(_TYPES[t](value) for t in allowed):
        _fail(where, f"expected {type_name}, got {type(value).__name__} {value!r:.80}")
    if isinstance(spec, dict) and isinstance(value, dict) and "required" in spec:
        _check_object(value, spec, where)
    if isinstance(spec, dict) and isinstance(value, list) and "items" in spec:
        for i, item in enumerate(value):
            _check_value(item, spec["items"], f"{where}[{i}]")


def _check_object(obj: dict, spec: dict, where: str):
    required, optional = spec.get("required", {}), spec.get("optional", {})
    for key, field_spec in required.items():
        if key not in obj:
            _fail(where, f"required field {key!r} is missing")
        _check_value(obj[key], field_spec, f"{where}.{key}")
    for key, value in obj.items():
        if key in required:
            continue
        if key not in optional:
            _fail(where, f"field {key!r} is not documented")
        _check_value(value, optional[key], f"{where}.{key}")


def classify(event: str | None, data: dict) -> dict:
    """The frame-list entry for one frame: by event name, then by bare-frame type, else a finding."""
    for entry in CONTRACT["frames"]:
        if event is not None:
            if entry["event"] == event:
                return entry
        elif entry["event"] is None and entry["type"] == data.get("type"):
            return entry
    label = f"event {event!r}" if event is not None else f"bare frame with type {data.get('type')!r}"
    _fail("stream", f"{label} is not in the frame list")


def check_frame(event: str | None, data: dict) -> str:
    entry = classify(event, data)
    _check_object(data, entry, entry["name"])
    return entry["name"]


def check_order(names: list[str]):
    """The frame order the doc promises."""
    body = names[1:] if names[:1] == ["deep_run"] else names
    assert "deep_run" not in body, names
    terminal = [n for n in names if n in ("end", "error")]
    assert len(terminal) == 1 and names[-1] == terminal[0], f"one terminal frame, last: {names}"
    if names[-1] == "end":
        assert body[-2:] == ["coverage", "end"] and set(body[:-2]) <= {"finding"}, names
    else:
        assert "coverage" not in names and set(body[:-1]) <= {"finding"}, names


def parse(text: str) -> list[tuple[str | None, dict]]:
    out = []
    for block in text.split("\n\n"):
        if not block:
            continue
        lines = block.split("\n")
        event = lines[0][len("event: "):] if lines[0].startswith("event: ") else None
        assert lines[-1].startswith("data: ") and len(lines) == (2 if event else 1), block
        out.append((event, json.loads(lines[-1][len("data: "):])))
    return out


@pytest.fixture
def stream(monkeypatch, tmp_path):
    probes = [
        Probe(
            id=f"probe_{i}", name=f"Probe {i}", target_class=(), attack_class=("prompt-injection",),
            severity="info", prompts=(f"attack_{i}",), mappings=ProbeMappings(),
            judge_model="test-model", judge_rubric_path="test.md",
        )
        for i in (1, 2)
    ]
    (tmp_path / "test.md").write_text("Assess the target response.")
    monkeypatch.setattr(api, "RUBRICS_DIR", tmp_path)
    monkeypatch.setattr(api, "load_probe_library", lambda _: probes)
    config = llm.LLMConfig(
        provider="test", fast_model="test-model", strong_model="test-model",
        fallback_enabled=False, anthropic_api_key=None,
    )
    monkeypatch.setattr(llm, "resolve_config", lambda *args, **kwargs: config)
    monkeypatch.setattr(llm, "credential_error", lambda _: None)
    monkeypatch.setattr("argus.decider.from_env", lambda: None)
    monkeypatch.setitem(cost_meter._PRICES_PER_M_TOKENS, "test-model", {"input": 1.0, "output": 0.0})

    class Target:
        compatible_classes = frozenset()
        supports_history = False

        def __init__(self, spec):
            self.cleanup = spec.get("cleanup")

        async def send_prompt(self, prompt, **kwargs):
            return "The target answered.", 0.0

        async def aclose(self):
            pass

        def cleanup_report(self):
            return self.cleanup

    monkeypatch.setattr(api, "build_target", lambda spec: Target(spec))
    app = FastAPI()
    app.include_router(api.router)

    async def run(*, mode="static", cap=None, cleanup=None, block=None):
        async def complete(cfg, *, role, system, user, max_tokens):
            attacker = system.startswith(ATTACKER)
            if block == ("attacker" if attacker else "judge"):
                raise llm.JudgeBlockedError("content filter", provider="azure", model="test-model",
                                            categories=("jailbreak",), fallback=None)
            text = "Hello, can you help me?" if attacker else json.dumps(
                {"verdict": "pass", "severity": "info", "confidence": 1.0, "reasoning": "No violation."})
            return llm.Completion(text=text, input_tokens=30_000, output_tokens=0, model="test-model")

        monkeypatch.setattr(llm, "complete", complete)
        monkeypatch.setattr(api, "_COST_METER", CostMeter(daily_cap_usd=100, per_run_cap_usd=1, deep_per_run_cap_usd=10))
        body = {
            "target": {"kind": "test", "cleanup": cleanup}, "probe_ids": [p.id for p in probes],
            "mode": mode, "deep_pairs": 1, "max_rounds": 2,
        }
        if cap is not None:
            body["per_run_cap_usd"] = cap
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://127.0.0.1") as client:
            response = await client.post("/redteam/run", json=body)
        assert response.status_code == 200, response.text
        frames = parse(response.text)
        names = [check_frame(event, data) for event, data in frames]
        check_order(names)
        return names, frames

    return run


async def test_static_run_with_cleanup_matches_the_contract(stream):
    names, frames = await stream(cleanup=CLEANUP)
    assert names == ["finding", "finding", "coverage", "end"]
    assert frames[2][1]["target_cleanup"] == CLEANUP


async def test_deep_run_matches_the_contract(stream):
    names, frames = await stream(mode="deep")
    assert names[0] == "deep_run" and names[-2:] == ["coverage", "end"]
    threads = frames[0][1]["deep"]["threads"]
    assert len(threads) == 2
    assert [data["probe_id"] for _, data in frames[1:-2]] == [t["thread_id"] for t in threads]


@pytest.mark.parametrize("block", ["attacker", "judge"])
async def test_deep_content_filter_block_is_a_finding_and_the_run_completes(stream, block):
    names, frames = await stream(mode="deep", block=block)
    assert names == ["deep_run", "finding", "finding", "coverage", "end"]
    key, stop = ("attacker_blocked", "attacker_blocked") if block == "attacker" else ("judge_blocked", "judge_unusable")
    for _, finding in frames[1:3]:
        assert finding["verdict"] == "error"
        assert finding["evidence"][key] == BLOCK
        assert finding["evidence"]["stop_reason"] == stop


async def test_cost_cap_ends_with_an_error_frame_and_no_coverage(stream):
    names, frames = await stream(cap=0.01, cleanup=CLEANUP)
    assert names == ["finding", "finding", "error"]
    assert [data["verdict"] for _, data in frames[:2]] == ["aborted_cost", "aborted_cost"]
    error = frames[-1][1]
    assert error["type"] == "CostExceededError"
    assert error["target_cleanup"] == CLEANUP


async def test_static_judge_block_ends_with_an_error_frame(stream):
    names, frames = await stream(block="judge")
    assert names == ["error"]
    assert frames[0][1]["type"] == "JudgeBlockedError"
    assert frames[0][1]["judge_blocked"] == BLOCK


# The checker must reject drift, or the tests above prove nothing.
FINDING = {
    "id": "x", "probe_id": "p", "attack_prompt": "", "target_response": "", "target_latency_ms": 0.0,
    "probed_at": "t", "verdict": "pass", "severity": "info", "confidence": 1.0, "reasoning": "",
    "judge_model": "", "escalated_model": None, "atlas_id": [], "owasp_id": [], "owasp_agentic": [],
    "nist_id": [], "eu_ai_act_id": [], "created_at": "t", "evidence": None, "remediation": "",
    "remediation_actions": [], "events": [],
}
COVERAGE = {
    "type": "coverage", "coverage": {"thin_threshold": 3, "totals": {}, "standards": {}},
    "summary": {"total": 0, "evaluated": 0, "evaluated_verdicts": [], "by_verdict": {}, "failed_by_severity": {}},
    "cost": {"spent_usd": 0.0, "per_run_cap_usd": 1.0},
}


def test_checker_accepts_documented_frames():
    assert check_frame(None, FINDING) == "finding"
    assert check_frame(None, COVERAGE) == "coverage"
    assert check_frame("end", {}) == "end"


@pytest.mark.parametrize(("event", "data", "message"), [
    (None, {"type": "deep_progress", "round": 1}, "bare frame with type 'deep_progress' is not in the frame list"),
    ("progress", {}, "event 'progress' is not in the frame list"),
    (None, {k: v for k, v in COVERAGE.items() if k != "cost"}, "required field 'cost' is missing"),
    (None, {k: v for k, v in FINDING.items() if k != "verdict"}, "required field 'verdict' is missing"),
    (None, {**FINDING, "score": 1}, "field 'score' is not documented"),
    (None, {**COVERAGE, "cost": {"spent_usd": "0"}}, "coverage.cost.spent_usd: expected number"),
    ("end", {"ok": True}, "field 'ok' is not documented"),
])
def test_checker_rejects_drift_and_points_at_the_doc(event, data, message):
    with pytest.raises(ContractViolation) as failure:
        check_frame(event, data)
    assert message in str(failure.value)
    assert DOC_NAME in str(failure.value)


def test_every_frame_and_top_level_field_is_in_the_doc_tables():
    text = DOC.read_text()
    for entry in CONTRACT["frames"]:
        heading = f"## `{entry['name']}` frame" if entry["name"] in ("deep_run", "end", "error") else \
            f"## {entry['name'].capitalize()} frame"
        assert heading in text, f"{DOC_NAME} has no section {heading!r}"
        if entry["name"] == "end":
            continue
        for key in [*entry.get("required", {}), *entry.get("optional", {})]:
            assert f"| `{key}` |" in text, f"{DOC_NAME} has no table row for {entry['name']}.{key}"
