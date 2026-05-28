import json
import pytest

from orchestrator.planner.tools.offer_choices import offer_choices


class _Session:
    def __init__(self):
        self.state = {}


class _Ctx:
    def __init__(self):
        self.session = _Session()
        self.session.state["wizard_state"] = {
            "active": True, "round_n": 2, "rounds": [
                {"n": 1, "answer_kind": "option_click"},
            ],
            "bound_context": {}, "dispatched": False,
        }


async def _drain(agen):
    out = []
    async for x in agen:
        out.append(x)
    return out


@pytest.mark.asyncio
async def test_happy_path_emits_wizard_round_and_stops_turn():
    ctx = _Ctx()
    events = await _drain(offer_choices(
        question="Where does it run?",
        options=["cloud agent", "my machine"],
        allow_free_text=False,
        round_label="run_where",
        ctx=ctx,
    ))
    assert events[0]["event_type"] == "wizard_round"
    payload = json.loads(events[0]["payload"])
    assert payload["round_n"] == 2
    assert payload["options"] == ["cloud agent", "my machine"]
    assert payload["allow_back"] is True  # because prior round was a click
    assert events[-1]["is_terminal"] is True
    assert events[-1]["stop_turn"] is True


@pytest.mark.asyncio
async def test_empty_options_and_no_free_text_is_tool_error():
    ctx = _Ctx()
    events = await _drain(offer_choices(
        question="?", options=[], allow_free_text=False,
        round_label="other", ctx=ctx,
    ))
    terminal = events[-1]
    assert terminal["is_terminal"] is True
    assert terminal.get("stop_turn") is not True  # loop continues so LLM retries
    assert "error" in terminal["result"].lower()


@pytest.mark.asyncio
async def test_options_truncated_to_6_and_long_items_truncated_to_60():
    ctx = _Ctx()
    over = [f"option number {i} with some filler " + "x" * 80 for i in range(10)]
    events = await _drain(offer_choices(
        question="?", options=over, allow_free_text=False,
        round_label="other", ctx=ctx,
    ))
    payload = json.loads(events[0]["payload"])
    assert len(payload["options"]) == 6
    assert all(len(o) <= 60 for o in payload["options"])


@pytest.mark.asyncio
async def test_bad_round_label_coerced_to_other():
    ctx = _Ctx()
    events = await _drain(offer_choices(
        question="?", options=["a"], allow_free_text=False,
        round_label="nonsense", ctx=ctx,
    ))
    payload = json.loads(events[0]["payload"])
    assert payload["round_label"] == "other"


@pytest.mark.asyncio
async def test_allow_back_false_when_no_prior_click():
    ctx = _Ctx()
    ctx.session.state["wizard_state"] = {
        "active": True, "round_n": 1, "rounds": [],
        "bound_context": {}, "dispatched": False,
    }
    events = await _drain(offer_choices(
        question="?", options=["a"], allow_free_text=False,
        round_label="intent", ctx=ctx,
    ))
    payload = json.loads(events[0]["payload"])
    assert payload["allow_back"] is False


@pytest.mark.asyncio
async def test_allow_back_false_after_fast_forward():
    ctx = _Ctx()
    ctx.session.state["wizard_state"] = {
        "active": True, "round_n": 5, "rounds": [
            {"n": 1, "answer_kind": "parsed_from_text"},
            {"n": 2, "answer_kind": "bound_context_skip"},
            {"n": 3, "answer_kind": "parsed_from_text"},
            {"n": 4, "answer_kind": "parsed_from_text"},
        ],
        "bound_context": {}, "dispatched": False,
    }
    events = await _drain(offer_choices(
        question="Ready?", options=["Run it", "Edit something"],
        allow_free_text=False, round_label="confirm", ctx=ctx,
    ))
    payload = json.loads(events[0]["payload"])
    assert payload["allow_back"] is False
