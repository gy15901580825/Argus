import json
from orchestrator.planner.events import planner_step, passthrough_event


def test_thinking_step_has_required_fields():
    event = planner_step(step_index=1, type="thinking", text="Planning...")
    assert event["event_type"] == "planner_step"
    payload = json.loads(event["payload"])
    assert payload["type"] == "thinking"
    assert payload["step_index"] == 1
    assert payload["text"] == "Planning..."
    assert "timestamp" in payload


def test_tool_use_start_includes_tool_name_and_input():
    event = planner_step(
        step_index=2, type="tool_use_start",
        tool_name="discover_apis",
        tool_input={"url": "https://example.com"},
    )
    payload = json.loads(event["payload"])
    assert payload["tool_name"] == "discover_apis"
    assert payload["tool_input"] == {"url": "https://example.com"}


def test_fallback_event():
    event = planner_step(step_index=0, type="fallback", reason="auth")
    payload = json.loads(event["payload"])
    assert payload["type"] == "fallback"
    assert payload["reason"] == "auth"


def test_passthrough_event_preserves_type():
    event = passthrough_event(
        event_type="ssh_result",
        payload={"success": True, "stdout": "ok"},
    )
    assert event["event_type"] == "ssh_result"
    assert json.loads(event["payload"]) == {"success": True, "stdout": "ok"}


def test_passthrough_event_does_not_double_encode_string_payload():
    """Wizard tool builders (events.wizard_round/aborted/guide) already
    json.dumps the payload. passthrough_event must pass strings through
    unchanged — re-encoding would produce a JSON-string-of-a-JSON-string
    that consumers (api_service _apply_event_to_state, frontend api.ts:785)
    would JSON.parse once and get a string instead of the WizardRoundEvent
    dict.
    """
    pre_encoded = json.dumps({"round_n": 1, "round_label": "intent"})
    event = passthrough_event(event_type="wizard_round", payload=pre_encoded)
    # Must round-trip back to the original dict in a single parse.
    assert json.loads(event["payload"]) == {"round_n": 1, "round_label": "intent"}
