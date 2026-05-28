import json

from orchestrator.planner.events import (
    wizard_round, wizard_aborted, wizard_guide,
)


def test_wizard_round_shape_and_payload_json_encoded():
    ev = wizard_round(
        round_n=2, question="Where?",
        options=["cloud agent", "my machine"],
        allow_free_text=False, allow_back=True,
        round_label="run_where",
    )
    assert ev["event_type"] == "wizard_round"
    payload = json.loads(ev["payload"])
    assert payload == {
        "round_n": 2,
        "question": "Where?",
        "options": ["cloud agent", "my machine"],
        "allow_free_text": False,
        "allow_back": True,
        "round_label": "run_where",
    }


def test_wizard_aborted_shape():
    ev = wizard_aborted(at_round_label="persona", rounds_used=3)
    assert ev["event_type"] == "wizard_aborted"
    payload = json.loads(ev["payload"])
    assert payload == {"at_round_label": "persona", "rounds_used": 3}


def test_wizard_guide_shape():
    ev = wizard_guide(kind="client_agent_install", markdown="# install")
    assert ev["event_type"] == "wizard_guide"
    payload = json.loads(ev["payload"])
    assert payload == {"kind": "client_agent_install", "markdown": "# install"}
