import json
from orchestrator.planner.prompts import SYSTEM_PROMPT, TOOL_SCHEMAS


def test_system_prompt_mentions_constraints():
    text = SYSTEM_PROMPT.lower()
    assert "15" in text  # max_steps
    assert "ask_user" in text
    assert "2" in text  # ask_user cap
    for tool_name in (
        "discover_apis", "run_api_test", "run_web_ui_local",
        "run_web_ui_cloud", "fetch_page", "ask_user", "extract_url",
    ):
        assert tool_name in text, f"system prompt missing tool: {tool_name}"


def test_tool_schemas_complete():
    expected = {
        "discover_apis", "run_api_test", "run_web_ui_local",
        "run_web_ui_cloud", "fetch_page", "ask_user", "extract_url",
    }
    names = {s["name"] for s in TOOL_SCHEMAS}
    assert names == expected


def test_each_schema_is_valid_json_shape():
    for schema in TOOL_SCHEMAS:
        assert "name" in schema
        assert "description" in schema
        assert "input_schema" in schema
        assert schema["input_schema"]["type"] == "object"
        json.dumps(schema)


def test_system_prompt_has_routing_decision_tree():
    """S1: explicit two-step decision tree replacing implicit routing prose."""
    text = SYSTEM_PROMPT
    # Section marker
    assert "S1 · ROUTING DECISION TREE" in text, "missing S1 section header"
    # Step 1 — intent classification
    assert "API_TEST" in text
    assert "WEB_UI_TEST" in text
    assert "INSPECT" in text
    assert "UNKNOWN" in text
    # Step 2 — tool routing
    assert "MUST, not" in text or "MUST, not substitutable" in text, \
        "S1 must mark run_web_ui_local as non-substitutable"
    # Bare URL hard rule
    assert "EXECUTION request" in text, \
        "S1 must declare bare URL = execution, not strategy doc"


def test_system_prompt_has_persona_label_rule():
    """S3: persona is a label, not a narrative."""
    text = SYSTEM_PROMPT
    assert "S3 · PERSONA IS A LABEL" in text, "missing S3 section header"
    # Positive example set
    assert "'new_user'" in text
    assert "'admin'" in text
    # Negative example marker
    assert "BAD persona values" in text
    # Hard limit reference
    assert "50 characters" in text or "max 50" in text
    # Default
    assert "persona" in text and "new_user" in text


def test_system_prompt_has_completion_criteria():
    """S7: four explicit exit conditions + required summary fields."""
    text = SYSTEM_PROMPT
    assert "S7 · TASK COMPLETION CRITERIA" in text, "missing S7 section header"
    # Four exit conditions
    for marker in ("(1) SUCCESS:", "(2) BLOCKED:", "(3) USER_CLARIFICATION:",
                   "(4) IRRECOVERABLE:"):
        assert marker in text, f"S7 missing exit condition marker: {marker}"
    # Required summary fields
    assert "final summary MUST include" in text
    assert "Artifacts produced" in text
    # Anti-pattern guard
    assert "strategy document" in text, \
        "S7 must forbid unsolicited strategy documents"


def test_system_prompt_wizard_has_all_w_markers():
    from orchestrator.planner.prompts import SYSTEM_PROMPT_WIZARD
    for marker in ("W1 ·", "W2 ·", "W3 ·", "W4 ·", "W5 ·", "W6 ·", "W7 ·"):
        assert marker in SYSTEM_PROMPT_WIZARD, f"missing {marker}"


def test_system_prompt_wizard_distinct_from_base():
    from orchestrator.planner.prompts import SYSTEM_PROMPT, SYSTEM_PROMPT_WIZARD
    assert SYSTEM_PROMPT != SYSTEM_PROMPT_WIZARD
    assert "offer_choices" in SYSTEM_PROMPT_WIZARD
    assert "offer_choices" not in SYSTEM_PROMPT


def test_wizard_tool_schemas_include_offer_choices_exclude_ask_user():
    from orchestrator.planner.prompts import WIZARD_TOOL_SCHEMAS
    names = [t["name"] for t in WIZARD_TOOL_SCHEMAS]
    assert "offer_choices" in names
    assert "ask_user" not in names
    for dispatch in ("run_api_test", "run_web_ui_local", "run_web_ui_cloud"):
        assert dispatch in names


def test_offer_choices_schema_enforces_label_enum():
    from orchestrator.planner.prompts import WIZARD_TOOL_SCHEMAS
    oc = next(t for t in WIZARD_TOOL_SCHEMAS if t["name"] == "offer_choices")
    props = oc["input_schema"]["properties"]
    assert props["round_label"]["enum"] == [
        "intent", "run_where", "credentials", "persona",
        "target_url", "local_setup_check", "confirm", "other",
    ]
    assert props["options"]["maxItems"] == 6
    assert props["options"]["items"]["maxLength"] == 60
    assert props["question"]["maxLength"] == 200
