from orchestrator.planner.fallback_client import anthropic_tools_to_openai_tools


def test_tool_translation_preserves_names_and_descriptions():
    anthropic = [{"name": "x", "description": "does x",
                  "input_schema": {"type": "object", "properties": {}}}]
    openai = anthropic_tools_to_openai_tools(anthropic)
    assert openai[0]["type"] == "function"
    assert openai[0]["function"]["name"] == "x"
    assert openai[0]["function"]["description"] == "does x"
    assert openai[0]["function"]["parameters"] == {"type": "object", "properties": {}}
