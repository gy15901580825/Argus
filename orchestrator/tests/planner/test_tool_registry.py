import json
import pytest

from orchestrator.planner.tools import ToolRegistry
from orchestrator.planner.prompts import TOOL_SCHEMAS


def test_registry_has_all_8_tools():
    expected = {
        "discover_apis", "run_api_test", "run_web_ui_local",
        "run_web_ui_cloud", "fetch_page", "ask_user", "extract_url",
        "offer_choices",
    }
    assert set(ToolRegistry.names()) == expected


def test_registry_schemas_match_prompts():
    schema_names = {s["name"] for s in TOOL_SCHEMAS}
    # offer_choices is wizard-only — lives in WIZARD_TOOL_SCHEMAS (Task 8), not TOOL_SCHEMAS
    assert set(ToolRegistry.names()) - {"offer_choices"} == schema_names


def test_registry_get_returns_callable():
    fn = ToolRegistry.get("extract_url")
    assert callable(fn)


def test_registry_get_unknown_raises():
    with pytest.raises(KeyError):
        ToolRegistry.get("nope")


@pytest.mark.asyncio
async def test_registry_dispatch_extract_url():
    fn = ToolRegistry.get("extract_url")
    events = [e async for e in fn(text="https://a.com", ctx=None)]
    assert events[-1]["is_terminal"] is True
    urls = json.loads(events[-1]["result"])
    assert urls == ["https://a.com"]
