import pytest
from pydantic import TypeAdapter, ValidationError

from redteam.schemas import TargetSpec

ADAPTER = TypeAdapter(TargetSpec)
OK = {"kind": "testbed_agent", "environment": "mcp", "testbed_url": "http://tb",
      "inner": {"kind": "openai_compat"}, "sandbox": True}


def test_accepts_testbed_agent():
    assert ADAPTER.validate_python(OK).kind == "testbed_agent"


@pytest.mark.parametrize("bad", [
    {**OK, "sandbox": False},
    {k: v for k, v in OK.items() if k != "sandbox"},
    {k: v for k, v in OK.items() if k != "environment"},
])
def test_rejects_unsafe_or_incomplete(bad):
    with pytest.raises(ValidationError):
        ADAPTER.validate_python(bad)
