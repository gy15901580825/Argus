import json
import pytest
from orchestrator.planner.tools.extract_url import extract_url


@pytest.mark.asyncio
async def test_extract_https_url():
    events = [e async for e in extract_url(text="Check https://a.com/path please", ctx=None)]
    assert len(events) == 1
    assert events[-1]["is_terminal"] is True
    urls = json.loads(events[-1]["result"])
    assert urls == ["https://a.com/path"]


@pytest.mark.asyncio
async def test_extract_www_prefixes_https():
    events = [e async for e in extract_url(text="go to www.example.org", ctx=None)]
    urls = json.loads(events[-1]["result"])
    assert urls == ["https://www.example.org"]


@pytest.mark.asyncio
async def test_extract_multiple():
    events = [e async for e in extract_url(
        text="https://a.com and https://b.com", ctx=None)]
    urls = json.loads(events[-1]["result"])
    assert set(urls) == {"https://a.com", "https://b.com"}


@pytest.mark.asyncio
async def test_extract_none():
    events = [e async for e in extract_url(text="no urls here", ctx=None)]
    urls = json.loads(events[-1]["result"])
    assert urls == []
