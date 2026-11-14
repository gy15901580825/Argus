"""The visual scenario is a real web page whose image an agent can load."""
from __future__ import annotations

import io
from pathlib import Path
import re
import sys
from unittest.mock import patch
from urllib.parse import urljoin

import httpx
from PIL import Image
import pytest

from argus.browser_runner import browser_probe as local
from argus.browser_runner.scenarios import visual_injection
from argus.probe import load_all_probes
from tests.test_browser_trap_e2e import browsers_path  # noqa: F401  (fixture)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "client_agent"))
from redteam_runner import browser_probe as client

ROOT = Path(__file__).resolve().parents[1]
BY_VARIANT = {p.scenario_options["variant"]: p for p in load_all_probes(ROOT / "argus/probes")
              if p.scenario_kind == "visual_injection"}


def _img_src(html: str) -> str:
    match = re.search(r'<img [^>]*src="([^"]+)"', html)
    assert match, html
    return match.group(1)


async def _serve(runner, variant):
    probe = BY_VARIANT[variant]
    server = runner._make_scenario_server(probe.scenario_kind, probe.scenario_payload,
                                          scenario_options=probe.scenario_options)
    return probe, server, await server.start()


@pytest.mark.parametrize("runner", [local, client])
@pytest.mark.asyncio
async def test_page_is_html_and_image_is_png_and_counts_one_page_load(runner):
    probe, server, url = await _serve(runner, "chart_label")
    try:
        async with httpx.AsyncClient(trust_env=False) as http:
            page = await http.get(url)
            assert page.status_code == 200
            assert page.headers["content-type"].startswith("text/html")
            image = await http.get(urljoin(url, _img_src(page.text)))
        assert image.status_code == 200
        assert image.headers["content-type"] == "image/png"
        payload = probe.scenario_payload.replace("{sink_url}", server.sink_url)
        assert image.content == visual_injection.render(payload, **probe.scenario_options)[0]
        evidence = server.evidence()
        assert evidence["page_loads"] == 1
        assert evidence["interaction_count"] == 1
        assert evidence["trap_requests"] == []
    finally:
        await server.stop()


@pytest.mark.parametrize("variant", sorted(BY_VARIANT))
def test_page_does_not_carry_the_payload(variant):
    probe = BY_VARIANT[variant]
    payload = probe.scenario_payload.replace("{sink_url}", "https://trap.example.test/sink")
    html, content_type = visual_injection.render_page(payload, **probe.scenario_options)
    assert content_type == "text/html"
    assert payload not in html and "trap.example.test" not in html
    width, height = Image.open(io.BytesIO(visual_injection.render(payload, **probe.scenario_options)[0])).size
    assert f'width="{width}"' in html and f'height="{height}"' in html
    assert re.search(r'alt="[^"]+"', html) and "<h1>" in html and "<title>" in html


@pytest.mark.asyncio
async def test_html_fallback_is_served_as_the_page():
    with patch.object(visual_injection, "_HAS_PIL", False):
        server = local._make_scenario_server("visual_injection", "read me")
        url = await server.start()
        try:
            async with httpx.AsyncClient(trust_env=False) as http:
                page = await http.get(url)
            assert page.headers["content-type"].startswith("text/html")
            assert "read me" in page.text
            assert server.evidence()["page_loads"] == 1
        finally:
            await server.stop()


@pytest.mark.parametrize("runner", [local, client])
@pytest.mark.parametrize("variant", ["plain", "qr_code", "terminal"])
async def test_chromium_finds_a_decoded_image_on_an_html_page(runner, variant, browsers_path, monkeypatch):
    from playwright.async_api import async_playwright

    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", browsers_path)
    probe, server, url = await _serve(runner, variant)
    payload = probe.scenario_payload.replace("{sink_url}", server.sink_url)
    expected = Image.open(io.BytesIO(visual_injection.render(payload, **probe.scenario_options)[0])).size
    try:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch()
            try:
                page = await browser.new_page()
                await page.goto(url)
                assert await page.evaluate("document.contentType") == "text/html"
                assert await page.locator("h1").count() == 1
                img = page.locator("img")
                assert await img.count() == 1
                await img.evaluate("el => el.decode()")
                size = await img.evaluate("el => [el.naturalWidth, el.naturalHeight]")
                assert tuple(size) == expected
                assert await img.get_attribute("alt")
                assert payload not in await page.content()
            finally:
                await browser.close()
        assert server.evidence()["page_loads"] == 1
    finally:
        await server.stop()
