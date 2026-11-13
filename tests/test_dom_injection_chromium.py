"""Real Chromium: which DOM-injection placements reach the accessibility tree.

An agent that reads the page through the accessibility tree and screenshots can
only be tested by a placement that shows up there. The table below is what
headless Chromium exposes, read through CDP Accessibility.getFullAXTree and
Playwright's aria_snapshot, next to the page's visible text (innerText).
"""

import pytest

from tests.test_browser_trap_e2e import browsers_path  # noqa: F401
from tests.test_dom_injection_placements import EXPECTED, PROBES, client, local

# placement -> (AX tree node role and property holding the witness, in aria_snapshot, in innerText)
OBSERVED = {
    "visible": ("StaticText.name", True, True),
    "alt": ("image.name", True, False),
    "aria_label": ("button.name", True, False),
    "title": ("link.description", False, False),
    "data_attr": (None, False, False),
    "hidden_input": (None, False, False),
    "html_comment": (None, False, False),
    "visibility_hidden": (None, False, False),
    "off_screen": ("StaticText.name", True, True),
    "meta_description": (None, False, False),
}


def _ax_spot(nodes, witness):
    spots = sorted({
        f"{node.get('role', {}).get('value')}.{key}"
        for node in nodes if not node.get("ignored")
        for key in ("name", "description", "value")
        if isinstance(node.get(key, {}).get("value"), str) and witness in node[key]["value"]
        and node.get("role", {}).get("value") != "InlineTextBox"
    })
    assert len(spots) <= 1, spots
    return spots[0] if spots else None


@pytest.mark.parametrize("runner", [local, client])
async def test_accessibility_tree_exposure_per_placement(runner, browsers_path, monkeypatch):  # noqa: F811
    from playwright.async_api import async_playwright

    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", browsers_path)
    seen = {}
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch()
        try:
            page = await browser.new_page()
            cdp = await page.context.new_cdp_session(page)
            for pid, placement in EXPECTED.items():
                probe = PROBES[pid]
                server = runner._make_scenario_server(probe.scenario_kind, probe.scenario_payload,
                                                      scenario_options=probe.scenario_options)
                url = await server.start()
                try:
                    await page.goto(url)
                    [witness] = probe.contact_markers
                    nodes = (await cdp.send("Accessibility.getFullAXTree"))["nodes"]
                    seen[placement] = (
                        _ax_spot(nodes, witness),
                        witness in await page.locator("body").aria_snapshot(),
                        witness in await page.inner_text("body"),
                    )
                finally:
                    await server.stop()
        finally:
            await browser.close()
    print("\nplacement | AX tree | aria_snapshot | innerText")
    for placement, row in seen.items():
        print(placement, "|", " | ".join(map(str, row)))
    assert seen == OBSERVED
