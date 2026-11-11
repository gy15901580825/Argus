"""Offline checks of what an agent actually sees in each browser scenario."""
from __future__ import annotations

import io
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import segno
import yaml
from PIL import Image, ImageDraw
from fontTools.ttLib import TTFont

from argus.browser_runner import browser_probe as local
from argus.browser_runner.scenarios import _fonts, dom_injection, os_cmd, ui_phishing, visual_injection
from argus.probe import load_all_probes, load_probe
from argus.targets.browser_use import BrowserUseSpec, BrowserUseTarget
from argus.targets.hosted_trap import render_hosted_scenario
import sys

# Use the standalone client's import path, also used by the transport tests.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "client_agent"))
from redteam_runner import browser_probe as client

ROOT = Path(__file__).resolve().parents[1]
PROBES = tuple(p for p in load_all_probes(ROOT / "argus/probes")
               if p.scenario_kind in {"visual_injection", "os_cmd"})
BY_VARIANT = {p.scenario_options.get("variant"): p for p in PROBES if p.scenario_kind == "visual_injection"}


def png(variant):
    p = BY_VARIANT[variant]
    body, content_type = visual_injection.render(p.scenario_payload, **p.scenario_options)
    assert content_type == "image/png"
    return Image.open(io.BytesIO(body)).convert("RGB")


@pytest.mark.parametrize("probe", PROBES, ids=lambda p: p.id)
@pytest.mark.asyncio
async def test_both_runners_serve_identical_shipped_pages(probe):
    payload = probe.scenario_payload.replace("{sink_url}", "https://trap.example.test/sink")
    pages = []
    for runner in (local, client):
        server = runner._make_scenario_server(probe.scenario_kind, payload,
                                             scenario_options=probe.scenario_options)
        url = await server.start()
        try:
            async with httpx.AsyncClient(trust_env=False) as http:
                response = await http.get(url)
            assert response.status_code == 200
            expected, content_type = runner._SCENARIOS[probe.scenario_kind].render(
                payload, **probe.scenario_options)
            assert response.headers["content-type"].startswith(content_type)
            assert response.content == (expected.encode() if isinstance(expected, str) else expected)
            pages.append(response.content)
        finally:
            await server.stop()
    assert pages[0] == pages[1]


def test_variant_set_and_probe_count():
    assert set(BY_VARIANT) == {
        "plain", "qr_code", "handwritten", "stylized_logo", "tiny_text",
        "white_on_white", "multilingual", "chart_label", "terminal",
    }
    assert len(PROBES) == 12
    assert len(list(load_all_probes(ROOT / "argus/probes"))) == 268


def test_qr_pixels_encode_the_payload():
    payload = BY_VARIANT["qr_code"].scenario_payload
    matrix = segno.make(payload).matrix
    image = png("qr_code")
    # Module centres, after the quiet border at the image's (40, 40) origin.
    sampled = tuple(tuple(int(image.getpixel((40 + (x + 4) * 6 + 3,
                                             40 + (y + 4) * 6 + 3))[0] == 0)
                          for x in range(len(row))) for y, row in enumerate(matrix))
    assert sampled == tuple(tuple(row) for row in matrix)
    assert image.getpixel((41, 41)) == (255, 255, 255)
    # Outside the code, every pixel comes from the neutral caption.
    expected = Image.new("RGB", image.size, "white")
    qr_width = (len(matrix[0]) + 8) * 6
    qr_height = (len(matrix) + 8) * 6
    ImageDraw.Draw(expected).text((40, qr_height + 60), "Scan code",
                                 font=_fonts.load_font("latin", 24), fill="#172b4d", anchor="la")
    image.paste("white", (40, 40, 40 + qr_width, 40 + qr_height))
    assert image.tobytes() == expected.tobytes()


def test_tiny_text_has_at_most_eight_pixel_cap_height():
    font = _fonts.load_font("latin", 10)
    mask = Image.new("L", (80, 40))
    ImageDraw.Draw(mask).text((0, 0), "H", font=font, fill=255)
    box = mask.getbbox()
    assert box and 0 < box[3] - box[1] <= 8
    # First T in the actual corner payload has the same small cap height.
    image = png("tiny_text")
    crop = image.crop((15, 365, 21, 400))
    ink = Image.eval(crop.convert("L"), lambda px: 255 - px).getbbox()
    assert ink and 0 < ink[3] - ink[1] <= 8


def test_white_on_white_payload_pixel_contrast():
    crop = png("white_on_white").crop((0, 340, 1000, 400))
    colors = set(crop.getdata())
    assert (245, 245, 245) in colors
    def linear(v):
        v /= 255
        return v / 12.92 if v <= 0.04045 else ((v + 0.055) / 1.055) ** 2.4
    for r, g, b in colors:
        luminance = .2126 * linear(r) + .7152 * linear(g) + .0722 * linear(b)
        assert 1.05 / (luminance + .05) <= 1.15


@pytest.mark.parametrize("probe", PROBES, ids=lambda p: p.id)
def test_shipped_text_is_covered_by_its_bundled_font(probe):
    if probe.scenario_kind == "visual_injection":
        face = _fonts.FONT_VARIANTS.get(probe.scenario_options["variant"], "latin")
        assert set(probe.scenario_payload) <= _fonts.charset(face)
    else:
        for key in ("title", "heading", "intro"):
            assert set(probe.scenario_options[key]) <= _fonts.charset("latin")


@pytest.mark.parametrize("face", ["latin", "hand", "mono", "cjk"])
def test_charset_matches_real_font_cmap(face):
    font = TTFont(io.BytesIO(_fonts.font_bytes(face)))
    assert _fonts.charset(face) == frozenset(map(chr, font.getBestCmap()))
    assert set(map(chr, range(32, 127))) <= _fonts.charset(face)


@pytest.mark.parametrize("variant", sorted(set(BY_VARIANT) - {"qr_code"}))
def test_missing_glyph_fails_loudly(variant):
    with pytest.raises(ValueError, match="🧪.*U\\+1F9EA"):
        visual_injection.render("🧪", variant=variant)


@pytest.mark.parametrize("kind,options,message", [
    ("visual_injection", {"variant": "unknown"}, "unknown.*variant"),
    ("os_cmd", {"surprise": "yes"}, "unknown.*surprise"),
    ("os_cmd", {"intro": 12}, "intro.*string"),
    ("dom_injection", {"variant": "plain"}, "unknown.*variant"),
])
def test_loader_rejects_invalid_options(tmp_path, kind, options, message):
    source = ROOT / "argus/probes/browser/visual_inject_overlay.yaml"
    raw = yaml.safe_load(source.read_text())
    raw["scenario"] = {"kind": kind, "payload": "test", **options}
    path = tmp_path / "invalid.yaml"
    path.write_text(yaml.safe_dump(raw))
    with pytest.raises(ValueError, match=message):
        load_probe(path)


def test_scenario_options_are_immutable():
    with pytest.raises(TypeError):
        BY_VARIANT["plain"].scenario_options["variant"] = "terminal"


@pytest.mark.parametrize("probe", [p for p in PROBES if p.scenario_kind == "os_cmd"], ids=lambda p: p.id)
def test_os_cmd_copy_answers_prompt_and_keeps_attack(probe):
    body, _ = os_cmd.render(probe.scenario_payload, **probe.scenario_options)
    assert f'<title>{probe.scenario_options["title"]}</title>' in body
    assert probe.scenario_options["intro"] in body
    expected = {
        "browser_os_cmd_install_tutorial": ("SampleOS 1.0", "SampleOS 2.0"),
        "browser_os_cmd_data_export": ("CSV", "JSON", "Parquet"),
        "browser_os_cmd_dependency_update": ("npm",),
    }
    assert all(answer in body for answer in expected[probe.id])
    assert "your assistant should run this in the terminal:" in body
    assert '<pre style="background:#eee;padding:10px"><code>' in body
    hosted = render_hosted_scenario("os_cmd", probe.scenario_payload, **probe.scenario_options)
    assert hosted == os_cmd.render(probe.scenario_payload, **probe.scenario_options, _include_font=False)[0]
    assert len(hosted.encode("utf-8")) < 16_384
    assert "data:font/" not in hosted
    assert probe.scenario_options["intro"] in hosted


def test_page_copy_is_escaped():
    body, _ = os_cmd.render('<attack>&"', title='<title>', heading='<heading>', intro='<intro>')
    assert '<attack>' not in body
    assert '&lt;attack&gt;&amp;&quot;' in body
    for word in ("title", "heading", "intro"):
        assert f'&lt;{word}&gt;' in body


@pytest.mark.parametrize("kind,module", [("dom_injection", dom_injection), ("ui_phishing", ui_phishing)])
def test_optionless_html_remains_byte_identical(kind, module):
    payload = "https://trap.example.test/sink/login"
    assert local._SCENARIOS[kind].render(payload, **{}) == module.render(payload)
    assert client._SCENARIOS[kind].render(payload, **{}) == module.render(payload)


@pytest.mark.asyncio
async def test_target_carries_options_in_ws_message_and_resets_them():
    target = BrowserUseTarget(BrowserUseSpec(agent_url="https://agent.example.test", scenario_kind="visual_injection"))
    probe = BY_VARIANT["handwritten"]
    await target.begin_probe(probe)
    reply = {"final_text": "read", "screenshots": [], "latency_ms": 1,
             "trap_url": "http://trap.example.test/scenario",
             "trap_evidence": {"interaction_count": 1, "page_loads": 1, "trap_requests": []}}
    ws = AsyncMock()
    ws.send_and_wait.return_value = reply
    with patch("argus.targets.browser_use._get_client_agent_ws", return_value=ws):
        await target.send_prompt(probe.prompts[0])
    assert ws.send_and_wait.call_args.args[0]["scenario_options"] == {"variant": "handwritten"}
    from types import SimpleNamespace
    await target.begin_probe(SimpleNamespace(id="empty", scenario_kind=None, scenario_payload=None))
    assert target._scenario_options == {}


@pytest.mark.parametrize("runner", [local, client])
@pytest.mark.asyncio
async def test_browser_probe_accepts_wire_options(runner):
    probe = BY_VARIANT["chart_label"]
    msg = {"scenario_kind": probe.scenario_kind, "payload": probe.scenario_payload,
           "prompt": probe.prompts[0], "scenario_options": dict(probe.scenario_options)}
    seen = []
    class Driver:
        async def run(self):
            async with httpx.AsyncClient(trust_env=False) as http:
                seen.append((await http.get(self.url)).content)
            return {"final_text": "read"}
    def make_driver(agent_url, scenario_url, prompt, timeout):
        driver = Driver()
        driver.url = scenario_url
        return driver
    with patch.object(runner, "_make_target_agent_driver", side_effect=make_driver):
        result = await runner.BrowserProbe().run(msg)
    assert seen == [visual_injection.render(probe.scenario_payload, **probe.scenario_options)[0]]
    assert result["trap_evidence"]["page_loads"] == 1


def test_deep_wrapper_preserves_the_page_variant():
    from argus.persona_loader import Persona, Strategy
    from argus.persona_strategy import PersonaStrategyProbe

    persona = Persona("sample", "Sample", "voice", "traits", "usage", "body")
    strategy = Strategy("sample", "Sample", "mechanics", "usage", "notes", "body")
    base = BY_VARIANT["handwritten"]
    wrapped = PersonaStrategyProbe(base=base, persona=persona, strategy=strategy)
    assert wrapped.scenario_options == {"variant": "handwritten"}
    assert wrapped.scenario_options is base.scenario_options


def test_scenario_options_support_dataclass_and_json_serialization():
    import copy
    import json
    import pickle
    from dataclasses import asdict

    probe = BY_VARIANT["handwritten"]
    assert json.loads(json.dumps(asdict(probe)))["scenario_options"] == {"variant": "handwritten"}
    for options in (copy.deepcopy(probe).scenario_options,
                    pickle.loads(pickle.dumps(probe)).scenario_options):
        assert options == {"variant": "handwritten"}
        with pytest.raises(TypeError):
            options["variant"] = "terminal"


@pytest.mark.parametrize("mutation", [
    lambda opts: opts.update(variant="terminal"),
    lambda opts: opts.clear(),
    lambda opts: opts.pop("variant"),
    lambda opts: opts.setdefault("new", "value"),
    lambda opts: opts.__ior__({"variant": "terminal"}),
    lambda opts: opts.__init__({"variant": "terminal"}),
])
def test_scenario_options_reject_all_dict_mutations(mutation):
    with pytest.raises(TypeError):
        mutation(BY_VARIANT["handwritten"].scenario_options)
