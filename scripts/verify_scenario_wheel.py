#!/usr/bin/env python3
"""Run with a freshly installed wheel, outside the checkout, without network."""
from __future__ import annotations

import io
import json
from pathlib import Path

import argus
from PIL import Image, ImageDraw
from argus.browser_runner.browser_probe import _SCENARIOS
from argus.browser_runner.scenarios import _fonts
from argus.probe import load_all_probes


def verify() -> None:
    package = Path(argus.__file__).resolve().parent
    probes = list(load_all_probes(package / "probes"))
    assert len(probes) == 271
    variants = set()
    os_pages = 0
    for probe in probes:
        if probe.scenario_kind not in ("visual_injection", "os_cmd"):
            continue
        payload = probe.scenario_payload.replace("{sink_url}", "https://trap.example.test/sink")
        body, kind = _SCENARIOS[probe.scenario_kind].render(payload, **probe.scenario_options)
        if kind == "image/png":
            image = Image.open(io.BytesIO(body))
            image.verify()
            variants.add(probe.scenario_options["variant"])
        else:
            assert probe.scenario_options["intro"] in body
            os_pages += 1
    assert variants == {"plain", "qr_code", "handwritten", "stylized_logo", "tiny_text",
                        "white_on_white", "multilingual", "chart_label", "terminal"}
    assert os_pages == 3
    for face in ("latin", "hand", "mono", "cjk"):
        assert (_fonts.FONT_DIR / f"{face}-OFL.txt").is_file()
        assert _fonts.font_bytes(face)
        assert len(_fonts.charset(face)) >= 95
    assert (_fonts.FONT_DIR / "README.md").is_file()
    assert not _fonts.FONT_DIR.is_symlink()
    cap = Image.new("L", (50, 40))
    ImageDraw.Draw(cap).text((0, 0), "H", font=_fonts.load_font("latin", 10), fill=255)
    bounds = cap.getbbox()
    cap_height = bounds[3] - bounds[1]
    assert cap_height <= 8
    font_asset_bytes = sum(p.stat().st_size for p in _fonts.FONT_DIR.iterdir())
    assert font_asset_bytes < 300_000
    print(json.dumps({"package": str(package), "probes": len(probes), "variants": sorted(variants),
                      "os_cmd_pages": os_pages, "tiny_cap_height_px": cap_height,
                      "font_asset_bytes": font_asset_bytes}, indent=2))


if __name__ == "__main__":
    verify()
