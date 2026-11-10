#!/usr/bin/env python3
"""Rebuild shipped font subsets from hash-pinned upstream sources (dev only)."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from urllib.request import urlopen

import yaml
from fontTools import subset
from fontTools.ttLib import TTFont
from fontTools.varLib.instancer import instantiateVariableFont

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "client_agent/redteam_runner/scenarios/fonts"
FONT_VARIANTS = {"handwritten": "hand", "multilingual": "cjk", "terminal": "mono"}


def checked(data: bytes, digest: str, source: str) -> bytes:
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError(f"sha256 mismatch for {source}")
    return data


def rebuild(cache: Path) -> None:
    manifest = json.loads((DEST / "upstream.json").read_text())
    chars = {key: set(chr(c) for c in range(32, 127)) | {"—"} for key in manifest}
    for path in (ROOT / "argus/probes/browser").glob("*.yaml"):
        scenario = yaml.safe_load(path.read_text())["scenario"]
        if scenario["kind"] == "visual_injection":
            key = FONT_VARIANTS.get(scenario.get("variant"), "latin")
            chars[key].update(scenario["payload"])
        elif scenario["kind"] == "os_cmd":
            for key in ("title", "heading", "intro"):
                chars["latin"].update(scenario[key])
    cache.mkdir(parents=True, exist_ok=True)
    for key, entry in manifest.items():
        source = cache / entry["source_file"]
        if not source.exists():
            source.write_bytes(urlopen(entry["url"], timeout=180).read())
        checked(source.read_bytes(), entry["sha256"], str(source))
        license_path = DEST / f"{key}-OFL.txt"
        if not license_path.exists():
            license_path.write_bytes(urlopen(entry["license_url"], timeout=60).read())
        checked(license_path.read_bytes(), entry["license_sha256"], str(license_path))
        font = TTFont(source, recalcTimestamp=False)
        header = (font["name"].getDebugName(0) or "") + (font["name"].getDebugName(13) or "")
        if "SIL Open Font License" not in header or "Reserved Font Name" in header:
            raise ValueError(f"review font license header: {source}")
        if "fvar" in font:
            axes = {axis.axisTag: (400 if axis.axisTag == "wght" else axis.defaultValue)
                    for axis in font["fvar"].axes}
            font = instantiateVariableFont(font, axes, inplace=True)
        cmap = font.getBestCmap()
        missing = chars[key] - set(map(chr, cmap))
        if missing:
            raise ValueError(f"{key} missing requested glyphs: {''.join(sorted(missing))}")
        options = subset.Options()
        options.recalc_timestamp = False
        options.name_IDs = [0, 1, 2, 3, 4, 5, 6, 13, 14]
        options.name_legacy = True
        options.name_languages = ['*']
        sub = subset.Subsetter(options=options)
        sub.populate(unicodes=sorted(map(ord, chars[key])))
        sub.subset(font)
        # Stable internal names for our modified subsets; copyright and license remain.
        for record in list(font['name'].names):
            if record.nameID in (1, 3, 4, 6):
                font['name'].setName(f"ArgusScenario-{key}", record.nameID,
                                     record.platformID, record.platEncID, record.langID)
        suffix = ".otf" if key == "cjk" else ".ttf"
        font.save(DEST / f"{key}{suffix}")
        charset = ''.join(sorted(map(chr, font.getBestCmap())))
        (DEST / f"{key}.charset.txt").write_text(charset, encoding="utf-8")
    total = sum(p.stat().st_size for p in DEST.iterdir() if p.is_file())
    if total >= 300_000:
        raise ValueError(f"font assets exceed 300 KB: {total}")
    print(f"Font assets: {total} bytes")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, default=ROOT / ".font-cache")
    rebuild(parser.parse_args().cache)
