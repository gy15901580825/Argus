# Browser scenario fonts

These are static font subsets for deterministic browser probe images and HTML. The only source copies live in this directory. `argus/browser_runner/scenarios/fonts` is a relative symlink to it; setuptools includes the actual assets in the wheel, so installations have no symlink or client checkout dependency. The client Docker image copies this directory with the runner; from `client_agent`, build with `docker build -f Dockerfile ..` (the existing shared transport package requires repository-root context). No font assets are duplicated in Git.

All four upstream fonts use SIL Open Font License 1.1. Their license headers and name-table copyright/license entries specify no Reserved Font Names. OFL permits modification and redistribution subject to retaining the license and copyright, and not selling the fonts by themselves. Each subset preserves those records and ships the corresponding `*-OFL.txt`; internal family names are changed to `ArgusScenario-*`.

Noto Sans is the readable Latin face, Caveat is the Google Fonts handwriting face, Noto Sans Mono draws terminal output, and Noto Sans CJK SC supplies Chinese glyphs. Each subset includes printable ASCII, an em dash used by existing callers, and the shipped payload/page copy assigned to that face. Charset files are exact Unicode character lists taken from the subset cmap, without a trailing newline. QR payloads are encoded rather than drawn.

## Rebuild

Install the development dependencies (`pip install -e ".[dev]"`), then run `python scripts/rebuild_scenario_fonts.py --cache /tmp/scenario-font-upstream`. Missing upstream files are fetched from the pinned URLs below, and both font and license SHA-256 are checked. A populated cache permits an offline rebuild. No system fonts or runtime fonttools are used.

## Upstream provenance

### Noto Sans (`latin`)

- Font: https://raw.githubusercontent.com/google/fonts/5bb28733cec313b63fbd415b574b5ae35c8aa8b8/ofl/notosans/NotoSans%5Bwdth,wght%5D.ttf
- Font SHA-256: `bfb7bb691513f12e734dc346c03a03f784912432d7e3fa8e56efcf906fe86b3d`
- License: https://raw.githubusercontent.com/google/fonts/5bb28733cec313b63fbd415b574b5ae35c8aa8b8/ofl/notosans/OFL.txt
- License SHA-256: `cee9892f9f0cc8fe882c9e9537ee6a89621d86ee7ceaf70b02e2b2b1c25c061a`

### Caveat (`hand`)

- Font: https://raw.githubusercontent.com/google/fonts/5bb28733cec313b63fbd415b574b5ae35c8aa8b8/ofl/caveat/Caveat%5Bwght%5D.ttf
- Font SHA-256: `0bdb6b660482d31531b3945849fba5916b3ef8695da7024a9e6b9ee3c4157988`
- License: https://raw.githubusercontent.com/google/fonts/5bb28733cec313b63fbd415b574b5ae35c8aa8b8/ofl/caveat/OFL.txt
- License SHA-256: `1f9d81d094273d82f3898a1ee8b598a717d050ecbf5ff7bede105b704880157b`

### Noto Sans Mono (`mono`)

- Font: https://raw.githubusercontent.com/google/fonts/5bb28733cec313b63fbd415b574b5ae35c8aa8b8/ofl/notosansmono/NotoSansMono%5Bwdth,wght%5D.ttf
- Font SHA-256: `2cb2adb378a8f574213e23df697050b83c54c27df465a2015552740b2769a081`
- License: https://raw.githubusercontent.com/google/fonts/5bb28733cec313b63fbd415b574b5ae35c8aa8b8/ofl/notosansmono/OFL.txt
- License SHA-256: `cee9892f9f0cc8fe882c9e9537ee6a89621d86ee7ceaf70b02e2b2b1c25c061a`

### Noto Sans CJK SC (`cjk`)

- Font: https://raw.githubusercontent.com/notofonts/noto-cjk/f8d157532fbfaeda587e826d4cd5b21a49186f7c/Sans/OTF/SimplifiedChinese/NotoSansCJKsc-Regular.otf
- Font SHA-256: `2c76254f6fc379fddfce0a7e84fb5385bb135d3e399294f6eeb6680d0365b74b`
- License: https://raw.githubusercontent.com/notofonts/noto-cjk/f8d157532fbfaeda587e826d4cd5b21a49186f7c/Sans/LICENSE
- License SHA-256: `6a73f9541c2de74158c0e7cf6b0a58ef774f5a780bf191f2d7ec9cc53efe2bf2`

`upstream.json` contains the same provenance for the rebuild script. Full upstream binaries are not committed. Total shipped assets, including licenses and provenance, must stay below 300 KB; the rebuild checks this limit.
