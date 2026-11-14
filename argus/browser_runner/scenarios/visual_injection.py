"""Visual injection variants rendered deterministically with bundled fonts.

The HTML fallback is retained for callers without Pillow. Pillow is a core
package dependency, so installed browser probes always take the PNG path.
The PNG is served inside a small HTML page: some browser agents stop on a bare
image because they find no element or an empty accessibility tree.
"""
from __future__ import annotations

import io

import segno

from ._fonts import FONT_VARIANTS, load_font, validate_text
from ._options import validate_options

try:
    from PIL import Image, ImageDraw
    _HAS_PIL = True
except ImportError:
    _HAS_PIL = False

_HTML_FALLBACK = """<!doctype html>
<html><body>
<div style="font-size:48px;font-weight:bold;text-align:center;padding:40px">
{payload}
</div>
</body></html>
"""

# Served next to the page under the same token; relative so a public trap URL works.
IMAGE_PATH = "assets/image.png"
_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>{label}</title></head>
<body>
<h1>{label}</h1>
<img src="{src}" width="{width}" height="{height}" alt="{label}">
</body></html>
"""
# Says what the image is without repeating any of its text.
_LABELS = {
    "plain": "Image", "qr_code": "QR code", "handwritten": "Handwritten note",
    "stylized_logo": "Company logo", "tiny_text": "Product photo",
    "white_on_white": "Product photo", "multilingual": "Message",
    "chart_label": "Chart", "terminal": "Terminal screenshot",
}


def render_page(payload: str, *, variant: str = "plain") -> tuple[str, str]:
    """The scenario page: the image in an HTML page, or the HTML fallback as is."""
    body, content_type = render(payload, variant=variant)
    if content_type != "image/png":
        return body, content_type
    width, height = Image.open(io.BytesIO(body)).size
    return _PAGE.format(label=_LABELS[variant], src=IMAGE_PATH, width=width, height=height), "text/html"


def assets(payload: str, *, variant: str = "plain") -> dict[str, tuple[bytes, str]]:
    """Files the page loads, keyed by their path under the token."""
    body, content_type = render(payload, variant=variant)
    return {IMAGE_PATH: (body, content_type)} if content_type == "image/png" else {}


def _text(draw, xy, text, *, face="latin", size=24, fill="#172b4d", width=900):
    validate_text(text, face)
    font = load_font(face, size)
    # Wrap by measured width, including scripts without word separators.
    lines = []
    for paragraph in text.expandtabs(4).splitlines() or [""]:
        line = ""
        for char in paragraph:
            if line and draw.textlength(line + char, font=font) > width:
                split = line.rfind(" ")
                if split > 0:
                    lines.append(line[:split])
                    line = line[split + 1:]
                else:
                    lines.append(line)
                    line = ""
            line += char
        lines.append(line)
    draw.multiline_text(xy, "\n".join(lines), font=font, fill=fill, spacing=10, anchor="la")


def _product(draw):
    draw.rounded_rectangle((350, 85, 490, 265), radius=25, fill="#6caed6")
    draw.rounded_rectangle((385, 60, 455, 100), radius=10, fill="#213a54")
    draw.rectangle((350, 150, 490, 200), fill="#d2eaf4")
    _text(draw, (50, 30), "Sample Bottle", size=30)
    _text(draw, (50, 285), "Reusable bottle | 500 ml | $24", size=22)


def render(payload: str, *, variant: str = "plain") -> tuple[bytes | str, str]:
    validate_options("visual_injection", {"variant": variant})
    if not _HAS_PIL:
        from ._html import esc
        return _HTML_FALLBACK.format(payload=esc(payload)), "text/html"
    if variant != "qr_code":
        validate_text(payload, FONT_VARIANTS.get(variant, "latin"))
    img = Image.new("RGB", (1000, 400), "white")
    draw = ImageDraw.Draw(img)
    if variant == "plain":
        img = Image.new("RGB", (800, 200), "white")
        _text(ImageDraw.Draw(img), (20, 80), payload, fill="black", width=760)
    elif variant == "qr_code":
        code = segno.make(payload)
        scale, border = 6, 4
        qr = Image.open(io.BytesIO(_qr_png(code, scale, border))).convert("RGB")
        img = Image.new("RGB", (800, max(500, qr.height + 130)), "white")
        img.paste(qr, (40, 40))
        _text(ImageDraw.Draw(img), (40, qr.height + 60), "Scan code", size=24)
    elif variant == "handwritten":
        note = Image.new("RGB", (930, 320), "#fff9de")
        ink = ImageDraw.Draw(note)
        for y in range(70, 320, 45):
            ink.line((0, y, 930, y), fill="#d6dfdf", width=1)
        ink.line((55, 0, 55, 320), fill="#e2a8a1", width=2)
        _text(ink, (80, 48), payload, face="hand", size=36, fill="#24456b", width=780)
        img = Image.new("RGB", (1000, 400), "#e6e9ed")
        note = note.rotate(2, resample=Image.Resampling.BICUBIC, expand=True, fillcolor="#e6e9ed")
        img.paste(note, ((1000 - note.width) // 2, (400 - note.height) // 2))
    elif variant == "stylized_logo":
        draw.regular_polygon((135, 140, 70), n_sides=6, rotation=30, fill="#3976ab")
        draw.ellipse((110, 115, 160, 165), fill="white")
        _text(draw, (245, 100), "Sample Orbit Co.", size=46)
        _text(draw, (60, 260), payload, size=24, width=880)
    elif variant == "tiny_text":
        _product(draw)
        _text(draw, (15, 365), payload, size=10, fill="#334155", width=970)
    elif variant == "white_on_white":
        _product(draw)
        _text(draw, (20, 345), payload, size=18, fill="#f5f5f5", width=960)
    elif variant == "multilingual":
        _text(draw, (40, 40), "Message", size=24)
        _text(draw, (40, 145), payload, face="cjk", size=32, width=920)
    elif variant == "chart_label":
        _text(draw, (40, 20), "Sample units by category", size=28)
        draw.line((90, 75, 90, 290, 950, 290), fill="#526779", width=3)
        for x, count, label in ((230, 12, "A"), (490, 28, "B"), (750, 19, "C")):
            draw.rectangle((x, 290 - count * 7, x + 110, 289), fill="#438dbb")
            _text(draw, (x + 40, 292), label, size=18)
            _text(draw, (x + 32, 255 - count * 7), str(count), size=18)
        _text(draw, (50, 340), payload, size=22, width=900)
    elif variant == "terminal":
        img = Image.new("RGB", (1000, 400), "#121820")
        draw = ImageDraw.Draw(img)
        draw.rectangle((0, 0, 1000, 45), fill="#303a46")
        for x, color in ((24, "#ef7878"), (50, "#efd478"), (76, "#78cf9d")):
            draw.ellipse((x, 16, x + 13, 29), fill=color)
        _text(draw, (120, 8), "terminal - sample session", face="mono", size=18, fill="#e1e7ed")
        _text(draw, (25, 90), "$ sample-tool status\nReady.\n" + payload,
              face="mono", size=20, fill="#d0e9d6", width=950)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue(), "image/png"


def _qr_png(code, scale, border):
    buf = io.BytesIO()
    code.save(buf, kind="png", scale=scale, border=border)
    return buf.getvalue()
