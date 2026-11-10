"""Bundled, subsetted fonts: reject unsupported text before drawing it."""

from functools import lru_cache
from pathlib import Path

FONT_DIR = Path(__file__).with_name("fonts")
FONT_VARIANTS = {"handwritten": "hand", "multilingual": "cjk", "terminal": "mono"}


@lru_cache(maxsize=None)
def charset(face: str) -> frozenset[str]:
    return frozenset((FONT_DIR / f"{face}.charset.txt").read_text(encoding="utf-8"))


def validate_text(text: str, face: str) -> None:
    missing = set(text) - charset(face) - {"\n", "\r", "\t"}
    if missing:
        names = ", ".join(f"{char!r} (U+{ord(char):04X})" for char in sorted(missing))
        raise ValueError(f"bundled {face} font lacks characters: {names}")


@lru_cache(maxsize=None)
def font_bytes(face: str) -> bytes:
    suffix = ".otf" if face == "cjk" else ".ttf"
    return (FONT_DIR / f"{face}{suffix}").read_bytes()


def load_font(face: str, size: int):
    import io
    from PIL import ImageFont

    return ImageFont.truetype(io.BytesIO(font_bytes(face)), size)
