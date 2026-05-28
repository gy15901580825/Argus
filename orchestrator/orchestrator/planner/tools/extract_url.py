"""extract_url tool — pull http/https URLs from raw text via regex."""

from __future__ import annotations

import json
import re
from typing import Any, AsyncGenerator

_FULL = re.compile(r"https?://[^\s\"'<>]+")
_WWW = re.compile(r"(?<![:/])www\.[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}[^\s\"'<>]*")


async def extract_url(*, text: str, ctx: Any) -> AsyncGenerator[dict, None]:
    urls = [m.rstrip(".,;:)") for m in _FULL.findall(text)]
    for m in _WWW.findall(text):
        cleaned = "https://" + m.rstrip(".,;:)")
        if cleaned not in urls:
            urls.append(cleaned)
    yield {"is_terminal": True, "result": json.dumps(urls)}
