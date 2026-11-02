import base64
import itertools
import re
from urllib.parse import unquote


_FIELDS = ("path", "query", "body")


def _variants(value):
    values = [value]
    for _ in range(3):
        decoded = unquote(values[-1])
        if decoded == values[-1]:
            break
        values.append(decoded)
    unsupported = unquote(values[-1]) != values[-1]
    for text in tuple(values):
        unicode_text = re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m[1], 16)), text)
        if unicode_text != text:
            values.append(unicode_text)
        for candidate in re.findall(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{8,}={0,2}(?![A-Za-z0-9+/=])", text):
            try:
                decoded = base64.b64decode(candidate, validate=True).decode("utf-8")
            except (ValueError, UnicodeError):
                continue
            values.append(decoded)
    return values, unsupported


def match_markers(markers, parts, *, complete, combination=()):
    variants = {key: _variants(value) for key, value in parts.items()}
    unknown = not complete or any(item[1] for item in variants.values())
    hits = []
    for marker_id, value in markers.items():
        found = False
        squeezed = re.sub(r"[\s-]", "", value)
        has_separators = squeezed != value
        for location, (texts, _) in variants.items():
            if any(value in text for text in texts):
                hits.append({"marker_id": marker_id, "location": location})
                found = True
                continue
            if has_separators and any(squeezed in re.sub(r"[\s-]", "", text) for text in texts):
                if len(squeezed) >= 8:
                    hits.append({"marker_id": marker_id, "location": location})
                    found = True
                else:
                    unknown = True
        fields = [parts[key] for key in _FIELDS if key in parts]
        if not found and len(fields) > 1:
            if combination and set(combination) == set(parts) and value == "".join(parts[key] for key in combination):
                hits.append({"marker_id": marker_id, "location": "combined"})
            elif any(value == "".join(order) for order in itertools.permutations(fields)):
                unknown = True
    return {"status": "unknown" if unknown else "hit" if hits else "miss", "hits": hits}
