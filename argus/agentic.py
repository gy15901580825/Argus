"""The official OWASP Agentic Top 10 taxonomy, loaded from packaged data."""
from importlib.resources import files

import yaml


_taxonomy = yaml.safe_load(
    files("argus").joinpath("data/owasp_agentic_top10.yaml").read_text(encoding="utf-8")
)
OWASP_AGENTIC_TOP10: tuple[tuple[str, str], ...] = tuple(
    (category["id"], category["name"]) for category in _taxonomy["categories"]
)
VALID_OWASP_AGENTIC_IDS = frozenset(category_id for category_id, _ in OWASP_AGENTIC_TOP10)
if tuple(category_id for category_id, _ in OWASP_AGENTIC_TOP10) != tuple(
    f"ASI{i:02}" for i in range(1, 11)
):
    raise ValueError("OWASP Agentic taxonomy must contain ASI01 through ASI10 in order")

OWASP_AGENTIC_METADATA = {
    key: _taxonomy[key] for key in ("framework", "edition", "published", "source_url", "sources")
}
