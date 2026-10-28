import os
from pathlib import Path

import pytest

_HERE = Path(__file__).resolve().parent


def pytest_collection_modifyitems(config, items):
    skip_e2e = pytest.mark.skip(reason="set ARGUS_E2E=1 + ANTHROPIC_API_KEY + TARGET_API_KEY to run")
    for item in items:
        # This hook sees every collected item: match this directory, not "e2e" anywhere in the absolute path.
        if "e2e" in item.keywords or Path(item.path).resolve().is_relative_to(_HERE):
            if not (
                os.environ.get("ARGUS_E2E") == "1"
                and os.environ.get("ANTHROPIC_API_KEY")
                and os.environ.get("TARGET_API_KEY")
            ):
                item.add_marker(skip_e2e)
