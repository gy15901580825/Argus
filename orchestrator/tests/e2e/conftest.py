import os
import pytest


def pytest_collection_modifyitems(config, items):
    skip_e2e = pytest.mark.skip(reason="set ARGUS_E2E=1 + ANTHROPIC_API_KEY + TARGET_API_KEY to run")
    for item in items:
        if "e2e" in item.keywords or "e2e" in str(item.fspath):
            if not (
                os.environ.get("ARGUS_E2E") == "1"
                and os.environ.get("ANTHROPIC_API_KEY")
                and os.environ.get("TARGET_API_KEY")
            ):
                item.add_marker(skip_e2e)
