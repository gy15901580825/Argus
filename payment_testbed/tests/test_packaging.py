"""What the image needs, not just what the tests need.

The demo agent imports httpx lazily and the unit tests inject a TestClient
instead, so a missing dependency stayed invisible until the container returned
500 on its first real fetch.
"""

from pathlib import Path

REQS = Path(__file__).resolve().parents[1] / "requirements.txt"


def test_runtime_dependencies_cover_the_real_http_path():
    text = REQS.read_text()
    for pkg in ("fastapi", "uvicorn", "httpx"):
        assert pkg in text, f"{pkg} missing from requirements.txt"


def test_no_chain_client_is_declared():
    """Real settlement must be absent, not disabled."""
    text = REQS.read_text().lower()
    for forbidden in ("web3", "eth-account", "solana"):
        assert forbidden not in text
