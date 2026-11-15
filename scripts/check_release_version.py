"""Reject unreleased builds before the release workflow publishes artifacts."""
import os
from pathlib import Path
import sys
import tomllib


def main() -> None:
    version = tomllib.loads(Path("pyproject.toml").read_text())["project"]["version"]
    tagged = os.environ.get("GITHUB_REF_TYPE") == "tag"
    if tagged:
        tag = os.environ["GITHUB_REF_NAME"]
        if tag != f"v{version}":
            sys.exit(f"Refusing release: tag {tag} must equal v{version}")
    if tagged or os.environ.get("RELEASE_TARGET") == "pypi":
        if "dev" in version.lower() or "+" in version:
            sys.exit(
                f"Refusing release: version {version} has a development or local segment; "
                "PyPI and GHCR publishing require a planned release version"
            )
    print(f"Release version check passed for {version}")


if __name__ == "__main__":
    main()
