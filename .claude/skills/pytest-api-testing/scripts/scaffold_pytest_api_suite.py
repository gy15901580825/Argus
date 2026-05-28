#!/usr/bin/env python3
"""Scaffold a pytest + requests API test suite."""

from __future__ import annotations

import argparse
import os
from textwrap import dedent


def _write_file(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)


def _conftest_content(base_url: str) -> str:
    return dedent(
        f"""
        import os
        import pytest
        import requests


        @pytest.fixture(scope="session")
        def base_url():
            return os.getenv("API_BASE_URL", "{base_url}")


        @pytest.fixture(scope="session")
        def api_client():
            return requests.Session()
        """
    ).lstrip()


def _reqres_tests() -> str:
    return dedent(
        """
        import requests


        def test_get_list_of_users(base_url):
            response = requests.get(f"{base_url}/api/users")
            assert response.status_code == 200


        def test_create_new_user(base_url):
            payload = {"name": "Paulo Oliveira", "movies": ["I Love You Man", "Role Models"]}
            response = requests.post(f"{base_url}/api/users", data=payload)
            assert response.status_code == 201


        def test_update_user(base_url):
            payload = {"name": "Paulo Updated"}
            response = requests.put(f"{base_url}/api/users/2", data=payload)
            assert response.status_code == 200


        def test_delete_user(base_url):
            response = requests.delete(f"{base_url}/api/users/2")
            assert response.status_code == 204
        """
    ).lstrip()


def _generic_tests() -> str:
    return dedent(
        """
        import requests


        def test_health_or_ping(base_url):
            response = requests.get(f"{base_url}/health")
            assert response.status_code in (200, 204, 404)


        def test_get_resource_list(base_url):
            response = requests.get(f"{base_url}/resources")
            assert response.status_code == 200


        def test_create_resource(base_url):
            payload = {"name": "example", "status": "active"}
            response = requests.post(f"{base_url}/resources", json=payload)
            assert response.status_code in (200, 201)
        """
    ).lstrip()


def _requirements_content() -> str:
    return """pytest>=7.0
requests>=2.31
"""


def main() -> None:
    parser = argparse.ArgumentParser(description="Scaffold pytest API test suite")
    parser.add_argument("--output", default="tests", help="Output directory for tests")
    parser.add_argument("--base-url", default="https://reqres.in", help="Base URL for API")
    parser.add_argument(
        "--template",
        choices=["reqres", "generic"],
        default="generic",
        help="Template suite to generate",
    )
    parser.add_argument(
        "--with-requirements",
        action="store_true",
        help="Generate a requirements.txt next to the output directory",
    )
    args = parser.parse_args()

    tests_dir = os.path.abspath(args.output)
    conftest_path = os.path.join(tests_dir, "conftest.py")
    test_file_path = os.path.join(tests_dir, "test_api_smoke.py")

    _write_file(conftest_path, _conftest_content(args.base_url))

    if args.template == "reqres":
        _write_file(test_file_path, _reqres_tests())
    else:
        _write_file(test_file_path, _generic_tests())

    if args.with_requirements:
        requirements_path = os.path.join(os.path.dirname(tests_dir), "requirements.txt")
        _write_file(requirements_path, _requirements_content())

    print(f"Scaffold created in: {tests_dir}")


if __name__ == "__main__":
    main()
"}