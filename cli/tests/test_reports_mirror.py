"""The CLI renders reports with a copy of api_service's renderer. Keep them identical."""

from pathlib import Path

import pytest

_CLI_PKG = Path(__file__).resolve().parents[1] / "argus_probe"
_API_SERVICE = Path(__file__).resolve().parents[2] / "api_service" / "redteam"

pytestmark = pytest.mark.skipif(
    not _API_SERVICE.exists(), reason="api_service checkout not present (installed from a wheel)"
)


def test_reports_module_matches_api_service_copy():
    assert (_CLI_PKG / "reports.py").read_bytes() == (_API_SERVICE / "reports.py").read_bytes()


def test_report_template_matches_api_service_copy():
    assert (
        (_CLI_PKG / "templates" / "report.html.j2").read_bytes()
        == (_API_SERVICE / "templates" / "report.html.j2").read_bytes()
    )
