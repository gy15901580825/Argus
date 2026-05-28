from unittest.mock import patch
from click.testing import CliRunner

from argus_probe.__main__ import main


def test_report_writes_existing_run(tmp_path):
    runner = CliRunner()
    out_file = tmp_path / "out.html"
    with patch("argus_probe.api_client.get_report", return_value="<html>R</html>"):
        result = runner.invoke(main, [
            "report",
            "--run-id", "abc-123",
            "--format", "html",
            "--out", str(out_file),
            "--token", "t",
            "--api-url", "https://x",
        ])
        assert result.exit_code == 0
        assert out_file.read_text() == "<html>R</html>"
