from unittest.mock import patch
from click.testing import CliRunner

from argus.cli.__main__ import main


def test_report_writes_existing_run(tmp_path):
    runner = CliRunner()
    out_file = tmp_path / "out.html"
    with patch("argus.cli.api_client.get_report", return_value="<html>R</html>"):
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


def _report_args(out_file):
    return ["report", "--run-id", "abc-123", "--format", "html", "--out", str(out_file),
            "--token", "t", "--api-url", "https://x"]


def test_report_out_in_missing_dir_exits_2_before_fetching(tmp_path):
    out_file = tmp_path / "missing" / "out.html"
    with patch("argus.cli.api_client.get_report", return_value="<html>R</html>") as get_report:
        result = CliRunner().invoke(main, _report_args(out_file))
    assert result.exit_code == 2, result.output
    assert f"the directory {out_file.parent} does not exist" in result.output
    get_report.assert_not_called()


def test_report_write_error_exits_1_without_traceback(tmp_path):
    out_dir = tmp_path / "out.html"
    out_dir.mkdir()  # a directory where the file should go, so the write fails
    with patch("argus.cli.api_client.get_report", return_value="<html>R</html>"):
        result = CliRunner().invoke(main, _report_args(out_dir))
    assert result.exit_code == 1, result.output
    assert f"Error: cannot write {out_dir}:" in result.stderr
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "Wrote" not in result.output
