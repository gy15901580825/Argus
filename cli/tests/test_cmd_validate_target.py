from unittest.mock import patch, MagicMock
from click.testing import CliRunner
from argus_probe.__main__ import main


def test_validate_target_returns_ok_for_valid_endpoint(tmp_path):
    target_file = tmp_path / "t.yaml"
    target_file.write_text(
        "endpoint_url: https://api.example.com/v1/chat/completions\n"
        "model: gpt-4o-mini\n"
        "api_key: sk-test\n"
    )
    fake_resp = MagicMock()
    fake_resp.status_code = 200
    fake_resp.json = lambda: {"choices": [{"message": {"content": "ok"}}]}
    with patch("argus_probe.cmd_validate_target.httpx.post", return_value=fake_resp):
        runner = CliRunner()
        result = runner.invoke(main, ["validate-target", "--target", str(target_file)])
        assert result.exit_code == 0
        assert "OK" in result.output
