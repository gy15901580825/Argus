from unittest.mock import patch, MagicMock
from click.testing import CliRunner
from argus.cli.__main__ import main


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
    with patch("argus.cli.cmd_validate_target.httpx.post", return_value=fake_resp):
        runner = CliRunner()
        result = runner.invoke(main, ["validate-target", "--target", str(target_file)])
        assert result.exit_code == 0
        assert "OK" in result.output


def _ok_resp():
    fake_resp = MagicMock()
    fake_resp.status_code = 200
    fake_resp.json = lambda: {"choices": [{"message": {"content": "ok"}}]}
    return fake_resp


def test_validate_target_waits_as_long_as_run_does(tmp_path):
    # validate-target must not fail an agent that `run` would wait for.
    target_file = tmp_path / "t.yaml"
    target_file.write_text("endpoint_url: https://api.example.com/v1/chat/completions\nmodel: m\n")
    with patch("argus.cli.cmd_validate_target.httpx.post", return_value=_ok_resp()) as post:
        CliRunner().invoke(main, ["validate-target", "--target", str(target_file)])
    assert post.call_args.kwargs["timeout"] == 120.0

    target_file.write_text("endpoint_url: https://api.example.com/v1/chat/completions\nmodel: m\ntimeout_s: 45\n")
    with patch("argus.cli.cmd_validate_target.httpx.post", return_value=_ok_resp()) as post:
        CliRunner().invoke(main, ["validate-target", "--target", str(target_file)])
    assert post.call_args.kwargs["timeout"] == 45.0
