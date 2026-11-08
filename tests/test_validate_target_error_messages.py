import json
import socket

import pytest
from click.testing import CliRunner

from argus.cli.__main__ import main
from test_transport_engine import spec_dict


@pytest.fixture(autouse=True)
def no_requests(monkeypatch):
    calls = []

    def reject_request(*args):
        calls.append(args)
        raise AssertionError("offline validation must not send a request")

    monkeypatch.setattr(socket.socket, "connect", reject_request)
    monkeypatch.setattr(socket.socket, "connect_ex", reject_request)
    yield
    assert calls == []


def target_spec(site):
    if site == "v1":
        return {"kind": "custom_http", "transport": spec_dict()}
    return {
        "kind": "custom_http",
        "request_url": "http://127.0.0.1:1/run",
        "request_body_template": '{"input": {{prompt|tojson}}}',
        "response_jsonpath": "$.answer",
    }


def invoke(tmp_path, spec):
    path = tmp_path / "target.json"
    path.write_text(json.dumps(spec))
    return CliRunner().invoke(main, ["validate-target", "--target", str(path), "--offline"])


@pytest.mark.parametrize("site", ["legacy", "v1"])
def test_offline_invalid_target_names_the_bad_field(tmp_path, site):
    spec = target_spec(site)
    if site == "legacy":
        spec["request_body_template"] = "{{ prompt | bad_field }}"
    else:
        spec["transport"]["request"]["body"]["json"]["goal"] = {"context": "bad_field"}
    result = invoke(tmp_path, spec)
    assert result.exit_code == 1
    assert "target spec invalid: ValueError:" in result.output
    assert "bad_field" in result.output
    assert "Traceback" not in result.output


@pytest.mark.parametrize("site", ["legacy", "v1"])
def test_offline_target_error_masks_the_spec_header(tmp_path, monkeypatch, site):
    marker = "synthetic-header-marker"
    spec = target_spec(site)
    if site == "legacy":
        spec["request_headers"] = {"X-Test": marker}
    else:
        spec["transport"]["request"]["headers"] = {"X-Test": marker}

    def reject_spec(*args, **kwargs):
        raise ValueError(f"bad_field rejected {marker}")

    monkeypatch.setattr("argus.targets.build_target", reject_spec)
    result = invoke(tmp_path, spec)
    assert result.exit_code == 1
    assert "target spec invalid: ValueError:" in result.output
    assert "bad_field rejected ***" in result.output
    assert marker not in result.output
    assert "Traceback" not in result.output


@pytest.mark.parametrize("site", ["legacy", "v1"])
def test_offline_valid_target_still_succeeds_without_requests(tmp_path, site):
    result = invoke(tmp_path, target_spec(site))
    assert result.exit_code == 0, result.output
    assert "requests.submit=0 requests.poll=0 requests.retry=0" in result.output
