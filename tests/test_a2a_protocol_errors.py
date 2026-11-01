import pytest
from fastapi.testclient import TestClient
from argus.demo.a2a_testbed.demo_agent import app as demo
from test_a2a_testbed_wire import setup_peer, send, request


def assert_protocol_error(response, status, reason=None):
    assert response.status_code == status
    error = response.json()["error"]
    assert error["code"] == status and isinstance(error["message"], str)
    assert isinstance(error["status"], str) and isinstance(error["details"], list)
    if reason:
        assert error["details"] == [
            {
                "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                "reason": reason,
                "domain": "a2a-protocol.org",
            }
        ]


def test_peer_a2a_error_envelope_preserves_controller_contract():
    tb, control, peer, sid = setup_peer()
    assert_protocol_error(
        peer.get(f"/s/{sid}/peers/invoice-worker/tasks/missing"), 404, "TASK_NOT_FOUND"
    )
    assert_protocol_error(send(peer, sid, {}), 400, "INVALID_ARGUMENT")
    response = control.post(
        "/sessions", headers={"Authorization": "Bearer wrong"}, json={}
    )
    assert (
        response.status_code == 401
        and response.json()["code"] == "control_unauthorized"
    )
    assert "error" not in response.json()


@pytest.mark.parametrize(
    "case,status,reason",
    [
        ("version", 400, "VERSION_NOT_SUPPORTED"),
        ("authentication", 401, "UNAUTHENTICATED"),
        ("argument", 400, "INVALID_ARGUMENT"),
        ("invalid_json", 400, "INVALID_ARGUMENT"),
    ],
)
def test_demo_receiver_errors_are_standard_a2a(case, status, reason):
    credentials = {
        role: "Bearer error-" + role for role in ("planner", "reviewer", "executor")
    }
    demo.configure(peer_base_url="http://127.0.0.1:8080", credentials=credentials)
    headers = {"Authorization": credentials["planner"], "A2A-Version": "1.0"}
    if case == "version":
        headers.pop("A2A-Version")
    if case == "authentication":
        headers["Authorization"] = "Bearer incorrect"
    with TestClient(demo.app) as client:
        if case == "invalid_json":
            response = client.post(
                "/agents/reviewer/message:send", headers=headers, content=b"{"
            )
        else:
            response = client.post(
                "/agents/reviewer/message:send", headers=headers, json={}
            )
    assert_protocol_error(response, status, reason)
    assert "Bearer" not in response.text
