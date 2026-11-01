from fastapi.testclient import TestClient

from demo_agent import app as demo


def test_demo_health_card_and_version_boundary():
    credentials = {r: "Bearer smoke-" + r for r in ("planner", "reviewer", "executor")}
    demo.configure(peer_base_url="http://127.0.0.1:8080", credentials=credentials)
    with TestClient(demo.app) as agent:
        assert agent.get("/healthz").json() == {"status": "ok"}
        for role in ("reviewer", "executor"):
            card = agent.get("/agents/" + role + "/.well-known/agent-card.json").json()
            assert card["supportedInterfaces"][0]["protocolVersion"] == "1.0"
            assert card["supportedInterfaces"][0]["protocolBinding"] == "HTTP+JSON"
            assert card["securityRequirements"]
        response = agent.post(
            "/agents/reviewer/message:send",
            headers={"Authorization": credentials["planner"]},
            json={},
        )
        assert response.status_code == 400
        assert response.json()["error"]["details"][0]["reason"] == "VERSION_NOT_SUPPORTED"
