from orchestrator.planner.wizard_guides import GUIDES


def test_guides_has_required_keys():
    assert set(GUIDES.keys()) == {"client_agent_install", "cdp_browser_launch"}


def test_client_agent_install_is_non_trivial():
    g = GUIDES["client_agent_install"]
    assert len(g) > 200
    # Must mention docker run + the public image name
    assert "docker run" in g
    assert "<your-gh-user>/client_agent" in g


def test_cdp_browser_launch_has_port_9222():
    g = GUIDES["cdp_browser_launch"]
    assert "--remote-debugging-port=9222" in g
