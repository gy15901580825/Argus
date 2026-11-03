from unittest.mock import AsyncMock, patch

import pytest

from argus.targets.browser_use import BrowserUseSpec, BrowserUseTarget
from tests.test_transport_engine import spec_dict


def hosted_spec(**changes):
    return BrowserUseSpec(
        **{
            "transport": spec_dict(),
            "scenario_kind": "ui_phishing",
            "trap_mode": "hosted",
            "hosted": {"service_url": "https://hosted-trap.example"},
            **changes,
        }
    )


@pytest.mark.parametrize(
    "changes,message",
    [
        ({"trap_mode": "other"}, "trap_mode"),
        ({"hosted": None}, "hosted is required"),
        ({"trap_mode": "local"}, "hosted must be empty"),
        ({"transport": None, "agent_url": "https://agent.example"}, "requires transport"),
        ({"trap_host": "0.0.0.0"}, "hosted and local trap settings conflict"),
        ({"trap_port": 8000}, "hosted and local trap settings conflict"),
        ({"trap_public_url": "https://local.example"}, "hosted and local trap settings conflict"),
    ],
)
def test_hosted_mode_rejects_incompatible_configuration(changes, message):
    with pytest.raises(ValueError, match=message):
        hosted_spec(**changes)


@pytest.mark.parametrize(
    "settings,message",
    [
        ({"service_url": "http://hosted-trap.example"}, "service_url"),
        ({"service_url": "ftp://hosted-trap.example"}, "service_url"),
        ({"service_url": "https://hosted-trap.example/path"}, "origin"),
        ({"service_url": "https://hosted-trap.example/"}, "origin"),
        ({"service_url": "https://hosted-trap.example?q=1"}, "origin"),
        ({"service_url": "https://hosted-trap.example#x"}, "origin"),
        ({"service_url": "https://user:pass@hosted-trap.example"}, "origin"),
        ({"service_url": "https://hosted-trap.example:bad"}, "service_url"),
        ({"service_url": ""}, "service_url"),
        ({"service_url": "https://hosted-trap.example", "owner_token_env": "lower"}, "owner_token_env"),
        ({"service_url": "https://hosted-trap.example", "owner_token_env": "A" * 65}, "owner_token_env"),
        ({"service_url": "https://hosted-trap.example", "run_ttl_s": 0}, "run_ttl_s"),
        ({"service_url": "https://hosted-trap.example", "run_ttl_s": 86401}, "run_ttl_s"),
        ({"service_url": "https://hosted-trap.example", "run_ttl_s": True}, "run_ttl_s"),
    ],
)
def test_hosted_config_validates_operator_boundary(settings, message):
    with pytest.raises(ValueError, match=message):
        hosted_spec(hosted=settings)


@pytest.mark.parametrize("origin", ["https://hosted-trap.example", "http://127.0.0.1:8000", "http://localhost:8000"])
def test_hosted_config_accepts_https_and_loopback_http(origin):
    spec = hosted_spec(hosted={"service_url": origin})
    assert spec.hosted.service_url == origin
    assert spec.hosted.owner_token_env == "ARGUS_HOSTED_OWNER_TOKEN"
    assert spec.hosted.run_ttl_s == 86400


async def test_hosted_rejected_over_bridge_before_any_message():
    from argus.targets._base import TargetDeliveryError

    bridge = AsyncMock()
    with patch("argus.targets.browser_use._get_client_agent_ws", return_value=bridge):
        with pytest.raises(TargetDeliveryError, match="trap_mode=hosted runs only with --local"):
            await BrowserUseTarget(hosted_spec()).send_prompt("Read the page")
    assert bridge.send_and_wait.call_count == 0
