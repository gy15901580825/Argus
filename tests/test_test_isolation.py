"""The test session must not see real credentials or reach a model provider."""

from __future__ import annotations

import os
from pathlib import Path

import pytest


def test_no_provider_credentials_are_visible():
    leaked = sorted(k for k in os.environ
                    if (k.endswith(("_API_KEY", "_API_TOKEN")) or k.startswith(("AWS_ACCESS", "AWS_SECRET",
                                                                                "AWS_SESSION", "AWS_PROFILE",
                                                                                "GOOGLE_API", "TYPESAFE_")))
                    and k not in {"AZURE_OPENAI_API_KEY"})  # conftest's own dummy value
    assert leaked == []
    assert os.environ.get("HF_TOKEN") is None and os.environ.get("ANTHROPIC_AUTH_TOKEN") is None


def test_home_and_cloud_config_point_into_a_temp_dir(tmp_path_factory):
    base = tmp_path_factory.getbasetemp()
    for name in ("HOME", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "CLOUDSDK_CONFIG",
                 "GOOGLE_APPLICATION_CREDENTIALS"):
        assert Path(os.environ[name]).is_relative_to(base), name
    assert Path.home().is_relative_to(base)
    assert not (Path.home() / ".aws").exists()
    assert os.environ["AWS_EC2_METADATA_DISABLED"] == "true"


async def test_an_unmocked_llm_call_is_refused_and_recorded(llm_call_guard):
    import litellm

    from argus import llm

    with pytest.raises(RuntimeError, match="real LLM call"):
        await litellm.acompletion(model="mistral/m", messages=[])
    with pytest.raises(RuntimeError, match="real LLM call"):
        litellm.completion(model="mistral/m", messages=[])
    with pytest.raises(RuntimeError, match="real LLM call"):
        await llm.complete(llm.resolve_config({"ANTHROPIC_API_KEY": "unused"}), role="fast", system="s", user="u",
                           max_tokens=1)
    assert [c["model"] for c in llm_call_guard] == ["mistral/m", "mistral/m", "anthropic client", "azure/gpt-5.4-mini"]
    llm_call_guard.clear()  # the guard fails a test that made such a call; this one expected it


def test_litellm_uses_its_bundled_price_map():
    # Without this, importing litellm downloads the map from GitHub and the suite needs the network.
    assert os.environ.get("LITELLM_LOCAL_MODEL_COST_MAP") == "True"
