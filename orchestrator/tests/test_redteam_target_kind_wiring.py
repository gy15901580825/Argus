"""每个 target 适配器都必须一路接到产品入口,否则客户根本用不到它。

`orchestrator/redteam/targets/__init__.py::_BUILDERS` 是适配器的真源,但客
户不是从 orchestrator 内部接口进来的:请求先过 api_service 的 `TargetSpec`
判别联合(不认识的 kind → 422),再过 CLI 的 `_KNOWN_KINDS` 预检(不认识的
kind → 本地就被拒)。这三份清单任意一处漏掉一种 kind,那种 kind 的探针、
rubric、testbed 全都是死代码——而且是静默的死代码,没有任何测试会红。

payment_agent 和 mcp_agent 先后各栽过一次同样的跟头,http_upload 更是从来
没被接上过。这个漂移守卫存在的意义就是:第 9 个适配器加进 `_BUILDERS` 的
那一刻,如果没同步这两处,它立刻变红。

这里用文件路径直接加载另外两个服务的模块,而不是 import 它们的包——两个
服务各有自己的依赖与 sys.path,而这份守卫必须在 orchestrator 这一个 CI job
里就能跑起来。被加载的两个文件都只依赖标准库和 pydantic。
"""
import importlib.util
import json
import sys
from pathlib import Path
from typing import get_args

import pytest

REPO = Path(__file__).resolve().parents[2]
API_SCHEMAS = REPO / "api_service" / "redteam" / "schemas.py"
CLI_LOADER = REPO / "cli" / "argus_probe" / "target_loader.py"


def _load(module_name: str, path: Path):
    assert path.is_file(), f"{path} is missing; this guard cannot check what it cannot read"
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _builder_kinds() -> set[str]:
    from orchestrator.redteam.targets import _BUILDERS

    return set(_BUILDERS)


def _api_service_kinds() -> set[str]:
    """The `kind` literals actually reachable through the TargetSpec union.

    Read off the union members rather than off the classes in the file: a model
    that exists but was never added to the union is exactly the bug this guards.
    """
    schemas = _load("_wiring_api_schemas", API_SCHEMAS)
    # TargetSpec is Annotated[Union[...], Field(discriminator="kind")].
    members = get_args(get_args(schemas.TargetSpec)[0])
    kinds = {get_args(m.model_fields["kind"].annotation)[0] for m in members}
    assert kinds, "could not read any kind out of TargetSpec — the guard has gone blind"
    return kinds


def _cli_kinds() -> set[str]:
    loader = _load("_wiring_cli_target_loader", CLI_LOADER)
    kinds = set(loader._KNOWN_KINDS)
    assert kinds, "could not read _KNOWN_KINDS — the guard has gone blind"
    return kinds


def test_every_adapter_is_reachable_through_the_api_service_union():
    missing = sorted(_builder_kinds() - _api_service_kinds())
    assert not missing, (
        f"{missing} are registered adapters that api_service's TargetSpec union "
        f"rejects with 422 — every probe, rubric and testbed behind them is "
        f"unreachable for any customer"
    )


def test_every_adapter_is_reachable_through_the_cli():
    missing = sorted(_builder_kinds() - _cli_kinds())
    assert not missing, (
        f"{missing} are registered adapters that `argus-probe` refuses locally "
        f"before the request is ever sent"
    )


def test_the_two_client_side_lists_do_not_invent_kinds_of_their_own():
    """The other direction: a kind offered to customers that no adapter serves
    is a 500 waiting to happen, not a 422."""
    builders = _builder_kinds()
    assert not sorted(_api_service_kinds() - builders)
    assert not sorted(_cli_kinds() - builders)


@pytest.mark.parametrize("kind", ["payment_agent", "mcp_agent"])
def test_world_acting_adapters_demand_sandbox_true_on_both_client_paths(kind):
    """`sandbox` is a safety interlock, not a convenience default: these two
    adapters move real money / reach a real MCP server if it is wrong. The
    orchestrator refuses a falsy sandbox, but it must not be the only refusal —
    a spec that never reaches the orchestrator must still be rejected."""
    import pydantic

    schemas = _load("_wiring_api_schemas", API_SCHEMAS)
    loader = _load("_wiring_cli_target_loader", CLI_LOADER)
    adapter = pydantic.TypeAdapter(schemas.TargetSpec)

    base = {"kind": kind, "testbed_url": "https://tb.example.com",
            "inner": {"kind": "openai_compat", "endpoint_url": "https://x", "model": "y"}}
    for bad in ({**base}, {**base, "sandbox": False}):
        with pytest.raises(pydantic.ValidationError):
            adapter.validate_python(bad)
        with pytest.raises(loader.TargetLoadError):
            loader.load_target_spec(json.dumps(bad))

    adapter.validate_python({**base, "sandbox": True})
    assert loader.load_target_spec(json.dumps({**base, "sandbox": True}))
