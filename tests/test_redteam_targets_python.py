"""The python target kind: a local function stands in for the agent."""
import asyncio
import textwrap
from pathlib import Path

import pytest

from argus.targets._base import TargetTransportError, Turn
from argus.targets.python_target import PythonSpec, PythonTarget, load_entry

FIXTURES = Path(__file__).parent / "fixtures" / "python_target"


def _entry(tmp_path, body, name="agent.py"):
    path = tmp_path / name
    path.write_text(textwrap.dedent(body))
    return f"{path}:call"


def _send(tmp_path, body, **spec):
    target = PythonTarget(PythonSpec(entry=_entry(tmp_path, body), **spec))
    return asyncio.run(target.send_prompt("hi")), target


@pytest.mark.parametrize("fixture", ["sync_target.py", "async_target.py"])
def test_sync_and_async_functions_both_answer(fixture):
    target = PythonTarget(PythonSpec(entry=f"{FIXTURES / fixture}:call"))
    text, _ = asyncio.run(target.send_prompt("hello"))
    assert text == "echo: hello | material=None"
    text, _ = asyncio.run(target.send_prompt("hello", material="doc"))
    assert text == "echo: hello | material='doc'"


def test_context_carries_history_conversation_and_probe(tmp_path):
    body = """
        def call(prompt, material, context):
            return {"output": repr(context)}
    """
    target = PythonTarget(PythonSpec(entry=_entry(tmp_path, body)))

    class _Probe:
        id = "probe_x"

    asyncio.run(target.begin_probe(_Probe()))
    history = (Turn("user", "q1"), Turn("assistant", "a1"))
    text, _ = asyncio.run(target.send_prompt("q2", history))
    context = eval(text)
    assert context["history"] == [
        {"role": "user", "content": "q1"},
        {"role": "assistant", "content": "a1"},
    ]
    assert context["probe_id"] == "probe_x"
    assert isinstance(context["conversation_id"], str) and context["conversation_id"]


def test_begin_probe_starts_a_new_conversation(tmp_path):
    body = """
        def call(prompt, material, context):
            return {"output": context["conversation_id"]}
    """
    target = PythonTarget(PythonSpec(entry=_entry(tmp_path, body)))

    class _Probe:
        id = "p"

    asyncio.run(target.begin_probe(_Probe()))
    first, _ = asyncio.run(target.send_prompt("a"))
    again, _ = asyncio.run(target.send_prompt("b"))
    asyncio.run(target.begin_probe(_Probe()))
    other, _ = asyncio.run(target.send_prompt("c"))
    assert first == again
    assert other != first


def test_output_required_error_maps_to_transport_error(tmp_path):
    body = """
        def call(prompt, material, context):
            return {"error": "SENTINEL-secret-detail"}
    """
    target = PythonTarget(PythonSpec(entry=_entry(tmp_path, body)))
    with pytest.raises(TargetTransportError) as exc:
        asyncio.run(target.send_prompt("hi"))
    assert str(exc.value) == "python_target_error"


def test_missing_output_is_mapping_error(tmp_path):
    body = """
        def call(prompt, material, context):
            return {}
    """
    target = PythonTarget(PythonSpec(entry=_entry(tmp_path, body)))
    with pytest.raises(TargetTransportError) as exc:
        asyncio.run(target.send_prompt("hi"))
    assert str(exc.value).startswith("mapping_error:")


def test_non_dict_and_non_str_output_are_mapping_errors(tmp_path):
    for returned in ('"just text"', '{"output": 7}'):
        body = f"""
            def call(prompt, material, context):
                return {returned}
        """
        target = PythonTarget(PythonSpec(entry=_entry(tmp_path, body)))
        with pytest.raises(TargetTransportError) as exc:
            asyncio.run(target.send_prompt("hi"))
        assert str(exc.value).startswith("mapping_error:")


def test_unknown_return_key_is_mapping_error(tmp_path):
    body = """
        def call(prompt, material, context):
            return {"output": "x", "extra": 1}
    """
    target = PythonTarget(PythonSpec(entry=_entry(tmp_path, body)))
    with pytest.raises(TargetTransportError) as exc:
        asyncio.run(target.send_prompt("hi"))
    assert str(exc.value) == "mapping_error: python target returned unknown keys"


def test_exception_records_class_name_only(tmp_path):
    body = """
        def call(prompt, material, context):
            raise KeyError("SENTINEL-secret-detail")
    """
    target = PythonTarget(PythonSpec(entry=_entry(tmp_path, body)))
    with pytest.raises(TargetTransportError) as exc:
        asyncio.run(target.send_prompt("hi"))
    assert str(exc.value) == "python_target_error: KeyError"
    assert "SENTINEL" not in str(exc.value)


def test_run_log_is_parsed(tmp_path):
    body = """
        def call(prompt, material, context):
            return {
                "output": "done",
                "run_log": {"events": [{"kind": "tool_call", "name": "t", "args": {}}]},
            }
    """
    target = PythonTarget(PythonSpec(entry=_entry(tmp_path, body)))
    assert target.last_run_log() is None
    text, _ = asyncio.run(target.send_prompt("hi"))
    assert text == "done"
    log = target.last_run_log()
    assert log is not None and len(log.events) == 1


def test_invalid_run_log_is_mapping_error(tmp_path):
    body = """
        def call(prompt, material, context):
            return {"output": "done", "run_log": 5}
    """
    target = PythonTarget(PythonSpec(entry=_entry(tmp_path, body)))
    with pytest.raises(TargetTransportError) as exc:
        asyncio.run(target.send_prompt("hi"))
    assert str(exc.value).startswith("mapping_error:")


@pytest.mark.parametrize("kind", ["sync", "async"])
def test_latency_measured_by_argus(tmp_path, kind):
    prefix = "async " if kind == "async" else ""
    sleep = "await asyncio.sleep(0.05)" if kind == "async" else "time.sleep(0.05)"
    body = f"""
        import asyncio, time

        {prefix}def call(prompt, material, context):
            {sleep}
            return {{"output": "slow", "latency_ms": 1}}
    """
    # A function cannot report its own latency: the key is unknown.
    target = PythonTarget(PythonSpec(entry=_entry(tmp_path, body)))
    with pytest.raises(TargetTransportError):
        asyncio.run(target.send_prompt("hi"))
    body = body.replace(', "latency_ms": 1', "")
    target = PythonTarget(PythonSpec(entry=_entry(tmp_path, body, "agent2.py")))
    _, latency_ms = asyncio.run(target.send_prompt("hi"))
    assert 50 <= latency_ms < 1000


@pytest.mark.parametrize("kind", ["sync", "async"])
def test_timeout_maps_to_error(tmp_path, kind):
    prefix = "async " if kind == "async" else ""
    sleep = "await asyncio.sleep(1)" if kind == "async" else "time.sleep(1)"
    body = f"""
        import asyncio, time

        {prefix}def call(prompt, material, context):
            {sleep}
            return {{"output": "late"}}
    """
    target = PythonTarget(PythonSpec(entry=_entry(tmp_path, body), timeout_s=0.05))
    with pytest.raises(TimeoutError) as exc:
        asyncio.run(target.send_prompt("hi"))
    assert str(exc.value) == "timeout: python target exceeded timeout_s"


def test_module_and_path_entry_load(tmp_path, monkeypatch):
    path = tmp_path / "pkg_agent.py"
    path.write_text('def call(p, m, c):\n    return {"output": "mod"}\n')
    monkeypatch.syspath_prepend(str(tmp_path))
    assert load_entry("pkg_agent:call")("x", None, {}) == {"output": "mod"}
    assert load_entry(f"{path}:call")("x", None, {}) == {"output": "mod"}


def test_load_entry_rejects_missing_or_uncallable_attribute(tmp_path):
    path = tmp_path / "agent.py"
    path.write_text("VALUE = 3\n")
    with pytest.raises(ValueError):
        load_entry(f"{path}:missing")
    with pytest.raises(ValueError):
        load_entry(f"{path}:VALUE")


def test_load_failure_maps_to_transport_error(tmp_path):
    path = tmp_path / "agent.py"
    path.write_text('raise RuntimeError("SENTINEL-secret-detail")\n')
    target = PythonTarget(PythonSpec(entry=f"{path}:call"))
    with pytest.raises(TargetTransportError) as exc:
        asyncio.run(target.send_prompt("hi"))
    assert str(exc.value) == "python_target_error: cannot load entry: RuntimeError"


def test_constructing_the_target_does_not_import(tmp_path, monkeypatch):
    marker = tmp_path / "marker"
    monkeypatch.setenv("ARGUS_TEST_IMPORT_MARKER", str(marker))
    target = PythonTarget(PythonSpec(entry=f"{FIXTURES / 'import_marker.py'}:call"))
    assert not marker.exists()
    text, _ = asyncio.run(target.send_prompt("hi"))
    assert text == "marker target answered"
    assert marker.read_text() == "imported"


@pytest.mark.parametrize(
    "bad",
    [
        {"entry": ""},
        {"entry": "no_colon"},
        {"entry": "mod:not an identifier"},
        {"entry": "dir/agent.txt:call"},
        {"entry": "/nonexistent/dir/agent.py:call"},
        {"entry": "mod:call", "timeout_s": 0},
        {"entry": "mod:call", "kind": "custom_http"},
    ],
)
def test_spec_rejects_malformed_entries(bad):
    with pytest.raises(ValueError):
        PythonSpec(**bad)


def test_history_flag_drives_supports_history():
    assert PythonTarget(PythonSpec(entry="mod:call")).supports_history is True
    assert PythonTarget(PythonSpec(entry="mod:call", history=False)).supports_history is False


def test_python_target_serves_the_same_probes_as_custom_http():
    from argus.targets.custom_http import CustomHTTPTarget

    assert PythonTarget.compatible_classes == CustomHTTPTarget.compatible_classes
    assert PythonTarget.material_channel is True


MESSAGE = "python targets run only on the local machine: use argus-probe run --local"


def _python_spec(entry):
    return {"kind": "python", "entry": entry}


def test_build_target_denies_python_by_default():
    from argus.targets import build_target

    with pytest.raises(ValueError) as exc:
        build_target(_python_spec("mod:call"))
    assert str(exc.value) == MESSAGE


def test_trusted_build_returns_python_target():
    from argus.targets import build_target

    target = build_target(_python_spec("mod:call"), trusted_code=True)
    assert isinstance(target, PythonTarget)
    assert target.spec.entry == "mod:call"


def _nested(entry, *, depth):
    inner = _python_spec(entry)
    for _ in range(depth):
        inner = {
            "kind": "payment_agent",
            "testbed_url": "http://127.0.0.1:1",
            "sandbox": True,
            "inner": inner,
        }
    return inner


@pytest.mark.parametrize("depth", [1, 2])
@pytest.mark.parametrize("trusted", [False, True])
def test_inner_python_is_denied_in_every_mode(tmp_path, monkeypatch, depth, trusted):
    from argus.targets import build_target

    marker = tmp_path / "marker"
    monkeypatch.setenv("ARGUS_TEST_IMPORT_MARKER", str(marker))
    spec = _nested(f"{FIXTURES / 'import_marker.py'}:call", depth=depth)
    with pytest.raises(ValueError) as exc:
        build_target(spec, trusted_code=trusted)
    assert str(exc.value) == "a python target cannot be nested in inner"
    assert not marker.exists()


def test_relative_path_is_relative_to_spec_file(tmp_path, monkeypatch):
    from argus.cli.target_loader import load_target_spec

    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "agent.py").write_text("def call(p, m, c):\n    return {'output': 'x'}\n")
    spec_file = tmp_path / "sub" / "target.json"
    spec_file.write_text('{"kind": "python", "entry": "agent.py:call"}')
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    spec = load_target_spec(str(spec_file))
    assert spec["entry"] == f"{tmp_path / 'sub' / 'agent.py'}:call"


def test_inline_json_and_module_entries_are_left_alone(tmp_path, monkeypatch):
    from argus.cli.target_loader import load_target_spec

    monkeypatch.chdir(tmp_path)
    assert load_target_spec('{"kind": "python", "entry": "agent.py:call"}')["entry"] == "agent.py:call"
    spec_file = tmp_path / "t.json"
    spec_file.write_text('{"kind": "python", "entry": "pkg.mod:call"}')
    assert load_target_spec(str(spec_file))["entry"] == "pkg.mod:call"


def test_loader_requires_entry():
    from argus.cli.target_loader import TargetLoadError, load_target_spec

    with pytest.raises(TargetLoadError, match="missing required fields: \\['entry'\\]"):
        load_target_spec('{"kind": "python"}')
