"""Fresh-process tests for registry admission and instance probe selection."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "registry_plugin"


def install_plugin(
    path, *, entries="registry_fixture = generic_plugin:adapter", pack=True
):
    shutil.copytree(
        FIXTURE / "generic_plugin", path / "generic_plugin", dirs_exist_ok=True
    )
    dist = path / "generic_registry_fixture-0.0.0.dist-info"
    dist.mkdir(exist_ok=True)
    (dist / "METADATA").write_text(
        "Metadata-Version: 2.1\nName: generic-registry-fixture\nVersion: 0.0.0\n"
    )
    text = "[argus.targets]\n" + entries + "\n"
    if pack:
        text += "[argus.probe_packs]\ngeneric = generic_plugin:probes_dir\n"
    (dist / "entry_points.txt").write_text(text)
    return dist


def fresh(path, code, *args, input=None):
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.endswith(("_API_KEY", "_API_TOKEN"))
    }
    env["LITELLM_LOCAL_MODEL_COST_MAP"] = "True"
    bootstrap = f"import sys; sys.path[:0] = {[str(ROOT), str(path)]!r}; "
    return subprocess.run(
        [sys.executable, "-c", bootstrap + code, *args],
        cwd=path,
        env=env,
        input=input,
        text=True,
        capture_output=True,
        check=False,
        timeout=60,
    )


def cli(path, *args, input=None):
    return fresh(
        path, "from argus.cli.__main__ import main; main()", *args, input=input
    )


def assert_ok(result):
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.fixture
def plugin(tmp_path):
    install_plugin(tmp_path)
    return tmp_path


def spec_file(path, **overrides):
    spec = {"kind": "registry_fixture", "token": str(path / "sends"), **overrides}
    file = path / "target.json"
    file.write_text(json.dumps(spec))
    return file


def test_loader_admits_plugin_and_derives_only_required_init_fields(plugin):
    r = fresh(
        plugin,
        "from argus.cli.target_loader import check_target_spec; import json; "
        "print(json.dumps(check_target_spec({'kind':'registry_fixture', 'token':'count'})[0]))",
    )
    assert_ok(r)
    assert json.loads(r.stdout) == {"kind": "registry_fixture", "token": "count"}
    r = fresh(
        plugin,
        "from argus.cli.target_loader import check_target_spec; "
        "check_target_spec({'kind':'registry_fixture'})",
    )
    assert r.returncode != 0
    assert (
        "target.kind='registry_fixture' missing required fields: ['token']" in r.stderr
    )


@pytest.mark.parametrize(
    "transport", ["plugin protocol", {"version": 2, "protocol": "generic"}]
)
def test_validate_offline_accepts_plugin_transport_and_rejects_missing_field(
    plugin, transport
):
    r = cli(
        plugin,
        "validate-target",
        "--offline",
        "--target",
        str(spec_file(plugin, transport=transport)),
    )
    assert_ok(r)
    assert "valid; requests.submit=0 requests.poll=0 requests.retry=0" in r.stdout
    assert not (plugin / "sends").exists()
    (plugin / "target.json").write_text('{"kind":"registry_fixture"}')
    r = cli(
        plugin, "validate-target", "--offline", "--target", str(plugin / "target.json")
    )
    assert r.returncode == 1
    assert "missing required fields: ['token']" in r.stderr


def test_local_run_uses_instance_compatibility_and_sends_once(plugin):
    r = cli(
        plugin,
        "run",
        "--local",
        "--target",
        str(spec_file(plugin)),
        "--probes",
        "registry_fixture_applicable,registry_fixture_nonapplicable",
        "--format",
        "json",
        "--out",
        "run.json",
    )
    assert_ok(r)
    report = json.loads((plugin / "run.json").read_text())
    assert [(f["probe_id"], f["verdict"]) for f in report["findings"]] == [
        ("registry_fixture_applicable", "pass"),
        ("registry_fixture_nonapplicable", "skipped"),
    ]
    assert (plugin / "sends").read_text() == "1"


def test_list_probes_selects_exact_instance_ids(plugin):
    r = cli(
        plugin,
        "list-probes",
        "--target",
        str(spec_file(plugin)),
        "--filter",
        "registry_fixture_",
    )
    assert_ok(r)
    assert r.stdout == "registry_fixture_applicable\n\n1 probes\n"


def test_init_offers_plugin_and_prompts_for_required_field(plugin):
    r = cli(plugin, "init", "--help")
    assert_ok(r)
    assert "registry_fixture" in r.stdout
    r = cli(
        plugin, "init", "--kind", "registry_fixture", "--no-workflow", input="count\n"
    )
    assert_ok(r)
    assert "token:" in r.stdout
    assert json.loads((plugin / "argus-target.json").read_text()) == {
        "kind": "registry_fixture",
        "token": "count",
    }
    r = fresh(
        plugin,
        "from argus.cli import cmd_init; cmd_init._stdin_is_tty = lambda: True; cmd_init.init_command()",
        "--output",
        "interactive.json",
        "--no-workflow",
        input="registry_fixture\ncount\n",
    )
    assert_ok(r)
    assert "registry_fixture" in r.stdout
    assert json.loads((plugin / "interactive.json").read_text())["token"] == "count"


def test_removed_plugin_is_unknown_in_a_fresh_process(plugin):
    assert_ok(
        cli(plugin, "validate-target", "--offline", "--target", str(spec_file(plugin)))
    )
    shutil.rmtree(plugin / "generic_registry_fixture-0.0.0.dist-info")
    r = cli(
        plugin, "validate-target", "--offline", "--target", str(plugin / "target.json")
    )
    assert r.returncode == 1
    assert "unknown target.kind 'registry_fixture'" in r.stderr


@pytest.mark.parametrize(
    "entries, expected, warning",
    [
        (
            "openai_compat = absent_module:adapter",
            "OpenAICompatTarget",
            "is a built-in kind",
        ),
        (
            "registry_fixture = generic_plugin:adapter\nregistry_fixture = zz_absent:adapter",
            "GenericTarget",
            "already registered",
        ),
        (
            "broken = absent_module:adapter\nregistry_fixture = generic_plugin:adapter",
            "GenericTarget",
            "failed to load; skipped",
        ),
    ],
)
def test_plugin_precedence_and_broken_entry_points(
    tmp_path, entries, expected, warning
):
    install_plugin(tmp_path, entries=entries, pack=False)
    kind = "openai_compat" if expected == "OpenAICompatTarget" else "registry_fixture"
    spec = (
        {"kind": kind, "token": "count"}
        if kind == "registry_fixture"
        else {"kind": kind, "endpoint_url": "http://127.0.0.1:9", "model": "generic"}
    )
    r = fresh(
        tmp_path,
        "from argus.targets import kinds, build_target; "
        f"assert {kind!r} in kinds(); print(type(build_target({spec!r})).__name__)",
    )
    assert_ok(r)
    assert r.stdout.strip() == expected
    assert warning in r.stderr
    if "broken =" in entries:
        r = fresh(
            tmp_path, "from argus.targets import kinds; assert 'broken' not in kinds()"
        )
        assert_ok(r)


def test_explicit_plugin_metadata_controls_chat_hint_questions_and_validation(plugin):
    with (plugin / "generic_plugin" / "__init__.py").open("a") as f:
        f.write("""
from argus.targets import KindInfo

def validate(spec):
    if spec.get("token") == "bad":
        raise ValueError("generic token rejected")

GenericTarget.kind_info = KindInfo(
    kind="registry_fixture", required=frozenset({"token"}),
    description="A generic product adapter", chat=True,
    no_text_hint="check generic reply mapping", init_questions=(("token", "Generic token", "count"),),
    validate=validate,
)
""")
    r = fresh(
        plugin,
        "from argus.targets import build_target; from argus.runner import _no_text_reason; "
        "print(_no_text_reason(build_target({'kind':'registry_fixture', 'token':'count'})))",
    )
    assert_ok(r)
    assert r.stdout.strip() == "target returned no text; check generic reply mapping"
    r = cli(plugin, "validate-target", "--execute", "--target", str(spec_file(plugin)))
    assert_ok(r)
    assert "replied with" in r.stdout
    r = cli(
        plugin,
        "init",
        "--kind",
        "registry_fixture",
        "--no-workflow",
        "--output",
        "explicit.json",
        input="\n",
    )
    assert_ok(r)
    assert "Generic token [count]" in r.stdout
    assert "--probes owasp_01_prompt_injection_basic,syscard_crescendo" in r.stdout
    r = cli(
        plugin,
        "validate-target",
        "--offline",
        "--target",
        str(spec_file(plugin, token="bad")),
    )
    assert r.returncode == 1
    assert "generic token rejected" in r.stderr


def test_mismatched_plugin_metadata_is_skipped_without_hiding_other_kinds(plugin):
    with (plugin / "generic_plugin" / "__init__.py").open("a") as f:
        f.write("""
from argus.targets import KindInfo
GenericTarget.kind_info = KindInfo(kind="different_kind")
""")
    r = fresh(
        plugin,
        "from argus.targets import kinds; "
        "assert 'openai_compat' in kinds(); assert 'registry_fixture' not in kinds()",
    )
    assert_ok(r)
    assert "kind_info" in r.stderr and "skipped" in r.stderr
    r = fresh(
        plugin,
        "from argus.targets import build_target; "
        "build_target({'kind':'registry_fixture', 'token':'count'})",
    )
    assert r.returncode != 0
    assert "unknown target kind: 'registry_fixture'" in r.stderr


def test_init_choices_are_resolved_after_command_import(tmp_path):
    r = fresh(
        tmp_path,
        "from argus.cli.cmd_init import init_command; "
        f"import sys; sys.path.insert(0, {str(ROOT / 'tests')!r}); "
        "from test_registry_kinds import install_plugin; from pathlib import Path; "
        "install_plugin(Path.cwd()); init_command()",
        "--kind",
        "registry_fixture",
        "--no-workflow",
        input="count\n",
    )
    assert_ok(r)
    assert json.loads((tmp_path / "argus-target.json").read_text())["token"] == "count"


def test_plugin_empty_reply_reports_its_hint_in_a_runner_finding(plugin):
    with (plugin / "generic_plugin" / "__init__.py").open("a") as f:
        f.write("""
from argus.targets import KindInfo
GenericTarget.kind_info = KindInfo(kind="registry_fixture", required=frozenset({"token"}),
    no_text_hint="check generic reply mapping")
""")
    code = """import asyncio, json
from dataclasses import replace
from pathlib import Path
from argus.targets import build_target
from argus.probe import load_probe
from argus.runner import Runner

class NoJudgeCalls:
    async def judge(self, **kwargs):
        raise AssertionError("empty replies must never reach the judge")

async def run():
    target = build_target({"kind":"registry_fixture", "token":"sends", "reply":""})
    probe = replace(load_probe(Path("generic_plugin/probes/applicable.yaml")), assertions=())
    runner = Runner(target, NoJudgeCalls(), Path(sys.path[0]) / "argus/rubrics")
    findings = [f async for f in runner.run_probe(probe)]
    print(json.dumps([[f.probe_id, f.verdict, f.reasoning] for f in findings]))

asyncio.run(run())
"""
    r = fresh(plugin, code)
    assert_ok(r)
    assert json.loads(r.stdout) == [
        [
            "registry_fixture_applicable",
            "error",
            "target returned no text; check generic reply mapping",
        ]
    ]
    assert (plugin / "sends").read_text() == "1"


def test_built_fixture_metadata_does_not_leave_a_second_registration(
    tmp_path, monkeypatch
):
    source = tmp_path / "source"
    shutil.copytree(FIXTURE, source)
    built = source / "generic_registry_fixture.egg-info"
    built.mkdir()
    (built / "PKG-INFO").write_text(
        "Metadata-Version: 2.1\nName: generic-registry-fixture\nVersion: 0.0.0\n"
    )
    (built / "entry_points.txt").write_text(
        "[argus.targets]\nregistry_fixture = generic_plugin:adapter\n"
    )
    monkeypatch.setattr(sys.modules[__name__], "FIXTURE", source)
    installed = tmp_path / "installed"
    dist = install_plugin(installed, pack=False)
    shutil.rmtree(dist)
    r = fresh(
        installed,
        "from argus.targets import kinds; assert 'registry_fixture' not in kinds()",
    )
    assert_ok(r)


@pytest.mark.parametrize("args", [
    ("--help",),
    ("init", "--kind", "openai_compat", "--workflow"),
    ("list-probes",),
    ("list-probes", "--target", "chat.json"),
    ("validate-target", "--offline", "--target", "chat.json"),
    ("validate-target", "--offline", "--target", "mcpserver.json"),
    ("validate-target", "--target", "mcpserver.json"),
    ("run", "--local", "--target", "chat.json", "--probes", ",", "--out", "run.json"),
    ("mcp-trap", "--target", "chat.json", "--print-config"),
    ("mcp-trap", "--help"),
    ("run", "--help"),
])
def test_builtin_commands_do_not_import_target_plugins(tmp_path, args):
    install_plugin(tmp_path, pack=False)
    with (tmp_path / "generic_plugin/__init__.py").open("a") as f:
        f.write("\nPath('imported').write_text('loaded')\n")
    (tmp_path / "chat.json").write_text(json.dumps({
        "kind": "openai_compat", "endpoint_url": "http://127.0.0.1:9/v1", "model": "m"
    }))
    (tmp_path / "mcpserver.json").write_text('{"kind":"mcp_server","url":"http://127.0.0.1:9"}')
    r = cli(tmp_path, *args, input="url\nmodel\nKEY\n")
    expected = 2 if (
        (args[0] == "run" and "--help" not in args)
        or (args[0] == "validate-target" and "--offline" not in args)
    ) else 0
    assert r.returncode == expected, r.stdout + r.stderr
    assert not (tmp_path / "imported").exists(), r.stdout + r.stderr


def test_builtin_engine_paths_do_not_import_target_plugins(tmp_path):
    install_plugin(tmp_path, pack=False)
    with (tmp_path / "generic_plugin/__init__.py").open("a") as f:
        f.write("\nPath('imported').write_text('loaded')\n")
    r = fresh(tmp_path, """from argus.cli.target_loader import check_target_spec
from argus.targets import build_target
from argus.runner import _no_text_reason
from argus.cli.cmd_init import _probes_for
spec = check_target_spec({'kind':'openai_compat','endpoint_url':'http://127.0.0.1:9','model':'m'})[0]
assert _no_text_reason(build_target(spec)) == 'target returned no text; the endpoint returned no message content'
assert _probes_for('openai_compat') == 'owasp_01_prompt_injection_basic,syscard_crescendo'
""")
    assert_ok(r)
    assert not (tmp_path / "imported").exists()


def validate_offline(path, spec):
    target = path / "validation.json"
    target.write_text(json.dumps(spec))
    return cli(path, "validate-target", "--offline", "--target", str(target))


@pytest.mark.parametrize("error", ["ImportError('broken')", "RuntimeError('broken')", "SystemExit('broken')"])
def test_broken_plugins_warn_once_without_a_traceback(tmp_path, error):
    install_plugin(tmp_path, entries="broken_kind = broken_plugin:adapter", pack=False)
    (tmp_path / "broken_plugin.py").write_text(f"raise {error}\n")
    r = validate_offline(tmp_path, {"kind":"broken_kind"})
    assert r.returncode == 1
    assert "unknown target.kind 'broken_kind'" in r.stderr
    assert r.stderr.count("failed to load; skipped") == 1
    assert "broken_kind" in r.stderr
    assert "Traceback" not in r.stderr
    r = fresh(tmp_path, "import logging; logging.basicConfig(level=logging.DEBUG); from argus.targets import kinds; kinds(); kinds()")
    assert_ok(r)
    assert r.stderr.count("failed to load; skipped") == 1
    assert "Traceback" in r.stderr
    r = validate_offline(tmp_path, {"kind":"openai_compat","endpoint_url":"u","model":"m"})
    assert_ok(r)
    assert not r.stderr


@pytest.mark.parametrize("error", ["KeyboardInterrupt", "GeneratorExit"])
def test_plugin_loading_preserves_process_control_exceptions(tmp_path, error):
    install_plugin(tmp_path, entries="broken_kind = broken_plugin:adapter", pack=False)
    (tmp_path / "broken_plugin.py").write_text(f"raise {error}\n")
    r = fresh(tmp_path, f"from argus.targets import kinds;\ntry: kinds()\nexcept {error}: print('propagated')\nelse: raise AssertionError('exception swallowed')")
    assert_ok(r)
    assert r.stdout.strip() == "propagated"


@pytest.mark.parametrize("transport", ["${ARGUS_FIXTURE_VALUE}", {"version": 2, "value": "${ARGUS_FIXTURE_VALUE}"}])
def test_plugin_fields_expand_environment_variables(plugin, transport):
    r = fresh(plugin, f"""import os, json
os.environ['ARGUS_FIXTURE_VALUE'] = 'expanded'
from argus.cli.target_loader import check_target_spec
spec, secrets = check_target_spec({{'kind':'registry_fixture','token':'${{ARGUS_FIXTURE_VALUE}}','transport':{transport!r},'labels':['${{ARGUS_FIXTURE_VALUE}}'],'nested':{{'transport':'${{ARGUS_FIXTURE_VALUE}}'}}}})
print(json.dumps([spec, secrets]))
""")
    assert_ok(r)
    spec, secrets = json.loads(r.stdout)
    assert spec["transport"] == ("expanded" if isinstance(transport, str) else {"version":2,"value":"expanded"})
    assert spec["token"] == "expanded"
    assert spec["labels"] == ["expanded"]
    assert spec["nested"] == {"transport":"expanded"}
    assert secrets == ["expanded"]


@pytest.mark.parametrize("error", ["KeyError('missing')", "RuntimeError('broken')", "TypeError('broken')", "SystemExit('broken')"])
def test_plugin_validation_failures_are_named_and_fail_closed(plugin, error):
    with (plugin / "generic_plugin/__init__.py").open("a") as f:
        f.write(f"\nfrom argus.targets import KindInfo\ndef validate(spec):\n    raise {error}\nGenericTarget.kind_info = KindInfo(kind='registry_fixture', required=frozenset({{'token'}}), validate=validate)\n")
    r = cli(plugin, "validate-target", "--offline", "--target", str(spec_file(plugin)))
    assert r.returncode == 1
    assert "registry_fixture" in r.stderr and "validation failed" in r.stderr
    assert error.split("(")[0] in r.stderr
    assert "Traceback" not in r.stderr
    assert not (plugin / "sends").exists()


@pytest.mark.parametrize("postponed", [False, True])
def test_dataclass_fallback_requires_initvars(tmp_path, postponed):
    install_plugin(tmp_path, pack=False)
    with (tmp_path / "generic_plugin/__init__.py").open("a") as f:
        f.write("""
from dataclasses import InitVar
from typing import ClassVar
@dataclass
class InitSpec:
    secret: InitVar[str]
    optional: InitVar[str] = 'default'
    kind: str = 'registry_fixture'
    constant: ClassVar[str]
    def __post_init__(self, secret, optional):
        pass
adapter = (InitSpec, GenericTarget)
""")
    if postponed:
        module = tmp_path / "generic_plugin/__init__.py"
        module.write_text("from __future__ import annotations\n" + module.read_text())
    r = fresh(tmp_path, "from argus.targets import kinds; assert kinds()['registry_fixture'].required == frozenset({'secret'})")
    assert_ok(r)
    r = validate_offline(tmp_path, {"kind":"registry_fixture"})
    assert r.returncode == 1 and "missing required fields: ['secret']" in r.stderr
    r = validate_offline(tmp_path, {"kind":"registry_fixture","secret":"present"})
    assert_ok(r)


def test_plugin_init_inserts_strict_sandbox_without_asking(plugin):
    with (plugin / "generic_plugin/__init__.py").open("a") as f:
        f.write("""
from argus.targets import KindInfo
@dataclass(frozen=True)
class SandboxSpec(GenericSpec):
    sandbox: bool = False
adapter = (SandboxSpec, GenericTarget)
GenericTarget.kind_info = KindInfo(kind='registry_fixture', required=frozenset({'token','sandbox'}), sandbox_reason='changes generic records')
""")
    r = cli(plugin, "init", "--kind", "registry_fixture", "--no-workflow", input="count\n")
    assert_ok(r)
    assert "sandbox:" not in r.stdout
    spec = json.loads((plugin / "argus-target.json").read_text())
    assert spec == {"kind":"registry_fixture", "token":"count", "sandbox": True}
    assert_ok(validate_offline(plugin, spec))
    assert not (plugin / "sends").exists()
    for sandbox in [False, 'true', 1]:
        r = validate_offline(plugin, {**spec, "sandbox":sandbox})
        assert r.returncode == 1 and "requires sandbox: true" in r.stderr


def test_loadable_plugin_cannot_replace_or_import_for_a_builtin_kind(tmp_path):
    install_plugin(tmp_path, entries="openai_compat = generic_plugin:adapter", pack=False)
    with (tmp_path / "generic_plugin/__init__.py").open("a") as f:
        f.write("\nPath('imported').write_text('loaded')\n")
    r = fresh(tmp_path, """from argus.targets import kinds, _BUILTIN_KINDS
assert kinds()['openai_compat'] is _BUILTIN_KINDS['openai_compat']
""")
    assert_ok(r)
    assert "is a built-in kind" in r.stderr
    assert not (tmp_path / "imported").exists()
