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
    shutil.copytree(FIXTURE, path, dirs_exist_ok=True)
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
