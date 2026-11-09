"""Run the plugin guide as an installed package in fresh processes."""
from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]
GUIDE = ROOT / "docs/plugins.md"


def run(code, cwd, env):
    result = subprocess.run(
        [sys.executable, "-c", code], cwd=cwd, env=env,
        text=True, capture_output=True, timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_plugin_guide_examples(tmp_path):
    text = GUIDE.read_text()
    fences = re.findall(r"(?:<!-- example: ([\w/.-]+) -->\n)?```(\w+)([^\n]*)\n(.*?)\n```", text, re.S)
    assert fences, "the guide must contain examples"
    scripts = []
    for filename, language, marker, source in fences:
        if "not-runnable" in marker:
            continue
        if language in {"python", "toml"}:
            assert filename, "executable examples need a filename"
            path = tmp_path / filename
            assert path.resolve().is_relative_to(tmp_path.resolve())
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source + "\n")
            if language == "python":
                scripts.append(path)
    assert scripts
    project = tomllib.loads((tmp_path / "pyproject.toml").read_text())
    assert project["project"]["entry-points"]["argus.targets"]
    env = dict(os.environ, LITELLM_LOCAL_MODEL_COST_MAP="True")
    installed = tmp_path / "installed"
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "--no-index", "--no-deps", "--no-build-isolation",
         "--target", str(installed), str(tmp_path)],
        cwd=tmp_path, env=env, text=True, capture_output=True, timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    env["PYTHONPATH"] = os.pathsep.join([str(installed), str(ROOT)])
    execution = tmp_path / "execution"
    execution.mkdir()
    for script in scripts:
        run(script_command(script), execution, env)
    run('''import asyncio
from argus.targets import build_target, kinds
from generic_plugin import GenericTarget
assert kinds()['registry_fixture'].required == frozenset({'token'})
async def check():
    target = build_target({'kind': 'registry_fixture', 'token': 'count'})
    assert type(target) is GenericTarget
    assert target.compatible_classes == frozenset({'registry_fixture'})
    await target.begin_probe(type('Probe', (), {'id': 'example'})())
    reply, latency = await target.send_prompt('hello')
    assert reply == 'Observed a neutral response.' and latency >= 0
    assert await target.collect_evidence() == {'interaction_count': 1, 'canary': 'GENERIC_CANARY'}
    await target.aclose()
asyncio.run(check())
''', execution, env)


def script_command(path):
    return f"import runpy; runpy.run_path({str(path)!r}, run_name='__main__')"


def test_plugin_guide_action_major_matches_readme():
    pattern = r"gy15901580825/argus-probe-action@v(\d+)\b"
    readme_versions = re.findall(pattern, (ROOT / "README.md").read_text())
    guide_versions = re.findall(pattern, GUIDE.read_text())
    assert readme_versions and guide_versions, "both docs must reference the Action"
    assert set(guide_versions) == set(readme_versions), "Action major must match README.md"


def test_documented_target_methods_exist():
    from argus.targets import Target
    from argus.targets.python_target import PythonTarget

    text = GUIDE.read_text()
    methods = re.findall(r"^\| `([a-z_]+)\([^`]*\)` \|", text, re.M)
    assert set(methods) == {
        'send_prompt', 'begin_probe', 'collect_evidence', 'aclose',
        'cleanup_report', 'last_run_log',
    }
    for name in methods:
        assert callable(getattr(PythonTarget, name, None))
        if name != 'cleanup_report':
            assert callable(getattr(Target, name, None))
