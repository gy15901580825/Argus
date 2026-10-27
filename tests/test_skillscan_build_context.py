"""The skillscan image build finds its Dockerfiles and context at the package path."""

import re
import subprocess
from pathlib import Path

import argus
from argus.skillscan import sandbox as sandbox_mod
from argus.skillscan.sandbox import _BUILD_FILES, image_tag

PKG_DOCKER_DIR = Path(argus.__file__).resolve().parent / "skillscan" / "docker"


def test_docker_dir_is_inside_the_argus_package():
    assert sandbox_mod.DOCKER_DIR.resolve() == PKG_DOCKER_DIR
    for kind, names in _BUILD_FILES.items():
        for name in names:
            assert (PKG_DOCKER_DIR / name).is_file(), f"{kind}: {name} missing from {PKG_DOCKER_DIR}"


def test_every_dockerfile_copy_source_is_a_hashed_build_file():
    # A COPY source outside _BUILD_FILES would change the image without changing its tag.
    for kind, names in _BUILD_FILES.items():
        text = (PKG_DOCKER_DIR / f"{kind}.Dockerfile").read_text()
        sources = re.findall(r"^(?:COPY|ADD)\s+(?:--\S+\s+)*(\S+)\s", text, flags=re.M)
        assert sources, f"{kind}.Dockerfile copies nothing"
        assert set(sources) <= set(names), (kind, sources)


def test_image_tag_hashes_the_package_files():
    tags = {kind: image_tag(kind) for kind in _BUILD_FILES}
    assert tags == {kind: image_tag(kind, PKG_DOCKER_DIR) for kind in _BUILD_FILES}
    assert all(re.fullmatch(rf"argus-skillscan-{k}:[0-9a-f]{{12}}", t) for k, t in tags.items())


def test_build_uses_the_package_dir_as_context(monkeypatch):
    builds = []

    def fake_run(cmd, **kw):
        if cmd[:2] == ["docker", "build"]:
            builds.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, "", "")
        return subprocess.CompletedProcess(cmd, 1, "", "No such image")

    monkeypatch.setattr(sandbox_mod.subprocess, "run", fake_run)
    sandbox_mod.ensure_images(lambda s: None)
    assert len(builds) == len(_BUILD_FILES)
    for cmd in builds:
        dockerfile = Path(cmd[cmd.index("-f") + 1])
        assert Path(cmd[-1]).resolve() == PKG_DOCKER_DIR
        assert dockerfile.resolve().parent == PKG_DOCKER_DIR and dockerfile.is_file()
