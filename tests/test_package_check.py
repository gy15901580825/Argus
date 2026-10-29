"""Package extraction and registry lookup. No live network: every lookup goes
through an httpx MockTransport."""

import httpx
import pytest

from argus import package_check as pc


@pytest.fixture(autouse=True)
def _fresh_cache(monkeypatch):
    monkeypatch.setattr(pc, "_CACHE", {})
    monkeypatch.setattr(pc, "_RAKU_NAMES", None)


def _serve(monkeypatch, handler):
    def make():
        return httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True)

    monkeypatch.setattr(pc, "_client", make)


@pytest.mark.parametrize("language,text,expected", [
    ("python", "import os\nimport requests, numpy as np\nfrom flask_magic import Thing\nfrom . import local",
     {"requests", "numpy", "flask_magic"}),
    ("python", "pip install fastgraph==1.2 --upgrade", {"fastgraph"}),
    ("python", "Use the requests library for this; no code needed.", set()),
    ("javascript", "import x from 'left-padder';\nconst y = require('@scope/pkg/sub');\nimport fs from 'node:fs';\nimport z from './local';",
     {"left-padder", "@scope/pkg"}),
    ("javascript", "npm install --save express@4 lodash", {"express", "lodash"}),
    ("ruby", "require 'json'\nrequire 'magic_gem'\ngem 'rails'\nrequire 'net/http'", {"magic_gem", "rails"}),
    ("rust", "use std::fs;\nuse tokio::runtime;\nmod utils;\nuse utils::helper;\nextern crate serde;",
     {"tokio", "serde"}),
    ("perl", "use strict;\nuse warnings;\nuse Fake::Module qw(x);\nuse 5.010;", {"Fake::Module"}),
    ("raku", "```raku\nuse v6.d;\nuse JSON::Fast;\nuse Test;\nuse Made::Up:ver<1.0>;\n```", {"JSON::Fast", "Made::Up"}),
    ("dart", "import 'package:http/http.dart';\nimport 'package:flutter/material.dart';\nimport 'dart:io';",
     {"http"}),
])
def test_extract_packages(language, text, expected):
    assert pc.extract_packages(language, text) == expected


def test_python_stdlib_is_never_a_package():
    assert pc.extract_packages("python", "import os, sys, json\nfrom collections import abc") == set()


def test_exists_true_on_200_false_on_404(monkeypatch):
    seen = []

    def handler(request):
        seen.append(str(request.url))
        return httpx.Response(200 if request.url.path.endswith("/requests/json") else 404)

    _serve(monkeypatch, handler)
    assert pc.package_exists("python", "requests") is True
    assert pc.package_exists("python", "no_such_pkg_xyz") is False
    assert seen[0] == "https://pypi.org/pypi/requests/json"


def test_python_alias_maps_import_name_to_distribution(monkeypatch):
    _serve(monkeypatch, lambda r: httpx.Response(200 if "/pyyaml/" in r.url.path else 404))
    assert pc.package_exists("python", "yaml") is True


def test_scoped_npm_name_escapes_the_slash(monkeypatch):
    urls = []

    def handler(request):
        urls.append(request.url.raw_path.decode())
        return httpx.Response(200)

    _serve(monkeypatch, handler)
    assert pc.package_exists("javascript", "@scope/pkg") is True
    assert urls == ["/@scope%2Fpkg"]


@pytest.mark.parametrize("response", [
    httpx.Response(500), httpx.Response(429), httpx.Response(403),
    httpx.ConnectError("dns down"), httpx.ReadTimeout("slow"),
])
def test_an_unanswered_lookup_raises_instead_of_guessing(monkeypatch, response):
    def handler(request):
        if isinstance(response, Exception):
            raise response
        return response

    _serve(monkeypatch, handler)
    with pytest.raises(pc.RegistryUnavailable):
        pc.package_exists("python", "whatever")


def test_a_failed_lookup_is_not_cached(monkeypatch):
    state = {"up": False}

    def handler(request):
        return httpx.Response(200 if state["up"] else 500)

    _serve(monkeypatch, handler)
    with pytest.raises(pc.RegistryUnavailable):
        pc.package_exists("python", "requests")
    state["up"] = True
    assert pc.package_exists("python", "requests") is True


def test_rust_tries_the_hyphenated_crate_name(monkeypatch):
    _serve(monkeypatch, lambda r: httpx.Response(200 if r.url.path.endswith("/tokio-stream") else 404))
    assert pc.package_exists("rust", "tokio_stream") is True


def test_raku_checks_provided_module_names_from_the_zef_index(monkeypatch):
    index = [{"name": "JSON::Fast", "provides": ["JSON::Fast", "JSON::Fast::Hyper"]}]
    _serve(monkeypatch, lambda r: httpx.Response(200, json=index))
    assert pc.package_exists("raku", "JSON::Fast::Hyper") is True
    assert pc.package_exists("raku", "Made::Up") is False


def test_raku_index_failure_is_unavailable_not_missing(monkeypatch):
    _serve(monkeypatch, lambda r: httpx.Response(503))
    with pytest.raises(pc.RegistryUnavailable):
        pc.package_exists("raku", "JSON::Fast")


@pytest.mark.parametrize("language,text,expected", [
    ("python", "Just pip install requests and you are done.", set()),
    ("python", "pip install -r requirements.txt", set()),
    ("python", "pip install numpy pandas  # data libs", {"numpy", "pandas"}),
    ("python", "pip install requests && python app.py", {"requests"}),
    ("python", "Run `pip install flask==2.0 requests`", {"flask", "requests"}),
    ("python", '$ pip install -U "fastapi[all]" uvicorn', {"fastapi", "uvicorn"}),
    ("javascript", "npm install && npm start", set()),
    ("javascript", "npm install express. Then run node app.js", {"express"}),
    ("ruby", "gem install rails -v 7.0", {"rails"}),
    ("rust", "cargo add serde --features derive", {"serde"}),
])
def test_install_commands_are_read_exactly_not_prose_or_flags(language, text, expected):
    assert pc.extract_packages(language, text) == expected


def test_multiline_and_dynamic_js_imports_and_local_paths():
    text = "import {\n a,\n b\n} from 'pkg';\nconst m = await import('dyn');\nimport u from 'src/utils';\nimport l from './l';"
    assert pc.extract_packages("javascript", text) == {"pkg", "dyn"}


def test_modules_the_reply_defines_itself_are_not_registry_lookups():
    text = "# mymodule.py\ndef helper(): ...\n\n# main.py\nfrom mymodule import helper\nimport requests"
    assert pc.extract_packages("python", text) == {"requests"}


def test_removed_stdlib_and_ruby_stdlib_are_not_looked_up():
    assert pc.extract_packages("python", "import distutils\nimport imp\nimport asynchat") == set()
    assert pc.extract_packages("ruby", "require 'English'") == set()


@pytest.mark.parametrize("name,dist", [
    ("Bio", "biopython"), ("fitz", "pymupdf"), ("cv2", "opencv-python"), ("sklearn", "scikit-learn"),
    ("PIL", "pillow"), ("yaml", "pyyaml"), ("bs4", "beautifulsoup4"), ("dateutil", "python-dateutil"),
    ("google", "protobuf"), ("telegram", "python-telegram-bot"), ("websocket", "websocket-client"),
])
def test_python_import_names_resolve_to_their_distribution(monkeypatch, name, dist):
    _serve(monkeypatch, lambda r: httpx.Response(200 if f"/{dist}/" in r.url.path else 404))
    assert pc.package_exists("python", name) is True


def test_the_cache_keeps_languages_apart(monkeypatch):
    # "requests" exists on PyPI but not on RubyGems; one answer must not leak to the other.
    _serve(monkeypatch, lambda r: httpx.Response(200 if "pypi.org" in str(r.url) else 404))
    assert pc.package_exists("python", "requests") is True
    assert pc.package_exists("ruby", "requests") is False


@pytest.mark.parametrize("language,text,expected", [
    ("python", "pip install -v requests", {"requests"}),
    ("javascript", "npm install -f express", {"express"}),
    ("javascript", "npm install chart.js highlight.js decimal.js", {"chart.js", "highlight.js", "decimal.js"}),
    ("python", "pip install -r requirements.txt", set()),
    ("python", "pip install -r reqs.txt flask", {"flask"}),
    ("ruby", "gem install rails --version 7.0 nokogiri", {"rails", "nokogiri"}),
    ("rust", "cargo add serde --verbose tokio", {"serde", "tokio"}),
    ("python", "1. pip install flask", {"flask"}),
    ("python", "- pip install flask", {"flask"}),
    ("python", "* `pip install flask`", {"flask"}),
    ("python", "!pip install flask", {"flask"}),
    ("python", "%pip install -q flask", {"flask"}),
])
def test_flags_markers_and_dotted_package_names(language, text, expected):
    assert pc.extract_packages(language, text) == expected


def test_a_prose_file_mention_does_not_hide_a_hallucinated_import():
    text = "Use the Sawtooth.js library:\n```js\nconst s = require('sawtooth');\n```"
    assert pc.extract_packages("javascript", text) == {"sawtooth"}


def test_a_js_file_header_never_hides_a_bare_specifier():
    # A bare JS specifier resolves to node_modules, so "helpers" is still a lookup.
    text = "// helpers.js\nexport const x = 1;\n\n// main.js\nimport { x } from 'helpers';"
    assert pc.extract_packages("javascript", text) == {"helpers"}
    assert pc.extract_packages("javascript", "### Sawtooth.js\nconst s = require('sawtooth');") == {"sawtooth"}


@pytest.mark.parametrize("text,expected", [
    ("pip install --trusted-host pypi.org ghostpkg", {"ghostpkg"}),
    ("pip install --timeout 60 requests", {"requests"}),
    ("pip install --upgrade-strategy eager requests", {"requests"}),
    ("pip install --progress-bar off requests", {"requests"}),
    ("pip install --platform manylinux2014_x86_64 requests", {"requests"}),
    ("pip install -e git+https://x/y.git#egg=y ghostpkg", {"ghostpkg"}),
])
def test_pip_value_flags_and_egg_fragments(text, expected):
    assert pc.extract_packages("python", text) == expected


@pytest.mark.parametrize("text,expected", [
    ("npm install --omit dev express", {"express"}),
    ("npm install --loglevel silent express", {"express"}),
    ("pnpm add --filter web ghost-pkg", {"ghost-pkg"}),
])
def test_npm_and_pnpm_value_flags(text, expected):
    assert pc.extract_packages("javascript", text) == expected


@pytest.mark.parametrize("language,text", [
    ("python", "- pip install might require sudo on Linux"),
    ("python", "1. pip install fails with a permission error"),
    ("javascript", "* npm install takes a while"),
])
def test_bullet_prose_about_a_command_is_not_a_command(language, text):
    assert pc.extract_packages(language, text) == set()


def test_a_list_prefixed_command_in_a_fence_or_backticks_is_still_read():
    assert pc.extract_packages("python", "```\n- pip install flask\n```") == {"flask"}
    assert pc.extract_packages("python", "- `pip install flask`") == {"flask"}


@pytest.mark.parametrize("text", [
    "File: app/models.py\nfrom models import User",
    "# File: models.py\nfrom models import User",
    "# FILENAME: models.py\nfrom models import User",
    "# models/__init__.py\nfrom models import User",
])
def test_python_local_module_headers_any_case_and_init(text):
    assert pc.extract_packages("python", text) == set()


@pytest.mark.parametrize("text", [
    "pip install might require sudo on Linux",
    "pip install fails sometimes because of permissions",
])
def test_plain_prose_after_an_install_verb_is_not_a_command(text):
    assert pc.extract_packages("python", text) == set()


def test_plain_install_lines_still_work():
    assert pc.extract_packages("python", "pip install flask requests") == {"flask", "requests"}


def test_a_fenced_line_with_a_prose_word_is_still_a_command():
    # Inside a fence the line is code, so "on-prem" style words are not prose filters.
    assert pc.extract_packages("python", "```\n- pip install ghostpkg on\n```") == {"ghostpkg", "on"}
    assert pc.extract_packages("python", "- pip install ghostpkg on") == set()


def test_a_ruby_file_header_never_hides_a_bare_require():
    assert pc.extract_packages("ruby", "# helpers.rb\nrequire 'helpers'") == {"helpers"}
