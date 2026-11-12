"""Target-class aliases select the same probes without changing compatibility."""

from collections import defaultdict
from dataclasses import replace

import pytest
from click.testing import CliRunner

from argus.api import PROBES_DIR
from argus.cli.__main__ import main
from argus.probe import (
    TARGET_CLASS_ALIASES,
    VALID_TARGET_CLASSES,
    equivalent_target_classes,
    load_probe_library,
)
from argus.targets import _BUILDERS


@pytest.mark.parametrize("aliases", TARGET_CLASS_ALIASES, ids=lambda group: ",".join(sorted(group)))
def test_list_probes_aliases_have_identical_nonempty_lists(aliases, monkeypatch):
    monkeypatch.delenv("ARGUS_API_URL", raising=False)
    wanted = sorted(p.id + (" [opt-in]" if p.opt_in else "")
                    for p in load_probe_library(PROBES_DIR) if aliases.intersection(p.target_class))
    assert wanted
    for name in sorted(aliases):
        result = CliRunner().invoke(main, ["list-probes", "--target-class", name])
        assert result.exit_code == 0, result.output
        assert result.output == "\n".join(wanted) + f"\n\n{len(wanted)} probes\n"


def test_alias_table_matches_adapter_declarations():
    # Equal adapter support identifies aliases without confusing a target's
    # multiple capabilities (for example, chat and tools) with equivalent names.
    support = defaultdict(set)
    for kind, (_, adapter) in _BUILDERS.items():
        if len(adapter.compatible_classes) == 2:
            for name in adapter.compatible_classes:
                assert equivalent_target_classes(name) == adapter.compatible_classes, (
                    f"{kind} declares an alias pair missing from the table"
                )
        for name in adapter.compatible_classes:
            support[name].add(kind)
    by_support = defaultdict(set)
    for name, kinds in support.items():
        by_support[frozenset(kinds)].add(name)
    for names in by_support.values():
        for name in names:
            assert equivalent_target_classes(name) == names, (
                f"{name}: adapters advertise equivalent names {sorted(names)}"
            )


@pytest.mark.parametrize("aliases", TARGET_CLASS_ALIASES, ids=lambda group: ",".join(sorted(group)))
def test_list_probes_matches_probes_written_with_either_alias(aliases, monkeypatch):
    monkeypatch.delenv("ARGUS_API_URL", raising=False)
    template = load_probe_library(PROBES_DIR)[0]
    probes = [replace(template, id=f"alias_{name}", target_class=(name,)) for name in sorted(aliases)]
    probes.append(replace(template, id="unrelated", target_class=("http-upload",)))
    monkeypatch.setattr("argus.cli.cmd_list_probes._local_probes", lambda: probes)
    wanted = sorted(p.id for p in probes if p.id != "unrelated")
    for name in sorted(aliases):
        result = CliRunner().invoke(main, ["list-probes", "--target-class", name])
        assert result.exit_code == 0, result.output
        assert result.output == "\n".join(wanted) + f"\n\n{len(wanted)} probes\n"


@pytest.mark.parametrize("name", sorted(VALID_TARGET_CLASSES - set().union(*TARGET_CLASS_ALIASES)))
def test_single_named_classes_remain_distinct(name):
    assert equivalent_target_classes(name) == {name}
