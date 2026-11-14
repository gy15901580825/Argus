"""Compute probe counts from the library and keep the docs that state them in sync.

    python scripts/probe_counts.py --check   # exit 1 if a stated count drifted
    python scripts/probe_counts.py --write   # rewrite the stated counts in place
    python scripts/probe_counts.py --total   # print the library total

Counts cover the bundled library only (argus/probes, loaded with
`argus.probe.load_all_probes`); installed probe packs are not counted.
docs/probe-mapping.md and docs/owasp-agentic-mapping.md have their own
generators and are not in REGISTRY.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIX = "run python scripts/probe_counts.py --write"

# Top-level probes (directly under argus/probes) belong to a family by id prefix.
TOP_LEVEL_FAMILIES = {
    "owasp": ("owasp_",),
    "chat_extraction": ("system_prompt_", "deployment_secret_"),
    "memory": ("memory_builtin_",),
    "syscard": ("syscard_",),
    "agent_autonomy": ("agents_md_", "autonomous_", "guardrail_log_noise"),
    "semia": ("ambient_persuasion_", "encoded_payload_", "install_time_", "missing_",
              "obfuscated_code_", "shadow_credentials_"),
}
MCP_ABUSE_DIRS = ("mcp", "mcp_world", "mcp_protocol", "mcp_trap", "mcp_server", "mcp_scan")

# (path, regex with one named group `n`, count key). Each regex must match exactly once.
REGISTRY: list[tuple[str, str, str]] = [
    ("README.md", r"Argus runs\s+(?P<n>\d+)\s+red-team", "total"),
    ("README.md", r"library of\s+(?P<n>\d+)\s+adversarial probes", "total"),
    ("README.md", r"\*\*(?P<n>\d+)\s+probes\*\*\s+in the bundled library", "total"),
    ("README.md", r"(?P<n>\d+)\s+OWASP LLM Top 10 hand-authored", "owasp"),
    ("README.md", r"(?P<n>\d+)\s+chat extraction probes", "chat_extraction"),
    ("README.md", r"(?P<n>\d+)\s+built-in memory probe", "memory"),
    ("README.md", r"(?P<n>\d+)\s+from public LLM system cards", "syscard"),
    ("README.md", r"(?P<n>\d+)\s+browser-agent specific", "dir:browser"),
    ("README.md", r"(?P<n>\d+)\s+payment-abuse probes", "dir:payment"),
    ("README.md", r"(?P<n>\d+)\s+MCP-abuse probes", "mcp_abuse"),
    ("README.md", r"(?P<n>\d+)\s+poisoned tool servers", "dir:mcp"),
    ("README.md", r"(?P<n>\d+)\s+agent work-environment probes", "dir:mcp_world"),
    ("README.md", r"(?P<n>\d+)\s+MCP protocol-surface probes", "dir:mcp_protocol"),
    ("README.md", r"(?P<n>\d+)\s+hostile-server scenarios", "dir:mcp_trap"),
    ("README.md", r"(?P<n>\d+)\s+exposure checks of an", "dir:mcp_server"),
    ("README.md", r"(?P<n>\d+)\s+checks of an MCP server's tools", "dir:mcp_scan"),
    ("README.md", r"(?P<n>\d+)\s+Semia-mapped agent-skill detectors", "semia"),
    ("README.md", r"(?P<n>\d+)\s+agent-autonomy probes", "agent_autonomy"),
    ("README.md", r"(?P<n>\d+)\s+A2A server checks", "dir:a2a_server"),
    ("README.md", r"(?P<n>\d+)\s+A2A peer probes", "dir:a2a_world"),
    ("README.md", r"(?P<n>\d+)\s+vLLM version check", "dir:vllm_server"),
    ("README.md", r"(?P<n>\d+)\s+custom unicode-smuggling probe", "dir:custom"),
    ("README.md", r"(?P<n>\d+)\s+\[garak\]", "dir:garak"),
    ("README.md", r"─ (?P<n>\d+) YAML\s", "total"),
    ("CITATION.cff", r"Argus runs (?P<n>\d+) red-team probes", "total"),
    ("CONTRIBUTING.md", r"the probe library \((?P<n>\d+) YAML files\)", "total"),
    ("CONTRIBUTING.md", r"(?P<n>\d+) wrappers around NVIDIA garak", "dir:garak"),
    ("docs/onboarding/probe-id-cheatsheet.md", r"Argus ships (?P<n>\d+) probes", "total"),
    ("argus/coverage.py", r"A library of (?P<n>\d+) probes", "total"),
    # quickstart runs servers.PROBE_IDS, which tests/test_redteam_demo.py pins to argus/probes/mcp.
    ("docs/onboarding/quickstart.md", r"runs the (?P<n>\d+) MCP probes", "dir:mcp"),
    ("docs/cli.md", r"\d+ of (?P<n>\d+) probes caught the demo agent", "dir:mcp"),
    ("README.md", r"finding details hidden: (?P<n>\d+) probes", "dir:mcp"),
    ("argus/cli/cmd_quickstart.py", r"Run (?P<n>\d+) MCP probes against", "dir:mcp"),
]

# A library-sized number (3+ digits) followed by "probes" or "YAML", optionally
# with one word between, reads as a statement of the total.
_TOTAL_MENTION = re.compile(r"\b(?P<n>\d{3,})\s+(?:[\w-]+\s+)?(?:probes|YAML)\b")


def counts(probes_dir: Path = ROOT / "argus" / "probes") -> dict[str, int]:
    """Every count key, computed from the probes under `probes_dir`."""
    from argus.probe import load_all_probes

    probes_dir = Path(probes_dir)
    result = {"total": 0, **dict.fromkeys(TOP_LEVEL_FAMILIES, 0)}
    unclassified = []
    for path in sorted(probes_dir.rglob("*.yaml")):
        result["total"] += 1
        parts = path.relative_to(probes_dir).parts
        if len(parts) > 1:
            key = f"dir:{parts[0]}"
            result[key] = result.get(key, 0) + 1
            continue
        family = [name for name, prefixes in TOP_LEVEL_FAMILIES.items() if path.stem.startswith(prefixes)]
        if len(family) != 1:
            unclassified.append(path.name)
            continue
        result[family[0]] += 1
    if unclassified:
        raise ValueError(f"top-level probes in no family (add a prefix to TOP_LEVEL_FAMILIES): {unclassified}")
    loaded = sum(1 for _ in load_all_probes(probes_dir))
    if loaded != result["total"]:
        raise ValueError(f"loader returned {loaded} probes but {result['total']} YAML files exist")
    result["mcp_abuse"] = sum(result.get(f"dir:{name}", 0) for name in MCP_ABUSE_DIRS)
    return result


def _matches(root: Path) -> tuple[list[tuple[str, re.Match | None, str, int]], list[str]]:
    rows, errors = [], []
    for rel, pattern, key in REGISTRY:
        found = list(re.finditer(pattern, (root / rel).read_text()))
        if len(found) != 1:
            errors.append(f"{rel}: expected one match for {pattern!r}, found {len(found)}")
        rows.append((rel, found[0] if len(found) == 1 else None, key, len(found)))
    return rows, errors


def check(root: Path = ROOT, probes_dir: Path | None = None) -> list[str]:
    """Errors for every stated count that differs from the library; empty when in sync."""
    computed = counts(probes_dir or root / "argus" / "probes")
    rows, errors = _matches(root)
    for rel, match, key, _ in rows:
        if match and int(match["n"]) != computed[key]:
            errors.append(f"{rel}: states {match['n']} for {key}, library has {computed[key]}")
    for rel in sorted({rel for rel, _, _ in REGISTRY}):
        for mention in _TOTAL_MENTION.finditer((root / rel).read_text()):
            if int(mention["n"]) != computed["total"]:
                errors.append(f"{rel}: stale total {mention.group(0)!r}, library has {computed['total']}")
    return errors


def write(root: Path = ROOT, probes_dir: Path | None = None) -> list[str]:
    """Rewrite every registered count in place; return the files that changed."""
    computed = counts(probes_dir or root / "argus" / "probes")
    rows, errors = _matches(root)
    if errors:
        raise ValueError("\n".join(errors))
    changed = []
    for rel in dict.fromkeys(rel for rel, _, _ in REGISTRY):
        path = root / rel
        text = path.read_text()
        spans = sorted(((m.span("n"), computed[key]) for r, m, key, _ in rows if r == rel), reverse=True)
        new = text
        for (start, end), value in spans:
            new = new[:start] + str(value) + new[end:]
        if new != text:
            path.write_text(new)
            changed.append(rel)
    return changed


def main(argv: list[str]) -> int:
    # Run as a script, Python puts only scripts/ on sys.path; load argus from this checkout.
    sys.path.insert(0, str(ROOT))
    if argv == ["--total"]:
        print(counts()["total"])
        return 0
    if argv == ["--write"]:
        for rel in write():
            print(f"updated {rel}")
        argv = ["--check"]
    if argv == ["--check"]:
        errors = check()
        for error in errors:
            print(error)
        if errors:
            print(FIX)
            return 1
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
