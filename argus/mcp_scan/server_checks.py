"""The four existing `mcp_server` checks inside a scan-mcp run: all four over HTTP, the two that apply over stdio."""
from __future__ import annotations

import functools
import json
from dataclasses import asdict
from pathlib import Path

import argus
from argus.assertions import evaluate_assertions
from argus.mcp_scan import rules
from argus.mcp_scan.findings import finding
from argus.mcp_scan.models import RESULT_KEEP, ServerInfo, ToolInfo
from argus.probe import Probe, load_all_probes
from argus.runner import VERDICT_ERROR, VERDICT_FAIL, VERDICT_PASS, VERDICT_SKIPPED
from argus.targets.mcp_server import MCPServerSpec, MCPServerTarget

SERVER_PROBES_DIR = Path(argus.__file__).parent / "probes" / "mcp_server"
HTTP_ONLY = frozenset({"mcp_server_foreign_origin", "mcp_server_no_auth"})
HTTP_ONLY_REASON = "HTTP-only check; this server speaks stdio"
# The evidence copy in each finding keeps this many tools, each description redacted and then cut.
TOOLS_KEEP = 50
DESCRIPTION_KEEP = rules.EXCERPT
NOT_REACHED = "the server never answered these checks, so the probe did not actually run; this is not a defended result"


@functools.lru_cache(maxsize=1)
def server_probes() -> tuple[Probe, ...]:
    return tuple(load_all_probes(SERVER_PROBES_DIR))


def _redacted(value):
    """A copy with every string redacted: tool descriptions and serverInfo are the server's own text."""
    if isinstance(value, str):
        return rules.redact(value)
    if isinstance(value, dict):
        return {k: _redacted(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redacted(v) for v in value]
    return value


def _shown_evidence(evidence: dict) -> dict:
    """The evidence written to the report: redacted, with the tool list bounded."""
    tools = evidence.get("tools")
    shown = _redacted({k: v for k, v in evidence.items() if k != "tools"})
    if isinstance(tools, list):
        shown["tools"] = [{k: rules.redact(str(v))[:DESCRIPTION_KEEP] for k, v in t.items()}
                          for t in tools[:TOOLS_KEEP] if isinstance(t, dict)]
        shown["tools_listed"] = len(tools)
    elif "tools" in evidence:
        shown["tools"] = tools
    return shown


def _assertion_finding(probe: Probe, evidence: dict, latency_ms: float) -> dict:
    """What Runner._assertion_finding builds, with server text redacted and the results kept as evidence items."""
    raw = json.dumps(evidence, sort_keys=True)
    shown = _shown_evidence(evidence)
    common = dict(attack_prompt=probe.prompts[0], target_response=rules.redact(raw)[:RESULT_KEEP],
                  latency_ms=latency_ms)
    if probe.requires_interaction and not evidence.get("interaction_count"):
        return finding(probe, verdict=VERDICT_ERROR, severity="info", reasoning=NOT_REACHED,
                       evidence={**shown, "items": []}, **common)
    results = evaluate_assertions(probe.assertions, evidence, raw)
    failed = [r for r in results if not r.passed]
    reasoning = rules.redact("; ".join(r.reason for r in (failed or results)))
    items = [_redacted(asdict(r)) for r in results]
    return finding(probe, verdict=VERDICT_FAIL if failed else VERDICT_PASS,
                   severity=probe.severity if failed else "info", reasoning=reasoning,
                   evidence={**shown, "items": items}, **common)


async def http_server_findings(url: str, headers: tuple[tuple[str, str], ...], timeout_s: float,
                               mask: rules.Mask = rules.same) -> list[dict]:
    target = MCPServerTarget(MCPServerSpec(url=url, headers=headers, timeout_s=timeout_s))
    _, latency_ms = await target.send_prompt("")
    # Masked whole, before the evidence is cut: a cut through a known secret keeps a part no mask matches.
    evidence = rules.mask_strings(await target.collect_evidence(), mask)
    return [_assertion_finding(p, evidence, latency_ms) for p in server_probes()]


def stdio_server_findings(tools: list[ToolInfo], server_info: ServerInfo | None) -> list[dict]:
    evidence = {"interaction_count": 1,
                "tools": [{"name": t.name, "description": t.description} for t in tools],
                "server_info": {"name": server_info.name, "version": server_info.version} if server_info else None}
    out = []
    for p in server_probes():
        if p.id in HTTP_ONLY:
            out.append(finding(p, verdict=VERDICT_SKIPPED, severity="info", reasoning=HTTP_ONLY_REASON,
                               evidence={"items": []}))
        else:
            out.append(_assertion_finding(p, evidence, 0.0))
    return out
