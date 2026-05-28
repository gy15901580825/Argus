"""State dataclasses threaded through the four web-UI exploration phases."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class PhaseResult:
    """Structured output produced by a single phase."""
    phase: str
    raw_output: str
    parsed: dict[str, Any]
    steps_used: int


@dataclass
class PhaseState:
    """Accumulated state across all phases. Mutated in-place by the runner."""
    url: str
    domain: str
    credentials: dict[str, str] | None = None
    business_context: str | None = None
    user_persona: str = "new_user"

    auth: PhaseResult | None = None
    discovery: PhaseResult | None = None
    feature_results: list[dict[str, Any]] = field(default_factory=list)
    bugs: list[dict[str, Any]] = field(default_factory=list)

    def to_prompt_context(self) -> str:
        """Serialise prior-phase outputs as text injected into the next phase's prompt."""
        parts: list[str] = []
        if self.auth:
            parts.append(f"AUTH: {self.auth.parsed.get('auth_status', 'unknown')}")
        if self.discovery:
            features = self.discovery.parsed.get("features", [])
            if features:
                parts.append("DISCOVERED FEATURES:")
                for f in features:
                    parts.append(f"  - {f.get('name', '?')} @ {f.get('url', '?')}")
        if self.feature_results:
            parts.append(f"FEATURES TESTED: {len(self.feature_results)}")
        if not parts:
            return "No prior phases completed."
        return "\n".join(parts)

    def as_final_report(self) -> str:
        """Produce the text format expected by `_count_bugs` and `_generate_test_script`."""
        sev_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for b in self.bugs:
            sev = b.get("severity", "low").lower()
            if sev not in sev_counts:
                sev = "low"
            sev_counts[sev] += 1

        lines = [
            "FINAL REPORT",
            f"URL: {self.url}",
            "",
            "BUG SUMMARY:",
            f"  Critical: {sev_counts['critical']}",
            f"  High: {sev_counts['high']}",
            f"  Medium: {sev_counts['medium']}",
            f"  Low: {sev_counts['low']}",
            "",
            "BUGS:",
        ]
        for b in self.bugs:
            sev = b.get("severity", "low").upper()
            cat = b.get("category", "FUNC")
            desc = b.get("description", "")
            lines.append(f"BUG [{sev}] [{cat}]: {desc}")
            if b.get("steps"):
                lines.append(f"  Steps: {b['steps']}")
            if b.get("evidence"):
                lines.append(f"  Evidence: {b['evidence']}")
        return "\n".join(lines)
