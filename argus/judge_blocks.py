"""Diagnostics for exchanges a judge provider could not assess."""
from argus import llm


def block_reason(exc: llm.JudgeBlockedError) -> str:
    fallback = ("fallback was not tried" if exc.fallback in (None, "off")
                else f"fallback was tried and failed: {exc.fallback}")
    reason = (f"JudgeBlockedError: {exc.provider} {exc.model}: the provider content filter blocked the judge prompt "
              f"(categories: {', '.join(exc.categories) or 'not given'}); {fallback}")
    if exc.escalated_from is not None:
        reason += f"; strong escalation was blocked after fast {exc.escalated_from}; the fast verdict was not retained"
    return reason


def block_evidence(exc: llm.JudgeBlockedError, evidence: dict | None = None) -> dict:
    return {**(evidence or {}), "judge_blocked": exc.as_dict(), "reason_code": "judge_blocked"}


def blocks_in_evidence(evidence: dict | None) -> list[dict]:
    """Read block metadata from findings and their trial/scan records, without counting a finding twice."""
    evidence = evidence or {}
    blocks = [evidence["judge_blocked"]] if evidence.get("judge_blocked") else []
    blocks.extend(evidence.get("judge_blocks", []))
    for trial in evidence.get("trials", []):
        for observation in (trial.get("attack") or {}).get("observations", []):
            blocks.extend(blocks_in_evidence(observation.get("evidence")))
    for item in evidence.get("items", []):
        if isinstance(item, dict) and item.get("judge_blocked"):
            blocks.append(item["judge_blocked"])
    return blocks


def block_note(summary: dict) -> str | None:
    blocked = summary.get("judge_blocked")
    if not blocked:
        return None
    count = blocked["count"]
    noun = "finding" if count == 1 else "findings"
    categories = ", ".join(blocked["categories"]) or "not given"
    return (f"{count} {noun} could not be judged: the judge provider's content filter blocked "
            f"{'it' if count == 1 else 'them'} (categories: {categories})")
