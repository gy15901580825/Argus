"""DB operations on redteam_runs and redteam_findings."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any
from uuid import UUID

from database import database


def _parse_iso(v):
    """asyncpg requires datetime for TIMESTAMPTZ; orchestrator emits ISO strings."""
    if v is None or isinstance(v, datetime):
        return v
    return datetime.fromisoformat(v)


async def create_run(user_id: UUID, target_spec: dict, probe_suite: str) -> UUID:
    row = await database.fetch_one(
        """
        INSERT INTO redteam_runs (user_id, target_spec, probe_suite, status)
        VALUES (:user_id, :target_spec, :probe_suite, 'queued')
        RETURNING id
        """,
        {"user_id": user_id, "target_spec": json.dumps(target_spec), "probe_suite": probe_suite},
    )
    return row["id"]


async def update_run_status(run_id: UUID, status: str, summary: dict | None = None) -> None:
    await database.execute(
        """
        UPDATE redteam_runs
        SET status = :status,
            finished_at = CASE WHEN :status IN ('completed', 'failed', 'cancelled') THEN NOW() ELSE finished_at END,
            summary = COALESCE(:summary, summary)
        WHERE id = :id
        """,
        {"id": run_id, "status": status, "summary": json.dumps(summary) if summary else None},
    )


def decode_run_row(row: dict) -> dict:
    """JSONB comes back from the driver as text.

    Left as a string, `target_spec` would still be truthy in the report
    template while every attribute lookup on it (e.g. `target_spec.kind`)
    silently returned undefined — a blank Target line instead of an error.
    """
    run = dict(row)
    raw = run.get("target_spec")
    if isinstance(raw, str):
        try:
            run["target_spec"] = json.loads(raw)
        except ValueError:
            run["target_spec"] = None
    return run


async def get_run(run_id: UUID, user_id: UUID) -> dict | None:
    row = await database.fetch_one(
        "SELECT * FROM redteam_runs WHERE id = :id AND user_id = :user_id",
        {"id": run_id, "user_id": user_id},
    )
    return decode_run_row(row) if row else None


async def insert_finding(run_id: UUID, finding: dict) -> None:
    await database.execute(
        """
        INSERT INTO redteam_findings (
            id, run_id, probe_id, verdict, severity, evidence_blob_url, evidence,
            atlas_id, owasp_id, nist_id, eu_ai_act_id,
            attack_prompt, target_response, target_latency_ms, probed_at,
            confidence, reasoning, judge_model, escalated_model
        )
        VALUES (
            :id, :run_id, :probe_id, :verdict, :severity, :evidence_blob_url, :evidence,
            :atlas_id, :owasp_id, :nist_id, :eu_ai_act_id,
            :attack_prompt, :target_response, :target_latency_ms, :probed_at,
            :confidence, :reasoning, :judge_model, :escalated_model
        )
        """,
        {
            "id": finding.get("id"),
            "run_id": run_id,
            "probe_id": finding["probe_id"],
            "verdict": finding["verdict"],
            "severity": finding.get("severity"),
            "evidence_blob_url": finding.get("evidence_blob_url"),
            # What the target was observed doing. Serialised here rather than
            # passed as a dict: asyncpg binds JSONB from text, and a finding
            # from a text-only adapter carries None.
            "evidence": (
                json.dumps(finding["evidence"]) if finding.get("evidence") is not None else None
            ),
            "atlas_id": finding.get("atlas_id", []),
            "owasp_id": finding.get("owasp_id", []),
            "nist_id": finding.get("nist_id", []),
            "eu_ai_act_id": finding.get("eu_ai_act_id", []),
            "attack_prompt": finding.get("attack_prompt"),
            "target_response": finding.get("target_response"),
            "target_latency_ms": finding.get("target_latency_ms"),
            "probed_at": _parse_iso(finding.get("probed_at")),
            "confidence": finding.get("confidence"),
            "reasoning": finding.get("reasoning"),
            "judge_model": finding.get("judge_model"),
            "escalated_model": finding.get("escalated_model"),
        },
    )


def decode_finding_row(row: dict) -> dict:
    """JSONB comes back from the driver as text.

    Left as a string, `evidence` would still be truthy in the report template
    while every attribute lookup on it silently returned undefined — a finding
    that quietly renders "no payment authorization was presented" over the top
    of captured evidence.
    """
    finding = dict(row)
    raw = finding.get("evidence")
    if isinstance(raw, str):
        try:
            finding["evidence"] = json.loads(raw)
        except ValueError:
            finding["evidence"] = None
    return finding


async def list_findings(run_id: UUID) -> list[dict]:
    rows = await database.fetch_all(
        "SELECT * FROM redteam_findings WHERE run_id = :run_id ORDER BY created_at",
        {"run_id": run_id},
    )
    return [decode_finding_row(r) for r in rows]
