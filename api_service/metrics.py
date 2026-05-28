"""Prometheus metric definitions for the planner option-picker wizard.

HTTP /metrics endpoint exposure is deferred to Task 17 (rollout/ops concern).
Most call sites live in routers/orchestrator.py and are wired as part of the
wizard lifecycle. Two metrics — WIZARD_FAST_FORWARDS_TOTAL and
WIZARD_LOCAL_SETUP_CHECKS_TOTAL — are defined but not yet wired; their call
sites depend on wizard tool paths that do not currently route through
api_service. They appear in /metrics as zero-valued placeholders for now.
"""
from prometheus_client import Counter, Histogram

WIZARD_ROUNDS_TOTAL = Histogram(
    "wizard_rounds_total",
    "Rounds completed per wizard dispatch",
    ["round_label", "dispatched_tool"],
    buckets=(1, 2, 3, 4, 5, 6, 7, 8, 9, float("inf")),
)
WIZARD_DISPATCH_TOOL_TOTAL = Counter(
    "wizard_dispatch_tool_total",
    "Wizard dispatches bucketed by dispatched tool name",
    ["tool"],
)
WIZARD_VALIDATION_ERRORS_TOTAL = Counter(
    "wizard_validation_errors_total",
    "Wizard input validation errors bucketed by error type",
    ["error_type"],
)
WIZARD_BACKS_TOTAL = Counter(
    "wizard_backs_total",
    "Wizard back navigations bucketed by from and to round label",
    ["from_round_label", "to_round_label"],
)
WIZARD_ABORTS_TOTAL = Counter(
    "wizard_aborts_total",
    "Wizard abort events bucketed by the round label at abort time",
    ["at_round_label"],
)
# No call site yet — observed from fast-forward path (future wizard tool hook).
WIZARD_FAST_FORWARDS_TOTAL = Counter(
    "wizard_fast_forwards_total",
    "Wizard fast-forward events bucketed by matched bound-context field count",
    ["matched_fields_count"],
)
# No call site yet — observed from local_setup_check resolution (future hook).
WIZARD_LOCAL_SETUP_CHECKS_TOTAL = Counter(
    "wizard_local_setup_checks_total",
    "Wizard local-setup check resolutions bucketed by outcome",
    ["resolution"],
)
WIZARD_ROUND_LATENCY_SECONDS = Histogram(
    "wizard_round_latency_seconds",
    "Latency between wizard_round emit and user answer",
    ["round_label"],
)
