"""Per-phase step budget allocation.

Phase 0 (auth): 2 steps if credentials provided, else 0.
Phase 1 (discovery): floor(15%) of non-auth budget, min 1.
Phase 2 (features): floor(35%) of non-auth budget, min 1.
Phase 3 (bug_hunt): remainder (>= 50% of non-auth budget by construction, min 1).

Using floor (not round) guarantees bug_hunt receives the lion's share and
prevents banker's-rounding from dropping it below 50%.
"""
from __future__ import annotations

import math


def allocate_phase_budgets(max_steps: int, has_credentials: bool) -> dict[str, int]:
    min_required = 5 if has_credentials else 4
    if max_steps < min_required:
        raise ValueError(
            f"max_steps must be >= {min_required} "
            f"(has_credentials={has_credentials}), got {max_steps}"
        )

    auth = 2 if has_credentials else 0
    remaining = max_steps - auth

    discovery = max(1, math.floor(remaining * 0.15))
    features = max(1, math.floor(remaining * 0.35))
    bug_hunt = remaining - discovery - features

    if bug_hunt < 1:
        bug_hunt = 1
        if features > 1:
            features -= 1
        elif discovery > 1:
            discovery -= 1

    return {
        "auth": auth,
        "discovery": discovery,
        "features": features,
        "bug_hunt": bug_hunt,
    }
