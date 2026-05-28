"""Smart model routing based on subscription plan and task complexity."""

import logging
import os
import re

logger = logging.getLogger("ModelRouter")

# Azure OpenAI models
_DEFAULT_MODEL = os.getenv("AZURE_OPENAI_MODEL", "gpt-5.4-mini")
_MINI_MODEL = os.getenv("AZURE_OPENAI_MINI_MODEL", "gpt-5.4-mini")

# Plan → allowed models mapping
PLAN_MODELS = {
    "free": {
        "browser": _MINI_MODEL,
        "script": _MINI_MODEL,
    },
    "starter": {
        "browser": _MINI_MODEL,
        "script": _MINI_MODEL,
    },
    "pro": {
        "browser": _DEFAULT_MODEL,
        "script": _DEFAULT_MODEL,
    },
    "enterprise": {
        "browser": _DEFAULT_MODEL,
        "script": _DEFAULT_MODEL,
    },
}

# Complexity indicators for smart routing (Pro plan only)
COMPLEX_INDICATORS = [
    r"multi[- ]?step",
    r"cross[- ]?system",
    r"integration",
    r"workflow",
    r"e2e",
    r"end[- ]?to[- ]?end",
    r"oauth",
    r"payment",
    r"checkout",
    r"database.*migration",
    r"microservice",
    r"api.*chain",
]

SIMPLE_INDICATORS = [
    r"login",
    r"form.*submit",
    r"button.*click",
    r"navigation",
    r"link.*check",
    r"simple",
    r"basic",
    r"single.*page",
]


def classify_complexity(content: str) -> str:
    """
    Classify task complexity as 'simple', 'complex', or 'cross_system'.
    Used only for Pro plan smart routing.
    """
    text = content.lower()

    complex_score = sum(1 for p in COMPLEX_INDICATORS if re.search(p, text))
    simple_score = sum(1 for p in SIMPLE_INDICATORS if re.search(p, text))

    # Cross-system: multiple integrations or explicit mentions
    cross_system_keywords = ["cross-system", "microservice", "api chain", "multi-service"]
    if any(kw in text for kw in cross_system_keywords) or complex_score >= 4:
        return "cross_system"
    elif complex_score > simple_score and complex_score >= 2:
        return "complex"
    else:
        return "simple"


def select_models(plan: str, content: str = "") -> dict:
    """
    Select browser and script models based on plan and content complexity.

    Returns:
        dict with keys: browser_model, script_model, routing_reason
    """
    if plan not in PLAN_MODELS:
        plan = "free"

    base = PLAN_MODELS[plan].copy()

    if plan in ("pro", "enterprise") and content:
        complexity = classify_complexity(content)
        logger.info(f"Smart routing: complexity={complexity}")

        if complexity == "cross_system":
            base["browser"] = _DEFAULT_MODEL
            base["script"] = _DEFAULT_MODEL
            routing_reason = f"cross_system → {_DEFAULT_MODEL}: complex multi-service scenario"
        elif complexity == "complex":
            base["browser"] = _DEFAULT_MODEL
            base["script"] = _DEFAULT_MODEL
            routing_reason = f"complex → {_DEFAULT_MODEL}: multi-step or integration scenario"
        else:
            base["browser"] = _MINI_MODEL
            base["script"] = _MINI_MODEL
            routing_reason = f"simple → {_MINI_MODEL}: standard test scenario (cost-optimized)"

        return {
            "browser_model": base["browser"],
            "script_model": base["script"],
            "routing_reason": routing_reason,
            "complexity": complexity,
        }

    return {
        "browser_model": base["browser"],
        "script_model": base.get("script", base["browser"]),
        "routing_reason": f"plan={plan}",
        "complexity": "n/a",
    }
